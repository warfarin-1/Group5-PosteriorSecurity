"""Tests for gs.py (Groth-Sahai PPE proofs) and zk_proof.py (the concealed
Boneh-Boyen relation).

Pairings are slow in pure Python, so expensive objects are built once per
module and tests that only differ in what they tamper with reuse them.
"""

import dataclasses

import pytest

from posterior import boneh_boyen as bb
from posterior import commit_g2, gs, zk_proof
from posterior.pairing import (
    G1,
    G2,
    ORDER,
    ZERO_G1,
    ZERO_G2,
    add_g1,
    add_g2,
    neg,
    pairing,
    points_equal,
    random_scalar,
    scalar_mul,
)


@pytest.fixture(scope="module")
def crs():
    return gs.CRS.generate()


@pytest.fixture(scope="module")
def statement():
    """A real BB signature converted to a commitment: everything the prover
    knows (s, t, r) and the public statement (X, Y, C, h2)."""
    sk, vk = bb.keygen()
    m = bb.hash_message(b"hello concealed world")
    sig = bb.sign(m, sk)
    assert bb.verify(sig, m, vk)
    h2 = commit_g2.setup()
    t = random_scalar()
    C = commit_g2.commit(m, t, h2).point
    return dict(s=sig.s, t=t, r=sig.r, X=vk.X, Y=vk.Y, C=C, h2=h2, m=m)


def pub(st):
    return dict(X=st["X"], Y=st["Y"], C=st["C"], h2=st["h2"])


@pytest.fixture(scope="module")
def good_proof(statement, crs):
    return zk_proof.prove(
        statement["s"], statement["t"], statement["r"], crs=crs, **pub(statement)
    )


# --- zk_proof: completeness ----------------------------------------------

def test_honest_proof_verifies(good_proof, statement, crs):
    assert zk_proof.verify(good_proof, crs=crs, **pub(statement))


def test_proof_is_randomised(statement, crs, good_proof):
    other = zk_proof.prove(
        statement["s"], statement["t"], statement["r"], crs=crs, **pub(statement)
    )
    assert not points_equal(other.c_s[1], good_proof.c_s[1])
    assert zk_proof.verify(other, crs=crs, **pub(statement))


def test_proof_object_does_not_carry_witness(good_proof, statement):
    fields = {f.name for f in dataclasses.fields(good_proof)}
    assert not fields & {"s", "t", "r"}
    # and none of the stored elements is the plaintext signature element
    for vec in (good_proof.c_s, good_proof.c_xt, good_proof.c_xr):
        assert not any(points_equal(p, statement["s"]) for p in vec)


# --- zk_proof: soundness against wrong statements / witnesses ---------------

def test_rejects_wrong_commitment(good_proof, statement, crs):
    st = pub(statement)
    st["C"] = add_g2(st["C"], G2)  # a different message commitment
    assert not zk_proof.verify(good_proof, crs=crs, **st)


@pytest.mark.parametrize("field", ["X", "Y", "h2"])
def test_rejects_wrong_public_value(good_proof, statement, crs, field):
    st = pub(statement)
    st[field] = scalar_mul(st[field], 2)
    assert not zk_proof.verify(good_proof, crs=crs, **st)


@pytest.mark.parametrize("bad", ["s", "t", "r"])
def test_proof_for_wrong_witness_is_rejected(statement, crs, bad):
    w = dict(s=statement["s"], t=statement["t"], r=statement["r"])
    if bad == "s":
        w["s"] = add_g1(w["s"], G1)
    else:
        w[bad] = (w[bad] + 1) % ORDER
    proof = zk_proof.prove(w["s"], w["t"], w["r"], crs=crs, **pub(statement))
    assert not zk_proof.verify(proof, crs=crs, **pub(statement))


def test_rejects_unlinked_exponent_witnesses(statement, crs):
    """The attack that breaks naive 'auxiliary witness' encodings: w1 is
    consistent with E1 (so E1 holds) but xt hides a *different* exponent.
    The linear equation E2 must catch it."""
    st = pub(statement)
    t, r = statement["t"], statement["r"]
    t_fake = (t + 12345) % ORDER
    # Choose the G2 variable w1 for the *fake* t so E1 can be made to hold
    # only if we also fudge s -- instead we keep E1 valid with the true
    # (w1, w2) and bind xt to a different exponent.
    w1 = neg(scalar_mul(st["h2"], t))
    w2 = scalar_mul(st["Y"], r)
    xt = scalar_mul(G1, t_fake)  # mismatched with w1
    xr = scalar_mul(G1, r)
    s = statement["s"]
    c_s, R_s = gs.commit_g1(s, crs)
    c_xt, R_xt = gs.commit_g1(xt, crs)
    c_xr, R_xr = gs.commit_g1(xr, crs)
    d_w1, S_w1 = gs.commit_g2(w1, crs)
    d_w2, S_w2 = gs.commit_g2(w2, crs)
    eqs = zk_proof._equations(**{k: st[k] for k in ("X", "Y", "C", "h2")})
    pfs = [
        gs.prove_ppe(eq, [s, xt, xr], [w1, w2], [R_s, R_xt, R_xr], [S_w1, S_w2], crs)
        for eq in eqs
    ]
    assert not gs.verify_ppes(eqs, pfs, [c_s, c_xt, c_xr], [d_w1, d_w2], crs)


# --- zk_proof: tampering with the proof itself --------------------------------

_JUNK_G1 = scalar_mul(G1, 987654321)
_JUNK_G2 = scalar_mul(G2, 123456789)


def _tweak_vec(vec, which, junk):
    lst = list(vec)
    lst[which] = add_g1(lst[which], junk) if junk is _JUNK_G1 else add_g2(lst[which], junk)
    return tuple(lst)


@pytest.mark.parametrize("name", ["c_s", "c_xt", "c_xr"])
@pytest.mark.parametrize("which", [0, 1])
def test_rejects_tampered_g1_commitment(good_proof, statement, crs, name, which):
    bad = dataclasses.replace(
        good_proof, **{name: _tweak_vec(getattr(good_proof, name), which, _JUNK_G1)}
    )
    assert not zk_proof.verify(bad, crs=crs, **pub(statement))


@pytest.mark.parametrize("name", ["d_w1", "d_w2"])
def test_rejects_tampered_g2_commitment(good_proof, statement, crs, name):
    bad = dataclasses.replace(
        good_proof, **{name: _tweak_vec(getattr(good_proof, name), 1, _JUNK_G2)}
    )
    assert not zk_proof.verify(bad, crs=crs, **pub(statement))


@pytest.mark.parametrize("eq_idx", [0, 1, 2])
@pytest.mark.parametrize("part", ["pi", "theta"])
def test_rejects_tampered_equation_proof(good_proof, statement, crs, eq_idx, part):
    ep = good_proof.eq_proofs[eq_idx]
    if part == "pi":
        vecs = (_tweak_vec(ep.pi[0], 1, _JUNK_G2), ep.pi[1])
        new_ep = dataclasses.replace(ep, pi=vecs)
    else:
        vecs = (_tweak_vec(ep.theta[0], 1, _JUNK_G1), ep.theta[1])
        new_ep = dataclasses.replace(ep, theta=vecs)
    pfs = list(good_proof.eq_proofs)
    pfs[eq_idx] = new_ep
    bad = dataclasses.replace(good_proof, eq_proofs=tuple(pfs))
    assert not zk_proof.verify(bad, crs=crs, **pub(statement))


def test_rejects_swapped_equation_proofs(good_proof, statement, crs):
    e = list(good_proof.eq_proofs)
    e[1], e[2] = e[2], e[1]
    bad = dataclasses.replace(good_proof, eq_proofs=tuple(e))
    assert not zk_proof.verify(bad, crs=crs, **pub(statement))


def test_rejects_proof_under_a_different_crs(good_proof, statement):
    assert not zk_proof.verify(good_proof, crs=gs.CRS.generate(), **pub(statement))


def test_rejects_point_outside_subgroup(good_proof, statement, crs):
    """A G1 point on the curve but outside the order-p subgroup."""
    from py_ecc.optimized_bls12_381 import FQ, b, is_on_curve, multiply, is_inf

    # find a curve point by trying x = 1, 2, ...; cofactor-clear NOT applied
    x = 1
    while True:
        y2 = x**3 + 4
        y = pow(y2, (0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB + 1) // 4, 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB)
        if (y * y - y2) % 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB == 0:
            pt = (FQ(x), FQ(y), FQ(1))
            if is_on_curve(pt, b) and not is_inf(multiply(pt, ORDER)):
                break
        x += 1
    bad = dataclasses.replace(good_proof, c_s=(good_proof.c_s[0], pt))
    assert not zk_proof.verify(bad, crs=crs, **pub(statement))


# --- gs.py directly: toy PPE, checked against a naive reference verifier -------

def _reference_verify(eq, proof, cs, ds, crs):
    """Entry-by-entry check of the 2x2 GT matrix identity (no batching)."""
    u, v = (crs.u1, crs.u2), (crs.v1, crs.v2)

    def e(p1, q2):
        return pairing(q2, p1)

    iota1 = lambda a: (ZERO_G1, a)
    iota2 = lambda b: (ZERO_G2, b)
    for a in range(2):
        for b_ in range(2):
            lhs = None
            terms = []
            for j in range(eq.ny):
                terms.append(e(iota1(eq.A[j])[a], ds[j][b_]))
            for i in range(eq.nx):
                terms.append(e(cs[i][a], iota2(eq.B[i])[b_]))
                for j in range(eq.ny):
                    terms.append(e(cs[i][a], ds[j][b_]) ** (eq.gamma[i][j] % ORDER))
            rhs_terms = []
            if a == 1 and b_ == 1:
                for p1, q2 in eq.target:
                    rhs_terms.append(e(p1, q2))
            for k in range(2):
                rhs_terms.append(e(u[k][a], proof.pi[k][b_]))
            for l in range(2):
                rhs_terms.append(e(proof.theta[l][a], v[l][b_]))
            lhs = terms[0]
            for t_ in terms[1:]:
                lhs = lhs * t_
            rhs = rhs_terms[0]
            for t_ in rhs_terms[1:]:
                rhs = rhs * t_
            if lhs != rhs:
                return False
    return True


def _toy(crs, x, y):
    eq = gs.PPE(A=[ZERO_G1], B=[ZERO_G2], gamma=[[1]], target=[(x, y)])
    c, R = gs.commit_g1(x, crs)
    d, S = gs.commit_g2(y, crs)
    return eq, c, d, gs.prove_ppe(eq, [x], [y], [R], [S], crs)


def test_toy_ppe_reference_and_batched_agree(crs):
    x, y = scalar_mul(G1, 7), scalar_mul(G2, 11)
    eq, c, d, pf = _toy(crs, x, y)
    assert _reference_verify(eq, pf, [c], [d], crs)
    assert gs.verify_ppes([eq], [pf], [c], [d], crs)
    # false statement: same proof, different claimed target
    eq_bad = dataclasses.replace(eq, target=[(scalar_mul(G1, 8), y)])
    assert not _reference_verify(eq_bad, pf, [c], [d], crs)
    assert not gs.verify_ppes([eq_bad], [pf], [c], [d], crs)


def test_ppe_with_constants_and_gamma(crs):
    """e(A, y) . e(x, B) . e(x, y)^3 = target, exercising every term kind."""
    x, y = scalar_mul(G1, 5), scalar_mul(G2, 9)
    A, B = scalar_mul(G1, 2), scalar_mul(G2, 3)
    # e(A,y) e(x,B) e(x,y)^3 = e(G1,G2)^(2*9 + 5*3 + 3*5*9)
    k = 2 * 9 + 5 * 3 + 3 * 5 * 9
    eq = gs.PPE(A=[A], B=[B], gamma=[[3]], target=[(scalar_mul(G1, k), G2)])
    c, R = gs.commit_g1(x, crs)
    d, S = gs.commit_g2(y, crs)
    pf = gs.prove_ppe(eq, [x], [y], [R], [S], crs)
    assert gs.verify_ppes([eq], [pf], [c], [d], crs)
    wrong = dataclasses.replace(eq, target=[(scalar_mul(G1, k + 1), G2)])
    assert not gs.verify_ppes([wrong], [pf], [c], [d], crs)
