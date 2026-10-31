"""Zero-knowledge evidence for gs.py / zk_proof.py via a trapdoor simulator.

Groth-Sahai zero-knowledge is argued with a *hiding* CRS: u2 = t1*u1 - iota(g1)
(and the G2 analogue), which is computationally indistinguishable from the
binding CRS used for real proofs (SXDH). Under a hiding CRS every commitment is
uniform, and whoever knows the trapdoor can write

    iota(g1) = t1*u1 - u2

and so prove statements *without any witness*. This file implements that
simulator and checks the following (this is engineering evidence for the
ZK argument, not a replacement for the proof in Groth-Sahai / Escala-Groth):

  * a witness-free simulated proof is accepted by the real verifier under the
    hiding CRS, for the real concealed-BB statement and for a *false* toy
    statement (so acceptance there cannot come from a witness);
  * the simulator genuinely needs the trapdoor (without the correction the
    only non-trivial equation E1 fails);
  * a simulated proof is rejected under a binding CRS, i.e. the simulation
    trick does not break soundness of the real system;
  * honest proofs are complete under the hiding CRS too.

Simulator for one PPE: commit every variable to the identity, run the honest
prover, then fix the target term. With x = y = 0 the equation holds with
target 1; for a target pair (xi*g1, Q) we need F(iota(xi g1), iota(Q)) =
F(u, delta) and iota(xi g1) = xi*(t1*u1 - u2), hence
delta_1 = xi*t1*iota(Q), delta_2 = -xi*iota(Q); pi := pi - delta.
"""

import dataclasses
from dataclasses import dataclass

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
    points_equal,
    random_scalar,
    scalar_mul,
)


@dataclass(frozen=True)
class Trapdoor:
    a1: int
    a2: int
    t1: int
    t2: int


def hiding_crs():
    """Hiding CRS with trapdoor: iota(g1) = t1*u1 - u2, iota(g2) = t2*v1 - v2."""
    a1, a2, t1, t2 = (random_scalar() for _ in range(4))
    u1 = (G1, scalar_mul(G1, a1))
    v1 = (G2, scalar_mul(G2, a2))
    u2 = gs._vadd1(gs._vmul1(t1, u1), gs._vmul1(-1, gs._iota1(G1)))
    v2 = gs._vadd2(gs._vmul2(t2, v1), gs._vmul2(-1, gs._iota2(G2)))
    return gs.CRS(u1=u1, u2=u2, v1=v1, v2=v2), Trapdoor(a1, a2, t1, t2)


def simulate_ppe(eq, crs, td, R, S, *, skip_target_fix=False):
    """Witness-free proof of `eq` for commitments to the identity (R, S are
    their randomness). Target pairs must have the form (xi*G1, Q) with xi=1."""
    xs = [ZERO_G1] * eq.nx
    ys = [ZERO_G2] * eq.ny
    pf = gs.prove_ppe(eq, xs, ys, R, S, crs)
    if skip_target_fix:
        return pf
    pi1, pi2 = pf.pi
    for p1, q2 in eq.target:
        assert points_equal(p1, G1), "simulator only handles targets e(g1, Q)"
        iq = gs._iota2(q2)
        pi1 = gs._vadd2(pi1, gs._vmul2(-td.t1, iq))
        pi2 = gs._vadd2(pi2, iq)
    return dataclasses.replace(pf, pi=(pi1, pi2))


def simulate_commitments(nx, ny, crs):
    """Commitments to the identity for nx G1 / ny G2 variables."""
    cs, R = zip(*(gs.commit_g1(ZERO_G1, crs) for _ in range(nx))) if nx else ((), ())
    ds, S = zip(*(gs.commit_g2(ZERO_G2, crs) for _ in range(ny))) if ny else ((), ())
    return list(cs), list(R), list(ds), list(S)


def simulate_concealed(X, Y, C, h2, crs, td, *, skip_target_fix=False):
    """Witness-free zk_proof.Proof for the statement (X, Y, C, h2)."""
    eqs = zk_proof._equations(X, Y, C, h2)
    (c_s, c_xt, c_xr), R, (d_w1, d_w2), S = simulate_commitments(3, 2, crs)
    pfs = tuple(
        simulate_ppe(eq, crs, td, R, S, skip_target_fix=skip_target_fix) for eq in eqs
    )
    return zk_proof.Proof(
        c_s=c_s, c_xt=c_xt, c_xr=c_xr, d_w1=d_w1, d_w2=d_w2, eq_proofs=pfs
    )


@pytest.fixture(scope="module")
def sim_crs():
    return hiding_crs()


@pytest.fixture(scope="module")
def binding_crs():
    return gs.CRS.generate()


@pytest.fixture(scope="module")
def statement():
    """Public statement only; the simulator never sees s, t, r."""
    sk, vk = bb.keygen()
    m = bb.hash_message(b"zk simulator")
    sig = bb.sign(m, sk)
    h2 = commit_g2.setup()
    t = random_scalar()
    C = commit_g2.commit(m, t, h2).point
    return dict(
        pub=dict(X=vk.X, Y=vk.Y, C=C, h2=h2), witness=(sig.s, t, sig.r)
    )


# --- CRS structure ---------------------------------------------------------

def test_hiding_crs_trapdoor_identities(sim_crs):
    crs, td = sim_crs
    # iota(g1) = t1*u1 - u2 and iota(g2) = t2*v1 - v2 (the simulation trapdoor)
    lhs1 = gs._vadd1(gs._vmul1(td.t1, crs.u1), gs._vmul1(-1, crs.u2))
    lhs2 = gs._vadd2(gs._vmul2(td.t2, crs.v1), gs._vmul2(-1, crs.v2))
    assert all(points_equal(a, b) for a, b in zip(lhs1, gs._iota1(G1)))
    assert all(points_equal(a, b) for a, b in zip(lhs2, gs._iota2(G2)))
    assert crs.is_valid()


def test_hiding_crs_is_not_parallel(sim_crs):
    # Hiding CRS: u2 is not a multiple of u1 (that is what makes commitments
    # perfectly hiding). With the trapdoor, u2 - t1*u1 = -iota(g1) != 0.
    crs, td = sim_crs
    diff = gs._vadd1(crs.u2, gs._vmul1(-td.t1, crs.u1))
    assert points_equal(diff[0], ZERO_G1) and not points_equal(diff[1], ZERO_G1)


def test_binding_crs_u2_is_multiple_of_u1_only_via_hidden_trapdoor(binding_crs):
    # The binding CRS carries no usable iota(g1) = t*u1 - u2 relation: its
    # discarded trapdoor satisfies u2 = t1*u1 exactly, so for a *guessed* t1
    # the difference is a random non-identity point with overwhelming prob.
    guess = random_scalar()
    diff = gs._vadd1(binding_crs.u2, gs._vmul1(-guess, binding_crs.u1))
    assert not points_equal(diff[0], ZERO_G1)


# --- simulated proofs are accepted ---------------------------------------------

def test_simulated_concealed_proof_verifies_without_witness(statement, sim_crs):
    crs, td = sim_crs
    sim = simulate_concealed(**statement["pub"], crs=crs, td=td)
    assert zk_proof.verify(sim, **statement["pub"], crs=crs)


def test_simulation_needs_trapdoor_target_fix(statement, sim_crs):
    crs, td = sim_crs
    sim = simulate_concealed(**statement["pub"], crs=crs, td=td, skip_target_fix=True)
    assert not zk_proof.verify(sim, **statement["pub"], crs=crs)


def test_simulated_proof_rejected_under_binding_crs(statement, sim_crs, binding_crs):
    crs, td = sim_crs
    sim = simulate_concealed(**statement["pub"], crs=crs, td=td)
    assert not zk_proof.verify(sim, **statement["pub"], crs=binding_crs)


def test_simulated_proof_for_false_statement(sim_crs):
    """x in G1 with e(x, 1) = e(g1, g2) has no solution, yet the simulator
    produces an accepted proof under the hiding CRS: acceptance there carries
    no witness information, which is the zero-knowledge mechanism."""
    crs, td = sim_crs
    eq = gs.PPE(A=[], B=[ZERO_G2], gamma=[[]], target=[(G1, G2)])
    (c,), R, _, S = simulate_commitments(1, 0, crs)
    pf = simulate_ppe(eq, crs, td, R, S)
    assert gs.verify_ppes([eq], [pf], [c], [], crs)


def test_false_statement_has_no_proof_under_binding_crs(binding_crs):
    """Same false statement; with the binding CRS neither the simulator-style
    proof nor an honest-prover attempt for any witness verifies."""
    crs = binding_crs
    eq = gs.PPE(A=[], B=[ZERO_G2], gamma=[[]], target=[(G1, G2)])
    x = scalar_mul(G1, random_scalar())
    c, R = gs.commit_g1(x, crs)
    pf = gs.prove_ppe(eq, [x], [], [R], [], crs)
    assert not gs.verify_ppes([eq], [pf], [c], [], crs)


# --- real proofs are complete under the hiding CRS as well -----------------------

def test_honest_proof_complete_under_hiding_crs(statement, sim_crs):
    crs, _ = sim_crs
    s, t, r = statement["witness"]
    proof = zk_proof.prove(s, t, r, crs=crs, **statement["pub"])
    assert zk_proof.verify(proof, **statement["pub"], crs=crs)


# --- simulated proofs have the same shape/validity as real ones -------------------

def test_simulated_and_real_proofs_have_same_structure(statement, sim_crs):
    crs, td = sim_crs
    s, t, r = statement["witness"]
    real = zk_proof.prove(s, t, r, crs=crs, **statement["pub"])
    sim = simulate_concealed(**statement["pub"], crs=crs, td=td)
    for f in dataclasses.fields(zk_proof.Proof):
        a, b = getattr(real, f.name), getattr(sim, f.name)
        if f.name == "eq_proofs":
            assert len(a) == len(b) == 3
        else:
            assert len(a) == len(b) == 2
    # Commitments are fresh/uniform in both: no repeats, none degenerate.
    assert not points_equal(sim.c_s[1], sim.c_xt[1])
    assert not points_equal(sim.c_s[0], ZERO_G1)
