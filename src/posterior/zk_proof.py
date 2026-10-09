"""Zero-knowledge proof of knowledge for the concealed Boneh-Boyen
signature (paper §5.3):

    e(s, X . C . h2^-t . Y^r) = e(g1, g2)
    witness: s in G1, t, r in Zp          public: X, Y (BB public key), C, h2

Groth-Sahai proofs (see `gs.py`) handle pairing-product equations whose
variables are *group elements*, whereas t and r are exponents. We turn
the relation into a system of three pure PPEs by introducing four extra
hidden group elements, each pinned to an exponent through a fixed,
public base:

    w1 = h2^-t,  w2 = Y^r      (in G2)        xt = g1^t,  xr = g1^r  (in G1)

    (E1)  e(s, X.C) . e(s, w1) . e(s, w2)  =  e(g1, g2)       [quadratic]
    (E2)  e(g1, w1) . e(xt, h2)            =  1               [linear]
    (E3)  e(g1, w2) . e(xr, Y^-1)          =  1               [linear]

E2 forces w1 = h2^-t' and E3 forces w2 = Y^r' for the exponents t', r'
with xt = g1^t', xr = g1^r' (the groups are cyclic of prime order), and
E1 then says e(s, X.C.h2^-t'.Y^r') = e(g1, g2). The same commitments to
s, w1, w2, xt, xr are shared by all three equations, which is what ties
them together. Soundness (perfect, binding CRS) and zero-knowledge
(SXDH) are inherited from Groth-Sahai; the proof contains only
commitments and the per-equation proof elements -- never s, t or r.

The extractable witness is (s, h2^-t', Y^r', g1^t', g1^r'); extraction
of t', r' as integers is not possible in general (the usual Groth-Sahai
caveat for exponents), which is why the Pedersen commitment's binding
and the BB unforgeability reduction in the paper go through group
elements only.
"""

from dataclasses import dataclass
from typing import Optional, Tuple

from posterior import gs
from posterior.pairing import G1, G2, ZERO_G1, ZERO_G2, add_g2, neg, scalar_mul

_crs_cache: Optional[gs.CRS] = None


def setup() -> gs.CRS:
    """Generate a fresh Groth-Sahai CRS (trusted setup; see `gs.CRS`)."""
    return gs.CRS.generate()


def default_crs() -> gs.CRS:
    """Process-wide CRS, generated on first use. Both prover and verifier
    in the same process share it; to use a CRS across processes, create
    one with `setup()` and pass it explicitly to `prove`/`verify`."""
    global _crs_cache
    if _crs_cache is None:
        _crs_cache = setup()
    return _crs_cache


@dataclass(frozen=True)
class Proof:
    """Commitments to the hidden variables plus one proof per equation."""

    c_s: gs.Vec1
    c_xt: gs.Vec1
    c_xr: gs.Vec1
    d_w1: gs.Vec2
    d_w2: gs.Vec2
    eq_proofs: Tuple[gs.EqProof, gs.EqProof, gs.EqProof]


def _equations(X, Y, C, h2):
    """The three PPEs over variables x = (s, xt, xr), y = (w1, w2)."""
    xc = add_g2(X, C)
    e1 = gs.PPE(
        A=[ZERO_G1, ZERO_G1],
        B=[xc, ZERO_G2, ZERO_G2],
        gamma=[[1, 1], [0, 0], [0, 0]],
        target=[(G1, G2)],
    )
    e2 = gs.PPE(
        A=[G1, ZERO_G1],
        B=[ZERO_G2, h2, ZERO_G2],
        gamma=[[0, 0]] * 3,
        target=[],
    )
    e3 = gs.PPE(
        A=[ZERO_G1, G1],
        B=[ZERO_G2, ZERO_G2, neg(Y)],
        gamma=[[0, 0]] * 3,
        target=[],
    )
    return [e1, e2, e3]


def prove(
    s: tuple,
    t: int,
    r: int,
    *,
    X: tuple,
    Y: tuple,
    C: tuple,
    h2: tuple,
    crs: Optional[gs.CRS] = None,
) -> Proof:
    """Prove knowledge of (s, t, r) with e(s, X.C.h2^-t.Y^r) = e(g1, g2).

    This does not check that the witness is valid: a proof for a false
    witness is produced just the same and simply fails `verify`.
    """
    crs = crs or default_crs()
    w1 = neg(scalar_mul(h2, t))
    w2 = scalar_mul(Y, r)
    xt = scalar_mul(G1, t)
    xr = scalar_mul(G1, r)

    c_s, R_s = gs.commit_g1(s, crs)
    c_xt, R_xt = gs.commit_g1(xt, crs)
    c_xr, R_xr = gs.commit_g1(xr, crs)
    d_w1, S_w1 = gs.commit_g2(w1, crs)
    d_w2, S_w2 = gs.commit_g2(w2, crs)

    xs, R = [s, xt, xr], [R_s, R_xt, R_xr]
    ys, S = [w1, w2], [S_w1, S_w2]
    eq_proofs = tuple(
        gs.prove_ppe(eq, xs, ys, R, S, crs) for eq in _equations(X, Y, C, h2)
    )
    return Proof(c_s=c_s, c_xt=c_xt, c_xr=c_xr, d_w1=d_w1, d_w2=d_w2, eq_proofs=eq_proofs)


def verify(
    proof: Proof,
    *,
    X: tuple,
    Y: tuple,
    C: tuple,
    h2: tuple,
    crs: Optional[gs.CRS] = None,
) -> bool:
    """Verify `proof` against the public statement (X, Y, C, h2)."""
    crs = crs or default_crs()
    return gs.verify_ppes(
        _equations(X, Y, C, h2),
        list(proof.eq_proofs),
        [proof.c_s, proof.c_xt, proof.c_xr],
        [proof.d_w1, proof.d_w2],
        crs,
    )
