"""Groth-Sahai proofs for pairing-product equations over an SXDH group.

Implements the non-interactive witness-indistinguishable / zero-knowledge
proof system of Groth-Sahai (Eurocrypt 2008) for *pairing-product
equations* (PPEs) in the asymmetric setting, in the 2x2-matrix notation
of Escala-Groth, "Fine-Tuning Groth-Sahai Proofs" (PKC 2014). Only the
PPE case with all variables being group elements is implemented -- that
is all the concealed Boneh-Boyen signature needs (see `zk_proof.py`).

Notation (additive for G1/G2, GT written multiplicatively):

    variables   x_i in G1  (i < nx)      y_j in G2  (j < ny)
    equation    sum_j e(A_j, y_j) + sum_i e(x_i, B_i)
                + sum_ij gamma_ij e(x_i, y_j)  =  target

with public A_j in G1, B_i in G2, gamma_ij in Zp and `target` a product
of pairings (a list of (G1, G2) pairs, empty = the identity).

Commitments live in G1^2 / G2^2: for a CRS with binding key
u1=(g1, a1 g1), u2 = t1 u1 (and the G2 analogue v1, v2),

    c_i = (0, x_i) + r_i1 u1 + r_i2 u2        d_j = (0, y_j) + s_j1 v1 + s_j2 v2

which is a perfectly binding, extractable ElGamal-style commitment under
this key, and computationally hiding under SXDH. The proof for each
equation is (pi_1, pi_2 in G2^2; theta_1, theta_2 in G1^2).

Trusted setup: `CRS.generate` samples the extraction trapdoors (a1, a2,
t1, t2) and discards them. Anyone who learns them can open every
commitment, which destroys zero-knowledge, so the CRS must come from a
party that really forgets them (or from an MPC ceremony in a real
deployment). See `zk_proof.py` for how the project uses this.
"""

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from posterior.pairing import (
    G1,
    G2,
    ORDER,
    ZERO_G1,
    ZERO_G2,
    add_g1,
    add_g2,
    is_valid_g1,
    is_valid_g2,
    multi_pairing_is_one,
    neg,
    random_scalar,
    scalar_mul,
)

Vec1 = Tuple[tuple, tuple]  # element of G1^2
Vec2 = Tuple[tuple, tuple]  # element of G2^2


# --- G1^2 / G2^2 vector helpers -----------------------------------------

def _iota1(x) -> Vec1:
    return (ZERO_G1, x)


def _iota2(y) -> Vec2:
    return (ZERO_G2, y)


def _vadd1(a: Vec1, b: Vec1) -> Vec1:
    return (add_g1(a[0], b[0]), add_g1(a[1], b[1]))


def _vadd2(a: Vec2, b: Vec2) -> Vec2:
    return (add_g2(a[0], b[0]), add_g2(a[1], b[1]))


def _vmul1(k: int, a: Vec1) -> Vec1:
    return (scalar_mul(a[0], k), scalar_mul(a[1], k))


def _vmul2(k: int, a: Vec2) -> Vec2:
    return (scalar_mul(a[0], k), scalar_mul(a[1], k))


_ZERO_VEC1: Vec1 = (ZERO_G1, ZERO_G1)
_ZERO_VEC2: Vec2 = (ZERO_G2, ZERO_G2)


# --- CRS ------------------------------------------------------------------

@dataclass(frozen=True)
class CRS:
    """Binding-mode SXDH Groth-Sahai common reference string."""

    u1: Vec1
    u2: Vec1
    v1: Vec2
    v2: Vec2

    @staticmethod
    def generate() -> "CRS":
        """Sample a fresh binding CRS and forget the trapdoors."""
        a1, a2 = random_scalar(), random_scalar()
        t1, t2 = random_scalar(), random_scalar()
        u1 = (G1, scalar_mul(G1, a1))
        v1 = (G2, scalar_mul(G2, a2))
        return CRS(u1=u1, u2=_vmul1(t1, u1), v1=v1, v2=_vmul2(t2, v1))

    def is_valid(self) -> bool:
        return all(is_valid_g1(p) for p in self.u1 + self.u2) and all(
            is_valid_g2(p) for p in self.v1 + self.v2
        )


# --- Commitments ------------------------------------------------------------

def commit_g1(x, crs: CRS) -> Tuple[Vec1, Tuple[int, int]]:
    """Commit to a G1 element. Returns (commitment, randomness (r1, r2))."""
    r = (random_scalar(), random_scalar())
    c = _vadd1(_iota1(x), _vadd1(_vmul1(r[0], crs.u1), _vmul1(r[1], crs.u2)))
    return c, r


def commit_g2(y, crs: CRS) -> Tuple[Vec2, Tuple[int, int]]:
    """Commit to a G2 element. Returns (commitment, randomness (s1, s2))."""
    s = (random_scalar(), random_scalar())
    d = _vadd2(_iota2(y), _vadd2(_vmul2(s[0], crs.v1), _vmul2(s[1], crs.v2)))
    return d, s


# --- Equations & proofs -------------------------------------------------------

@dataclass(frozen=True)
class PPE:
    """One pairing-product equation (see module docstring)."""

    A: Sequence[tuple]  # length ny, G1 constants paired with y_j
    B: Sequence[tuple]  # length nx, G2 constants paired with x_i
    gamma: Sequence[Sequence[int]]  # nx x ny, entries in Zp
    target: Sequence[Tuple[tuple, tuple]]  # product of pairings (G1, G2)

    @property
    def nx(self) -> int:
        return len(self.B)

    @property
    def ny(self) -> int:
        return len(self.A)


@dataclass(frozen=True)
class EqProof:
    pi: Tuple[Vec2, Vec2]  # pi_1, pi_2 in G2^2
    theta: Tuple[Vec1, Vec1]  # theta_1, theta_2 in G1^2


def prove_ppe(
    eq: PPE,
    xs: Sequence[tuple],
    ys: Sequence[tuple],
    R: Sequence[Tuple[int, int]],
    S: Sequence[Tuple[int, int]],
    crs: CRS,
) -> EqProof:
    """Proof that the committed (xs, ys) satisfy `eq`.

    `R[i]`, `S[j]` are the commitment randomness of x_i, y_j (the same
    commitments must be reused across all equations that share a
    variable -- that sharing is what ties the equations together).
    """
    u = (crs.u1, crs.u2)
    v = (crs.v1, crs.v2)
    T = [[random_scalar(), random_scalar()] for _ in range(2)]

    pi = []
    for k in range(2):
        # iota2( sum_i R_ik B_i + sum_ij gamma_ij R_ik y_j )
        g2_part = ZERO_G2
        for i in range(eq.nx):
            g2_part = add_g2(g2_part, scalar_mul(eq.B[i], R[i][k]))
            for j in range(eq.ny):
                coef = eq.gamma[i][j] * R[i][k]
                if coef % ORDER:
                    g2_part = add_g2(g2_part, scalar_mul(ys[j], coef))
        vec = _iota2(g2_part)
        # + sum_l (sum_ij gamma_ij R_ik S_jl + T_kl) v_l
        for l in range(2):
            coef = T[k][l]
            for i in range(eq.nx):
                for j in range(eq.ny):
                    coef += eq.gamma[i][j] * R[i][k] * S[j][l]
            vec = _vadd2(vec, _vmul2(coef, v[l]))
        pi.append(vec)

    theta = []
    for l in range(2):
        # iota1( sum_j S_jl A_j + sum_ij gamma_ij S_jl x_i ) - sum_k T_kl u_k
        g1_part = ZERO_G1
        for j in range(eq.ny):
            g1_part = add_g1(g1_part, scalar_mul(eq.A[j], S[j][l]))
            for i in range(eq.nx):
                coef = eq.gamma[i][j] * S[j][l]
                if coef % ORDER:
                    g1_part = add_g1(g1_part, scalar_mul(xs[i], coef))
        vec = _iota1(g1_part)
        for k in range(2):
            vec = _vadd1(vec, _vmul1(-T[k][l], u[k]))
        theta.append(vec)

    return EqProof(pi=(pi[0], pi[1]), theta=(theta[0], theta[1]))


def _proof_points_valid(proof: EqProof) -> bool:
    g2_pts = [p for vec in proof.pi for p in vec]
    g1_pts = [p for vec in proof.theta for p in vec]
    return all(is_valid_g2(p) for p in g2_pts) and all(is_valid_g1(p) for p in g1_pts)


def verify_ppes(
    eqs: Sequence[PPE],
    proofs: Sequence[EqProof],
    cs: Sequence[Vec1],
    ds: Sequence[Vec2],
    crs: CRS,
) -> bool:
    """Verify all equations against the commitments `cs` (G1) / `ds` (G2).

    The 2x2 matrix identity of every equation is checked at once via a
    random linear combination (random rank-one projection alpha^T M beta
    of each matrix, random per-equation weight), so the whole batch is a
    single product of pairings. A false statement slips through with
    probability O(1/p) over the verifier's randomness.
    """
    if len(eqs) != len(proofs):
        return False
    if not crs.is_valid():
        return False
    if not (
        all(is_valid_g1(p) for c in cs for p in c)
        and all(is_valid_g2(p) for d in ds for p in d)
        and all(_proof_points_valid(pf) for pf in proofs)
    ):
        return False

    alpha = (random_scalar(), random_scalar())
    beta = (random_scalar(), random_scalar())

    def pg1(vec: Vec1):  # alpha . vec  (G1)
        return add_g1(scalar_mul(vec[0], alpha[0]), scalar_mul(vec[1], alpha[1]))

    def pg2(vec: Vec2):  # beta . vec  (G2)
        return add_g2(scalar_mul(vec[0], beta[0]), scalar_mul(vec[1], beta[1]))

    pairs: List[Tuple[tuple, tuple]] = []  # we check prod e(P,Q) == 1
    # Projections are reused across equations, so compute them once.
    proj_c = [pg1(c) for c in cs]
    proj_d = [pg2(d) for d in ds]
    proj_u = [pg1(crs.u1), pg1(crs.u2)]
    proj_v = [pg2(crs.v1), pg2(crs.v2)]

    for eq, pf in zip(eqs, proofs):
        if len(cs) != eq.nx or len(ds) != eq.ny:
            return False
        rho = random_scalar()

        def lhs(p1, q2, k=1):
            pairs.append((scalar_mul(p1, rho * k), q2))

        # LHS: sum_j F(iota1 A_j, d_j) + sum_i F(c_i, iota2 B_i)
        #      + sum_ij gamma_ij F(c_i, d_j), projected by (alpha, beta).
        for j in range(eq.ny):
            lhs(scalar_mul(eq.A[j], alpha[1]), proj_d[j])
        for i in range(eq.nx):
            lhs(proj_c[i], scalar_mul(eq.B[i], beta[1]))
            for j in range(eq.ny):
                g = eq.gamma[i][j] % ORDER
                if g:
                    lhs(proj_c[i], proj_d[j], g)
        # RHS: iota_T(target) + sum_k F(u_k, pi_k) + sum_l F(theta_l, v_l);
        # move to the left by negating the G1 side.
        for p1, q2 in eq.target:
            pairs.append((neg(scalar_mul(p1, rho * alpha[1] * beta[1])), q2))
        for k in range(2):
            pairs.append((neg(scalar_mul(proj_u[k], rho)), pg2(pf.pi[k])))
        for l in range(2):
            pairs.append((neg(scalar_mul(pg1(pf.theta[l]), rho)), proj_v[l]))

    return multi_pairing_is_one(pairs)
