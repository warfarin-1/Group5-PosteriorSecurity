"""Thin wrapper around py_ecc's optimized BLS12-381 backend.

Concealed Signature (paper §5.3) works over an asymmetric pairing group
(G1, G2, GT, e) satisfying SXDH. This module is the only place that
imports py_ecc directly; everything else in the codebase goes through
these functions, so the backend can be swapped later without touching
callers.

Points are whatever representation py_ecc's optimized backend uses
internally (Jacobian coordinates) -- treat them as opaque values, and
always compare them with `points_equal`, never `==` (raw tuples with
different Z-coordinates can represent the same point).
"""

import hashlib
import secrets

from py_ecc.optimized_bls12_381 import (
    G1 as _G1,
    G2 as _G2,
    Z1 as _Z1,
    Z2 as _Z2,
    add as _add,
    curve_order as _curve_order,
    eq as _eq,
    multiply as _multiply,
    neg as _neg,
    pairing as _pairing,
)

# --- Public constants -------------------------------------------------

G1 = _G1
"""Generator of G1."""

G2 = _G2
"""Generator of G2."""

ZERO_G1 = _Z1
"""Identity element of G1."""

ZERO_G2 = _Z2
"""Identity element of G2."""

ORDER = _curve_order
"""Order p of the scalar field Zp (also the order of G1, G2, GT)."""


# --- Group operations ---------------------------------------------------

def add_g1(p, q):
    """p + q for two G1 points."""
    return _add(p, q)


def add_g2(p, q):
    """p + q for two G2 points."""
    return _add(p, q)


def scalar_mul(point, scalar: int):
    """scalar * point (additive notation for point^scalar).

    Works for G1 or G2 points; py_ecc dispatches on the point's field.
    `scalar` is reduced mod ORDER first, so callers don't need to.
    """
    return _multiply(point, scalar % ORDER)


def neg(point):
    """-point (additive inverse), for either G1 or G2."""
    return _neg(point)


def points_equal(p, q) -> bool:
    """Equality for G1/G2 points. Always use this instead of `==`."""
    return _eq(p, q)


def pairing(g2_point, g1_point):
    """e(Q, P) for Q in G2, P in G1 -> element of GT (FQ12).

    Note the argument order: G2 point first, matching py_ecc's convention.
    GT elements support `==` and `**` directly (unlike G1/G2 points).
    """
    return _pairing(g2_point, g1_point)


# --- Scalars -------------------------------------------------------------

def random_scalar() -> int:
    """Uniform random element of Zp \\ {0} (for keys, nonces, blinding)."""
    return secrets.randbelow(ORDER - 1) + 1


def hash_to_scalar(*parts: bytes, domain: bytes = b"posterior-security") -> int:
    """Deterministically map byte strings to an element of Zp.

    Domain-separated SHA-256 reduced mod p. The bias from reducing a
    256-bit hash mod a ~255-bit prime is cryptographically negligible for
    our purposes (this is not used as a hash-to-curve function, only for
    turning arbitrary messages/transcripts into scalars). Callers should
    pass a distinct `domain` tag per use site to keep hashes unlinkable
    across contexts (Fiat-Shamir style domain separation).
    """
    h = hashlib.sha256(domain + b"|" + b"|".join(parts)).digest()
    return int.from_bytes(h, "big") % ORDER
