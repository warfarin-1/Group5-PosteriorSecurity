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

from py_ecc.bls.point_compression import (
    compress_G1 as _compress_G1, compress_G2 as _compress_G2,
    decompress_G1 as _decompress_G1, decompress_G2 as _decompress_G2,
)

from py_ecc.bls.hash_to_curve import hash_to_G2 as _hash_to_G2
from py_ecc.fields import optimized_bls12_381_FQ12 as _FQ12
from py_ecc.optimized_bls12_381 import (
    G1 as _G1,
    G2 as _G2,
    Z1 as _Z1,
    Z2 as _Z2,
    add as _add,
    b as _b,
    b2 as _b2,
    curve_order as _curve_order,
    eq as _eq,
    is_inf as _is_inf,
    is_on_curve as _is_on_curve,
    multiply as _multiply,
    normalize as _normalize,
    neg as _neg,
    pairing as _pairing,
)
from py_ecc.optimized_bls12_381.optimized_pairing import (
    final_exponentiate as _final_exponentiate,
    miller_loop as _miller_loop,
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


def encode_g1(point) -> bytes:
    """Canonical 48-byte compressed point, checked for subgroup membership."""
    if not is_valid_g1(point):
        raise ValueError("invalid G1 subgroup point")
    return int(_compress_G1(point)).to_bytes(48, "big")


def decode_g1(data: bytes) -> tuple:
    """Decode canonical compressed G1, including identity; reject other subgroups."""
    if not isinstance(data, bytes) or len(data) != 48:
        raise ValueError("G1 encoding must be exactly 48 bytes")
    point = _decompress_G1(int.from_bytes(data, "big"))
    if encode_g1(point) != data:
        raise ValueError("non-canonical G1 encoding")
    return point


def encode_g2(point) -> bytes:
    """Canonical 96-byte compressed point, checked for subgroup membership."""
    if not is_valid_g2(point):
        raise ValueError("invalid G2 subgroup point")
    return b"".join(int(x).to_bytes(48, "big") for x in _compress_G2(point))


def decode_g2(data: bytes) -> tuple:
    """Decode canonical compressed G2, including identity; reject other subgroups."""
    if not isinstance(data, bytes) or len(data) != 96:
        raise ValueError("G2 encoding must be exactly 96 bytes")
    point = _decompress_G2((int.from_bytes(data[:48], "big"), int.from_bytes(data[48:], "big")))
    if encode_g2(point) != data:
        raise ValueError("non-canonical G2 encoding")
    return point


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
    k = scalar % ORDER
    return point if k == 1 else _multiply(point, k)


def neg(point):
    """-point (additive inverse), for either G1 or G2."""
    return _neg(point)


def points_equal(p, q) -> bool:
    """Equality for G1/G2 points. Always use this instead of `==`."""
    return _eq(p, q)


_SUBGROUP_CACHE_MAX = 4096
_subgroup_cache = {}


def affine_key(point):
    """Hashable canonical form of a G1/G2 point (equal points, equal keys)."""
    if _is_inf(point):
        return None
    return tuple(
        tuple(c.coeffs) if hasattr(c, "coeffs") else c.n for c in _normalize(point)[:2]
    ) + (len(point[0].coeffs) if hasattr(point[0], "coeffs") else 1,)


def _in_subgroup(point, b) -> bool:
    """On-curve + order-p check, memoised on the affine coordinates.

    Verification re-checks the same public points (CRS, keys, parameters)
    on every call and several times within one call; each check is a full
    scalar multiplication, so remembering successful and failed results is
    a pure speed-up (the result depends only on the point's value).
    """
    if not _is_on_curve(point, b):
        return False
    try:
        key = (b is _b, affine_key(point))
    except (TypeError, AttributeError, ValueError):
        return _is_inf(_multiply(point, _curve_order))
    hit = _subgroup_cache.get(key)
    if hit is None:
        hit = _is_inf(_multiply(point, _curve_order))
        if len(_subgroup_cache) >= _SUBGROUP_CACHE_MAX:
            _subgroup_cache.clear()
        _subgroup_cache[key] = hit
    return hit


def is_valid_g1(point) -> bool:
    """True iff `point` is on the G1 curve and in the prime-order subgroup.

    Must be applied to any G1 element that came from an untrusted party
    (e.g. a proof) before pairing it: BLS12-381 G1 has a non-trivial
    cofactor, so an on-curve point can lie outside the order-p subgroup.
    """
    return _in_subgroup(point, _b)


def is_valid_g2(point) -> bool:
    """G2 analogue of `is_valid_g1`."""
    return _in_subgroup(point, _b2)


def multi_pairing_is_one(pairs) -> bool:
    """Check prod_i e(P_i, Q_i) == 1 for `pairs` = [(P_i in G1, Q_i in G2)].

    Runs all Miller loops and a single final exponentiation, which is
    several times cheaper than evaluating each pairing separately. Pairs
    containing the identity are skipped (they contribute 1).
    """
    acc = None
    for p1, q2 in pairs:
        if _is_inf(p1) or _is_inf(q2):
            continue
        m = _miller_loop(q2, p1, final_exponentiate=False)
        acc = m if acc is None else acc * m
    if acc is None:
        return True
    return _final_exponentiate(acc) == _FQ12.one()


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


def hash_to_g2(*parts: bytes, domain: bytes = b"posterior-security") -> tuple:
    """Deterministically map byte strings to a G2 point with *unknown*
    discrete log relative to G2 (a proper hash-to-curve map: RFC 9380
    -style SSWU + cofactor clearing, via py_ecc).

    Do NOT approximate this as "hash to a scalar, then multiply G2" --
    that makes the discrete log trivially computable (it's just the
    hash output), which breaks the binding property of anything built
    on top of the resulting point (e.g. a Pedersen commitment's second
    generator). Use this whenever a fresh "nothing up my sleeve"
    generator is needed.
    """
    dst = b"POSTERIOR-SECURITY-" + domain + b"_XMD:SHA-256_SSWU_RO_"
    return _hash_to_G2(b"|".join(parts), dst, hashlib.sha256)
