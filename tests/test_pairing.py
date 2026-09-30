"""Sanity tests for the pairing group wrapper: bilinearity and identities.

If these fail, nothing built on top of `pairing.py` can be trusted, so
this is the first thing to run after any change to that module.
"""

from posterior.pairing import (
    G1,
    G2,
    ORDER,
    ZERO_G1,
    add_g1,
    hash_to_scalar,
    neg,
    pairing,
    points_equal,
    random_scalar,
    scalar_mul,
)


def test_bilinearity_scalar_on_both_sides():
    a, b = 7, 11
    p = scalar_mul(G1, a)
    q = scalar_mul(G2, b)
    assert pairing(q, p) == pairing(G2, G1) ** (a * b)


def test_bilinearity_additive_on_g1():
    p = scalar_mul(G1, 5)
    assert pairing(G2, add_g1(p, p)) == pairing(G2, p) ** 2


def test_additive_inverse_is_identity():
    p = scalar_mul(G1, 42)
    assert points_equal(add_g1(p, neg(p)), ZERO_G1)


def test_scalar_mul_wraps_mod_order():
    k = 9
    assert points_equal(scalar_mul(G1, k), scalar_mul(G1, ORDER + k))


def test_random_scalar_in_range():
    for _ in range(20):
        r = random_scalar()
        assert 0 < r < ORDER


def test_hash_to_scalar_deterministic_and_domain_separated():
    a = hash_to_scalar(b"hello")
    b = hash_to_scalar(b"hello")
    c = hash_to_scalar(b"hello", domain=b"other-domain")
    assert a == b
    assert a != c
    assert 0 <= a < ORDER
