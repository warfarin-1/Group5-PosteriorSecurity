"""Correctness + tamper tests for the standard Boneh-Boyen baseline.

This is the object Concealed Signature will convert, and also our
no-privacy performance baseline: later benchmarks compare Concealed's
Convert/CVerify/Decom overhead against plain Sign/Verify here.
"""

from posterior.boneh_boyen import Signature, hash_message, keygen, sign, verify
from posterior.pairing import G1, add_g1


def test_sign_then_verify_succeeds():
    sk, vk = keygen()
    m = hash_message(b"hello, world")
    sigma = sign(m, sk)
    assert verify(sigma, m, vk)


def test_wrong_message_is_rejected():
    sk, vk = keygen()
    sigma = sign(hash_message(b"original message"), sk)
    assert not verify(sigma, hash_message(b"tampered message"), vk)


def test_tampered_s_is_rejected():
    sk, vk = keygen()
    m = hash_message(b"hello")
    sigma = sign(m, sk)
    tampered = Signature(s=add_g1(sigma.s, G1), r=sigma.r)
    assert not verify(tampered, m, vk)


def test_tampered_r_is_rejected():
    sk, vk = keygen()
    m = hash_message(b"hello")
    sigma = sign(m, sk)
    tampered = Signature(s=sigma.s, r=sigma.r + 1)
    assert not verify(tampered, m, vk)


def test_signature_from_wrong_key_is_rejected():
    sk1, _ = keygen()
    _, vk2 = keygen()
    m = hash_message(b"hello")
    sigma = sign(m, sk1)
    assert not verify(sigma, m, vk2)


def test_boundary_messages():
    sk, vk = keygen()
    for m in (0, 1, 2**300):  # 0, smallest nonzero, and larger than the order
        sigma = sign(m, sk)
        assert verify(sigma, m, vk)
