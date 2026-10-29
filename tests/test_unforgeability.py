"""Negative integrity tests, not a proof of cryptographic unforgeability."""

from dataclasses import replace

import pytest

from posterior import concealed, serialization as wire
from posterior.pairing import G1, G2, ORDER, add_g1, add_g2, encode_g1, encode_g2


def test_invalid_original_signature_returns_bottom(concealed_case):
    params, _, vk, message, sig, _, _ = concealed_case
    assert concealed.convert(replace(sig, s=add_g1(sig.s, G1)), message, vk, params) is None
    assert concealed.convert(sig, (message + 1) % ORDER, vk, params) is None


@pytest.mark.parametrize("which", ["X", "Y"])
def test_replay_with_changed_key(concealed_case, which):
    params, _, vk, _, _, cs, _ = concealed_case
    bad = replace(vk, **{which: add_g2(getattr(vk, which), G2)})
    assert not concealed.cverify(cs, bad, params)


# Every one of the 34 point slots (commitments and all three equation proofs).
_SLOTS = [(4 + 48 * i, 48) for i in range(6)]
_SLOTS += [(292 + 96 * i, 96) for i in range(4)]
for _eq in range(3):
    _base = 676 + _eq * 576
    _SLOTS += [(_base + i * 96, 96) for i in range(4)]
    _SLOTS += [(_base + 384 + i * 48, 48) for i in range(4)]


@pytest.mark.parametrize("offset,size", _SLOTS)
def test_every_proof_point_tamper_rejected(concealed_case, offset, size):
    params, _, vk, _, _, cs, _ = concealed_case
    encoded = wire.encode_proof(cs.proof)
    from posterior.pairing import decode_g1, decode_g2
    decode, encode, add, generator = (
        (decode_g1, encode_g1, add_g1, G1) if size == 48
        else (decode_g2, encode_g2, add_g2, G2)
    )
    changed = encode(add(decode(encoded[offset:offset + size]), generator))
    proof = wire.decode_proof(encoded[:offset] + changed + encoded[offset + size:])
    assert not concealed.cverify(replace(cs, proof=proof), vk, params)
