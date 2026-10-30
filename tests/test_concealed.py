"""C: complete workflows and binding across independently created signatures."""

from dataclasses import replace

import pytest

from posterior import boneh_boyen as bb
from posterior import concealed, serialization as wire
from posterior.pairing import ORDER


@pytest.mark.parametrize("message", [1, ORDER // 2, bb.hash_message(b"C: settlement")])
def test_message_roundtrip_after_transport(concealed_case, message):
    params, sk, vk, _, _, _, _ = concealed_case
    signature = bb.sign(message, sk)
    assert bb.verify(signature, message, vk)
    cs, opening = concealed.convert(signature, message, vk, params)
    public = wire.decode_cs(wire.encode_cs(cs))
    shared = wire.decode_params(wire.encode_params(params))
    assert concealed.cverify(public, vk, shared)
    assert concealed.decom(message, public, opening, shared)
    assert not concealed.decom((message + 1) % ORDER, public, opening, shared)


def test_commitment_and_proof_cannot_be_spliced(concealed_case, monkeypatch):
    params, sk, vk, message, _, cs, opening = concealed_case
    # Force a different commitment without relying on a random inequality.
    other_message = (message + 1) % ORDER
    monkeypatch.setattr(concealed, "_random_opening", lambda: opening)
    other, _ = concealed.convert(bb.sign(other_message, sk), other_message, vk, params)
    mixed = replace(other, proof=cs.proof)
    assert not concealed.cverify(mixed, vk, params)
    # A valid opening alone does not authenticate a signed message.
    assert concealed.decom(other_message, mixed, opening, params)
