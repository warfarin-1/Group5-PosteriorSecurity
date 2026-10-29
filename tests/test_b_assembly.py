"""B integration checks; C can add its broader end-to-end/edge-case suite."""

from dataclasses import replace

import pytest

from posterior import concealed, cs_params
from posterior.pairing import ORDER, ZERO_G2


def test_convert_verify_open(concealed_case):
    params, _, vk, message, _, cs, aux = concealed_case
    assert concealed.cverify(cs, vk, params)
    assert concealed.decom(message, cs, aux, params)
    assert not concealed.decom((message + 1) % ORDER, cs, aux, params)
    assert not concealed.decom(message, cs, (aux + 1) % ORDER, params)


@pytest.mark.parametrize("bad", [-1, ORDER, True, None, "message"])
def test_noncanonical_message_rejected(concealed_case, bad):
    params, _, vk, _, sig, cs, aux = concealed_case
    assert concealed.convert(sig, bad, vk, params) is None
    assert not concealed.decom(bad, cs, aux, params)


def test_bottom_and_malformed_inputs(concealed_case):
    params, _, vk, message, sig, cs, aux = concealed_case
    assert concealed.convert(None, message, vk, params) is None
    assert not concealed.cverify(None, vk, params)
    assert not concealed.cverify(replace(cs, proof=object()), vk, params)
    assert not concealed.cverify(replace(cs, proof=replace(cs.proof, c_s=())), vk, params)
    assert not concealed.cverify(replace(cs, C=(1,)), vk, params)
    assert not concealed.cverify(replace(cs, C={}), vk, params)
    assert not concealed.cverify(cs, vk, replace(params, h2={}))
    assert concealed.convert(sig, message, replace(vk, X=ZERO_G2), params) is None
    assert not concealed.decom(message, cs, True, params)
    assert not concealed.cverify(cs, vk, replace(params, h2=ZERO_G2))


def test_wrong_crs_rejected(concealed_case):
    _, _, vk, _, _, cs, _ = concealed_case
    assert not concealed.cverify(cs, vk, cs_params.setup())


@pytest.mark.parametrize("message", [0, ORDER - 1])
def test_boundary_messages_and_zero_opening(concealed_case, monkeypatch, message):
    from posterior import boneh_boyen as bb
    params, sk, vk, _, _, _, _ = concealed_case
    monkeypatch.setattr(concealed, "_random_opening", lambda: 0)
    cs, aux = concealed.convert(bb.sign(message, sk), message, vk, params)
    assert aux == 0
    assert concealed.cverify(cs, vk, params)
    assert concealed.decom(message, cs, aux, params)
