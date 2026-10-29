"""C: malformed fields, parameter binding and consequences of opening reuse."""

from dataclasses import replace

import pytest

from posterior import boneh_boyen as bb
from posterior import concealed
from posterior.pairing import G1, G2, ORDER, add_g2, neg, points_equal, scalar_mul


@pytest.mark.parametrize("value", [-1, ORDER, True, 1.5, b"0", {}, None])
def test_invalid_nonce_and_opening(concealed_case, value):
    params, _, vk, message, signature, cs, _ = concealed_case
    assert concealed.convert(replace(signature, r=value), message, vk, params) is None
    assert not concealed.decom(message, cs, value, params)


@pytest.mark.parametrize("field", ["X", "Y"])
def test_malformed_key_fields(concealed_case, field):
    params, _, vk, message, signature, cs, _ = concealed_case
    bad = replace(vk, **{field: {}})
    assert concealed.convert(signature, message, bad, params) is None
    assert not concealed.cverify(cs, bad, params)


@pytest.mark.parametrize("field", ["c_s", "c_xt", "c_xr", "d_w1", "d_w2", "eq_proofs"])
def test_malformed_proof_vectors(concealed_case, field):
    params, _, vk, _, _, cs, _ = concealed_case
    assert not concealed.cverify(replace(cs, proof=replace(cs.proof, **{field: ()})), vk, params)


def test_wrong_h2_and_malformed_crs(concealed_case):
    params, _, vk, message, signature, cs, opening = concealed_case
    changed = replace(params, h2=add_g2(params.h2, G2))
    assert not concealed.cverify(cs, vk, changed)
    if opening != 0:
        assert not concealed.decom(message, cs, opening, changed)
    bad = replace(params, crs=replace(params.crs, u1=(G1,)))
    assert concealed.convert(signature, message, vk, bad) is None
    assert not concealed.cverify(cs, vk, bad)
    assert not concealed.decom(message, cs, opening, bad)


@pytest.mark.parametrize("field", ["pi", "theta"])
def test_malformed_equation_matrix(concealed_case, field):
    params, _, vk, _, _, cs, _ = concealed_case
    equations = list(cs.proof.eq_proofs)
    equations[1] = replace(equations[1], **{field: ((G1,),)})
    bad = replace(cs, proof=replace(cs.proof, eq_proofs=tuple(equations)))
    assert not concealed.cverify(bad, vk, params)


def test_reused_opening_leaks_message_difference(concealed_case, monkeypatch):
    params, sk, vk, _, _, _, _ = concealed_case
    monkeypatch.setattr(concealed, "_random_opening", lambda: 7)
    first, t1 = concealed.convert(bb.sign(10, sk), 10, vk, params)
    second, t2 = concealed.convert(bb.sign(11, sk), 11, vk, params)
    assert t1 == t2 == 7
    for message, cs in ((10, first), (11, second)):
        assert concealed.cverify(cs, vk, params)
        assert concealed.decom(message, cs, 7, params)
    difference = add_g2(second.C, neg(first.C))
    assert points_equal(difference, G2)  # C2 - C1 = (m2-m1) g2
    assert not concealed.decom(11, first, 7, params)


def test_identity_commitment_is_valid_for_zero_opening(concealed_case, monkeypatch):
    params, sk, vk, _, _, _, _ = concealed_case
    monkeypatch.setattr(concealed, "_random_opening", lambda: 0)
    cs, opening = concealed.convert(bb.sign(0, sk), 0, vk, params)
    assert points_equal(cs.C, scalar_mul(G2, 0))
    assert concealed.cverify(cs, vk, params)
    assert concealed.decom(0, cs, opening, params)
