import os
from pathlib import Path
import subprocess
import sys
from dataclasses import replace

import pytest

from posterior import concealed, serialization as wire
from posterior.pairing import (
    G1, G2, ZERO_G1, ZERO_G2, decode_g1, decode_g2, encode_g1, encode_g2,
)


def test_all_roundtrips_and_sizes(concealed_case):
    params, _, vk, message, _, cs, aux = concealed_case
    for obj, encode, decode, size in (
        (cs.proof, wire.encode_proof, wire.decode_proof, 2404),
        (cs, wire.encode_cs, wire.decode_cs, 2504),
        (params.crs, wire.encode_crs, wire.decode_crs, 580),
        (params, wire.encode_params, wire.decode_params, 680),
    ):
        encoded = encode(obj)
        assert len(encoded) == size
        assert encode(decode(encoded)) == encoded
        for bad in (encoded[:-1], encoded + b"\x00", b"BAD!" + encoded[4:]):
            with pytest.raises(ValueError):
                decode(bad)
    assert wire.signature_size(cs) == 2504
    restored = wire.decode_cs(wire.encode_cs(cs))
    shared = wire.decode_params(wire.encode_params(params))
    assert concealed.cverify(restored, vk, shared)
    assert concealed.decom(message, restored, aux, shared)


def test_shared_parameters_in_fresh_process(concealed_case):
    params, _, vk, message, _, cs, aux = concealed_case
    payload = wire.encode_params(params) + wire.encode_cs(cs) + encode_g2(vk.X) + encode_g2(vk.Y)
    code = """
import sys
from posterior import concealed, serialization as w
from posterior.boneh_boyen import VerifyKey
from posterior.pairing import decode_g2
d = sys.stdin.buffer.read()
p = w.decode_params(d[:680])
c = w.decode_cs(d[680:3184])
vk = VerifyKey(decode_g2(d[3184:3280]), decode_g2(d[3280:3376]))
assert concealed.cverify(c, vk, p)
assert concealed.decom(int(sys.argv[1]), c, int(sys.argv[2]), p)
"""
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    result = subprocess.run([sys.executable, "-c", code, str(message), str(aux)],
                            input=payload, capture_output=True, env=env, timeout=120)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("point,encode,decode,size", [
    (G1, encode_g1, decode_g1, 48), (ZERO_G1, encode_g1, decode_g1, 48),
    (G2, encode_g2, decode_g2, 96), (ZERO_G2, encode_g2, decode_g2, 96),
])
def test_point_encoding(point, encode, decode, size):
    encoded = encode(point)
    assert encode(decode(encoded)) == encoded
    for bad in (bytes(size), b"\xff" * size, encoded[:-1], encoded + b"\x00"):
        with pytest.raises(ValueError):
            decode(bad)


def test_decode_rejects_non_subgroup_points(concealed_case):
    # Compression alone accepts curve points outside the prime-order subgroup.
    from py_ecc.bls.point_compression import compress_G1, compress_G2, decompress_G1, decompress_G2
    from py_ecc.optimized_bls12_381 import FQ, field_modulus as q, multiply, is_inf
    from posterior.pairing import ORDER
    for x in range(1, 100):
        y = pow((x**3 + 4) % q, (q + 1) // 4, q)
        if (y*y - x**3 - 4) % q == 0:
            pt1 = (FQ(x), FQ(y), FQ(1))
            if not is_inf(multiply(pt1, ORDER)):
                break
    else:
        pytest.fail("no test G1 point found")
    raw1 = int(compress_G1(pt1)).to_bytes(48, "big")
    assert not is_inf(multiply(decompress_G1(int.from_bytes(raw1, "big")), ORDER))
    # Find a decompressible G2 point without cofactor clearing.
    for x in range(1, 100):
        try:
            pt2 = decompress_G2(((1 << 383) + x, 0))
        except ValueError:
            continue
        if not is_inf(multiply(pt2, ORDER)):
            break
    else:
        pytest.fail("no test G2 point found")
    raw2 = b"".join(int(n).to_bytes(48, "big") for n in compress_G2(pt2))
    for raw, decode in ((raw1, decode_g1), (raw2, decode_g2)):
        with pytest.raises(ValueError):
            decode(raw)
    params, _, _, _, _, cs, _ = concealed_case
    proof = wire.encode_proof(cs.proof)
    with pytest.raises(ValueError):
        wire.decode_proof(proof[:4] + raw1 + proof[52:])
    encoded = wire.encode_cs(cs)
    with pytest.raises(ValueError):
        wire.decode_cs(encoded[:4] + raw2 + encoded[100:])
    with pytest.raises(ValueError):
        wire.encode_params(replace(params, h2=ZERO_G2))
    with pytest.raises(ValueError):
        wire.encode_crs(replace(params.crs, u2=(ZERO_G1, ZERO_G1)))


def test_decode_does_not_replace_verification(concealed_case):
    from posterior.pairing import add_g2
    params, _, vk, _, _, cs, _ = concealed_case
    changed = replace(cs, C=add_g2(cs.C, G2))
    decoded = wire.decode_cs(wire.encode_cs(changed))
    assert not concealed.cverify(decoded, vk, params)
