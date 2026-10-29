"""Small real-CRS hiding-game smoke test and exact toy Pedersen sanity check.

T=8 intentionally avoids thousands of slow GS proofs. No success-rate gate:
eight trials cannot establish indistinguishability. Simulator-based GS ZK
testing belongs to A; these tests catch exposed witnesses/reused outputs only.
"""

import secrets
from dataclasses import fields

from posterior import boneh_boyen as bb
from posterior import concealed, serialization as wire


def _candidate_adversary(public, sk, messages, signatures):
    # Knows signing key, candidate messages and original signatures, but no t.
    # A fixed public-bit distinguisher is only a smoke-test adversary.
    return public[-1] & 1


def test_small_message_hiding_game(concealed_case, record_property):
    params, sk, vk, _, _, _, _ = concealed_case
    messages = (0, 1)
    signatures = tuple(bb.sign(m, sk) for m in messages)
    successes, seen = 0, set()
    assert {f.name for f in fields(concealed.ConcealedSignature)} == {"proof", "C"}
    assert not {"s", "t", "r", "message"} & {f.name for f in fields(wire.zk_proof.Proof)}
    for _ in range(8):
        bit = secrets.randbelow(2)
        cs, opening = concealed.convert(signatures[bit], messages[bit], vk, params)
        public = wire.encode_cs(cs)
        assert public not in seen
        seen.add(public)
        assert concealed.cverify(cs, vk, params)
        assert concealed.decom(messages[bit], cs, opening, params)
        successes += _candidate_adversary(public, sk, messages, signatures) == bit
    record_property("hiding_game_trials", 8)
    record_property("hiding_game_successes", successes)
    record_property("limitation", "smoke test only; no statistical security claim")


def test_toy_pedersen_uniform_distribution():
    # Exhaustive scalar-exponent model: uniform t permutes all group elements
    # for each m. This checks algebra, not the real CRS's ZK property.
    p, h = 101, 7
    for m in (0, 1, p - 1):
        assert sorted((m + h * t) % p for t in range(p)) == list(range(p))
