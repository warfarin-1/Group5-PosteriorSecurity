# Part B: concealed signatures and wire format

The implementation follows the team's internal task split (Part A–D).
It uses A's existing Groth–Sahai proof without changing its interface.

## API

```python
from posterior import boneh_boyen as bb
from posterior import concealed, cs_params, serialization as wire

params = cs_params.setup()  # once, in a trusted setup
sk, vk = bb.keygen()
m = bb.hash_message(b"payment reference")
result = concealed.convert(bb.sign(m, sk), m, vk, params)
assert result is not None  # None represents the paper's bottom symbol
cs, opening = result
assert concealed.cverify(cs, vk, params)
assert concealed.decom(m, cs, opening, params)
assert not concealed.decom((m + 1) % bb.ORDER, cs, opening, params)

# Give these public bytes to another process; retain opening privately.
parameter_bytes = wire.encode_params(params)
signature_bytes = wire.encode_cs(cs)
received_params = wire.decode_params(parameter_bytes)
received_cs = wire.decode_cs(signature_bytes)
assert concealed.cverify(received_cs, vk, received_params)
print(wire.signature_size(cs))  # 2504
```

For scripts use `PYTHONPATH=src` (PowerShell: `$env:PYTHONPATH = 'src'`).
Tests already obtain this path from `pyproject.toml`.

`convert(signature, message, vk, params)` validates the BB signature, public
key and parameters before sampling a fresh uniform opening in `[0, ORDER)`.
It returns `(ConcealedSignature(proof, C), opening)`; rejected inputs return
`None`. Public signatures contain no message, original signature or opening.
Messages, original signature nonces and openings must be canonical integers
in `[0, ORDER)`; booleans and integers outside this range are rejected.

`cverify(cs, vk, params)` takes no message or opening and returns a boolean.
Malformed inputs return `False`. `decom(message, cs, opening, params)` checks
the commitment opening only. A revealed message is accepted only when both
`cverify` and `decom` succeed. This distinction avoids repeating an expensive
proof verification whenever an already verified commitment is opened.

Parameters are explicit: every participant must use the same CRS. A fresh
`setup()` call produces a new, incompatible CRS. The wire format can carry
public parameters across processes; it never serializes setup trapdoors.

## Binary format v1

Each object starts with a four-byte ASCII type/version tag. Points use the
installed `py_ecc` compressed BLS12-381 format: 48 bytes for G1, 96 bytes for
G2; integers are big endian. No new dependency was added. Backend imports
remain in `pairing.py`.

| Object | Tag | Payload order | Total bytes |
|---|---|---|---:|
| Proof | `PSP1` | `c_s`, `c_xt`, `c_xr` (two G1 each); `d_w1`, `d_w2` (two G2 each); three equation proofs, each `pi` (four G2) then `theta` (four G1) | 2404 |
| ConcealedSignature | `PSC1` | `C` (G2), complete tagged Proof | 2504 |
| CRS | `PSR1` | `u1`, `u2` (two G1 each), `v1`, `v2` (two G2 each) | 580 |
| PublicParameters | `PST1` | `h2` (G2), complete tagged CRS | 680 |

Proof point vectors and matrices use their tuple order. The proof payload
contains 18 G1 and 16 G2 points: 2400 bytes. The public signature's raw point
payload is 2496 bytes; its two tags add eight bytes. `signature_size(cs)`
measures the actual 2504-byte encoded object, excluding shared parameters,
the public key and the private opening. This is an encoding-specific size,
not a claim that the implementation achieves the paper's most compact proof.

Use `encode_proof/decode_proof`, `encode_cs/decode_cs`, `encode_crs/decode_crs`
and `encode_params/decode_params`. Decoders require exact type/version/length,
canonical coordinates and prime-order subgroup membership. Identity points
are legal proof/commitment components; parameter bases must be nonidentity,
and the first CRS coordinates must match the implementation's generators.
Invalid encodings raise `ValueError`. Deserialization does not verify a
signature: call `cverify` after decoding.

CRS point checks cannot certify honest generation, erasure of trapdoors or
the required linear dependencies. Likewise a supplied `h2` cannot be checked
for an unknown discrete logarithm. Obtain parameters from a trusted source;
production setup ceremonies and parameter authentication are outside Part B.

## Verification and limits

Run `.venv\python.exe -m pytest -q` on the current Windows environment.
If the existing pytest cache directory is not writable, add
`-p no:cacheprovider`. To export the hiding-game properties without the
default xunit2 compatibility warning, add
`-o junit_family=xunit1 --junitxml=../part_b_tests.xml`.
`test_b_assembly.py` checks B's integration, failures and boundary messages;
C retains ownership of its planned broader end-to-end and edge-case suites.
Serialization tests include round trips, rejection of wrong lengths/tags,
off-subgroup G1/G2 points and verification in a fresh Python process.
Integrity tests modify every one of the 34 GS proof point slots with a valid
subgroup point addition, change the public key and reject invalid BB inputs.

The message-hiding game uses eight real conversions/validations with the
signing key and both candidate signatures available to its fixed public-bit
adversary. Trial counts and successes are recorded as JUnit properties.
There is deliberately no success-rate pass threshold: eight trials have very
little statistical power. This is a smoke test, not evidence establishing
cryptographic indistinguishability. The exact toy Pedersen distribution test
checks only the hiding algebra. Neither replaces A's planned GS simulator
tests or a security proof. Trusted setup and the inherited group-element
(rather than scalar) extraction limitation remain as documented in `gs.py`
and `zk_proof.py`.

AI assisted the Part B implementation, tests and this integration note on
2026-10-17; execution evidence is in the tests and `docs/evidence/`.

## Branch delivery record (2026-10-30)

Part B is delivered on `part-b/concealed-signatures-2026-10-30`, created
from `cc901ca`. This delivery includes explicit shared public parameters,
Convert/CVerify/Decom, compressed point and object serialization, subgroup
checks, integration and boundary tests, a message-hiding smoke test, and
proof-tampering rejection tests. Local environment settings are excluded.

Validation on 2026-10-30: `106 passed in 606.44s`, with no warnings, using
`.venv\python.exe -m pytest -q -p no:cacheprovider -o junit_family=xunit1
--junitxml=../part_b_tests-2026-10-30.xml`. The XML report is kept outside
the repository. `pip check` and the staged diff whitespace check also passed.
The GitHub push targets only this new branch; `main` is not a push target.
