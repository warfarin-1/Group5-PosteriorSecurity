# Implementation decisions and open review items

This records decisions visible in the source and tests, rather than inventing
historical discussions. It supplements the local plan and `PART_B.md`.

| Issue | Implemented choice | Consequence / evidence |
|---|---|---|
| Message representation | canonical int in `[0,ORDER)` at concealed API; bytes can be hashed | reject bool, floats, negatives and modulus aliases rather than silently reduce; low-level BB API assumes valid inputs |
| Setup ownership | explicit `PublicParameters(h2,crs)` | serialize and distribute once; a fresh setup is incompatible |
| h2 generation | deterministic, domain-separated hash to G2 | avoids constructing h2 with a known discrete log; custom supplied parameters still require trust |
| Proof mechanism | actual GS PPE implementation, not fallback Sigma | old plan/README references to undecided proof mechanism are stale |
| Scalar witnesses in GS | shared commitments to group encodings, three linked PPEs | extraction gives group elements, not integer t/r; security-reduction correspondence needs review by A |
| Decom semantics | only the Pedersen opening is checked | an opening can pass for a signature with an invalid proof; require CVerify AND Decom to accept a signed message |
| Failure values | Convert: `None`; CVerify/Decom: `False` for supported malformed inputs; wire decoder: `ValueError` | consumers must distinguish parsing from verification; internal prover/runtime errors are not all swallowed |
| Randomness endpoints | uniform t includes zero | valid `m=t=0` gives identity commitment; proof/commitment identity is allowed, parameter identity is rejected |
| Repeated opening | caller API samples fresh t; test-only replacement demonstrates reuse | `C2-C1=(m2-m1)g2`; low-entropy differences become guessable, so never intentionally reuse t |
| Serialization | compressed BLS12-381, explicit version/type tags, subgroup checks | decoder accepts valid group objects without authenticating the proof or parameter provenance |
| Size comparison | CS wire bytes vs BB point/scalar payload | 2504 B vs 80 B; formats differ in headers; no shared parameters/vk/opening charged per signature |
| Timing boundaries | public APIs, setup/keygen/serialization outside intervals | Convert includes original BB verification; CVerify includes input validation; Decom is opening only |
| Timing comparison | report both Convert+CVerify and full Sign+Convert+CVerify+Decom | conversion assumes an existing signature; full workflow is useful for lifecycle cost but performs additional functionality |
| Benchmark sample count | default 20 measured trials plus one warmup; median and interpolated IQR | fulfills evaluation-plan target; CLI allows smaller debugging runs but those should not be represented as full evaluation |
| Hiding experiment | B's 8-trial smoke test, no success-rate gate | cannot establish statistical indistinguishability or replace a proof; not repeated 1000 times just to satisfy stale plan text |
| Security tests | malformed/tampered inputs and wrong openings are rejected | passing tests do not establish q-SDH, SXDH, full unforgeability, or zero knowledge |

## Items still outside C's completed work

- A: GS simulator-based tests, proof/reduction review, trusted-setup and
  extraction caveats, optional verifier optimization. Current parameter
  checks cannot establish honest generation or trapdoor destruction.
- D: CBDC demo, release packaging and presentation. This implementation does
  **not** contain a range proof; a hidden transaction amount is not thereby
  proved positive or within a balance.
- Incognito: background reference only, no claim of implementing it or
  directly comparing distinct privacy goals using our measured numbers.

## Implementation report material

The core engineering problem was expressing exponent witnesses in a
group-element PPE interface. The implemented solution uses E1/E2/E3 with
shared commitments, documented in `PAPER_MAP_CONCEALED.md`. A second problem
was sharing a CRS across processes: explicit serializable parameters remove
dependence on the process-local default CRS. Parsing validates encodings
and subgroup membership; signature authentication remains a separate step.

Part C extends these checks with multi-message workflows, mixed proof and
commitment rejection, malformed field tests and an explicit demonstration
of opening reuse leakage. The evaluation preserves raw samples and timing
boundaries so that privacy overhead is not conflated with setup, plotting
or serialization costs. Environment and source revision metadata accompany
the measured data. See `PART_C.md` for results and reproduction commands.

AI assisted Part C code, tests, evaluation and these notes on 2026-10-30.
