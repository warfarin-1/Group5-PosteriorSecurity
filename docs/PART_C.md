# Part C: tests, evaluation and implementation notes

Part C extends the Part B APIs without changing cryptographic algorithms.
It is delivered on `part-c/evaluation-and-docs-2026-10-30`, based on Part B
commit `4157a1c`. Only this new branch is a GitHub push target; `main` is
not modified. The dated measurement snapshot is included with the delivery.

## Delivered files

- `tests/test_concealed.py`: multiple messages through signing, conversion,
  parameter/signature transport, verification and opening; proof/commitment
  splicing rejection even when the substituted commitment opens correctly.
- `tests/test_edge_cases.py`: malformed nonce/opening/key fields, proof vector
  and equation-matrix shapes, incompatible h2/CRS, valid identity commitment,
  and an explicit demonstration of opening reuse exposing message differences.
- `bench/run_bench_concealed.py`: 20 measured trials by default, one warmup,
  per-operation raw timings, paired workflow timings, median/IQR, actual byte
  counts, Python/platform/backend/source metadata. It does not export secrets.
- `bench/plot_results.py`: headless PNG/SVG timing and size charts.
- `PAPER_MAP_CONCEALED.md`, `AMBIGUITIES.md`: current formula/API mapping,
  implemented choices, evidence limits and material for the report.
- Root README: corrected stale implementation status and proof-mechanism
  text, added running/evaluation commands. Final demo/release work remains D's.
- `requirements.txt`: added `matplotlib==3.9.4` (supports project Python 3.9).

Existing B tests already cover 34 proof-point slots, subgroups, independent
processes and an eight-trial hiding smoke test. C complements that coverage.

## Reproduce

From the repository root in the existing Windows Conda prefix:

```powershell
.\.venv\python.exe -m pip install -r requirements.txt
.\.venv\python.exe -m pytest -q -p no:cacheprovider -o junit_family=xunit1 --junitxml=../part_c_tests.xml
.\.venv\python.exe bench/run_bench_concealed.py --repeats 20 --warmup 1 --output bench/results/local
.\.venv\python.exe bench/plot_results.py --input bench/results/local
```

The benchmark runs sequentially; avoid other CPU-heavy jobs while measuring.
Each sample signs a different hashed message under a shared key/CRS and uses
fresh cryptographic randomness. Setup, key generation, correctness checks
outside the API being timed, and encoding are excluded from timing. No
timer call includes plotting or file I/O. Public API validation is included.

`raw.csv` has 20 samples for each of five operations and three workflow
totals. Totals are sums **within the same trial**, then summarized; summing
separate medians is not used. Quartiles interpolate at `(n-1)*q`, with
`IQR=Q3-Q1`. These are descriptive measurements of this machine, not confidence
intervals or claims about production performance.

Compare `BB Sign+Verify` with `Convert+CVerify` only as the conversion-stage
cost for an existing signature. The complete concealed lifecycle is also
reported as `Sign+Convert+CVerify+Decom`; Convert already verifies BB, so
there is no additional standalone Verify in that total. Decom checks only
the opening and is not a substitute for CVerify.

Sizes compare a compressed BB payload (48-byte point + 32-byte nonce,
**80 B**, without a custom tag) with the tagged CS wire format (**2504 B**).
Shared parameters (**680 B**), vk and private opening are separate. CS is
31.30 times the BB payload size (2424 additional bytes), with eight bytes
of CS/proof type tags included. The proof itself is 2404 B. This is an
implementation-specific encoding comparison, not the paper's compactness claim.

Result files live in `bench/results/2026-10-31/` (re-run after the Part A verifier
optimisation; see the note below). Although generated result
directories are ignored by default, this dated snapshot is explicitly tracked, including raw samples, metadata and PNG/SVG charts.

## Verification and measured results

Final C test run on 2026-10-30: **24 passed in 82.17s**, no warnings:
`pytest -q -p no:cacheprovider tests/test_concealed.py tests/test_edge_cases.py
-o junit_family=xunit1 --junitxml=../part_c_tests-2026-10-30.xml`.
The XML is outside the repository. B's earlier full-suite run was 106 passed;
that unchanged suite was not rerun in this C session. `pip check`, compilation
of source/tests/bench and `git diff --check` passed.

Measured on Windows / Intel64 Family 6 Model 154, Python 3.9.13,
py-ecc 8.0.0; **n=20 after one excluded warmup**, sequential execution:

| Operation / workflow | Median (ms) | IQR (ms) |
|---|---:|---:|
| BB Sign | 7.968 | 0.733 |
| BB Verify | 1041.955 | 88.482 |
| Convert (including BB verification) | 3322.319 | 326.423 |
| CVerify | 2315.166 | 186.104 |
| Decom | 77.264 | 5.119 |
| BB Sign + Verify | 1050.077 | 87.351 |
| Convert + CVerify | 5663.227 | 446.248 |
| Sign + Convert + CVerify + Decom | 5747.848 | 447.691 |

The ratio of medians for conversion-stage cost vs BB Sign+Verify is **5.39x**;
for the complete concealed lifecycle it is **5.47x**. These comparisons
perform different functionality and must be read with the timing boundaries
above. They are local measurements, not paper numbers or optimized-backend
performance predictions. CVerify costs **2.22x** a plain BB Verify.

**Re-run note (2026-10-31).** The first Part C snapshot (`2026-10-30`, still
in the repository history) predates Part A's verifier optimisation and was
taken on a different machine (Intel64 Family 6 Model 170, Python 3.9.23), so
the two snapshots are *not* a controlled before/after comparison; the
optimisation's own effect was measured on one machine (single `cverify`
3.8 s -> 2.3 s, see `SECURITY_ARGUMENT.md` §5). The old numbers were:
CVerify 3943.954 ms, Decom 345.626 ms, Convert+CVerify 7716.062 ms, full
workflow 8064.135 ms (ratios 7.33x / 7.66x). This snapshot's repository
revision is recorded in its `metadata.json`.

Results: [raw samples](../bench/results/2026-10-31/raw.csv),
[summary](../bench/results/2026-10-31/summary.csv),
[metadata](../bench/results/2026-10-31/metadata.json),
[timings](../bench/results/2026-10-31/timings.png),
[sizes](../bench/results/2026-10-31/sizes.png), plus SVG versions.
The 160 raw rows (8 operations/workflows x 20 trials), per-trial totals and
benchmark source hash were independently checked. Both charts were visually
inspected. The dated snapshot is included on the delivery branch so these
links also resolve on GitHub.

Matplotlib's default home cache was not writable on the first render;
the script now defaults its cache to a writable temporary directory using
`MPLCONFIGDIR`, while respecting an existing user setting. Rerendering passed
without the cache warning.

## Security and scope

Opening-reuse tests deliberately replace only `_random_opening`; they do not
weaken BB or GS randomness. Reusing t is not prevented by a stateful global
registry: fresh independent sampling is the API's design. Differences in
commitments can then reveal small message differences if t is reused.

Tests establish rejection behavior and successful workflows. They do not
prove SXDH/q-SDH assumptions, a full unforgeability reduction or statistical
message hiding. A's GS simulator/security review remains separate. D's demo,
Incognito background experiment and final packaging remain separate.

AI assisted Part C implementation, tests, evaluation and documentation on
2026-10-30; execution evidence is recorded in the local `process.md`.
