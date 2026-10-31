# Group5-PosteriorSecurity

FIT5163 Assignment 2 (Programming Option) — a reproduction/implementation project based on:

> Yuen, Chen, Pan, Yu, Liu. *Posterior Security: Anonymity and Message Hiding of Standard Signatures*. ACM CCS 2025 (ePrint 2025/855).

## Status

**Concealed implementation, evaluation tooling and CBDC demo are available.**

- [`PAPER_MAP.md`](./PAPER_MAP.md) — background reading notes on the Incognito Signature construction (not implemented, reference only)

(Team-internal planning/progress documents, not part of the final submission, are kept elsewhere and are not referenced from this file.)

Implemented so far:
- `src/posterior/pairing.py` — thin wrapper over `py_ecc`'s BLS12-381 backend (group ops, pairing, scalar/hash-to-scalar/hash-to-G2 helpers), with bilinearity/identity tests
- `src/posterior/boneh_boyen.py` — standard Boneh-Boyen sign/verify (§5.3's base scheme; also our no-privacy performance baseline), with correctness + tamper tests
- `src/posterior/commit_g2.py` — Pedersen-in-G2 commitment (`C = g2^m . h2^t`), with a properly derived "nothing up my sleeve" `h2`, and binding/hiding sanity tests
- `src/posterior/gs.py` — Groth-Sahai proofs for pairing-product equations over BLS12-381 (SXDH), following Escala-Groth (PKC 2014), with a batched verifier
- `src/posterior/zk_proof.py` — zero-knowledge proof of knowledge for the concealed Boneh-Boyen relation, built on `gs.py` (the exponents `t`, `r` are encoded as group elements tied to fixed public bases by two linear equations), with completeness, tampering and soundness tests

- `src/posterior/cs_params.py`, `concealed.py`, `serialization.py` — explicit shared parameters, Convert/CVerify/Decom, compressed encodings and subgroup checks
- `tests/test_concealed.py`, `test_edge_cases.py` — additional end-to-end, input validation, parameter-binding and opening-reuse checks
- `bench/run_bench_concealed.py`, `bench/plot_results.py` — raw measurements, median/IQR summaries, environment metadata and charts
- [`docs/PART_B.md`](docs/PART_B.md), [`docs/PART_C.md`](docs/PART_C.md) — interface and evaluation notes
- [`docs/PAPER_MAP_CONCEALED.md`](docs/PAPER_MAP_CONCEALED.md), [`docs/AMBIGUITIES.md`](docs/AMBIGUITIES.md) — actual construction-to-code mapping and engineering decisions

- `demo/cbdc_concealed.py` — wallet/bank/verifier/reveal illustration with rejection paths
- [`docs/PART_D.md`](docs/PART_D.md) — verified demo, external reference experiment and packaging notes
- `tools/build_submission.py` — allowlisted source ZIP and SHA-256 manifest
- `presentation/` and `submission/` — editable slide skeleton, demo runbook, Q&A, cover worksheet and final checklist

- `tests/test_gs_simulator.py` — hiding-CRS trapdoor simulator: witness-free proofs of the concealed relation (and of a false toy statement) verify under a hiding CRS, fail under a binding CRS; evidence for the ZK argument, not a proof

- [`docs/SECURITY_ARGUMENT.md`](docs/SECURITY_ARGUMENT.md) — hiding/unforgeability argument, the integer-extraction gap, trusted-setup caveats, verifier optimisation notes

Remaining team work is the final report/coversheet/slides review, rehearsal and upload.
Tests provide engineering evidence, not a full cryptographic security proof.

## Scope

The paper has two main contributions: **Incognito Signature** (posterior anonymity) and **Concealed Signature** (posterior message hiding). This project's scope was narrowed after discussion with the teaching team (the paper's co-author is our unit's tutor):

- **Concealed Signature is the sole construction we implement**: Boneh–Boyen signatures over BLS12-381, converted so the signed message is hidden behind a commitment, verified with the implemented Groth–Sahai pairing-product proofs. Shared commitments link three PPEs; trusted setup and group-element extraction limitations are described in the implementation notes.
- **Incognito Signature is not re-implemented.** The tutor has already published an open-source Rust implementation (`incognito-sig/incognito`). We treat it purely as background reading and, where useful, a source of reference benchmark numbers — properly cited, not copied. No Rust code is written or maintained in this repository.
- **The combined "Incognito Concealed" construction (paper §6) is out of scope**, since it would require an Incognito implementation to combine with.

## Repository layout

```
src/posterior/       # pairing group wrapper, Boneh-Boyen sign/verify,
                      # commitment, ZK proof, Convert/CVerify/Decom assembly
demo/                # end-to-end demo scenario
tests/                # correctness, security-property, and edge-case tests
bench/                # performance benchmarks and plots
docs/                # paper-to-code mapping, ambiguity/decision notes
tools/               # source packaging and external result collection
presentation/        # slide skeleton, demo runbook and Q&A preparation
submission/          # cover fields and review checklist
```

## Run and reproduce

### Environment requirements

- Python **3.9+** (tested: 3.9.13, Windows 11); no Rust, C compiler or GPU needed.
- Pinned packages in `requirements.txt`: `py-ecc==8.0.0`, `pytest==8.4.2`,
  `pytest-benchmark==5.2.3`, `matplotlib==3.9.4`, `numpy==2.0.2`.
- Use a **fresh virtual environment**; installing into a shared Conda/base
  environment upgrades numpy and can break unrelated packages (scipy, numba).
- Pure-Python pairings are slow: full `pytest` takes ~5 min, one `cverify` ~2.3 s.

```powershell
py -3.9 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pytest -q
```

From the repository root in PowerShell, using the existing project environment:

```powershell
.\.venv\python.exe -m pip install -r requirements.txt
.\.venv\python.exe demo/cbdc_concealed.py --amount 123.45
.\.venv\python.exe -m pytest -q -p no:cacheprovider
.\.venv\python.exe bench/run_bench_concealed.py --repeats 20 --warmup 1 --output bench/results/local
.\.venv\python.exe bench/plot_results.py --input bench/results/local
```

For a fresh environment, create a Python 3.9+ virtual environment first
(`py -3.9 -m venv .venv`); its Windows executable is then
`.venv\Scripts\python.exe` instead of the existing Conda prefix's
`.venv\python.exe`. Run scripts from the repository root; benchmark scripts
add `src` themselves. See Part B's note for application imports and usage.

The demo prints CVerify PASS without requiring the amount/opening, then
reveals `123.45`, prints Decom PASS and confirms four rejection scenarios.
It uses fresh randomness, so public hashes vary. There is no cryptographic
range/balance proof, payment settlement or replay protection. See the
[demo runbook](presentation/DEMO_RUNBOOK.md) for the recorded-output fallback.

Expected results: pytest reports passing tests; the benchmark writes
`raw.csv`, `summary.csv`, `metadata.json`; plotting adds PNG/SVG timing
and size charts. A full benchmark can take several minutes. New generated
directories under `bench/results/` are ignored by Git; the measured
`bench/results/2026-10-30/` snapshot is explicitly tracked for Part C.
Preserve the intended result directory when preparing the final evaluation
archive. Never include `.venv` or private keys.

## Source delivery and external reference data

```powershell
.\.venv\python.exe tools/build_submission.py
```

This writes `../deliverables/Group5-PosteriorSecurity-source.zip`, verifies
archive contents against its SHA-256 manifest, and excludes environments,
toolchains, caches, Git metadata and internal notes. It is a review copy:
complete the [submission checklist](submission/CHECKLIST.md) and official
CoverSheet before any upload. Member information remains TO FILL by request.

Rust is not needed for this Python project. The separate official Incognito
reference benchmark was run unchanged; its source revision, raw measurements
and limitations are in [INCOGNITO_REFERENCE.md](docs/INCOGNITO_REFERENCE.md).

## Tech stack

- Python 3.9+
- `py_ecc` (BLS12-381 pairing operations)
- `pytest` for testing, `matplotlib` for benchmark plots

## Attribution & academic integrity

- Incognito Signature: not implemented here; background understanding and any cited benchmark figures are drawn from the tutor/author's public repository, credited explicitly wherever referenced.
- AI-assisted work (planning, code, or documentation) is disclosed per unit policy in the project's provenance notes.
- Parts B/C/D AI assistance and dependencies are disclosed in [PROVENANCE.md](docs/PROVENANCE.md); the team must review the final submission and complete personal declarations.
