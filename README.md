# Group5-PosteriorSecurity

FIT5163 Assignment 2 (Programming Option) — a reproduction/implementation project based on:

> Yuen, Chen, Pan, Yu, Liu. *Posterior Security: Anonymity and Message Hiding of Standard Signatures*. ACM CCS 2025 (ePrint 2025/855).

## Status

**Concealed implementation and Part B/C evaluation tooling are available.**

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

Remaining team work includes A's GS simulator/security review and optional
optimization, and D's demo, final packaging and presentation. Tests provide
engineering evidence, not a full cryptographic security proof.

## Scope

The paper has two main contributions: **Incognito Signature** (posterior anonymity) and **Concealed Signature** (posterior message hiding). This project's scope was narrowed after discussion with the teaching team (the paper's co-author is our unit's tutor):

- **Concealed Signature is the sole construction we implement**: Boneh–Boyen signatures over BLS12-381, converted so the signed message is hidden behind a commitment, verified with the implemented Groth–Sahai pairing-product proofs. Shared commitments link three PPEs; trusted setup and group-element extraction limitations are described in the implementation notes.
- **Incognito Signature is not re-implemented.** The tutor has already published an open-source Rust implementation (`incognito-sig/incognito`). We treat it purely as background reading and, where useful, a source of reference benchmark numbers — properly cited, not copied. No Rust code is written or maintained in this repository.
- **The combined "Incognito Concealed" construction (paper §6) is out of scope**, since it would require an Incognito implementation to combine with.

## Planned repository layout

```
src/posterior/       # pairing group wrapper, Boneh-Boyen sign/verify,
                      # commitment, ZK proof, Convert/CVerify/Decom assembly
demo/                # end-to-end demo scenario
tests/                # correctness, security-property, and edge-case tests
bench/                # performance benchmarks and plots
docs/                # paper-to-code mapping, ambiguity/decision notes
```

## Run and reproduce

From the repository root in PowerShell, using the existing project environment:

```powershell
.\.venv\python.exe -m pip install -r requirements.txt
.\.venv\python.exe -m pytest -q -p no:cacheprovider
.\.venv\python.exe bench/run_bench_concealed.py --repeats 20 --warmup 1 --output bench/results/local
.\.venv\python.exe bench/plot_results.py --input bench/results/local
```

For a fresh environment, create a Python 3.9+ virtual environment first
(`py -3.9 -m venv .venv`); its Windows executable is then
`.venv\Scripts\python.exe` instead of the existing Conda prefix's
`.venv\python.exe`. Run scripts from the repository root; benchmark scripts
add `src` themselves. See Part B's note for application imports and usage.

Expected results: pytest reports passing tests; the benchmark writes
`raw.csv`, `summary.csv`, `metadata.json`; plotting adds PNG/SVG timing
and size charts. A full benchmark can take several minutes. New generated
directories under `bench/results/` are ignored by Git; the measured
`bench/results/2026-10-30/` snapshot is explicitly tracked for Part C.
Preserve the intended result directory when preparing the final evaluation
archive. Never include `.venv` or private keys.

## Tech stack

- Python 3.9+
- `py_ecc` (BLS12-381 pairing operations)
- `pytest` for testing, `matplotlib` for benchmark plots

## Attribution & academic integrity

- Incognito Signature: not implemented here; background understanding and any cited benchmark figures are drawn from the tutor/author's public repository, credited explicitly wherever referenced.
- AI-assisted work (planning, code, or documentation) is disclosed per unit policy in the project's provenance notes.
- Part B and C AI assistance is disclosed in their integration/evaluation notes; final submission provenance and packaging are maintained by the team.
