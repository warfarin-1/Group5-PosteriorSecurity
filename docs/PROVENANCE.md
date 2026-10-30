# Sources, dependencies and AI assistance

## Project and external references

- Yuen, Chen, Pan, Yu and Liu. *Posterior Security: Anonymity and Message
  Hiding of Standard Signatures*. CCS 2025; ePrint 2025/855. The project's
  chosen scope is the Concealed construction (paper §5.3).
- Standard Boneh–Boyen signatures provide the base scheme and local baseline.
- `gs.py` documents the Groth–Sahai PPE construction and Escala–Groth matrix
  notation used by the project. This does not imply independent certification
  of the implementation's security reduction.
- [Official Incognito repository](https://github.com/incognito-sig/incognito),
  external Rust code, is used only for background/reference benchmarking.
  No Rust source is ported or included in our Python implementation/package.
  Revision, experiment settings and numbers are in `INCOGNITO_REFERENCE.md`.

## Direct Python dependencies

| Dependency | Role |
|---|---|
| py-ecc 8.0.0 | BLS12-381 arithmetic, pairings, compressed points and hash-to-curve |
| pytest 8.4.2 | automated tests |
| pytest-benchmark 5.2.3 | declared project test/benchmark dependency; C's timing script uses the standard library |
| matplotlib 3.9.4 | headless evaluation plots |

Pinned direct versions are in `requirements.txt`; transitive packages are
installed by pip. Rust is optional for the separate external reference run
and is not needed for the Concealed demo or tests.

## AI assistance disclosure

AI assisted environment setup, inspection and local progress notes; Part B
assembly/serialization/security smoke tests and integration documentation;
Part C supplementary tests, benchmark/plot scripts, measurements and mapping/
decision notes; and Part D demo, CLI tests, reference benchmark execution,
packaging script, documentation, slide skeleton and Q&A preparation.
Specific execution evidence and dates are retained in the local progress
record. Git commit authorship is not a claim that every line was manually
written by that person. Members must review the code, cite assistance using
the current unit policy and be able to explain what they submit.

No automatic report submission, signature, CoverSheet declaration or external
message has been made. Final academic analysis and submission approval remain
the team's responsibility. Known security and evidence limits are documented
in `AMBIGUITIES.md`, `PART_B.md`, `PART_C.md` and `PART_D.md`.
