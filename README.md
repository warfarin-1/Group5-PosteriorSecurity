# Group5-PosteriorSecurity

FIT5163 Assignment 2 (Programming Option) — a reproduction/implementation project based on:

> Yuen, Chen, Pan, Yu, Liu. *Posterior Security: Anonymity and Message Hiding of Standard Signatures*. ACM CCS 2025 (ePrint 2025/855).

## Status

**Planning / early implementation stage.** No application code has been written yet — this repository currently only holds project scaffolding and planning documents:

- [`复现计划.md`](./复现计划.md) — detailed implementation plan (scope, algorithm breakdown, tech stack, milestones, risks)
- [`PAPER_MAP.md`](./PAPER_MAP.md) — background reading notes on the Incognito Signature construction (not implemented, reference only)
- [`Group5-PosteriorSecurity-研究笔记.md`](./Group5-PosteriorSecurity-研究笔记.md) — early feasibility/background research notes

(A separate, internal-only progress/decision log and teaching-team correspondence draft are kept locally and are not part of this repo.)

## Scope

The paper has two main contributions: **Incognito Signature** (posterior anonymity) and **Concealed Signature** (posterior message hiding). This project's scope was narrowed after discussion with the teaching team (the paper's co-author is our unit's tutor):

- **Concealed Signature is the sole construction we implement**: Boneh–Boyen signatures over BLS12-381, converted so the signed message is hidden behind a commitment, verified via a pairing-based zero-knowledge proof for the relevant pairing-product equation. The exact proof mechanism (an existing ZK/cryptography library vs. a hand-rolled Sigma-protocol NIZK for this specific equation) is still being finalized — both approaches have been confirmed acceptable by the teaching team.
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

## Tech stack (planned)

- Python 3.9+
- `py_ecc` (BLS12-381 pairing operations)
- `pytest` for testing, `matplotlib` for benchmark plots

## Attribution & academic integrity

- Incognito Signature: not implemented here; background understanding and any cited benchmark figures are drawn from the tutor/author's public repository, credited explicitly wherever referenced.
- AI-assisted work (planning, code, or documentation) is disclosed per unit policy in the project's provenance notes.
- This repository will include a full README with setup, dependency, and reproduction instructions once implementation begins.
