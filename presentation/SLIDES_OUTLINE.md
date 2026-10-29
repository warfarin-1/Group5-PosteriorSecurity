# Group 5 presentation skeleton — 20 minutes

Format: editable slide-by-slide Markdown skeleton with speaker notes, ready
to transfer into the team's PowerPoint template. This is not a rendered PPTX.
All names, student IDs and presentation date remain **TO FILL**, as requested.
The final report, official coversheet and submitted slides require team review.

## 1 — Posterior message hiding (0:30, D)

On slide: Group 5 · FIT5163 Assignment 2 · Concealed Boneh–Boyen signatures.
Names/IDs/date: TO FILL.

Notes: Attribute Yuen, Chen, Pan, Yu and Liu, *Posterior Security: Anonymity
and Message Hiding of Standard Signatures*, CCS 2025, ePrint 2025/855.
Our implementation covers Concealed; Incognito is external background.

## 2 — The CBDC illustration (1:00, D)

On slide: Wallet signs an amount → bank conceals it → public verifier checks
the signature → authorized holder reveals the amount and opening.

Notes: Show the four-stage flow as a horizontal diagram. It illustrates a
signed scalar: there is no range proof, balance check, actual payment or
identity protocol. Roles run in one process. Source: `demo/cbdc_concealed.py`.

## 3 — Public and private data (1:00, B)

On slide: Public = `(proof,C)`, verification key and shared parameters.
Private = signing key; amount/original signature at conversion; opening t.

Notes: The bank's Convert call does not need sk. A public verifier calls
CVerify without the message or opening. Decom needs both. Transport uses
the serialized public parameters and signature. Source: `docs/PART_B.md`.

## 4 — Standard BB signature (2:00, A)

On slide: `s=g1^(1/(x+m+yr))`, `X=g2^x`, `Y=g2^y`.
Accept if `e(s,X g2^m Y^r)=e(g1,g2)`.

Notes: Explain scalar field, fresh nonce and inverse-denominator retry.
q-SDH underlies the base scheme's security assumptions, not a property
proved by our tests. Source: `boneh_boyen.py`, paper-to-code map.

## 5 — Conceal the message (2:00, A)

On slide: `C=g2^m h2^t`; prove
`e(s, X C h2^(-t) Y^r)=e(g1,g2)` without revealing s, r, t.

Notes: t is sampled uniformly, including zero. The discrete log between h2
and g2 must be unknown; h2 is derived by hash-to-G2. Decom checks the opening
only. Source: `commit_g2.py`, `concealed.py`, `docs/AMBIGUITIES.md`.

## 6 — Three linked PPEs and their limits (2:00, A)

On slide: `w1=h2^-t`, `w2=Y^r`, `xt=g1^t`, `xr=g1^r`.
E1 verifies BB; E2 binds w1/xt; E3 binds w2/xr. Commitments are shared.

Notes: Use the three-equation table in `PAPER_MAP_CONCEALED.md`. Actual code
is GS, not the old Sigma fallback. Explain trusted setup, group-element
extraction and A's outstanding simulator/security-review work. Avoid claiming
that engineering tests establish the complete paper reduction.

## 7 — Encoding and defensive checks (1:00, B)

On slide: G1 = 48 B, G2 = 96 B; CS = 2504 B; shared parameters = 680 B.
Decode checks type/version, shape, canonical coordinates and subgroups.

Notes: Parsing is not authentication. Nonidentity parameter bases differ
from valid identity proof/commitment points. Source: `serialization.py`.

## 8 — Live demo: accept and reject paths (4:00, B/D)

On slide: `python demo/cbdc_concealed.py --amount 123.45`.
CVerify passes before reveal; Decom passes after reveal; wrong amount,
opening, changed commitment and invalid original signature are rejected.

Notes: Follow `presentation/DEMO_RUNBOOK.md`. The terminal output is stable
in structure, while crypto randomness stays fresh. If execution fails, show
the captured transcript and report, clearly labelled as a prior run.
Do not claim the absence of a plaintext field proves zero knowledge.

## 9 — Local performance evidence (2:00, C)

On slide: n=20, one excluded warmup; median/IQR.
BB Sign+Verify 1.052 s; Convert 3.777 s; CVerify 3.944 s; Decom 0.346 s.

Notes: Insert `bench/results/2026-10-30/timings.png`. Full concealed workflow
is 8.064 s. Setup/keygen/encoding are outside timed intervals; public API
validation is included. Compare distinct functionality explicitly. Source:
`docs/PART_C.md` and raw measurement snapshot. This is Python on this machine.

## 10 — Size and security evidence (1:30, C)

On slide: CS 2504 B vs BB payload 80 B (different headers); shared setup
cost separate. Tamper/boundary/workflow tests; no empirical security proof.

Notes: Insert `sizes.png`. Explain opening reuse:
`C2/C1=g2^(m2-m1)` if the same t is reused. B's hiding game has only 8 trials;
it is a smoke test. C added 24 tested scenarios. Cite the actual latest test
counts from `docs/PART_D.md`; do not count collection-only checks as passes.

## 11 — Incognito background and scope (1:30, D)

On slide: Incognito conceals signer identity; Concealed hides the message.
Official Rust benchmark is external implementation evidence.

Notes: Use `docs/INCOGNITO_REFERENCE.md`, its pinned source revision and
labelled external result snapshot. Rust/secp256k1 vs Python/BLS12-381 and
different privacy goals prevent a direct speed ranking. No Incognito source
was ported or incorporated into our implementation.

## 12 — Findings and open work (1:30, D)

On slide: Working conversion, public verification and reveal; measured
privacy overhead; trusted setup and security-review limits.

Notes: Distinguish delivered B/C/D artifacts from A's simulator review and
the team's final report/signatures. Disclose AI help using `docs/PROVENANCE.md`.
Close the 20-minute presentation and transition to the 40-minute individual Q&A.

## Q&A holding slide (no presentation time)

On slide: Questions · all members prepare every component.
Notes: Use `presentation/QA_REHEARSAL.md`; final schedule and speaker names
remain TO FILL. Check actual teaching-team instructions before presenting.
