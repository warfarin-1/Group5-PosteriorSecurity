# Team roles and project plan

FIT5163 Assignment 2 (Programming Option), Group 5. Individual contributions
can be checked in the Git history (commits and merged pull requests).

## Team and responsibilities

| Role | Member | Responsibility |
|---|---|---|
| A | Yixuan Guo | Groth–Sahai proof system (`gs.py`) and the concealed-relation proof (`zk_proof.py`); GS simulator tests; verifier optimisation; security argument (`docs/SECURITY_ARGUMENT.md`); review of other members' modules; Git repository management (branches, pull-request merging, repository settings) |
| B | Yujun Zhang | `concealed.py` and `cs_params.py` (Setup/Convert/CVerify/Decom); wire format (`serialization.py`); message-hiding and unforgeability tests |
| C | Zixuan Zhang | End-to-end and edge-case tests; benchmark and plotting scripts (`bench/`); construction-to-code map and decision notes (`docs/PAPER_MAP_CONCEALED.md`, `docs/AMBIGUITIES.md`) |
| D | Tianxiang Lan | CBDC demo (`demo/`); reference run of the authors' Incognito benchmark; README and reproduction steps; source packaging (`tools/`); presentation and delivery preparation |

### Note on Git authorship

The commit author names do not map one-to-one to members:

- The accounts `Yixuan Guo`, `warfarin-1` and `scyyg5` are all Yixuan Guo's
  (the first appears on GitHub-generated pull-request merge commits).
- The Part B, C and D deliverables were committed together by Yujun Zhang
  (author `Yujun`). Parts C and D were written by Zixuan Zhang and
  Tianxiang Lan respectively and handed to Yujun, who committed them on the
  team's behalf. The history therefore does not show C and D as separate authors.

Shared by all members: reading the complete paper, the foundation modules
(`pairing.py`, `boneh_boyen.py`, `commit_g2.py`), cross-review of one
module not written by the reviewer, report writing, and presenting.

## Scope decision

Only the **Concealed Boneh–Boyen signature** (paper §5.3) is implemented.
The Incognito Signature (§4) and the composed construction (§6) are out of
scope; the authors' released Rust implementation is used as read-only
background and is not copied (see `PROVENANCE.md`, `INCOGNITO_REFERENCE.md`).
Reason: depth over breadth, and the pairing-based stack (BLS12-381 +
Groth–Sahai) is not covered by that code base.

## Milestones

| # | Milestone | Deliverable |
|---|---|---|
| M0 | Paper reading, environment | pinned `requirements.txt`, shared understanding of §5.3 |
| M1 | Primitives | `pairing.py`, `boneh_boyen.py`, `commit_g2.py` with tests |
| M2 | Zero-knowledge layer | `gs.py`, `zk_proof.py` (three linked PPEs) |
| M3 | Scheme assembly | `cs_params.py`, `concealed.py`, `serialization.py` |
| M4 | Tests and security review | edge-case, tampering, simulator and reduction-algebra tests |
| M5 | Evaluation | `bench/` timings and sizes; Incognito reference benchmark |
| M6 | Demo and packaging | `demo/cbdc_concealed.py`, `tools/build_submission.py` |
| M7 | Report and presentation | report, slides, rehearsal |

## Evaluation plan

Correctness and rejection tests (`tests/`); timing of Sign/Verify/Convert/
CVerify/Decom against plain Boneh–Boyen (20 trials, median/IQR) and encoded
sizes; security argument and its limits (`docs/SECURITY_ARGUMENT.md`).

## Known limitations

Trusted-setup CRS, group-element (not scalar) extraction in the
unforgeability argument, no range proof in the demo, pure-Python speed. See
`docs/SECURITY_ARGUMENT.md` and `docs/AMBIGUITIES.md`.
