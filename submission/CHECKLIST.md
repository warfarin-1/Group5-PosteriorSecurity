# Submission checklist and proposed file names

This is a review package, not an uploaded or certified final submission.
Moodle's current requirements and official templates take precedence over
the older local planning dates. No submission site has been accessed here.

## Prepared in this delivery

- [x] Runnable CBDC demo and acceptance/rejection CLI tests
- [x] Setup, run, test and evaluation commands in README
- [x] Captured demo execution and post-reveal report
- [x] Part C raw samples, metadata and PNG/SVG charts
- [x] Source ZIP builder with explicit inclusion rules and SHA-256 manifest
- [x] Slide skeleton, four-minute demo runbook and cross-component Q&A bank
- [x] Cover information worksheet with explicit unfilled member fields
- [x] Provenance and external implementation attribution

## Team must complete before uploading

- [ ] Copy all member names/IDs into the official CoverSheet
- [ ] Each member reviews and personally completes required declarations
- [ ] Write/review the final report; include critical analysis and citations
- [ ] Transfer the Markdown slide skeleton into the team's slide template
- [ ] Fill speaker names and the confirmed presentation/rehearsal schedule
- [ ] Rehearse the timed live demo and fallback; optionally record a video
- [x] GS simulator test added (`tests/test_gs_simulator.py`)
- [x] A's review + verifier optimisation done; disclose the extraction gap in `docs/SECURITY_ARGUMENT.md` §3 in the report
- [ ] Recheck the actual portal's deadline, file rules and required file names
- [ ] Run final tests for the exact submitted revision and retain the report
- [ ] Inspect the generated ZIP/manifest and upload only after team review

## Proposed names (confirm official naming convention)

| Artifact | Suggested name | Status |
|---|---|---|
| Source ZIP | `Group5-PosteriorSecurity-source.zip` | generated review copy |
| Report | `Group5-PosteriorSecurity-report.pdf` | team to write/review |
| Official CoverSheet | `Group5-PosteriorSecurity-coversheet.pdf` | template and signatures required |
| Final slides | `Group5-PosteriorSecurity-slides.pptx` | transfer/review skeleton |
| Optional backup video | `Group5-PosteriorSecurity-demo.mp4` | not recorded here |

## Build and inspect

```powershell
python tools/build_submission.py
```

Default output is `../deliverables/Group5-PosteriorSecurity-source.zip`.
An internal `MANIFEST.json` lists every included relative path, byte count and
SHA-256. The builder verifies the archive CRC and every content hash.
The archive excludes `.venv`, `.git`, editor/cache/toolchain folders, local
`process.md`, internal planning and email drafts. The official external Rust
repository and compiler are not copied into the source ZIP.

Extract into a new directory, select an installed Python, install requirements
and run the demo/tests. This session's exact extraction checks and their
outcomes are recorded in `docs/PART_D.md`; do not infer a clean-environment
dependency install merely from running with the existing interpreter.
