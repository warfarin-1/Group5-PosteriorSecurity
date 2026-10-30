# Part D: demo, reference experiment and delivery preparation

Delivered on `part-d/demo-and-delivery-2026-10-30`, based on Part C commit
`c74a275`. GitHub delivery targets only this new branch; `main` is not a
push target. No portal submission or merge into `main` is performed.

## Deliverables

| Area | Files / behavior |
|---|---|
| CBDC illustration | `demo/cbdc_concealed.py`: wallet signs cents, bank converts without sk, verifier consumes serialized public inputs, authorized holder reveals and opens |
| Failure paths | wrong amount/opening, changed commitment and invalid original BB signature are rejected; invalid CLI amounts fail before setup |
| CLI checks | `tests/test_demo.py`: actual subprocess execution, verifier input list, expected byte counts, report contents and early input rejection |
| Prior-run fallback | `docs/evidence/demo-transcript.txt`, `demo-report.json`; no private key or opening is persisted |
| External Incognito | official `bench_incognito` completed across 6 ring sizes and 2 operations; `INCOGNITO_REFERENCE.md`, raw JSON and summary CSV |
| Packaging | `tools/build_submission.py`: allowlisted ZIP, internal byte counts/hashes, CRC/content verification; no environment/toolchains/Git metadata/local process file |
| Presentation preparation | `presentation/SLIDES_OUTLINE.md`: 20-minute slide skeleton and speaker notes; `DEMO_RUNBOOK.md`: 4-minute live/fallback plan; `QA_REHEARSAL.md`: 22 question anchors and rehearsal worksheet |
| Cover and checklist | `submission/COVER_DETAILS.md` and `CHECKLIST.md`; member details/date left TO FILL as explicitly requested |
| Provenance | `PROVENANCE.md`, root README, reference revision and experiment settings |

The slide skeleton is **Markdown, not an exported PPTX**. The presentation
skill's Artifact Tool dependency-loading/session tools are unavailable in
this environment, so a rendered PowerPoint is not claimed. The user requested
a skeleton as part of the team task; this editable outline can be transferred
to the team's template. The official CoverSheet is not present: the worksheet
does not substitute for it, fill declarations or provide anyone's signature.

## Run the demo

```powershell
.\.venv\python.exe demo/cbdc_concealed.py --amount 123.45
.\.venv\python.exe demo/cbdc_concealed.py --amount 123.45 --report demo-report.json
.\.venv\python.exe -m pytest -q -p no:cacheprovider tests/test_demo.py
.\.venv\python.exe tools/build_submission.py
```

For a regular Windows venv use `.venv\Scripts\python.exe`; on another OS use
the corresponding Python executable. Scripts locate `src` relative to their
own path and run without an editable package installation. Tests use the
repository's `pyproject.toml` configuration.

The transcript displays the amount only at reveal. All roles are nevertheless
in one process: this is not a claim of process isolation or networking.
Only a signed scalar is proved, without range, balance, payment-settlement
or replay guarantees. Crypto randomness remains fresh; only the narrative
and expected pass/reject outcomes are stable.

## Execution evidence

- Demo CLI tests: **5 passed in 36.33s**, no pytest warnings. JUnit XML is
  outside the repository at `../part_d_demo_tests-2026-10-30.xml`.
- Official external benchmark: 12 cases completed, source worktree clean;
  pinned source and shortened sample settings are documented separately.
- The recorded demo ran the actual APIs with amount 123.45 and all six
  acceptance/rejection checks passed; the transcript/report are prior-run
  fallback material, not a fabricated or deterministic cryptographic trace.
- Source ZIP: `../deliverables/Group5-PosteriorSecurity-source.zip`, **53
  allowlisted files** plus `MANIFEST.json`. CRC and every file's SHA-256 were
  verified. Forbidden environment/Git/cache/toolchain/process paths are absent.
- The ZIP was extracted into `../deliverables/source-smoke-2026-10-30/`.
  Running its own `tests/test_demo.py` from the extracted project root with
  the existing project interpreter passed: **5 passed in 20.74s**. XML:
  `../part_d_archive_tests-2026-10-30.xml` relative to the original repo.
  This verifies the extracted source/demo, not installation into a newly
  created empty Python environment. Final documentation updates were then
  included in a rebuilt ZIP; runtime code remained identical.
- `pip check`, `compileall -q src tests bench demo tools`, and
  `git diff --check` passed. Existing B/C security tests were not rerun in
  this D session because their core implementations are unchanged.

## Team completion items

The source artifact is a **review copy**. The final report, official
CoverSheet/member declarations, final PPTX styling, actual rehearsal,
optional backup video and portal submission remain for the team. Member
names, IDs and confirmed dates remain TO FILL by user instruction. A's
simulator/security review remains a separate task. None of these activities
is falsely marked as performed. See `submission/CHECKLIST.md`.

AI assisted Part D demo/tests, reference execution, packaging and preparation
documents on 2026-10-30. Local `process.md` records execution and branch status.
