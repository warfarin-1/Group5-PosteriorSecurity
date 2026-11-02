# Live demo and backup runbook

## Before the session

1. Work from the extracted source root. Install `requirements.txt` into the
   selected Python 3.9 environment, then run `python -m pip check`.
2. Run `python demo/cbdc_concealed.py --amount 123.45` once. Expect about ten seconds
   of computation (measured 2026-10-31 on the dev machine). Use the same interpreter during the presentation.
3. Open `docs/evidence/demo-transcript.txt` and `demo-report.json` as backup,
   and the Part C timing/size images. Make the terminal font readable.
4. Disconnect from network if desired: the Python demo is fully local after
   dependency installation. Rust is not required to run it.

## Three-and-a-half-minute walkthrough

| Time | Action / explanation |
|---|---|
| 0:00–0:20 | Explain wallet, bank and public verifier; amount is represented in cents |
| 0:20–0:30 | Run `python demo/cbdc_concealed.py --amount 123.45` (about 10 s on the dev machine) |
| 0:30–1:15 | While it runs: verifier inputs are CS, vk, shared parameters; no amount or opening |
| 1:15–1:55 | Point to CVerify PASS (CS = 2504 B) |
| 1:55–2:30 | Authorized reveal: amount, then Decom PASS |
| 2:30–3:05 | Rejection summary: wrong amount/opening, changed commitment, invalid BB signature |
| 3:05–3:30 | State limits: no range proof, balance check, settlement or replay prevention; hand over to the performance slide |

The terminal does not print the amount before the reveal stage. The complete
demo process necessarily knows it; role separation is a data-flow illustration.
Fresh cryptographic randomness is never replaced with a presentation seed.

## Expected output structure

```text
[1] Wallet signs an amount; bank receives the signature and amount.
[2] Bank converts it; verifier receives CS + vk + shared parameters.
[3] CVerify: PASS; amount/opening not required. CS=2504 B
[4] Authorized reveal: amount=123.45; Decom: PASS
[5] Wrong amount/opening, changed commitment and invalid BB signature: REJECTED
No range/balance proof or payment settlement is implemented.
```

## Backup and recovery

- If dependency import fails: confirm `python -m pip show py-ecc` uses the
  same interpreter as the demo. Do not reinstall packages on stage.
- If the demo fails or stalls: stop it and show the saved transcript/report
  as a **prior recorded execution**, not as a fresh run.
- The report contains only a post-reveal demo amount, public hash/byte counts
  and boolean outcomes; it stores no signing key or opening.
- A backup video can be recorded by the team from this runbook. No video
  recording is claimed to have been produced in this delivery.

## Rehearsal sign-off (team to fill)

Date/time: TO FILL · machine/interpreter: TO FILL · presenter: TO FILL.
Record demo wall time, successful fallback and who advances each slide.
