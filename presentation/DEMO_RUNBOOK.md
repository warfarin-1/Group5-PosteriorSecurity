# Live demo and backup runbook

## Before the session

1. Work from the extracted source root. Install `requirements.txt` into the
   selected Python 3.9 environment, then run `python -m pip check`.
2. Run `python demo/cbdc_concealed.py --amount 123.45` once. Expect seconds
   of computation. Use the same interpreter during the presentation.
3. Open `docs/evidence/demo-transcript.txt` and `demo-report.json` as backup,
   and the Part C timing/size images. Make the terminal font readable.
4. Disconnect from network if desired: the Python demo is fully local after
   dependency installation. Rust is not required to run it.

## Four-minute walkthrough

| Time | Action / explanation |
|---|---|
| 0:00–0:40 | Explain wallet, bank and public verifier; amount is represented in cents |
| 0:40–1:10 | Run `python demo/cbdc_concealed.py --amount 123.45` |
| 1:10–2:00 | Explain verifier inputs: CS, vk, shared parameters; no amount or opening |
| 2:00–2:40 | Point to CVerify PASS, then amount reveal and Decom PASS |
| 2:40–3:30 | Show rejection summary: wrong amount/opening, changed commitment, invalid BB signature |
| 3:30–4:00 | State limits: no range proof, balance check, settlement or replay prevention |

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
