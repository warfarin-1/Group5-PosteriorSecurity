"""Single-process CBDC illustration: wallet signs, bank conceals, verifier checks.

This proves possession of a signed scalar, not balance, range, settlement,
identity or replay prevention. Role separation is illustrative, not networking.
Fresh cryptographic randomness is retained. No key or opening is written out.
"""

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from posterior import boneh_boyen as bb
from posterior import concealed, cs_params, serialization as wire
from posterior.pairing import G1, G2, ORDER, add_g1, add_g2, decode_g2, encode_g2


def parse_amount(value):
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]{1,2})?", value):
        raise argparse.ArgumentTypeError("amount must be nonnegative with at most two decimal places")
    # String arithmetic avoids Decimal context rounding for large values.
    whole, _, fraction = value.partition(".")
    cents = int(whole) * 100 + int(fraction.ljust(2, "0") or "0")
    if cents >= ORDER:
        raise argparse.ArgumentTypeError("amount in cents must be below the scalar order")
    return cents


def run_demo(cents):
    if type(cents) is not int or not 0 <= cents < ORDER:
        raise ValueError("amount must be a canonical nonnegative integer in cents")
    params = cs_params.setup()
    sk, vk = bb.keygen()
    original = bb.sign(cents, sk)  # wallet; sk stays here
    converted = concealed.convert(original, cents, vk, params)  # bank: no sk argument
    if converted is None:
        raise RuntimeError("valid wallet signature unexpectedly rejected")
    public, opening = converted
    parameter_bytes = wire.encode_params(params)
    signature_bytes = wire.encode_cs(public)
    # Verifier receives public bytes and vk; not cents, original, sk or opening.
    received_params = wire.decode_params(parameter_bytes)
    received = wire.decode_cs(signature_bytes)
    received_vk = bb.VerifyKey(decode_g2(encode_g2(vk.X)), decode_g2(encode_g2(vk.Y)))
    verified = concealed.cverify(received, received_vk, received_params)
    # Reveal stage: the authorized holder supplies cents and opening.
    opened = concealed.decom(cents, received, opening, received_params)
    wrong_message = concealed.decom((cents + 1) % ORDER, received, opening, received_params)
    wrong_opening = concealed.decom(cents, received, (opening + 1) % ORDER, received_params)
    tampered = replace(received, C=add_g2(received.C, G2))
    tampered_accepted = concealed.cverify(tampered, received_vk, received_params)
    bad_original = replace(original, s=add_g1(original.s, G1))
    bad_converted = concealed.convert(bad_original, cents, vk, params)
    checks = {"cverify": verified, "decom": opened,
              "wrong_amount_rejected": not wrong_message,
              "wrong_opening_rejected": not wrong_opening,
              "tampered_commitment_rejected": not tampered_accepted,
              "invalid_original_rejected": bad_converted is None}
    if not all(checks.values()):
        raise RuntimeError(f"demo failed: {checks}")
    return {"scenario": "wallet -> bank -> public verifier -> authorized reveal",
            "public_verifier_inputs": ["concealed_signature", "verification_key", "public_parameters"],
            "concealed_signature_bytes": len(signature_bytes),
            "public_parameters_bytes": len(parameter_bytes),
            "public_signature_sha256": hashlib.sha256(signature_bytes).hexdigest(),
            "revealed_amount": f"{cents // 100}.{cents % 100:02d}",
            "checks": checks,
            "limitations": ["same-process illustration", "no range or balance proof",
                            "no settlement or replay protocol", "trusted setup required"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--amount", type=parse_amount, default="123.45", help="demo amount, e.g. 123.45")
    parser.add_argument("--report", type=Path, help="optional post-reveal JSON report; no keys or opening")
    args = parser.parse_args()
    print("[1] Wallet signs an amount; bank receives the signature and amount.", flush=True)
    print("[2] Bank converts it; verifier receives CS + vk + shared parameters.", flush=True)
    report = run_demo(args.amount)
    print(f"[3] CVerify: PASS; amount/opening not required. CS={report['concealed_signature_bytes']} B")
    print(f"[4] Authorized reveal: amount={report['revealed_amount']}; Decom: PASS")
    print("[5] Wrong amount/opening, changed commitment and invalid BB signature: REJECTED")
    print("No range/balance proof or payment settlement is implemented.")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
