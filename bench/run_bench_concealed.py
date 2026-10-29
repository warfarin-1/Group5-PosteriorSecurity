"""Measure real public APIs; emit raw timings, summary and environment metadata.

Setup/key generation and correctness checks are outside each timed interval.
Convert includes its required BB verification; CVerify includes input checks.
No message, key, signature, proof or opening is written to result files.
"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from posterior import boneh_boyen as bb
from posterior import concealed, cs_params, serialization as wire
from posterior.pairing import ORDER, encode_g1


def summarize(values):
    ordered = sorted(values)
    def percentile(fraction):
        position = (len(ordered) - 1) * fraction
        low = int(position)
        high = min(low + 1, len(ordered) - 1)
        return ordered[low] + (ordered[high] - ordered[low]) * (position - low)
    return {"n": len(values), "median_ms": statistics.median(values),
            "q1_ms": percentile(.25), "q3_ms": percentile(.75),
            "iqr_ms": percentile(.75) - percentile(.25),
            "min_ms": min(values), "max_ms": max(values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--output", type=Path, default=ROOT / "bench/results")
    args = parser.parse_args()
    if args.repeats < 1 or args.warmup < 0:
        parser.error("repeats must be positive; warmup must be nonnegative")
    args.output.mkdir(parents=True, exist_ok=True)
    params = cs_params.setup()
    sk, vk = bb.keygen()
    rows = []
    sizes = None
    for index in range(-args.warmup, args.repeats):
        message = bb.hash_message(b"Part C benchmark/" + str(index).encode())
        timings = {}
        def timed(name, call):
            start = perf_counter_ns()
            result = call()
            timings[name] = (perf_counter_ns() - start) / 1e6
            return result
        signature = timed("bb_sign", lambda: bb.sign(message, sk))
        if not timed("bb_verify", lambda: bb.verify(signature, message, vk)):
            raise RuntimeError("BB verification failed")
        converted = timed("convert", lambda: concealed.convert(signature, message, vk, params))
        if converted is None:
            raise RuntimeError("conversion failed")
        cs, opening = converted
        if not timed("cverify", lambda: concealed.cverify(cs, vk, params)):
            raise RuntimeError("concealed verification failed")
        if not timed("decom", lambda: concealed.decom(message, cs, opening, params)):
            raise RuntimeError("opening failed")
        if concealed.decom((message + 1) % ORDER, cs, opening, params):
            raise RuntimeError("wrong message accepted")
        if index >= 0:
            timings["bb_sign_verify"] = timings["bb_sign"] + timings["bb_verify"]
            timings["convert_cverify"] = timings["convert"] + timings["cverify"]
            timings["full_concealed"] = timings["bb_sign"] + timings["convert_cverify"] + timings["decom"]
            rows.extend({"trial": index + 1, "operation": op, "elapsed_ms": value}
                        for op, value in timings.items())
        sizes = {"bb_signature_payload": len(encode_g1(signature.s)) + 32,
                 "proof": len(wire.encode_proof(cs.proof)), "concealed_signature": len(wire.encode_cs(cs)),
                 "crs": len(wire.encode_crs(params.crs)), "public_parameters": len(wire.encode_params(params)),
                 "opening_scalar": 32}
        print("warmup" if index < 0 else f"trial {index + 1}/{args.repeats}", flush=True)
    operations = sorted({r["operation"] for r in rows})
    summaries = [{"operation": op, **summarize([r["elapsed_ms"] for r in rows if r["operation"] == op])}
                 for op in operations]
    for filename, data in (("raw.csv", rows), ("summary.csv", summaries)):
        with (args.output / filename).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(data[0]))
            writer.writeheader()
            writer.writerows(data)
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True)
    metadata = {"recorded_utc": datetime.now(timezone.utc).isoformat(),
                "python": sys.version, "platform": platform.platform(), "processor": platform.processor(),
                "py_ecc": importlib.metadata.version("py-ecc"),
                "git_head": revision.stdout.strip(), "git_dirty": bool(status.stdout.strip()),
                "repeats": args.repeats, "warmup": args.warmup, "sizes_bytes": sizes,
                "quantiles": "linear interpolation at (n-1)*q", "timing_clock": "perf_counter_ns",
                "benchmark_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "scope": "sequential single-process public APIs; setup/keygen/encoding excluded",
                "comparisons": "convert+cverify excludes original signing; full_concealed includes signing and opening",
                "bb_size": "48-byte compressed G1 + 32-byte scalar payload; no BB wire API or tag"}
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
