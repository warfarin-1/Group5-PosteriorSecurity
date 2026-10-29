"""Collect external Criterion outputs, preserving raw samples and attribution."""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--criterion", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/evidence")
    args = parser.parse_args()
    source = args.source.resolve()
    def git(*options):
        return subprocess.check_output(["git", "-c", f"safe.directory={source.as_posix()}",
                                        "-C", str(source), *options], text=True).strip()
    rows, snapshots = [], []
    for group in ("incognito signing", "incognito verification"):
        for ring in (32, 64, 128, 256, 512, 1024):
            folder = args.criterion / group / str(ring) / "new"
            estimate = json.loads((folder / "estimates.json").read_text())
            sample = json.loads((folder / "sample.json").read_text())
            benchmark = json.loads((folder / "benchmark.json").read_text())
            median = estimate["median"]
            interval = median["confidence_interval"]
            rows.append({"external_benchmark": benchmark["full_id"], "ring_size": ring,
                         "operation": "convert" if group.endswith("signing") else "verify",
                         "median_ms": median["point_estimate"] / 1e6,
                         "lower_95_ms": interval["lower_bound"] / 1e6,
                         "upper_95_ms": interval["upper_bound"] / 1e6,
                         "sample_count": len(sample["times"])})
            snapshots.append({"benchmark": benchmark, "estimates": estimate, "sample": sample})
    metadata = {"source": "https://github.com/incognito-sig/incognito",
                "source_revision": git("rev-parse", "HEAD"),
                "source_worktree_clean": git("status", "--porcelain") == "",
                "cargo_lock_sha256": hashlib.sha256((source / "Cargo.lock").read_bytes()).hexdigest(),
                "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
                "platform": platform.platform(), "processor": platform.processor(),
                "recorded_utc": datetime.now(timezone.utc).isoformat(),
                "command": "cargo bench --locked --bench bench_incognito -- --sample-size 10 --warm-up-time 1 --measurement-time 2 --noplot",
                "settings": {"sample_size": 10, "warmup_seconds": 1, "target_measurement_seconds": 2,
                             "network_latency_emulation": False},
                "attribution": "External official implementation, not Group 5's Concealed implementation",
                "statistic": "Criterion median estimate and its 95% bootstrap confidence interval; nanoseconds converted to milliseconds",
                "notes": "Signing label measures Incognito conversion; terminal default slope/mean may differ from median. Criterion extends measurement duration when required."}
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "incognito-summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (args.output / "incognito-results.json").write_text(
        json.dumps({"metadata": metadata, "benchmarks": snapshots}, indent=2) + "\n", encoding="utf-8")
    print(f"Collected {len(rows)} external cases; clean source={metadata['source_worktree_clean']}")
    for row in rows:
        print(f"{row['external_benchmark']}: median {row['median_ms']:.3f} ms")


if __name__ == "__main__":
    main()
