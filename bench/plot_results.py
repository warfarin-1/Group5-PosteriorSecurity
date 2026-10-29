"""Plot measured medians/IQR and explicitly separated signature payload sizes."""

import argparse
import csv
import json
import os
from pathlib import Path
import tempfile

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "posterior-matplotlib"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path(__file__).resolve().parent / "results")
    args = parser.parse_args()
    with (args.input / "summary.csv").open(encoding="utf-8") as handle:
        summary = {row["operation"]: row for row in csv.DictReader(handle)}
    metadata = json.loads((args.input / "metadata.json").read_text(encoding="utf-8"))
    plt.rcParams.update({"font.size": 11, "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(1, 2, figsize=(12, 5), layout="constrained")
    groups = [("bb_sign", "bb_verify", "convert", "cverify", "decom"),
              ("bb_sign_verify", "convert_cverify", "full_concealed")]
    labels = [("BB Sign", "BB Verify", "Convert", "CVerify", "Decom"),
              ("BB Sign + Verify", "Convert + CVerify", "Sign + Convert +\nCVerify + Decom")]
    for ax, operations, names in zip(axes, groups, labels):
        medians = [float(summary[op]["median_ms"]) for op in operations]
        lower = [m - float(summary[op]["q1_ms"]) for m, op in zip(medians, operations)]
        upper = [float(summary[op]["q3_ms"]) - m for m, op in zip(medians, operations)]
        ax.errorbar(medians, range(len(names)), xerr=[lower, upper],
                    fmt="o", capsize=4, color="#356c9b", markersize=7)
        ax.set_yticks(range(len(names)), names)
        ax.set_xscale("log")
        ax.set_xlabel("Milliseconds (log scale); median with Q1–Q3")
        ax.invert_yaxis()
        ax.grid(axis="x", alpha=.2)
    axes[0].set_title("Public API timings")
    axes[1].set_title("Paired per-trial workflow timings")
    fig.suptitle(f"Concealed Boneh–Boyen · n={metadata['repeats']}, warmup={metadata['warmup']}")
    for extension in ("png", "svg"):
        fig.savefig(args.input / f"timings.{extension}", dpi=180)
    plt.close(fig)
    sizes = metadata["sizes_bytes"]
    fig, ax = plt.subplots(figsize=(8, 4), layout="constrained")
    values = [sizes["bb_signature_payload"], sizes["concealed_signature"], sizes["public_parameters"]]
    bars = ax.barh(["BB payload (no tag)", "Concealed wire signature", "Shared parameters (separate)"],
                   values, color=["#788995", "#356c9b", "#c59440"])
    ax.bar_label(bars, labels=[f"{v:,} B" for v in values], padding=5)
    ax.set_xlim(0, max(values) * 1.25)
    ax.invert_yaxis()
    ax.set_xlabel("Bytes; public key and private opening excluded")
    ax.set_title("Signature size and shared setup cost")
    for extension in ("png", "svg"):
        fig.savefig(args.input / f"sizes.{extension}", dpi=180)
    plt.close(fig)


if __name__ == "__main__":
    main()
