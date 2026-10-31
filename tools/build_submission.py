"""Build an allowlisted source ZIP and a per-file SHA-256 manifest.

Never packages a virtual environment, Git metadata, local process records,
Rust toolchains, credentials, private openings or arbitrary workspace files.
Inspect the included submission checklist before uploading anything.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = ("README.md", "requirements.txt", "pyproject.toml", "PAPER_MAP.md")
TEXT_DIRS = ("src/posterior", "tests", "demo", "tools", "docs", "presentation", "submission")
EXTENSIONS = {".py", ".md", ".json", ".csv", ".txt", ".png", ".svg", ".pptx", ".pdf"}
FORBIDDEN = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".aws", ".codex", ".vscode", "node_modules"}


def selected_files():
    paths = [ROOT / name for name in ROOT_FILES]
    paths += [ROOT / "bench/run_bench_concealed.py", ROOT / "bench/plot_results.py"]
    for folder in TEXT_DIRS + ("bench/results/2026-10-31",):
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.is_file() and p.suffix.lower() in EXTENSIONS)
    result = []
    for p in sorted(set(paths)):
        relative = p.relative_to(ROOT)
        if not p.is_file() or p.is_symlink() or not p.resolve().is_relative_to(ROOT):
            raise ValueError(f"missing/unsafe package input: {relative}")
        if any(part in FORBIDDEN or part.startswith(".") for part in relative.parts):
            continue
        if p.name in {"process.md", "email-to-brian-draft.md"}:
            continue
        result.append(p)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT.parent / "deliverables/Group5-PosteriorSecurity-source.zip")
    args = parser.parse_args()
    paths = selected_files()
    manifest = {"generated_utc": datetime.now(timezone.utc).isoformat(),
                "status": "review copy; official coversheet, report and member details require team completion",
                "files": [{"path": p.relative_to(ROOT).as_posix(), "bytes": p.stat().st_size,
                           "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for p in paths:
            archive.write(p, "Group5-PosteriorSecurity/" + p.relative_to(ROOT).as_posix())
        archive.writestr("Group5-PosteriorSecurity/MANIFEST.json", json.dumps(manifest, indent=2) + "\n")
    with zipfile.ZipFile(args.output) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("ZIP checksum verification failed")
        for row in manifest["files"]:
            payload = archive.read("Group5-PosteriorSecurity/" + row["path"])
            if hashlib.sha256(payload).hexdigest() != row["sha256"]:
                raise RuntimeError(f"manifest mismatch: {row['path']}")
    print(f"Verified {len(paths)} files: {args.output}")
    print("Review copy only: see submission/CHECKLIST.md before any upload.")


if __name__ == "__main__":
    main()
