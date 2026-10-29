"""Exercise the actual demo CLI and its distributable post-reveal report."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_demo_roles_and_rejection_paths(tmp_path):
    report = tmp_path / "report.json"
    result = subprocess.run([sys.executable, str(ROOT / "demo/cbdc_concealed.py"),
                             "--amount", "123.45", "--report", str(report)],
                            capture_output=True, text=True, timeout=120, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["revealed_amount"] == "123.45"
    assert data["concealed_signature_bytes"] == 2504
    assert data["public_parameters_bytes"] == 680
    assert all(data["checks"].values())
    assert data["public_verifier_inputs"] == ["concealed_signature", "verification_key", "public_parameters"]
    assert not {"sk", "opening", "original_signature", "private_key"} & data.keys()
    assert "[3] CVerify: PASS" in result.stdout
    assert "123.45" not in result.stdout.split("[4]")[0]


@pytest.mark.parametrize("amount", ["-1", "0.001", "NaN", "1e2"])
def test_demo_rejects_invalid_amount_before_setup(amount):
    result = subprocess.run([sys.executable, str(ROOT / "demo/cbdc_concealed.py"),
                             "--amount", amount], capture_output=True, text=True, timeout=15)
    assert result.returncode == 2
    assert "[1]" not in result.stdout
