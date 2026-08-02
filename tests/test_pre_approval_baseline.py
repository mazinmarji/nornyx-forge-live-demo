"""The baseline gate must fail on any diagnostic that is not the approval gap."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = "scripts/check_pre_approval_baseline.py"
CONTRACTS = Path(".nornyx/contracts")


def _tree(tmp_path: Path) -> Path:
    workspace = tmp_path / "repo"
    (workspace / "scripts").mkdir(parents=True)
    shutil.copy2(ROOT / SCRIPT, workspace / "scripts")
    shutil.copytree(ROOT / CONTRACTS, workspace / CONTRACTS)
    return workspace


def _run(workspace: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT],
        cwd=workspace,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(shutil.which("nornyx") is None, reason="nornyx CLI is not installed")
def test_baseline_passes_when_only_approval_is_missing(tmp_path: Path):
    completed = _run(_tree(tmp_path))
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "pass"
    assert report["human_approval_present"] is False
    for contract in report["contracts"]:
        assert contract["approval_blocked"] is True
        assert contract["unexpected_diagnostics"] == []


@pytest.mark.skipif(shutil.which("nornyx") is None, reason="nornyx CLI is not installed")
def test_baseline_fails_on_a_non_approval_defect(tmp_path: Path):
    """A stale revision is a defect, not an approval gap, so it must fail.

    Without this the gate would pass any broken contract that also happened to
    be missing its approval record.
    """
    workspace = _tree(tmp_path)
    contract = workspace / CONTRACTS / "runtime_network.nyx"
    contract.write_text(
        contract.read_text(encoding="utf-8").replace(
            "subject_revision: git:", "subject_revision: git:dead", 1
        ),
        encoding="utf-8",
    )

    completed = _run(workspace)
    assert completed.returncode == 2, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "fail"
    offending = [
        item for entry in report["contracts"] for item in entry["unexpected_diagnostics"]
    ]
    assert offending, report
