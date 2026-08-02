"""The baseline gate must fail on any diagnostic that is not the approval gap."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

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
def test_contracts_fail_only_for_want_of_human_approval(tmp_path: Path):
    """State-agnostic: each contract either validates or is approval-blocked.

    This holds before a human approval exists and after one is supplied, so the
    gate does not have to be rewritten when an approval lands or expires. What it
    never tolerates is a diagnostic that is not about the approval.
    """
    completed = _run(_tree(tmp_path))
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "pass"
    for contract in report["contracts"]:
        assert contract["validates"] or contract["approval_blocked"], contract
        assert contract["unexpected_diagnostics"] == [], contract


@pytest.mark.skipif(shutil.which("nornyx") is None, reason="nornyx CLI is not installed")
def test_human_approval_is_present_on_this_branch(tmp_path: Path):
    """This reviewer branch carries a human approval, so both contracts validate."""
    report = json.loads(_run(_tree(tmp_path)).stdout)
    assert report["human_approval_present"] is True
    for contract in report["contracts"]:
        assert contract["validates"] is True, contract


def _nornyx_check(contract: Path, *, as_of: str, cwd: Path) -> tuple[int, str]:
    completed = subprocess.run(
        [shutil.which("nornyx") or "nornyx", "check", str(contract), "--as-of", as_of],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return completed.returncode, completed.stdout + completed.stderr


@pytest.mark.skipif(shutil.which("nornyx") is None, reason="nornyx CLI is not installed")
@pytest.mark.parametrize(
    "contract", ["runtime_network.nyx", "architecture_governance.nyx"]
)
def test_approval_expiry_closes_the_contract(contract: str):
    """Once the approval window elapses the contract must stop validating.

    The approval is time-bounded on purpose. Evaluated past its expiry the
    contract has to fail again, otherwise a stale approval would keep a system
    open indefinitely.
    """
    path = ROOT / CONTRACTS / contract
    code, output = _nornyx_check(path, as_of="2026-09-01T00:00:00Z", cwd=ROOT)
    assert code != 0, f"expired approval still validated: {output}"
    assert "EXPIRED" in output or "STALE" in output, output


@pytest.mark.skipif(shutil.which("nornyx") is None, reason="nornyx CLI is not installed")
def test_approval_is_not_valid_before_it_was_issued():
    """An approval cannot authorize anything that happened before it existed."""
    path = ROOT / CONTRACTS / "runtime_network.nyx"
    code, output = _nornyx_check(path, as_of="2026-08-01T00:00:00Z", cwd=ROOT)
    assert code != 0, f"approval validated before it was issued: {output}"
    assert "NOT_YET_VALID" in output or "FUTURE" in output, output


@pytest.mark.skipif(shutil.which("nornyx") is None, reason="nornyx CLI is not installed")
def test_removing_the_human_approval_closes_the_contract(tmp_path: Path):
    """Strip the human approval and the contract must fail once more.

    Guards the fail-closed guarantee itself. Every other test here runs against a
    tree that already carries an approval, so without this the "no approval"
    branch would never be exercised again.
    """
    workspace = _tree(tmp_path)
    contracts = workspace / CONTRACTS
    for artifact in ("runtime_human_approval.json", "architecture_human_approval.json"):
        (contracts / "evidence" / artifact).unlink()

    for name in ("runtime_network.nyx", "architecture_governance.nyx"):
        path = contracts / name
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["governance_evidence"]["records"] = [
            record
            for record in document["governance_evidence"]["records"]
            if record["id"] != "approval_record"
        ]
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    completed = _run(workspace)
    report = json.loads(completed.stdout)
    assert report["human_approval_present"] is False, report
    for contract in report["contracts"]:
        assert contract["validates"] is False, contract
        assert contract["approval_blocked"] is True, contract
        assert contract["unexpected_diagnostics"] == [], contract
    assert completed.returncode == 0, "blocked-only is the expected healthy state"


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
