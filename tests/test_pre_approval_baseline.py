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
    for script in (SCRIPT, "scripts/refresh_governance_evidence.py",
                   "scripts/check_architecture.py"):
        shutil.copy2(ROOT / script, workspace / "scripts")
    shutil.copytree(ROOT / CONTRACTS, workspace / CONTRACTS)
    # --regenerate shells out to the refresh script, which needs the package and
    # a real revision to bind evidence to.
    shutil.copytree(ROOT / "src", workspace / "src")
    for command in (
        ["init", "-q"],
        ["config", "user.email", "fixture@example.invalid"],
        ["config", "user.name", "fixture"],
        ["add", "-A"],
        ["commit", "-qm", "fixture baseline"],
    ):
        subprocess.run(["git", *command], cwd=workspace, check=True, capture_output=True)
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
    ("as_of", "regenerate"),
    [
        # Inside the committed machine-evidence window: healthy as committed.
        ("2026-08-09T00:00:00Z", False),  # past the reviewer window once baked in
        # Beyond it: healthy after the documented review-time regeneration.
        ("2030-01-01T00:00:00Z", True),
        ("2045-12-31T23:59:59Z", True),
    ],
)
def test_the_baseline_is_reviewer_ready_at_any_future_instant(
    as_of: str, regenerate: bool, tmp_path: Path
):
    """The baseline must be reviewer-ready whenever someone arrives.

    Authority declarations previously carried a reviewer-specific expiry, so the
    tree started failing with APPROVAL_EXPIRED - a diagnostic that is not about a
    missing approval - once that date passed. They now carry the non-expiring
    representation, so that failure cannot return.

    Machine evidence is a different matter and this test is deliberately split
    to say so. Nornyx has no non-expiring representation for it, so it carries a
    real finite window and the guarantee is regeneration, not permanence. An
    earlier version of this test asserted permanence and passed only because a
    2099 sentinel made "expired" look far away. See
    docs/governance/EVIDENCE_FRESHNESS.md.
    """
    command = [sys.executable, SCRIPT, "--as-of", as_of]
    if regenerate:
        command.append("--regenerate")
    completed = subprocess.run(
        command,
        cwd=_tree(tmp_path),
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "pass"
    assert report["human_approval_present"] is False
    for contract in report["contracts"]:
        assert contract["approval_blocked"] is True, contract
        assert contract["unexpected_diagnostics"] == [], contract


@pytest.mark.skipif(shutil.which("nornyx") is None, reason="nornyx CLI is not installed")
def test_no_approval_is_inferred_or_generated(tmp_path: Path):
    """Regenerating evidence must never bring an approval into existence."""
    workspace = _tree(tmp_path)
    evidence = workspace / CONTRACTS / "evidence"
    assert not list(evidence.glob("*human_approval*")), "an approval artifact exists"
    report = json.loads(
        subprocess.run(
            [sys.executable, SCRIPT], cwd=workspace, capture_output=True, text=True
        ).stdout
    )
    assert report["human_approval_present"] is False


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
