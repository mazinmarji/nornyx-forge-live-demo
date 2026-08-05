"""What expires, what does not, and which of those Nornyx can actually express.

An earlier release claimed the baseline "no longer expires" while carrying
`expires_at: "2099-01-01T00:00:00Z"`. These drive the real CLI to pin down what
1.11.0 supports, so the claim and the implementation cannot drift apart again.

See docs/governance/EVIDENCE_FRESHNESS.md.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = Path(".nornyx/contracts")
GOVERNANCE = ("runtime_network.nyx", "architecture_governance.nyx")

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)

# The three diagnostics that mean "no human has approved this yet". A healthy
# pre-approval baseline produces these and nothing else, at any instant.
APPROVAL_GAP_CODES = {
    "AN_APPROVAL_RECORD_MISSING",
    "APPROVAL_EVIDENCE_MISSING",
    "EVIDENCE_REQUIRED_MISSING",
}

FAR_FUTURE = ["2100-01-01T00:00:00Z", "2200-01-01T00:00:00Z"]


def _workspace(tmp_path: Path) -> Path:
    """A throwaway clone, so regeneration never touches the real tree."""
    work = tmp_path / "repo"
    work.mkdir()
    for item in ("scripts", "src", "docs", ".nornyx"):
        shutil.copytree(ROOT / item, work / item)
    shutil.copy2(ROOT / "pyproject.toml", work / "pyproject.toml")
    subprocess.run(["git", "init", "-q"], cwd=work, check=True, capture_output=True)
    for key, value in (("user.email", "fixture@example.invalid"), ("user.name", "fixture")):
        subprocess.run(["git", "config", key, value], cwd=work, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=work, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=work, check=True, capture_output=True)
    return work


def _run(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    return subprocess.run(
        [sys.executable, *args], cwd=work, capture_output=True, text=True, env=env
    )


def _codes(work: Path, contract: str, as_of: str) -> set[str]:
    completed = subprocess.run(
        ["nornyx", "check", str(CONTRACTS / contract), "--as-of", as_of],
        cwd=work,
        capture_output=True,
        text=True,
        check=False,
    )
    return set(re.findall(r'"code":\s*"([A-Z_]+)"', completed.stdout + completed.stderr))


@needs_nornyx
def test_the_authority_declaration_genuinely_does_not_expire():
    """`expires_at: null` on a declaration is a real non-expiring representation.

    Not a distant date standing in for one. A declaration names who may approve
    and over what scope; it is not itself an approval and has no reason to decay.
    """
    import yaml

    for contract in GOVERNANCE:
        text = (ROOT / CONTRACTS / contract).read_text(encoding="utf-8")
        declarations = yaml.safe_load(text)["approvals"]
        assert declarations, f"{contract} declares no authority"
        for declaration in declarations:
            assert declaration["expires_at"] is None, (
                f"{contract} authority {declaration.get('id')!r} expires at "
                f"{declaration['expires_at']!r}, not the non-expiring "
                "representation Nornyx accepts"
            )


@needs_nornyx
@pytest.mark.parametrize("as_of", FAR_FUTURE)
def test_no_approval_expiry_diagnostic_at_far_future_instants(as_of: str, tmp_path: Path):
    """The declaration must still be live long after any sentinel date."""
    work = _workspace(tmp_path)
    for contract in GOVERNANCE:
        assert "APPROVAL_EXPIRED" not in _codes(work, contract, as_of)


@needs_nornyx
def test_no_sentinel_date_survives_anywhere_in_the_contracts():
    """The 2099 placeholder is gone, in every block that used to carry it."""
    for contract in (*GOVERNANCE, "forge_control.nyx"):
        text = (ROOT / CONTRACTS / contract).read_text(encoding="utf-8")
        assert "2099-01-01" not in text, f"{contract} still carries the sentinel"


@needs_nornyx
@pytest.mark.parametrize("as_of", FAR_FUTURE)
def test_regeneration_restores_a_healthy_baseline_at_any_instant(as_of: str, tmp_path: Path):
    """The documented workflow, driven end to end at 2100 and 2200.

    Nornyx has no non-expiring representation for machine evidence, so this is
    the honest guarantee the project makes instead: one command produces a
    baseline whose only remaining diagnostics are the ones that say a human has
    not approved it.
    """
    work = _workspace(tmp_path)

    completed = _run(
        work, "scripts/check_pre_approval_baseline.py", "--regenerate", "--as-of", as_of
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

    report = json.loads(completed.stdout)
    assert report["status"] == "pass"
    assert report["human_approval_present"] is False
    for entry in report["contracts"]:
        assert entry["approval_blocked"] is True, entry
        assert entry["unexpected_diagnostics"] == [], entry

    # And directly against the CLI, so the assertion does not rest on our own
    # checker agreeing with itself.
    for contract in GOVERNANCE:
        assert _codes(work, contract, as_of) <= APPROVAL_GAP_CODES


@needs_nornyx
def test_machine_evidence_carries_a_real_finite_window(tmp_path: Path):
    """No magic constant. The window is a genuine interval from the run."""
    work = _workspace(tmp_path)
    assert _run(work, "scripts/refresh_governance_evidence.py", "--as-of",
                "2026-08-03T00:00:00Z").returncode == 0

    index = json.loads((work / CONTRACTS / "evidence" / "INDEX.json").read_text(encoding="utf-8"))
    assert index["generated_at"] == "2026-08-03T00:00:00Z"
    assert index["expires_at"] == "2027-08-03T00:00:00Z"
    assert "2099" not in json.dumps(index)


@needs_nornyx
def test_the_stale_baseline_is_detected_rather_than_hidden(tmp_path: Path):
    """Honesty runs both ways: an un-regenerated far-future check must fail.

    If this passed, the finite window would be decorative and the regeneration
    workflow would prove nothing.
    """
    work = _workspace(tmp_path)
    assert _run(work, "scripts/refresh_governance_evidence.py", "--as-of",
                "2026-08-03T00:00:00Z").returncode == 0
    assert _run(work, "scripts/refresh_governance_evidence.py", "--sync-contracts").returncode == 0

    completed = _run(work, "scripts/check_pre_approval_baseline.py", "--as-of", FAR_FUTURE[0])
    assert completed.returncode != 0, "a stale baseline reported healthy"
    assert "EVIDENCE_STALE" in completed.stdout
