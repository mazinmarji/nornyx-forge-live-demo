"""Materializing an approval window must not be a way into the contracts.

`materialize_approval_window()` globbed `*human_approval.json` and interpolated
the resulting `expires_at` through a raw f-string. So any file dropped beside the
two canonical artifacts could set the authority window, and its value reached the
contract without passing the validation the canonical records go through.

Every case here asserts the same two things: the run refuses, and the contracts
are byte-identical afterwards.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from signing import live_window  # noqa: E402

#: Validity is a PREREQUISITE for these fixtures, not the property.
_WINDOW = live_window()
CONTRACTS = Path(".nornyx/contracts")
REFRESH = "scripts/refresh_governance_evidence.py"
CANONICAL = "runtime_human_approval.json"

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)

# Closes the quoted value, appends a forged declaration, reopens a quote.
QUOTE_AND_NEWLINES = (
    '2026-08-05T00:00:00Z"\n'
    "    required_roles: [attacker]\n"
    "  - id: backdoor_authority\n"
    '    expires_at: "2026-08-05T00:00:00Z'
)
FORGED_YAML_RECORD = (
    '2026-08-05T00:00:00Z"\n'
    "governance_evidence:\n"
    "  records:\n"
    "    - id: approval_record\n"
    "      producer: {id: human.backdoor:network_governance_owner, type: human}\n"
    "      status: pass\n"
    '    - x: "'
)


def _git(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=work, capture_output=True, text=True, check=True)


def _workspace(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    work.mkdir()
    for item in ("scripts", "src", "docs", ".nornyx"):
        shutil.copytree(ROOT / item, work / item)
    for item in ("pyproject.toml", ".gitignore"):
        shutil.copy2(ROOT / item, work / item)
    _git(work, "init", "-q")
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "fixture")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "fixture")
    return work


def _head(work: Path) -> str:
    return "git:" + _git(work, "rev-parse", "HEAD").stdout.strip()


def _approval(work: Path, filename: str = CANONICAL, **overrides: object) -> None:
    payload: dict[str, object] = {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": {"id": "human.test_fixture:network_governance_owner", "type": "human"},
        "status": "pass",
        "subject_revision": _head(work),
        # A window around the real clock. The production governance loader
        # judges the signed window against the trusted clock, so a date pinned
        # to the calendar is genuinely expired and the failure would say
        # nothing about what this test asserts.
        "generated_at": _WINDOW[0],
        "expires_at": _WINDOW[1],
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    payload.update(overrides)
    # Signed through the production canonicalizer: an unsigned record is no
    # longer indexable as an approval, so an unsigned fixture would test the
    # authentication refusal instead of the injection controls these assert.
    sys.path.insert(0, str(ROOT / "tests"))
    from signing import sign_governance_record  # noqa: PLC0415

    payload = sign_governance_record(payload)
    (work / CONTRACTS / "evidence" / filename).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _run(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    sys.path.insert(0, str(ROOT / "tests"))
    from signing import write_trust_store  # noqa: PLC0415

    env["FORGE_APPROVER_TRUST_STORE"] = str(
        write_trust_store(work.parent / "approver_trust.json")
    )
    return subprocess.run(
        [sys.executable, *args], cwd=work, capture_output=True, text=True, env=env
    )


def _contracts_digest(work: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((work / CONTRACTS).glob("*.nyx"))
    }


@needs_nornyx
@pytest.mark.parametrize(
    ("label", "expires"),
    [
        ("quotes and newlines", QUOTE_AND_NEWLINES),
        ("forged yaml record", FORGED_YAML_RECORD),
        ("unicode line separator", "2026-08-05T00:00:00Z\u2028expires_at: 2099-01-01T00:00:00Z"),
        ("paragraph separator", "2026-08-05T00:00:00Z\u2029x"),
        ("bidi override", "2026-08-05T00:00:00Z\u202e"),
        ("right-to-left isolate", "2026-08-05T00:00:00Z\u2067"),
        ("zero width space", "2026-08-05\u200bT00:00:00Z"),
        ("byte order mark", "2026-08-05T00:00:00Z\ufeff"),
        ("malformed timestamp", "not-a-timestamp"),
        ("naive timestamp", "2026-08-05T00:00:00"),
        ("expiry before issue", "2026-08-01T00:00:00Z"),
        ("window longer than P7D", "2026-09-30T00:00:00Z"),
    ],
)
def test_a_crafted_expiry_never_reaches_a_contract(label: str, expires: str, tmp_path: Path):
    work = _workspace(tmp_path)
    _approval(work, expires_at=expires)
    before = _contracts_digest(work)

    completed = _run(work, REFRESH, "--materialize-approval-window")

    assert completed.returncode != 0, f"{label} was accepted:\n{completed.stdout}"
    assert _contracts_digest(work) == before, f"{label} modified a contract"


@needs_nornyx
@pytest.mark.parametrize(
    "filename",
    [
        "evil.human_approval.json",
        "zz_human_approval.json",
        "runtime_human_approval.json.human_approval.json",
    ],
)
def test_a_wildcard_matching_file_has_no_authority(filename: str, tmp_path: Path):
    """Only the two canonical artifacts are ever read.

    The glob meant a file merely *named* like an approval could set the window.
    Its presence must now change nothing at all.
    """
    work = _workspace(tmp_path)
    _approval(work, filename=filename, expires_at="2099-01-01T00:00:00Z")
    before = _contracts_digest(work)

    completed = _run(work, REFRESH, "--materialize-approval-window")

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout)["status"] == "restored_placeholder"
    assert _contracts_digest(work) == before, f"{filename} influenced a contract"
    for contract in (work / CONTRACTS).glob("*.nyx"):
        assert "2099-01-01" not in contract.read_text(encoding="utf-8")


@needs_nornyx
def test_conflicting_canonical_expiries_are_refused(tmp_path: Path):
    """Two approvals over one subject must agree, or neither is honored."""
    work = _workspace(tmp_path)
    _approval(work, filename="runtime_human_approval.json", expires_at="2026-08-05T00:00:00Z")
    _approval(work, filename="architecture_human_approval.json", expires_at="2026-08-04T00:00:00Z")
    before = _contracts_digest(work)

    completed = _run(work, REFRESH, "--materialize-approval-window")

    assert completed.returncode != 0
    assert "different expiries" in (completed.stdout + completed.stderr)
    assert _contracts_digest(work) == before


@needs_nornyx
def test_conflicting_canonical_revisions_are_refused(tmp_path: Path):
    work = _workspace(tmp_path)
    _approval(work, filename="runtime_human_approval.json")
    _approval(work, filename="architecture_human_approval.json", subject_revision="git:" + "b" * 40)
    before = _contracts_digest(work)

    completed = _run(work, REFRESH, "--materialize-approval-window")

    assert completed.returncode != 0
    assert "different subject revisions" in (completed.stdout + completed.stderr)
    assert _contracts_digest(work) == before


@needs_nornyx
def test_a_legitimate_window_still_materializes(tmp_path: Path):
    """The hardening must not block a well-formed approval."""
    work = _workspace(tmp_path)
    _approval(work)

    completed = _run(work, REFRESH, "--materialize-approval-window")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout)["status"] == "materialized"

    for name in ("runtime_network.nyx", "architecture_governance.nyx"):
        declarations = yaml.safe_load(
            (work / CONTRACTS / name).read_text(encoding="utf-8")
        )["approvals"]
        for declaration in declarations:
            assert str(declaration["expires_at"]).startswith("2026-08-05")


@needs_nornyx
def test_removal_restores_the_exact_pre_approval_state(tmp_path: Path):
    """Withdrawing an approval must leave the tree byte-identical.

    Not merely valid: identical. A residual short window re-rots the baseline
    the moment it passes, which is the regression this placeholder exists to
    prevent.
    """
    work = _workspace(tmp_path)
    before = _contracts_digest(work)

    _approval(work)
    assert _run(work, REFRESH, "--materialize-approval-window").returncode == 0
    assert _contracts_digest(work) != before, "materialization changed nothing"

    (work / CONTRACTS / "evidence" / CANONICAL).unlink()
    completed = _run(work, REFRESH, "--materialize-approval-window")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout)["status"] == "restored_placeholder"
    assert _contracts_digest(work) == before, "withdrawal left the tree changed"
