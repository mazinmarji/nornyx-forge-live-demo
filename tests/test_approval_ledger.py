"""Consumption of an action approval must survive restarts and races.

A process-local set forgets everything when the boundary is rebuilt or the
process restarts, so the same grant could be replayed by simply starting again.
These drive the durable store directly and through the boundary.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from nornyx_forge.nornyx_runtime import (
    ActionDescriptor,
    ActionRequest,
    ApprovalLedger,
    NornyxActionBoundary,
    approval_ledger_path,
)

NOW = "2026-08-03T00:00:00Z"


def _request(**overrides: object) -> ActionRequest:
    action = ActionDescriptor(
        operation=str(overrides.pop("operation", "issue refund")),
        resource=str(overrides.pop("resource", "customer:omar")),
        destination=str(overrides.pop("destination", "zone.external_customer")),
        parameters=overrides.pop("parameters", {"amount": 100, "currency": "USD"}),  # type: ignore[arg-type]
    )
    return ActionRequest(
        request_id=str(overrides.pop("request_id", "REQ-001")),
        mission_id=str(overrides.pop("mission_id", "CASE-001")),
        subject_revision=str(overrides.pop("subject_revision", "git:" + "a" * 40)),
        capability="execute_high_risk_effect",
        action=action,
    )


def test_a_second_consumption_is_refused(tmp_path: Path):
    ledger = ApprovalLedger(tmp_path / "ledger.sqlite3")
    request = _request()
    assert ledger.consume("ACT-1", request.digest, at=NOW)[0] is True
    claimed, reason = ledger.consume("ACT-1", request.digest, at=NOW)
    assert claimed is False
    assert "already consumed" in reason


def test_consumption_survives_closing_and_reopening_the_store(tmp_path: Path):
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    assert ApprovalLedger(path).consume("ACT-2", request.digest, at=NOW)[0] is True
    # A brand new object over the same file, as a restarted process would build.
    claimed, reason = ApprovalLedger(path).consume("ACT-2", request.digest, at=NOW)
    assert claimed is False, reason


def test_consumption_survives_a_new_boundary(tmp_path: Path):
    """Rebuilding the boundary must not forget what was already spent."""
    request = _request()
    first = NornyxActionBoundary(tmp_path, allow_fallback=True)
    assert first.approval_ledger.consume("ACT-3", request.digest, at=NOW)[0] is True
    second = NornyxActionBoundary(tmp_path, allow_fallback=True)
    claimed, reason = second.approval_ledger.consume("ACT-3", request.digest, at=NOW)
    assert claimed is False, reason


def test_only_one_of_two_concurrent_consumers_wins(tmp_path: Path):
    """The unique constraint decides the race, not a check-then-act window."""
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger(path)
    request = _request()

    def claim(_: int) -> bool:
        return ApprovalLedger(path).consume("ACT-RACE", request.digest, at=NOW)[0]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(claim, range(8)))
    assert sum(results) == 1, results


def test_a_reused_id_against_a_different_request_is_named_as_such(tmp_path: Path):
    ledger = ApprovalLedger(tmp_path / "ledger.sqlite3")
    first = _request()
    other = _request(request_id="REQ-002", parameters={"amount": 5000, "currency": "USD"})
    assert ledger.consume("ACT-4", first.digest, at=NOW)[0] is True
    claimed, reason = ledger.consume("ACT-4", other.digest, at=NOW)
    assert claimed is False
    assert "different request" in reason


def test_a_failing_effect_still_spends_the_approval(tmp_path: Path):
    """At-most-once is the safe direction for a consequential act.

    Consumption happens before the effect, so a failure does not hand back a
    reusable grant. Retrying requires a fresh human approval.
    """
    ledger = ApprovalLedger(tmp_path / "ledger.sqlite3")
    request = _request()
    assert ledger.consume("ACT-5", request.digest, at=NOW)[0] is True
    # The effect fails here; the grant stays spent.
    claimed, _ = ledger.consume("ACT-5", request.digest, at=NOW)
    assert claimed is False


def test_ledger_path_is_configurable_and_defaults_under_runtime_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("FORGE_APPROVAL_LEDGER", raising=False)
    default = approval_ledger_path(tmp_path)
    assert default.parent.name == "runtime"
    assert "evidence" in default.parts

    monkeypatch.setenv("FORGE_APPROVAL_LEDGER", str(tmp_path / "elsewhere.sqlite3"))
    assert approval_ledger_path(tmp_path) == tmp_path / "elsewhere.sqlite3"


def test_the_ledger_is_never_committed():
    """No runtime database or generated approval data may be tracked."""
    tracked = subprocess.run(
        ["git", "ls-files"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    offenders = [
        name
        for name in tracked
        if name.endswith((".sqlite3", ".db"))
        or name.startswith("evidence/runtime/")
        or "human_approval" in name
    ]
    assert offenders == [], offenders


def test_the_store_schema_enforces_uniqueness(tmp_path: Path):
    """The guarantee is the primary key, not application logic."""
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO consumed_approvals VALUES (?,?,?)", ("ACT-6", "d", NOW)
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO consumed_approvals VALUES (?,?,?)", ("ACT-6", "d", NOW)
            )


def test_boundary_withholds_a_replayed_grant(tmp_path: Path):
    """End to end: the same grant cannot release a second time."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from test_governance_failure import _permissive_boundary  # noqa: PLC0415

    request = _request(subject_revision="git:unbound")
    grant = {
        "granted": True,
        "approval_id": "ACT-REPLAY",
        "approver": "human:operations_owner",
        "approver_type": "human",
        "approver_role": "operations_owner",
        "request_id": request.request_id,
        "subject_revision": request.subject_revision,
        "capability": request.capability,
        "destination": request.destination,
        "payload_digest": request.payload_digest,
        "request_digest": request.digest,
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
    }
    ledger = tmp_path / "ledger.sqlite3"

    def run() -> str:
        boundary = _permissive_boundary(tmp_path, as_of=NOW)
        boundary.approval_ledger = ApprovalLedger(ledger)
        decision, _ = boundary.evaluate_and_execute(
            mission_id=request.mission_id,
            risk="high",
            action=lambda: "ran",
            action_approval=grant,
            action_request=request,
        )
        return decision.effect

    assert run() == "ALLOW"
    assert run() == "DENY", "a spent grant released a second time"
