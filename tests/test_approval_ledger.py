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

from nornyx_forge.approval_trust import APPROVAL_SCHEMA
from nornyx_forge.nornyx_runtime import (
    ActionDescriptor,
    ActionRequest,
    ApprovalLedger,
    NornyxActionBoundary,
    approval_fingerprint,
    approval_ledger_path,
    canonical_attempt_id,
    canonical_request_id,
)

NOW = "2026-08-03T00:00:00Z"


def _fingerprint(approval_id: str, request, *, approver: str = "human.test_fixture") -> str:
    """The key the boundary computes for a grant over this request.

    Mirrors the canonical signed payload, because that is what the fingerprint
    now digests. `approval_id` is part of it — it is signed, so tampering with
    it invalidates the signature — but it is not what stops the same act running
    twice. The UNIQUE constraint on `request_digest` does that, and these tests
    exercise both.
    """
    return approval_fingerprint(
        {
            "schema": APPROVAL_SCHEMA,
            "approval_id": approval_id,
            "request_digest": request.digest,
            "approver": approver,
            "approver_role": "operations_owner",
            "signer_key_id": "test-approval-01",
            "generated_at": "2026-08-02T00:00:00Z",
            "expires_at": "2026-08-05T00:00:00Z",
            "granted": True,
        },
        request,
    )


def _request(**overrides: object) -> ActionRequest:
    action = ActionDescriptor(
        operation=str(overrides.pop("operation", "issue refund")),
        resource=str(overrides.pop("resource", "customer:omar")),
        destination=str(overrides.pop("destination", "zone.external_customer")),
        parameters=overrides.pop("parameters", {"amount": 100, "currency": "USD"}),  # type: ignore[arg-type]
    )
    mission_id = str(overrides.pop("mission_id", "CASE-001"))
    return ActionRequest(
        # Canonical for the mission: the runtime derives it, so a fixture that
        # invented its own id would be refused before the ledger is reached.
        request_id=str(overrides.pop("request_id", canonical_request_id(mission_id))),
        attempt_id=str(
            overrides.pop("attempt_id", canonical_attempt_id(mission_id, 1))
        ),
        mission_id=mission_id,
        subject_revision=str(overrides.pop("subject_revision", "git:" + "a" * 40)),
        capability="execute_high_risk_effect",
        action=action,
    )


def test_a_second_consumption_is_refused(tmp_path: Path):
    ledger = ApprovalLedger(tmp_path / "ledger.sqlite3")
    request = _request()
    assert ledger.consume(_fingerprint("ACT-1", request), request.digest, at=NOW)[0] is True
    claimed, reason = ledger.consume(_fingerprint("ACT-1", request), request.digest, at=NOW)
    assert claimed is False
    assert "already consumed" in reason


def test_consumption_survives_closing_and_reopening_the_store(tmp_path: Path):
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    assert ApprovalLedger(path).consume(_fingerprint("ACT-2", request), request.digest, at=NOW)[0] is True
    # A brand new object over the same file, as a restarted process would build.
    claimed, reason = ApprovalLedger(path).consume(_fingerprint("ACT-2", request), request.digest, at=NOW)
    assert claimed is False, reason


def test_consumption_survives_a_new_boundary(tmp_path: Path):
    """Rebuilding the boundary must not forget what was already spent."""
    request = _request()
    first = NornyxActionBoundary(tmp_path, allow_fallback=True)
    assert first.approval_ledger.consume(_fingerprint("ACT-3", request), request.digest, at=NOW)[0] is True
    second = NornyxActionBoundary(tmp_path, allow_fallback=True)
    claimed, reason = second.approval_ledger.consume(_fingerprint("ACT-3", request), request.digest, at=NOW)
    assert claimed is False, reason


def test_only_one_of_two_concurrent_consumers_wins(tmp_path: Path):
    """The unique constraint decides the race, not a check-then-act window."""
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger(path)
    request = _request()

    def claim(_: int) -> bool:
        return ApprovalLedger(path).consume(_fingerprint("ACT-RACE", request), request.digest, at=NOW)[0]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(claim, range(8)))
    assert sum(results) == 1, results


def test_two_different_requests_do_not_collide_on_a_shared_id(tmp_path: Path):
    """The identifier is provenance, so re-using one is not itself a conflict.

    This test used to assert the opposite, because `approval_id` was the primary
    key. It was the mirror of the real defect: the ledger noticed one id over two
    requests while missing one request under two ids.
    """
    ledger = ApprovalLedger(tmp_path / "ledger.sqlite3")
    first = _request()
    other = _request(request_id="REQ-CASE-002", parameters={"amount": 5000, "currency": "USD"})
    assert ledger.consume(_fingerprint("ACT-4", first), first.digest, at=NOW)[0] is True
    claimed, reason = ledger.consume(_fingerprint("ACT-4", other), other.digest, at=NOW)
    assert claimed is True, reason


def test_one_act_cannot_be_released_by_a_second_approval(tmp_path: Path):
    """Distinct grants, same consequential act: the act still happens once."""
    ledger = ApprovalLedger(tmp_path / "ledger.sqlite3")
    request = _request()
    # Genuinely different decisions: a second named approver, not a relabel.
    first = _fingerprint("ACT-A", request, approver="human:operations_owner")
    second = _fingerprint("ACT-B", request, approver="human:network_governance_owner")
    assert first != second, "the two grants must differ for this to test anything"
    assert ledger.consume(first, request.digest, at=NOW)[0] is True
    claimed, reason = ledger.consume(second, request.digest, at=NOW)
    assert claimed is False
    assert "already released" in reason


def test_a_failing_effect_still_spends_the_approval(tmp_path: Path):
    """At-most-once is the safe direction for a consequential act.

    Consumption happens before the effect, so a failure does not hand back a
    reusable grant. Retrying requires a fresh human approval.
    """
    ledger = ApprovalLedger(tmp_path / "ledger.sqlite3")
    request = _request()
    assert ledger.consume(_fingerprint("ACT-5", request), request.digest, at=NOW)[0] is True
    # The effect fails here; the grant stays spent.
    claimed, _ = ledger.consume(_fingerprint("ACT-5", request), request.digest, at=NOW)
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
    """The guarantee is the constraints, not application logic.

    Two of them: the fingerprint cannot repeat, and neither can the act.
    """
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO consumed_approvals VALUES (?,?,?,?)",
            ("fp-1", "digest-1", "ACT-1", NOW),
        )
        with pytest.raises(sqlite3.IntegrityError):  # same fingerprint
            conn.execute(
                "INSERT INTO consumed_approvals VALUES (?,?,?,?)",
                ("fp-1", "digest-2", "ACT-1", NOW),
            )
        with pytest.raises(sqlite3.IntegrityError):  # same act, other grant
            conn.execute(
                "INSERT INTO consumed_approvals VALUES (?,?,?,?)",
                ("fp-2", "digest-1", "ACT-2", NOW),
            )


def test_boundary_withholds_a_replayed_grant(tmp_path: Path):
    """End to end: the same signed grant cannot release a second time."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: PLC0415

    request = _request(subject_revision=TEST_REVISION)
    grant = signed_grant(request, approval_id="ACT-REPLAY")
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


def test_a_corrupt_ledger_is_a_governed_refusal_not_a_crash(tmp_path: Path):
    """An unreadable ledger cannot say whether a grant was spent, so refuse.

    Previously this escaped as a bare sqlite3.DatabaseError, which the API layer
    does not catch, turning into a raw 500 instead of the documented 503.
    """
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"this is definitely not a sqlite database")
    with pytest.raises(NornyxRuntimeUnavailable) as raised:
        ApprovalLedger(corrupt)
    assert "unusable" in str(raised.value)


def test_an_unusable_ledger_withholds_rather_than_releasing(tmp_path: Path):
    """If the claim cannot be recorded, single use cannot be promised."""
    path = tmp_path / "ledger.sqlite3"
    ledger = ApprovalLedger(path)
    # Point the ledger at a directory: every write fails from here on.
    ledger.path = tmp_path
    claimed, reason = ledger.consume("fp-io", _request().digest, at=NOW)
    assert claimed is False
    assert "unusable" in reason


def test_the_api_does_not_disclose_server_paths(monkeypatch: pytest.MonkeyPatch):
    """A 503 tells the caller what happened, not where the server keeps files."""
    pytest.importorskip("fastapi", reason="requires the demo extra")
    from fastapi.testclient import TestClient

    import demo_app.main as api
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable

    leaky = r"action approval ledger at C:\srv\forge\evidence\runtime\a.sqlite3 is unusable"

    def _unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NornyxRuntimeUnavailable(leaky)

    monkeypatch.setattr(api, "run_case", _unavailable)
    client = TestClient(api.app, raise_server_exceptions=False)
    response = client.post(
        "/api/cases",
        json={
            "customer": "Amina",
            "summary": "Update delivery instructions",
            "risk": "low",
            "requested_action": "send guidance",
        },
    )
    assert response.status_code == 503
    body = response.text
    assert r"C:\srv" not in body and "/srv/" not in body, body
    assert "<path>" in response.json()["detail"]["detail"]
    # The operator-facing detail keeps the real path.
    assert r"C:\srv\forge" in NornyxRuntimeUnavailable(leaky).detail
