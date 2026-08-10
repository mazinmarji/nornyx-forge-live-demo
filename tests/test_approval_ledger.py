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
    ledger = ApprovalLedger.provision(tmp_path / "ledger.sqlite3")
    request = _request()
    assert ledger.consume(_fingerprint("ACT-1", request), request.digest, at=NOW)[0] is True
    claimed, reason = ledger.consume(_fingerprint("ACT-1", request), request.digest, at=NOW)
    assert claimed is False
    assert "already consumed" in reason


def test_consumption_survives_closing_and_reopening_the_store(tmp_path: Path):
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    assert ApprovalLedger.provision(path).consume(_fingerprint("ACT-2", request), request.digest, at=NOW)[0] is True
    # A brand new object over the same file, as a restarted process would build.
    claimed, reason = ApprovalLedger(path).consume(_fingerprint("ACT-2", request), request.digest, at=NOW)
    assert claimed is False, reason


def test_consumption_survives_a_new_boundary(tmp_path: Path):
    """Rebuilding the boundary must not forget what was already spent."""
    request = _request()
    # Provisioned once, deliberately, before any boundary exists. A boundary
    # cannot create its own replay state; that is the point of this change.
    ApprovalLedger.provision(approval_ledger_path(tmp_path))
    first = NornyxActionBoundary(tmp_path, allow_fallback=True)
    assert first.approval_ledger.consume(_fingerprint("ACT-3", request), request.digest, at=NOW)[0] is True
    second = NornyxActionBoundary(tmp_path, allow_fallback=True)
    claimed, reason = second.approval_ledger.consume(_fingerprint("ACT-3", request), request.digest, at=NOW)
    assert claimed is False, reason


def test_only_one_of_two_concurrent_consumers_wins(tmp_path: Path):
    """The unique constraint decides the race, not a check-then-act window."""
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path)
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
    ledger = ApprovalLedger.provision(tmp_path / "ledger.sqlite3")
    first = _request()
    other = _request(request_id="REQ-CASE-002", parameters={"amount": 5000, "currency": "USD"})
    assert ledger.consume(_fingerprint("ACT-4", first), first.digest, at=NOW)[0] is True
    claimed, reason = ledger.consume(_fingerprint("ACT-4", other), other.digest, at=NOW)
    assert claimed is True, reason


def test_one_act_cannot_be_released_by_a_second_approval(tmp_path: Path):
    """Distinct grants, same consequential act: the act still happens once."""
    ledger = ApprovalLedger.provision(tmp_path / "ledger.sqlite3")
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
    ledger = ApprovalLedger.provision(tmp_path / "ledger.sqlite3")
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
    ApprovalLedger.provision(path)
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
    ApprovalLedger.provision(ledger)

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
    ledger = ApprovalLedger.provision(path)
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


# --------------------------------------------------------------------------
# Provisioning is an operator act, not something a consequential act does
# --------------------------------------------------------------------------


def test_deleting_the_ledger_does_not_restore_a_spent_grant(tmp_path: Path):
    """The defect, stated as the exploit it enabled.

    `CREATE TABLE IF NOT EXISTS` ran on every construction, so removing the file
    produced an empty ledger in which nothing had been spent — and every grant
    ever consumed became replayable. Deleting a file is not an authorization
    decision and must not act like one.
    """
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    fingerprint = _fingerprint("ACT-DELETE", request)
    assert ApprovalLedger.provision(path).consume(fingerprint, request.digest, at=NOW)[0] is True

    path.unlink()

    reopened = ApprovalLedger(path)
    assert reopened.available is False
    claimed, reason = reopened.consume(fingerprint, request.digest, at=NOW)
    assert claimed is False, "deleting the ledger released a spent grant again"
    assert ApprovalLedger.MISSING in reason


def test_an_unprovisioned_ledger_refuses_rather_than_creating_itself(tmp_path: Path):
    """A first-ever consequential act must not mint its own replay state."""
    path = tmp_path / "never-provisioned.sqlite3"
    request = _request()

    ledger = ApprovalLedger(path)
    claimed, reason = ledger.consume(_fingerprint("ACT-FIRST", request), request.digest, at=NOW)

    assert claimed is False
    assert ApprovalLedger.MISSING in reason
    assert not path.exists(), "the refusal created the ledger it was refusing over"


def test_a_boundary_cannot_provision_its_own_replay_state(tmp_path: Path):
    """Constructing the boundary must not be a way to get a ledger."""
    boundary = NornyxActionBoundary(tmp_path, allow_fallback=True)
    assert boundary.approval_ledger.available is False
    assert not approval_ledger_path(tmp_path).exists()


def test_provisioning_is_idempotent_and_never_clears_what_was_spent(tmp_path: Path):
    """Re-running setup must not be a way to launder a spent grant."""
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    fingerprint = _fingerprint("ACT-REPROVISION", request)
    assert ApprovalLedger.provision(path).consume(fingerprint, request.digest, at=NOW)[0] is True

    again = ApprovalLedger.provision(path)
    claimed, reason = again.consume(fingerprint, request.digest, at=NOW)
    assert claimed is False, "re-provisioning emptied the ledger"
    assert "already consumed" in reason


def test_a_ledger_missing_its_table_is_unavailable_not_silently_rebuilt(tmp_path: Path):
    """An empty database file is not an empty ledger.

    It is a file that cannot answer the question, and rebuilding the table under
    it would answer "nothing was spent" on no evidence at all.
    """
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable

    path = tmp_path / "tableless.sqlite3"
    sqlite3.connect(path).close()
    with pytest.raises(NornyxRuntimeUnavailable) as raised:
        ApprovalLedger(path)
    assert "unusable" in str(raised.value)


def test_a_constraint_free_table_is_refused(tmp_path: Path):
    """The constraints ARE the single-use guarantee, so the name is not enough.

    An independent review replaced the ledger with a table of the right name and
    no PRIMARY KEY or UNIQUE, and released the same grant three times: every
    duplicate insert succeeded, so `consume` reported a fresh claim each time.
    Opening checked that a table called `consumed_approvals` existed, which is
    checking the label on the box.
    """
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable

    path = tmp_path / "constraint_free.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE consumed_approvals ("
        " fingerprint TEXT, request_digest TEXT, approval_id TEXT, consumed_at TEXT)"
    )
    conn.commit()
    conn.close()

    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        ApprovalLedger(path)
    assert "constraint" in str(refusal.value).lower()


def test_a_partially_constrained_table_is_refused(tmp_path: Path):
    """Both constraints, not either. They answer different questions.

    PRIMARY KEY stops one human decision being spent twice under different
    labels; UNIQUE stops one consequential act running twice under any decision.
    A table with only the first would still let two distinct grants release the
    same act.
    """
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable

    path = tmp_path / "half_constrained.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE consumed_approvals ("
        " fingerprint TEXT PRIMARY KEY, request_digest TEXT NOT NULL,"
        " approval_id TEXT NOT NULL, consumed_at TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()

    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        ApprovalLedger(path)
    assert "unique" in str(refusal.value).lower()


def test_re_provisioning_over_a_deleted_ledger_starts_empty(tmp_path: Path):
    """Documented, not defended. This leg of the finding stays open.

    Deleting the ledger and re-running the documented provisioning command
    yields an empty ledger in which nothing has been spent, so a still-valid
    grant releases again. Constraint checking cannot see this: the recreated
    table is correct in every respect except that it has forgotten.

    Distinguishing "first-time setup" from "setup after someone removed the
    history" needs state the ledger cannot hold about itself. Asserting the
    current behaviour rather than pretending otherwise, so the exposure is
    recorded and a future anchor has a test to flip.
    """
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    fingerprint = _fingerprint("ACT-REPROVISION-GAP", request)
    assert ApprovalLedger.provision(path).consume(fingerprint, request.digest, at=NOW)[0] is True

    path.unlink()
    for suffix in ("-wal", "-shm"):
        sibling = path.with_name(path.name + suffix)
        if sibling.exists():
            sibling.unlink()

    reborn = ApprovalLedger.provision(path)
    claimed, _ = reborn.consume(fingerprint, request.digest, at=NOW)
    assert claimed is True, (
        "behaviour changed: if re-provisioning now refuses a previously spent "
        "grant, this exposure is closed and this test should assert that instead"
    )


def test_provisioning_over_a_legacy_schema_refuses_rather_than_reporting_success(
    tmp_path: Path,
):
    """`CREATE TABLE IF NOT EXISTS` cannot upgrade a table that already exists.

    Found in the working tree, not in theory: a ledger created before the
    fingerprint model survived there with `approval_id TEXT PRIMARY KEY` and no
    UNIQUE on request_digest -- keying single use on a caller-selectable label,
    which is the defect that motivated binding consumption to a validated
    approval fingerprint in the first place.

    An operator re-running the documented provisioning command over such a file
    must not be told `status: pass`, because the obsolete table would remain and
    the ledger still could not promise single use. This holds because `provision`
    returns through the ordinary constructor and so inherits its checks; building
    the instance directly would skip them and hand back a false success.
    """
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable

    path = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE consumed_approvals ("
        " approval_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL,"
        " consumed_at TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()

    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        ApprovalLedger.provision(path)
    assert "unique" in str(refusal.value).lower()
