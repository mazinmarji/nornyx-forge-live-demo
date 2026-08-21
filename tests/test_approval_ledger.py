"""Consumption of an action approval must survive restarts and races.

A process-local set forgets everything when the boundary is rebuilt or the
process restarts, so the same grant could be replayed by simply starting again.
These drive the durable store directly and through the boundary.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest
from signing import GRANT_ISSUED, LEDGER_ESTABLISHED  # noqa: E402

from nornyx_forge.approval_trust import APPROVAL_SCHEMA
from nornyx_forge.nornyx_runtime import (
    GRANT_PREDATES_LEDGER,
    LEDGER_METADATA_TABLE,
    LEDGER_ROLLED_BACK,
    ActionDescriptor,
    ActionRequest,
    ApprovalLedger,
    NornyxActionBoundary,
    NornyxRuntimeUnavailable,
    approval_fingerprint,
    approval_ledger_path,
    canonical_action_request,
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
    ledger = ApprovalLedger.provision(tmp_path / "ledger.sqlite3", established_at=LEDGER_ESTABLISHED)
    request = _request()
    assert ledger.consume(_fingerprint("ACT-1", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)[0] is True
    claimed, reason = ledger.consume(_fingerprint("ACT-1", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)
    assert claimed is False
    assert "already consumed" in reason


def test_consumption_survives_closing_and_reopening_the_store(tmp_path: Path):
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    assert ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED).consume(_fingerprint("ACT-2", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)[0] is True
    # A brand new object over the same file, as a restarted process would build.
    claimed, reason = ApprovalLedger(path).consume(_fingerprint("ACT-2", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)
    assert claimed is False, reason


def test_consumption_survives_a_new_boundary(tmp_path: Path):
    """Rebuilding the boundary must not forget what was already spent."""
    request = _request()
    # Provisioned once, deliberately, before any boundary exists. A boundary
    # cannot create its own replay state; that is the point of this change.
    ApprovalLedger.provision(approval_ledger_path(tmp_path), established_at=LEDGER_ESTABLISHED)
    first = NornyxActionBoundary(tmp_path, allow_fallback=True)
    assert first.approval_ledger.consume(_fingerprint("ACT-3", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)[0] is True
    second = NornyxActionBoundary(tmp_path, allow_fallback=True)
    claimed, reason = second.approval_ledger.consume(_fingerprint("ACT-3", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)
    assert claimed is False, reason


def test_only_one_of_two_concurrent_consumers_wins(tmp_path: Path):
    """The unique constraint decides the race, not a check-then-act window."""
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    request = _request()

    def claim(_: int) -> bool:
        return ApprovalLedger(path).consume(_fingerprint("ACT-RACE", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)[0]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(claim, range(8)))
    assert sum(results) == 1, results


def test_two_different_requests_do_not_collide_on_a_shared_id(tmp_path: Path):
    """The identifier is provenance, so re-using one is not itself a conflict.

    This test used to assert the opposite, because `approval_id` was the primary
    key. It was the mirror of the real defect: the ledger noticed one id over two
    requests while missing one request under two ids.
    """
    ledger = ApprovalLedger.provision(tmp_path / "ledger.sqlite3", established_at=LEDGER_ESTABLISHED)
    first = _request()
    other = _request(request_id="REQ-CASE-002", parameters={"amount": 5000, "currency": "USD"})
    assert ledger.consume(_fingerprint("ACT-4", first), first.digest, at=NOW, grant_issued_at=GRANT_ISSUED)[0] is True
    claimed, reason = ledger.consume(_fingerprint("ACT-4", other), other.digest, at=NOW, grant_issued_at=GRANT_ISSUED)
    assert claimed is True, reason


def test_one_act_cannot_be_released_by_a_second_approval(tmp_path: Path):
    """Distinct grants, same consequential act: the act still happens once."""
    ledger = ApprovalLedger.provision(tmp_path / "ledger.sqlite3", established_at=LEDGER_ESTABLISHED)
    request = _request()
    # Genuinely different decisions: a second named approver, not a relabel.
    first = _fingerprint("ACT-A", request, approver="human:operations_owner")
    second = _fingerprint("ACT-B", request, approver="human:network_governance_owner")
    assert first != second, "the two grants must differ for this to test anything"
    assert ledger.consume(first, request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)[0] is True
    claimed, reason = ledger.consume(second, request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)
    assert claimed is False
    assert "already released" in reason


def test_a_failing_effect_still_spends_the_approval(tmp_path: Path):
    """At-most-once is the safe direction for a consequential act.

    Consumption happens before the effect, so a failure does not hand back a
    reusable grant. Retrying requires a fresh human approval.
    """
    ledger = ApprovalLedger.provision(tmp_path / "ledger.sqlite3", established_at=LEDGER_ESTABLISHED)
    request = _request()
    assert ledger.consume(_fingerprint("ACT-5", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)[0] is True
    # The effect fails here; the grant stays spent.
    claimed, _ = ledger.consume(_fingerprint("ACT-5", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)
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
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
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
    ApprovalLedger.provision(ledger, established_at=LEDGER_ESTABLISHED)

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
    ledger = ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    # Point the ledger at a directory: every write fails from here on.
    ledger.path = tmp_path
    claimed, reason = ledger.consume("fp-io", _request().digest, at=NOW, grant_issued_at=GRANT_ISSUED)
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
    assert ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED).consume(fingerprint, request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)[0] is True

    path.unlink()

    reopened = ApprovalLedger(path)
    assert reopened.available is False
    claimed, reason = reopened.consume(fingerprint, request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)
    assert claimed is False, "deleting the ledger released a spent grant again"
    assert ApprovalLedger.MISSING in reason


def test_an_unprovisioned_ledger_refuses_rather_than_creating_itself(tmp_path: Path):
    """A first-ever consequential act must not mint its own replay state."""
    path = tmp_path / "never-provisioned.sqlite3"
    request = _request()

    ledger = ApprovalLedger(path)
    claimed, reason = ledger.consume(_fingerprint("ACT-FIRST", request), request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)

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
    assert ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED).consume(fingerprint, request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)[0] is True

    again = ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    claimed, reason = again.consume(fingerprint, request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)
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


def test_re_provisioning_over_a_deleted_ledger_refuses_the_spent_grant(tmp_path: Path):
    """The leg of the finding that used to stay open, now closed.

    This test previously asserted the permissive behaviour and carried its own
    flip instruction: re-running the documented provisioning command over a
    deleted ledger yielded an empty one in which nothing had been spent, so a
    still-valid grant released a second time. Constraint checking could not see
    it, because the recreated table is correct in every respect except that it
    has forgotten.

    The anchor that closes it is `established_at`. The re-provisioned ledger
    cannot say whether this grant was spent, and says so, rather than treating
    silence as permission.
    """
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    fingerprint = _fingerprint("ACT-REPROVISION-GAP", request)
    first = _established_ledger(path, LEDGER_ESTABLISHED)
    assert first.consume(
        fingerprint, request.digest, at=NOW, grant_issued_at=GRANT_ISSUED
    )[0] is True

    path.unlink()
    for suffix in ("-wal", "-shm"):
        sibling = path.with_name(path.name + suffix)
        if sibling.exists():
            sibling.unlink()

    # The ordinary operator action: re-run provisioning, on the real clock.
    reborn = ApprovalLedger.provision(path)
    claimed, reason = reborn.consume(
        fingerprint, request.digest, at=NOW, grant_issued_at=GRANT_ISSUED
    )
    assert claimed is False, "re-provisioning released a previously spent grant"
    assert GRANT_PREDATES_LEDGER in reason
    assert "A fresh human approval is required" in reason


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
        ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    # The refusal names the missing COLUMN, not the missing constraint: this
    # legacy table has no "fingerprint" column at all, so it fails the structural
    # before uniqueness is even considered. Asserting the precise class matters
    # -- "some refusal happened" would pass equally if the ledger were rejected
    # for an unrelated reason.
    message = str(refusal.value).lower()
    assert "missing columns" in message
    assert "fingerprint" in message


# --------------------------------------------------------------------------
# Replay continuity: losing the history must not restore spent grants
# --------------------------------------------------------------------------


def _established_ledger(path: Path, established_at: str) -> ApprovalLedger:
    """A ledger whose replay history began at a stated instant.

    Through the ordinary provisioning path, not by editing the row afterwards:
    a test that reaches around the API it is testing proves the database can
    hold a value, not that the runtime sets or honours it.
    """
    return ApprovalLedger.provision(path, established_at=established_at)


def test_deleting_the_ledger_makes_outstanding_grants_unusable(tmp_path: Path):
    """The disclosed residual, now closed at the property.

    Correct SQL schema never touched this: a recreated table is right in every
    respect except that it has forgotten. So the ledger stops trying to remember
    what was spent and instead makes forgetting SELF-DEFEATING -- it records when
    its history began, and a grant issued before that cannot be vouched for.

    Deleting the replay history therefore makes outstanding grants UNUSABLE
    rather than reusable. An attacker who removes the file to replay a grant
    finds it refused, because the grant predates the ledger now being asked
    whether it was already spent.
    """
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    fingerprint = _fingerprint("ACT-CONTINUITY", request)
    issued = "2026-08-02T00:00:00Z"

    ledger = _established_ledger(path, "2026-08-01T00:00:00Z")
    claimed, reason = ledger.consume(
        fingerprint, request.digest, at=NOW, grant_issued_at=issued
    )
    assert claimed is True, reason

    for suffix in ("", "-wal", "-shm"):
        sibling = path.with_name(path.name + suffix)
        if sibling.exists():
            sibling.unlink()

    reborn = _established_ledger(path, "2026-08-09T00:00:00Z")
    claimed, reason = reborn.consume(
        fingerprint, request.digest, at=NOW, grant_issued_at=issued
    )

    assert claimed is False, "a spent grant became usable again by deleting the ledger"
    assert "GRANT_PREDATES_LEDGER" in reason
    assert "cannot regain usability" in reason


def test_a_grant_issued_after_the_history_began_still_works(tmp_path: Path):
    """The benign control: continuity must not refuse ordinary operation.

    A property that made every grant unusable would be safe and useless. The
    normal case -- provision, then obtain an approval, then release -- has to
    keep working, or the control is a denial of service wearing a security
    argument.
    """
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    ledger = _established_ledger(path, "2026-08-01T00:00:00Z")

    claimed, reason = ledger.consume(
        _fingerprint("ACT-NORMAL", request),
        request.digest,
        at=NOW,
        grant_issued_at="2026-08-02T00:00:00Z",
    )
    assert claimed is True, reason


def test_a_ledger_without_an_establishment_record_refuses(tmp_path: Path):
    """A ledger that cannot say when it began cannot say what it has seen."""
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM ledger_identity")
    conn.commit()
    conn.close()

    request = _request()
    ledger = ApprovalLedger(path)
    claimed, reason = ledger.consume(
        _fingerprint("ACT-NOID", request),
        request.digest,
        at=NOW,
        grant_issued_at="2026-08-02T00:00:00Z",
    )
    assert claimed is False
    assert "LEDGER_CONTINUITY_UNKNOWN" in reason


def test_re_provisioning_preserves_the_original_establishment_instant(tmp_path: Path):
    """Re-running setup on a live ledger must not silently restart its history.

    If provisioning reset `established_at`, an operator running the documented
    command on a healthy ledger would invalidate every outstanding approval --
    and, worse, a second run after a deletion would look identical to the first.
    """
    path = tmp_path / "ledger.sqlite3"
    first = _established_ledger(path, "2026-08-01T00:00:00Z")
    assert first.established_at == "2026-08-01T00:00:00Z"

    again = ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    assert again.established_at == "2026-08-01T00:00:00Z", (
        "re-provisioning restarted the replay history on a live ledger"
    )


def test_a_grant_with_no_issuance_instant_is_refused(tmp_path: Path):
    """An unanswered question must not be recorded as a satisfied one.

    `grant_issued_at` was optional with a None default, and the boundary passed
    `str(approval.get("generated_at", "")) or None` -- so an approval carrying
    no issuance stamp produced None and SKIPPED continuity entirely. The
    argument is now required and an empty stamp is refused, because a grant that
    will not say when it was issued cannot be placed against the history.
    """
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    ledger = _established_ledger(path, LEDGER_ESTABLISHED)

    for absent in ("", "   ", "not-a-timestamp"):
        claimed, reason = ledger.consume(
            _fingerprint("ACT-NOSTAMP", request),
            request.digest,
            at=NOW,
            grant_issued_at=absent,
        )
        assert claimed is False, f"{absent!r} was accepted as an issuance instant"
        assert "GRANT_ISSUANCE_UNKNOWN" in reason


def test_a_timezone_offset_cannot_carry_a_grant_over_the_boundary(tmp_path: Path):
    """Continuity compares instants, not the text they are written in.

    This is the mutation that motivated parsing. Comparing the two stamps as
    STRINGS is wrong in the dangerous direction: an approval issued at
    `2026-08-01T01:00:00+02:00` is 2026-07-31T23:00Z -- an hour BEFORE a history
    beginning at 2026-08-01T00:00:00Z -- but `'2026-08-01T01:00:00+02:00'` sorts
    AFTER `'2026-08-01T00:00:00Z'` as text. Under string comparison the grant
    predating the ledger reads as postdating it, which is precisely what this
    control exists to refuse.
    """
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    established = "2026-08-01T00:00:00Z"
    before_in_time_after_as_text = "2026-08-01T01:00:00+02:00"

    assert before_in_time_after_as_text > established, (
        "this fixture only tests anything while the string sorts the wrong way"
    )

    ledger = _established_ledger(path, established)
    claimed, reason = ledger.consume(
        _fingerprint("ACT-TZ", request),
        request.digest,
        at=NOW,
        grant_issued_at=before_in_time_after_as_text,
    )
    assert claimed is False, "a timezone offset carried a stale grant past continuity"
    assert "GRANT_PREDATES_LEDGER" in reason


def test_a_naive_issuance_instant_is_refused(tmp_path: Path):
    """No zone means no instant, and guessing one would decide by assumption."""
    path = tmp_path / "ledger.sqlite3"
    request = _request()
    ledger = _established_ledger(path, LEDGER_ESTABLISHED)
    claimed, reason = ledger.consume(
        _fingerprint("ACT-NAIVE", request),
        request.digest,
        at=NOW,
        grant_issued_at="2026-08-02T00:00:00",
    )
    assert claimed is False
    assert "GRANT_ISSUANCE_UNKNOWN" in reason


def test_an_unreadable_establishment_record_is_refused(tmp_path: Path):
    """A corrupt anchor is not a permissive one.

    Continuity read `established_at` and compared it directly. A row holding
    junk would then have been compared as text against every grant, and junk
    that sorts low would have waved everything through. It has to parse.
    """
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    conn = sqlite3.connect(path)
    conn.execute("UPDATE ledger_identity SET established_at = '0'")
    conn.commit()
    conn.close()

    request = _request()
    claimed, reason = ApprovalLedger(path).consume(
        _fingerprint("ACT-JUNK", request),
        request.digest,
        at=NOW,
        grant_issued_at=GRANT_ISSUED,
    )
    assert claimed is False
    assert "LEDGER_CONTINUITY_UNKNOWN" in reason


def test_continuity_is_not_optional_at_the_call_site(tmp_path: Path):
    """Structural: no caller can omit issuance and silently skip continuity.

    A behavioural test cannot catch a default being reintroduced -- every
    existing call would keep passing. This asserts the signature itself.
    """
    import inspect

    parameter = inspect.signature(ApprovalLedger.consume).parameters["grant_issued_at"]
    assert parameter.default is inspect.Parameter.empty, (
        "grant_issued_at has a default again, so a caller that forgets it skips "
        "continuity instead of failing"
    )


def test_the_ledger_cannot_hold_two_establishment_instants(tmp_path: Path):
    """One history, one beginning. A second row is not a tie to be broken.

    A mutation that made provisioning re-insert the establishment row on every
    call SURVIVED the suite: the insert appended a second row, and the reader's
    `fetchone()` kept returning the first, so nothing observable changed. That
    is a control whose correctness depended on the caller inserting once.

    Two independent things fix it, and both are asserted here: the table refuses
    the second row, and a reader that finds more than one refuses to choose.
    """
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)

    conn = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                f"INSERT INTO {LEDGER_METADATA_TABLE} (id, established_at)"
                " VALUES (2, '1970-01-01T00:00:00Z')"
            )
        # A ledger built elsewhere carries no such constraint, so the reader
        # must hold the line on its own rather than trusting the schema.
        conn.execute(f"DROP TABLE {LEDGER_METADATA_TABLE}")
        conn.execute(f"CREATE TABLE {LEDGER_METADATA_TABLE} (established_at TEXT)")
        conn.executemany(
            f"INSERT INTO {LEDGER_METADATA_TABLE} (established_at) VALUES (?)",
            [("1970-01-01T00:00:00Z",), (LEDGER_ESTABLISHED,)],
        )
        conn.commit()
    finally:
        conn.close()

    request = _request()
    claimed, reason = ApprovalLedger(path).consume(
        _fingerprint("ACT-TWOROWS", request),
        request.digest,
        at=NOW,
        grant_issued_at=GRANT_ISSUED,
    )
    assert claimed is False, "a ledger with two establishment rows released a grant"
    assert "LEDGER_CONTINUITY_UNKNOWN" in reason


def test_provisioning_twice_leaves_exactly_one_establishment_row(tmp_path: Path):
    """The benign control for the constraint above.

    Re-running the documented setup command on a healthy ledger is ordinary
    operator behaviour and must stay quiet -- no error, no second row, and the
    original instant preserved.
    """
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    again = ApprovalLedger.provision(path, established_at="2026-08-09T00:00:00Z")

    assert again.established_at == LEDGER_ESTABLISHED, (
        "re-provisioning moved the anchor, so every outstanding grant would "
        "have been invalidated by an ordinary setup re-run"
    )
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(f"SELECT established_at FROM {LEDGER_METADATA_TABLE}").fetchall()
    finally:
        conn.close()
    assert len(rows) == 1, f"provisioning twice left {len(rows)} establishment rows"


# --------------------------------------------------------------------------
# The ledger schema is CLOSED, because the replay property is defeated by an
# EXTRA object rather than by a missing constraint.
# --------------------------------------------------------------------------

HOSTILE_LEDGER_OBJECTS = [
    ("a trigger that discards the insert",
     "CREATE TRIGGER t BEFORE INSERT ON consumed_approvals "
     "BEGIN SELECT RAISE(IGNORE); END"),
    # NAMED LIKE THE TABLE IT ATTACKS. Every hostile object here was called `t`,
    # and the guard filtered on NAME while discarding the KIND it had just
    # unpacked -- so SQLite happily let a TRIGGER share the TABLE's name and the
    # attack the guard was written to stop was the one spelling it admitted.
    # Measured before the repair: one grant, five released effects, zero
    # consumption rows, `established_at` untouched. 42 tests passed.
    ("a trigger wearing the consumption table's name",
     "CREATE TRIGGER consumed_approvals BEFORE INSERT ON consumed_approvals "
     "BEGIN SELECT RAISE(IGNORE); END"),
    ("a trigger wearing the identity table's name",
     "CREATE TRIGGER ledger_identity BEFORE INSERT ON consumed_approvals "
     "BEGIN SELECT RAISE(IGNORE); END"),
    ("a trigger wearing a permitted name that deletes the claim",
     "CREATE TRIGGER ledger_identity AFTER INSERT ON consumed_approvals "
     "BEGIN DELETE FROM consumed_approvals; END"),
    ("a view wearing the consumption table's name",
     "CREATE VIEW ledger_identity_view AS SELECT * FROM consumed_approvals"),
    ("a trigger that deletes the claim it just wrote",
     "CREATE TRIGGER t AFTER INSERT ON consumed_approvals "
     "BEGIN DELETE FROM consumed_approvals; END"),
    ("a deletion trigger",
     "CREATE TRIGGER t AFTER DELETE ON consumed_approvals BEGIN SELECT 1; END"),
    ("a view shadowing the consumption table",
     "CREATE VIEW consumed_shadow AS SELECT * FROM consumed_approvals"),
    ("an unexpected table",
     "CREATE TABLE side_channel (x TEXT)"),
]


@pytest.mark.parametrize(
    ("label", "ddl"), HOSTILE_LEDGER_OBJECTS,
    ids=[case[0] for case in HOSTILE_LEDGER_OBJECTS],
)
def test_an_unexpected_database_object_is_refused(tmp_path: Path, label: str, ddl: str):
    """`PRAGMA index_list` reports what the engine will CONSTRAIN, not what it
    will DO with the write.

    Measured before the schema was closed: one
    `BEFORE INSERT ... RAISE(IGNORE)` trigger made every consumption a silent
    no-op -- no IntegrityError, so `consume` reported success forever, the table
    stayed empty, and five callbacks came from one grant while `established_at`
    was intact and every uniqueness and continuity check passed.

    A trigger IS engine metadata and IS what the engine will do, so the object
    set is enumerated rather than sampled: anything not permitted is refused,
    because the next hostile object is the one nobody listed.
    """
    from signing import LEDGER_ESTABLISHED  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable  # noqa: PLC0415

    path = tmp_path / "hostile.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    conn = sqlite3.connect(path)
    conn.execute(ddl)
    conn.commit()
    conn.close()

    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        ApprovalLedger(path)
    assert "does not permit" in str(refusal.value), str(refusal.value)


def test_the_permitted_schema_is_still_accepted(tmp_path: Path):
    """The control. A closed set that refused everything would also be useless."""
    from signing import LEDGER_ESTABLISHED  # noqa: PLC0415

    path = tmp_path / "clean.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    ledger = ApprovalLedger(path)
    assert ledger.available, ledger.unavailable_reason


def test_a_hostile_trigger_releases_no_effect(tmp_path: Path):
    """The consequence, not the diagnosis.

    One grant must never produce more than one callback. Before the schema was
    closed this produced five.
    """
    from signing import LEDGER_ESTABLISHED, signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        canonical_action_request,
    )

    descriptor = ActionDescriptor(
        operation="wire transfer", resource="customer:omar",
        destination="zone.external_customer",
        parameters={"amount": 10_000_000, "currency": "USD"},
    )
    ApprovalLedger.provision(
        approval_ledger_path(tmp_path), established_at=LEDGER_ESTABLISHED
    )
    conn = sqlite3.connect(approval_ledger_path(tmp_path))
    conn.execute(
        "CREATE TRIGGER t BEFORE INSERT ON consumed_approvals "
        "BEGIN SELECT RAISE(IGNORE); END"
    )
    conn.commit()
    conn.close()

    request = canonical_action_request(
        mission_id="CASE-HOSTILE", risk="high", subject_revision=TEST_REVISION,
        descriptor=descriptor, attempt=1,
    )
    grant = signed_grant(request, approval_id="ACT-HOSTILE", role="operations_owner")

    calls: list[str] = []
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable  # noqa: PLC0415

    with pytest.raises(NornyxRuntimeUnavailable):
        boundary = _permissive_boundary(tmp_path, as_of="2026-08-03T00:00:00Z")
        boundary.evaluate_and_execute(
            mission_id="CASE-HOSTILE", risk="high",
            action=lambda: (calls.append("released"), "done")[1],
            action_approval=grant, action_descriptor=descriptor, attempt=1,
        )
    assert calls == [], "a hostile ledger structure released a consequential effect"


def test_a_missing_identity_table_denies_rather_than_reporting_an_outage(tmp_path: Path):
    """The closed set is closed over PRESENCE, and that asymmetry is deliberate.

    Written because closing the schema very nearly closed it symmetrically. A
    required-objects clause would have refused a ledger with no `ledger_identity`
    as unusable -- true, but it renames a decision as a fault. The ledger CAN
    say something about this grant: that it cannot place it against a history it
    has no start for. That is LEDGER_CONTINUITY_UNKNOWN, a DENY with a question
    attached, and it is not the same security state as a broken database.

    So: an EXTRA object is an outage, a MISSING establishment record is a denial,
    and neither may be reported as the other.
    """
    path = tmp_path / "no_identity.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE consumed_approvals ("
        " fingerprint TEXT PRIMARY KEY, request_digest TEXT NOT NULL,"
        " approval_id TEXT NOT NULL, consumed_at TEXT NOT NULL,"
        " UNIQUE (fingerprint), UNIQUE (request_digest))"
    )
    conn.commit()
    conn.close()

    ledger = ApprovalLedger(path)  # constructs: this is not an outage
    assert ledger.available, ledger.unavailable_reason
    assert ledger.established_at is None

    consumed, reason = ledger.consume(
        "f" * 64, "r" * 64, approval_id="ACT-1",
        grant_issued_at="2026-08-03T00:00:00Z", at="2026-08-03T00:00:01Z",
    )
    assert consumed is False
    assert "LEDGER_CONTINUITY_UNKNOWN" in reason, reason


# --------------------------------------------------------------------------
# The closed-object guard, proved at the BOUNDARY rather than on the schema.
#
# The schema-level tests above assert a refusal. These assert what the refusal
# is FOR: that no consequential effect is released and no approval is respent.
# The distinction matters because the guard was bypassable for months while
# every schema test passed -- they all named their trigger `t`, and the guard
# filtered on name while discarding kind.
# --------------------------------------------------------------------------

HOSTILE_TRIGGER = (
    "CREATE TRIGGER consumed_approvals BEFORE INSERT ON consumed_approvals "
    "BEGIN SELECT RAISE(IGNORE); END"
)


def _release_three_times(root: Path, *, install_after_establish: str = ""):
    """Present ONE valid grant three times. Returns (effects, callbacks, rows)."""
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: PLC0415

    descriptor = ActionDescriptor(
        operation="wire transfer", resource="customer:omar",
        destination="zone.external_customer", parameters={"amount": 10_000_000},
    )
    request = canonical_action_request(
        mission_id="CASE-REPLAY", risk="high", subject_revision=TEST_REVISION,
        descriptor=descriptor, attempt=1,
    )
    grant = signed_grant(request, approval_id="ACT-ONCE", role="operations_owner")

    boundary = _permissive_boundary(root, as_of="2026-08-03T00:00:00Z")
    if install_after_establish:
        # AFTER the boundary is built, which is the whole point: the ledger file
        # is writable by the governed process on every request.
        conn = sqlite3.connect(approval_ledger_path(root), isolation_level=None)
        conn.execute(install_after_establish)
        conn.close()

    calls: list[int] = []
    effects: list[str] = []
    for _ in range(3):
        decision, _result = boundary.evaluate_and_execute(
            mission_id="CASE-REPLAY", risk="high",
            action=lambda: (calls.append(1), "wired")[1],
            action_approval=grant, action_descriptor=descriptor, attempt=1,
        )
        effects.append(decision.effect)

    conn = sqlite3.connect(approval_ledger_path(root))
    rows = list(conn.execute("SELECT fingerprint FROM consumed_approvals"))
    conn.close()
    return effects, len(calls), len(rows)


def test_an_ordinary_ledger_still_releases_exactly_once(tmp_path: Path):
    """The control. Without it every refusal below could be 'refuses always'."""
    ApprovalLedger.provision(
        approval_ledger_path(tmp_path), established_at=LEDGER_ESTABLISHED
    )
    effects, callbacks, rows = _release_three_times(tmp_path)

    assert effects == ["ALLOW", "DENY", "DENY"], effects
    assert callbacks == 1, "at-most-once was not honoured on an ordinary ledger"
    assert rows == 1


def test_a_legitimate_unique_index_still_releases_exactly_once(tmp_path: Path):
    """A UNIQUE INDEX is a real way to enforce the property, not an attack.

    The guard refused these by NAME, so a correctly-built ledger was rejected as
    hostile -- the same defect as the trigger bypass, in the safe direction.
    Indexes are now permitted by KIND: an index cannot discard, rewrite or
    shadow a row, which is exactly what triggers and views can do.
    """
    ledger = approval_ledger_path(tmp_path)
    ApprovalLedger.provision(ledger, established_at=LEDGER_ESTABLISHED)
    conn = sqlite3.connect(ledger, isolation_level=None)
    conn.execute("CREATE UNIQUE INDEX ux_fingerprint ON consumed_approvals(fingerprint)")
    conn.close()

    effects, callbacks, rows = _release_three_times(tmp_path)

    assert effects == ["ALLOW", "DENY", "DENY"], effects
    assert callbacks == 1
    assert rows == 1


def test_a_trigger_wearing_a_permitted_name_releases_nothing(tmp_path: Path):
    """THE BYPASS, at the boundary.

    Measured before the repair: `effects=['ALLOW']*5, callbacks=5, rows=0` with
    `established_at` intact, so the continuity anchor never fired either. The
    ledger is bind-mounted read-write and gitignored, so the process that must
    not replay an approval owns the state that prevents it.
    """
    ledger = approval_ledger_path(tmp_path)
    ApprovalLedger.provision(ledger, established_at=LEDGER_ESTABLISHED)
    conn = sqlite3.connect(ledger, isolation_level=None)
    conn.execute(HOSTILE_TRIGGER)
    conn.close()

    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        _release_three_times(tmp_path)
    assert "consumed_approvals" in str(refusal.value)


def test_a_trigger_installed_after_establishment_is_caught_at_the_claim(
    tmp_path: Path,
):
    """Establishment-time validation proves the ledger at t0 and nothing after.

    THIS IS THE PATH THAT MATTERED. The three cases above all refuse during
    construction, which masked two real defects in the repair itself: an
    invented constant and a wrong call signature, both on the consume path,
    both invisible until a case got past construction.

    Nothing is released, and no row is written, because the structure is
    re-validated immediately before the insert that IS the claim.
    """
    ApprovalLedger.provision(
        approval_ledger_path(tmp_path), established_at=LEDGER_ESTABLISHED
    )
    effects, callbacks, rows = _release_three_times(
        tmp_path, install_after_establish=HOSTILE_TRIGGER
    )

    assert callbacks == 0, (
        f"a governed effect ran against a ledger whose structure changed after "
        f"establishment: effects={effects}"
    )
    assert effects == ["DENY", "DENY", "DENY"], effects
    assert rows == 0


# --------------------------------------------------------------------------
# R1 -- candidate-set incompleteness before closure evaluation.
#
# The hostile catalogue above varies the KIND and the STATEMENT of the object
# exhaustively. It never varies the NAME into the range the structural check's
# own enumeration discards, so three live bypasses sat under a green suite.
#
# Measured on the defective head: one fingerprint consumed FIVE times, every
# call granting, ZERO consumption rows persisted, ledger reporting `available`.
# `plain_hostile` is refused by the same code, which is what proves these three
# evade the check specifically rather than the check being absent.
# --------------------------------------------------------------------------

#: (label, object name, install via PRAGMA writable_schema, must be refused)
R1_SPECIMENS = [
    ("ordinary DDL, one wildcard char", "sqliteXshadow", False, True),
    ("ordinary DDL, digit after prefix", "sqlite0shadow", False, True),
    ("writable_schema, reserved prefix", "sqlite_shadow", True, True),
    ("control: an ordinary hostile name", "plain_hostile", False, True),
]


def _ledger_carrying(tmp_path: Path, name: str, *, writable_schema: bool) -> Path:
    """Provision a real ledger, then install one hostile trigger on it."""
    path = tmp_path / f"{name}.sqlite3"
    ApprovalLedger.provision(path, established_at="2026-08-01T00:00:00Z")
    ddl = (f"CREATE TRIGGER {name} BEFORE INSERT ON consumed_approvals "
           "BEGIN SELECT RAISE(IGNORE); END")
    with closing(sqlite3.connect(path, isolation_level=None)) as conn:
        if writable_schema:
            conn.execute("PRAGMA writable_schema=ON")
            conn.execute(
                "INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql) "
                "VALUES('trigger',?,'consumed_approvals',0,?)", (name, ddl))
            conn.execute("PRAGMA writable_schema=OFF")
        else:
            conn.execute(ddl)
    return path


@pytest.mark.parametrize(
    ("label", "name", "writable_schema", "must_refuse"),
    R1_SPECIMENS,
    ids=[case[0] for case in R1_SPECIMENS],
)
def test_r1_a_hostile_ledger_object_cannot_enable_replay(
    tmp_path: Path, label: str, name: str, writable_schema: bool, must_refuse: bool
):
    """Through the PRODUCTION path: `__init__` then `consume`, five times.

    Deliberately NOT a direct call to `_assert_ledger_structure`. A helper test
    proves the helper works; it cannot prove the production constructor invokes
    it, and this whole class of defect is a declared step that never executes.

    The assertion encodes the SEMANTIC unsafe state -- repeated consumes all
    granted AND no consumption rows -- rather than "the constructor raised".
    An unrelated exception must not be able to make this look green, and a
    future refactor that throws for a different reason must not count as a fix.
    """
    path = _ledger_carrying(tmp_path, name, writable_schema=writable_schema)

    try:
        ledger = ApprovalLedger(path)
    except NornyxRuntimeUnavailable:
        return  # refused at construction: the property holds

    granted = [
        ledger.consume(
            "FP-R1", "REQ-R1",
            at="2026-08-15T00:00:00Z", grant_issued_at="2026-08-10T00:00:00Z",
        )[0]
        for _ in range(5)
    ]
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("SELECT count(*) FROM consumed_approvals").fetchone()[0]

    replayed = all(granted) and rows == 0
    assert not replayed, (
        f"{label}: a ledger carrying {name!r} granted one fingerprint five "
        f"times and persisted {rows} consumption rows, so single-use replay "
        "protection is defeated. The structural check did not see the object "
        "because its enumeration excluded candidates before closure was "
        "evaluated -- the object was never a candidate to reject."
    )
    assert not all(granted), (
        f"{label}: every consume of one fingerprint was granted "
        f"({granted}); at most the first may be"
    )


def test_r1_a_legitimate_unique_index_is_still_accepted(tmp_path: Path):
    """Positive control. "Refuse every non-table object" would pass the hostile
    cases above while breaking ordinary SQLite structure, so over-closing has
    to be as visible as under-closing."""
    path = tmp_path / "extra_index.sqlite3"
    ApprovalLedger.provision(path, established_at="2026-08-01T00:00:00Z")
    with closing(sqlite3.connect(path, isolation_level=None)) as conn:
        conn.execute("CREATE UNIQUE INDEX extra_idx ON consumed_approvals(consumed_at)")

    ledger = ApprovalLedger(path)
    assert ledger.available, f"a legitimate UNIQUE index was refused: {ledger.unavailable_reason}"


def test_r1_a_clean_ledger_still_consumes_exactly_once(tmp_path: Path):
    """Positive control on the BEHAVIOUR, not just construction.

    The hostile assertions are about replay; this proves the non-hostile path
    still does the thing replay protection exists to allow -- one grant, one
    effect, one row -- so the fix cannot be "deny everything".
    """
    path = tmp_path / "clean.sqlite3"
    ApprovalLedger.provision(path, established_at="2026-08-01T00:00:00Z")
    ledger = ApprovalLedger(path)

    granted = [
        ledger.consume(
            "FP-CLEAN", "REQ-CLEAN",
            at="2026-08-15T00:00:00Z", grant_issued_at="2026-08-10T00:00:00Z",
        )[0]
        for _ in range(5)
    ]
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("SELECT count(*) FROM consumed_approvals").fetchone()[0]

    assert granted[0] is True, "the first consume of a fresh grant must be allowed"
    assert not any(granted[1:]), f"a spent grant was reusable: {granted}"
    assert rows == 1, f"expected exactly one consumption row, found {rows}"


def test_la01_a_surviving_ledger_object_re_reads_the_continuity_anchor(tmp_path: Path):
    """The anchor must be read at the CLAIM, not cached at construction.

    `_assert_ledger_structure` is deliberately re-run inside `consume` -- "a
    hostile object installed after establishment was never seen again ... this
    is the last moment before the claim". `established_at` lives in the same
    file, in the same directory, with the same write exposure, and was read
    ONCE in `__init__`.

    So a boundary object that outlives the documented ledger restore keeps
    vouching for a grant the restore was supposed to invalidate. No attacker is
    needed: an operator running the documented recovery while a request is in
    flight is enough.

    Both existing tests construct the ledger AFTER the restore, which is the
    one ordering where the property holds -- a running server produces the
    other. Measured before the fix: the surviving object granted a second
    consumption of the same fingerprint while a fresh object refused it.
    """
    path = tmp_path / "continuity.sqlite3"
    first, restored, issued, now = (
        "2026-08-01T00:00:00Z", "2026-08-02T12:00:00Z",
        "2026-08-02T00:00:00Z", "2026-08-03T00:00:00Z",
    )
    ApprovalLedger.provision(path, established_at=first)
    surviving = ApprovalLedger(path)
    claimed, _ = surviving.consume(
        "fp-la01", "rd-la01", at=now, grant_issued_at=issued, approval_id="LA01")
    assert claimed is True, "the first spend must succeed or this proves nothing"

    for sibling in tmp_path.glob("continuity.sqlite3*"):
        sibling.unlink()
    ApprovalLedger.provision(path, established_at=restored)

    replayed, reason = surviving.consume(
        "fp-la01", "rd-la01", at=now, grant_issued_at=issued, approval_id="LA01")
    assert replayed is False, (
        "a ledger object constructed before the restore released the same grant "
        "again, because it answered from a continuity anchor cached at "
        f"construction rather than read at the claim: {reason}"
    )
    assert "GRANT_PREDATES_LEDGER" in reason, reason


def test_la01_a_grant_issued_after_the_restore_still_works(tmp_path: Path):
    """Positive control: re-reading the anchor must not refuse legitimate use."""
    path = tmp_path / "continuity_ok.sqlite3"
    ApprovalLedger.provision(path, established_at="2026-08-01T00:00:00Z")
    surviving = ApprovalLedger(path)
    for sibling in tmp_path.glob("continuity_ok.sqlite3*"):
        sibling.unlink()
    ApprovalLedger.provision(path, established_at="2026-08-02T00:00:00Z")

    claimed, reason = surviving.consume(
        "fp-after", "rd-after", at="2026-08-03T00:00:00Z",
        grant_issued_at="2026-08-02T06:00:00Z", approval_id="AFTER")
    assert claimed is True, (
        f"a grant issued AFTER the restored anchor was refused: {reason}"
    )


# --------------------------------------------------------------------------
# A02 -- a RESTORED ledger, which the continuity anchor cannot see.
#
# The anchor makes DELETION self-defeating: an absent file is re-provisioned at
# a later epoch, so every outstanding grant predates it. Restoration is the
# other half, and the module comment claimed that one too -- an operator
# restoring a lost ledger with the documented command "now fails closed". It
# did not. `established_at` lives inside the file being rolled back, so the old
# epoch returns with the emptied rows and the pair is indistinguishable from a
# ledger set up early and not yet used. Measured before the fix: ONE human
# approval, FIVE releases, no adversary anywhere.
# --------------------------------------------------------------------------


def test_a02_a_restored_ledger_refuses_the_grant_it_forgot(tmp_path: Path):
    """The counterexample, exactly as reproduced, driven through `consume`."""
    path = tmp_path / "restore.sqlite3"
    backup = tmp_path / "restore.backup"
    request = _request()
    fingerprint = _fingerprint("ACT-RESTORE", request)
    issued = "2026-08-02T00:00:00Z"

    _established_ledger(path, "2026-08-01T00:00:00Z")
    # The ordinary operator backup: taken after setup, before any effect ran.
    shutil.copy2(path, backup)

    claimed, reason = ApprovalLedger(path).consume(
        fingerprint, request.digest, at=NOW, grant_issued_at=issued)
    assert claimed is True, f"first spend must succeed or this proves nothing: {reason}"

    released = 1
    for _ in range(4):
        shutil.copy2(backup, path)          # nothing adversarial: a restore
        again, reason = ApprovalLedger(path).consume(
            fingerprint, request.digest, at=NOW, grant_issued_at=issued)
        released += bool(again)
    assert released == 1, (
        f"one human approval released {released} effects across ordinary "
        "backup restores, so single use is guaranteed by nothing a restore "
        "cannot undo"
    )
    assert LEDGER_ROLLED_BACK in reason, reason


def test_a02_the_anchor_alone_cannot_see_a_restore(tmp_path: Path):
    """WHY the count is needed, as a measurement rather than a claim.

    If continuity could see a restore the sidecar would be redundant. It
    cannot: after the restore the anchor is the ORIGINAL instant and the grant
    was issued after it, so the continuity comparison says the grant is fresh.
    This pins the gap the new check fills -- if it ever closes by another
    route, this says so rather than leaving a duplicate control in place.
    """
    path = tmp_path / "gap.sqlite3"
    backup = tmp_path / "gap.backup"
    _established_ledger(path, "2026-08-01T00:00:00Z")
    shutil.copy2(path, backup)
    request = _request()
    ApprovalLedger(path).consume(
        _fingerprint("ACT-GAP", request), request.digest,
        at=NOW, grant_issued_at="2026-08-02T00:00:00Z")

    shutil.copy2(backup, path)
    restored = ApprovalLedger(path)
    assert restored.established_at == "2026-08-01T00:00:00Z", (
        "the restore was supposed to bring the ORIGINAL anchor back; if it "
        "does not, this specimen no longer reproduces the defect"
    )
    assert restored.established_at < "2026-08-02T00:00:00Z", (
        "the grant is issued AFTER the restored anchor, which is exactly why "
        "continuity passes it and something else has to catch it"
    )


def test_a02_a_removed_mark_is_refused_and_the_reversal_is_deliberate(tmp_path: Path):
    """THIS TEST ASSERTED THE OPPOSITE, AND THE OPPOSITE WAS MEASURABLY WRONG.

    It read: "A ledger written before this check existed, or one whose sidecar
    an operator removed while tidying, has nothing to compare against. Refusing
    it would turn a missing file into an outage for every legitimate grant." So
    it required a removed mark to release.

    A review then measured what that permits: delete the sidecar, restore an
    older ledger, and a grant that was already spent RELEASES THE EFFECT AGAIN
    -- and then every other forgotten grant in turn. One human approval, many
    effects. "Anyone who can delete the sidecar" had been written down as a
    disclosed residual; disclosing a hole is not the same as being unable to
    close it.

    So the policy is reversed on purpose. `provision` now writes the mark, so
    the mark exists whenever the ledger does, and its absence is removal rather
    than an unused ledger. The availability concern the old wording protected
    is real and is kept -- as the property it actually was:
    `test_a02_ordinary_use_advances_the_mark_and_is_never_refused` and
    `tests/test_ledger_continuity.py` both drive legitimate grants and require
    them to release, including six concurrent first-time consumers.

    THE COST: a ledger provisioned before this change refuses until
    `provision-ledger --reset-replay-history` is run, and the refusal says so.
    """
    path = tmp_path / "boot.sqlite3"
    request = _request()
    _established_ledger(path, "2026-08-01T00:00:00Z")
    ledger = ApprovalLedger(path)
    ledger.consume(_fingerprint("ACT-1", request), request.digest,
                   at=NOW, grant_issued_at="2026-08-02T00:00:00Z")
    ledger.watermark_path.unlink()

    second = _request(mission_id="CASE-BOOT-2")
    claimed, reason = ApprovalLedger(path).consume(
        _fingerprint("ACT-2", second), second.digest,
        at=NOW, grant_issued_at="2026-08-02T00:00:00Z")
    assert claimed is False, (
        "the replay high-water mark was deleted and the ledger released "
        "anyway, so removing one file disables replay detection entirely"
    )
    assert "LEDGER_CONTINUITY_UNKNOWN" in reason, reason
    assert "--reset-replay-history" in reason, (
        f"the refusal does not name the remedy an operator needs: {reason}"
    )


def test_a02_ordinary_use_advances_the_mark_and_is_never_refused(tmp_path: Path):
    """The positive control. Without it the check above could refuse everything.

    Twenty-five distinct grants, the shape of normal operation. If the mark
    were compared wrongly -- or read AFTER the row count rather than before it
    -- this is where that shows up.
    """
    path = tmp_path / "normal.sqlite3"
    _established_ledger(path, "2026-08-01T00:00:00Z")
    released = 0
    for index in range(25):
        request = _request(mission_id=f"CASE-N{index}")
        claimed, _ = ApprovalLedger(path).consume(
            _fingerprint(f"ACT-{index}", request), request.digest,
            at=NOW, grant_issued_at="2026-08-02T00:00:00Z")
        released += bool(claimed)
    assert released == 25, f"legitimate grants were refused: {released} of 25"


def test_a03_the_predates_refusal_names_the_anchor_the_decision_used(tmp_path: Path):
    """The message must not contradict the decision that produced it.

    `consume` re-reads the anchor at the claim -- that repair is what stopped a
    surviving boundary object replaying a spent grant. The refusal STRING went
    on interpolating the cached value, so the artifact written into runtime
    evidence named the stale instant and asserted an inequality that is false:
    "issued at 2026-08-02, before this replay history began at 2026-08-01".
    The regression asserted only that the CODE appeared, so the value it
    printed was measured by nothing.
    """
    path = tmp_path / "a03.sqlite3"
    request = _request()
    _established_ledger(path, "2026-08-01T00:00:00Z")
    surviving = ApprovalLedger(path)
    assert surviving.established_at == "2026-08-01T00:00:00Z"

    for suffix in ("", "-wal", "-shm", ".highwater"):
        sibling = path.with_name(path.name + suffix)
        if sibling.exists():
            sibling.unlink()
    _established_ledger(path, "2026-08-09T00:00:00Z")

    claimed, reason = surviving.consume(
        _fingerprint("ACT-A03", request), request.digest,
        at=NOW, grant_issued_at="2026-08-02T00:00:00Z")
    assert claimed is False, reason
    assert GRANT_PREDATES_LEDGER in reason, reason
    assert "2026-08-09T00:00:00Z" in reason, (
        "the refusal names an anchor the decision did not use: it must report "
        f"the instant re-read at the claim, not the cached one -- {reason}"
    )
    assert "2026-08-01T00:00:00Z" not in reason, (
        f"the stale cached anchor is still being published: {reason}"
    )


# --------------------------------------------------------------------------
# A05 -- opening a ledger must not CREATE one, in any spelling.
#
# This class removed `CREATE TABLE IF NOT EXISTS` from the point of use, and
# the docstring still says "Open an existing ledger. Creates nothing." The
# creation came back one layer down: `sqlite3.connect(path)` makes the file. So
# `consume` on a deleted ledger left a 0-byte residue, and the next
# NornyxActionBoundary raised on it -- turning "a missing ledger refuses
# consequential acts" into "the application serves nothing at all, including
# low-risk read-only work".
# --------------------------------------------------------------------------


def test_a05_consuming_against_a_deleted_ledger_creates_nothing(tmp_path: Path):
    """The refusal must leave the directory as it found it."""
    path = tmp_path / "gone.sqlite3"
    request = _request()
    _established_ledger(path, "2026-08-01T00:00:00Z")
    surviving = ApprovalLedger(path)
    for suffix in ("", "-wal", "-shm", ".highwater"):
        sibling = path.with_name(path.name + suffix)
        if sibling.exists():
            sibling.unlink()
    assert path.exists() is False, "the specimen must start with the ledger gone"

    claimed, reason = surviving.consume(
        _fingerprint("ACT-GONE", request), request.digest,
        at=NOW, grant_issued_at="2026-08-02T00:00:00Z")
    assert claimed is False, reason
    assert path.exists() is False, (
        "consuming against an absent ledger created it. An empty ledger is one "
        "in which nothing has been spent, which is the exact state this class "
        f"exists to refuse: {reason}"
    )


def test_a05_a_missing_ledger_still_leaves_the_boundary_constructable(tmp_path: Path):
    """The documented behaviour, which the residue silently replaced.

    A-014: a missing ledger DENIES consequential acts. It does not take the
    process down -- the residue made construction raise, so no case could be
    served at all.
    """
    path = tmp_path / "absent.sqlite3"
    request = _request()
    _established_ledger(path, "2026-08-01T00:00:00Z")
    ApprovalLedger(path).consume(
        _fingerprint("ACT-A", request), request.digest,
        at=NOW, grant_issued_at="2026-08-02T00:00:00Z")
    for suffix in ("", "-wal", "-shm", ".highwater"):
        sibling = path.with_name(path.name + suffix)
        if sibling.exists():
            sibling.unlink()
    ApprovalLedger(path).consume(
        _fingerprint("ACT-B", request), request.digest,
        at=NOW, grant_issued_at="2026-08-02T00:00:00Z")

    reopened = ApprovalLedger(path)
    assert reopened.available is False, (
        "a missing ledger must report itself unavailable rather than usable"
    )
    assert ApprovalLedger.MISSING in (reopened.unavailable_reason or ""), (
        reopened.unavailable_reason
    )


# --------------------------------------------------------------------------
# A04 -- the read-only pre-flight could not fire for the state it names.
#
# `BEGIN IMMEDIATE` SUCCEEDS on a read-only SQLite database. So did
# `PRAGMA journal_mode=WAL` and `ROLLBACK`. Only the INSERT failed -- at the
# worst moment, which is precisely what the pre-flight existed to avoid -- and
# the refusal it produced carried no code at all, while `UNWRITABLE` was
# emitted by nothing anywhere in the repository.
# --------------------------------------------------------------------------


def test_a04_a_read_only_ledger_is_refused_at_construction(tmp_path: Path):
    """Named, and named as UNWRITABLE rather than as some other failure."""
    path = tmp_path / "readonly.sqlite3"
    _established_ledger(path, "2026-08-01T00:00:00Z")
    for suffix in ("-wal", "-shm"):
        sibling = path.with_name(path.name + suffix)
        if sibling.exists():
            sibling.unlink()
    os.chmod(path, stat.S_IREAD)
    try:
        with pytest.raises(NornyxRuntimeUnavailable) as refusal:
            ApprovalLedger(path)
        assert ApprovalLedger.UNWRITABLE in str(refusal.value), (
            "a read-only ledger was refused without saying it is read-only, so "
            f"an operator cannot tell it from a corrupt one: {refusal.value}"
        )
    finally:
        os.chmod(path, stat.S_IWRITE)


def test_a04_a_writable_ledger_is_not_refused(tmp_path: Path):
    """The positive control: the probe write must roll back and change nothing.

    A pre-flight that recorded its own probe row would be a ledger that lies
    about what it has spent, so this asserts the row count as well as the
    absence of a refusal.
    """
    path = tmp_path / "writable.sqlite3"
    _established_ledger(path, "2026-08-01T00:00:00Z")
    ledger = ApprovalLedger(path)
    assert ledger.available is True, ledger.unavailable_reason
    with closing(sqlite3.connect(path)) as conn:
        rows = conn.execute("SELECT count(*) FROM consumed_approvals").fetchone()[0]
    assert rows == 0, f"the pre-flight left {rows} probe rows in the history"

    request = _request()
    claimed, reason = ledger.consume(
        _fingerprint("ACT-W", request), request.digest,
        at=NOW, grant_issued_at="2026-08-02T00:00:00Z")
    assert claimed is True, reason


# --------------------------------------------------------------------------
# A21 -- the high-water mark did not hold when consumptions OVERLAP.
#
# `_record_consumptions(held + 1)` used the row count read BEFORE the insert,
# on a different connection, so concurrent consumers all observed the same
# `held` and all recorded the same value. The mark then sat below the true row
# count and a backup holding any intermediate count restored undetected.
#
# Measured by a review on unmodified code: four barrier-pinned threads gave
# rows 4 / mark 1; the real method violated "never lower it" in 111 of 400
# trials; and end to end an already-spent grant was RELEASED AGAIN in 6 of 20
# trials at 12 consumers.
#
# WHY IT SURVIVED, which is the part worth keeping: every proof drove the one
# ordering where the property holds. The 25-grant test ran sequentially. The
# "never lowered" test called `_record_consumptions` DIRECTLY, twice, in order,
# never through `consume`. The restore test restored a 0-row backup after ONE
# sequential spend. And the module's only concurrency test raced eight
# consumers on the SAME fingerprint, where exactly one insert lands and the
# mark advances by one correctly.
#
# These drive `consume` concurrently with DISTINCT fingerprints, which is the
# case that was never exercised.
# --------------------------------------------------------------------------


def _race_consumers(path: Path, count: int) -> list:
    """`count` consumers, each its own ledger object, released together."""
    barrier = threading.Barrier(count)
    granted: list = []
    lock = threading.Lock()

    def consume(index: int) -> None:
        ledger = ApprovalLedger(path)
        barrier.wait()
        claimed, _reason = ledger.consume(
            f"fp-race-{index}", f"rd-race-{index}", at=NOW,
            grant_issued_at=GRANT_ISSUED, approval_id=f"ACT-RACE-{index}")
        with lock:
            granted.append(claimed)

    threads = [threading.Thread(target=consume, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return granted


def _rows(path: Path) -> int:
    connection = sqlite3.connect(path)
    try:
        return int(
            connection.execute("SELECT count(*) FROM consumed_approvals").fetchone()[0]
        )
    finally:
        connection.close()


def test_a21_the_mark_keeps_up_with_overlapping_consumptions(tmp_path: Path):
    """The invariant the rollback check depends on: mark == rows.

    Distinct fingerprints, so every insert lands. If the mark is computed from
    a pre-insert count, the threads collide and it falls behind -- which is
    exactly what a review measured, and what the module's existing
    same-fingerprint race could never show, because there only one insert
    succeeds.
    """
    path = tmp_path / "race.sqlite3"
    _established_ledger(path, LEDGER_ESTABLISHED)

    granted = _race_consumers(path, 6)
    assert all(granted), "distinct grants were refused; this measures nothing"

    rows = _rows(path)
    mark = ApprovalLedger(path)._recorded_consumptions()
    assert rows == 6, rows
    assert mark == rows, (
        f"the high-water mark is {mark} against {rows} committed rows. The "
        "rollback check compares a restored ledger's row count against this "
        f"number, so a backup holding any of {list(range(mark, rows))} rows "
        "would restore undetected and replay every grant it forgot."
    )


def test_a21_a_restore_after_overlapping_consumptions_is_still_refused(tmp_path: Path):
    """End to end, through the file-level restore an operator actually performs.

    The backup is taken BEFORE the concurrent burst, so the restored ledger has
    genuinely lost history. The WAL is checkpointed and removed, because
    copying the main database back while a `-wal` still holds the commits is
    not a restore -- SQLite simply replays it, and the test would pass without
    measuring anything.
    """
    path = tmp_path / "restore-race.sqlite3"
    backup = tmp_path / "restore-race.backup"
    _established_ledger(path, LEDGER_ESTABLISHED)
    source = sqlite3.connect(path)
    try:
        destination = sqlite3.connect(backup)
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()

    _race_consumers(path, 6)
    assert _rows(path) == 6

    checkpoint = sqlite3.connect(path)
    try:
        checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        checkpoint.close()
    for suffix in ("-wal", "-shm"):
        sibling = path.with_name(path.name + suffix)
        if sibling.exists():
            sibling.unlink()
    shutil.copy2(backup, path)
    assert _rows(path) == 0, "the restore did not actually lose history"

    claimed, reason = ApprovalLedger(path).consume(
        "fp-race-0", "rd-race-0", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-RACE-0")
    assert claimed is False, (
        "an already-spent grant was released again after a restore that "
        "followed overlapping consumptions"
    )
    assert LEDGER_ROLLED_BACK in reason, reason


def test_a21_the_mark_is_never_lowered_through_the_real_path(tmp_path: Path):
    """The property, exercised through `consume` rather than by calling the
    setter twice in order.

    The previous version of this test called `_record_consumptions(9)` then
    `(3)` directly. That is the setter agreeing with itself: it never observed
    two callers interleaving a read and a write, which is where the real method
    lost advances in 111 of 400 trials.
    """
    path = tmp_path / "monotonic.sqlite3"
    _established_ledger(path, LEDGER_ESTABLISHED)
    seen = []
    for burst in range(3):
        _race_consumers(path, 4)
        mark = ApprovalLedger(path)._recorded_consumptions()
        seen.append(mark)
        assert mark == _rows(path), (
            f"burst {burst}: mark {mark} against {_rows(path)} rows"
        )
    assert seen == sorted(seen), f"the mark went backwards across bursts: {seen}"


# --------------------------------------------------------------------------
# A35 -- `--reset-replay-history` is named INSIDE a security refusal as the
# route out of it, and had no test of any kind. A review measured it crashing
# on the one ledger state that most needs it.
# --------------------------------------------------------------------------


def _run_reset(root: Path):
    """Drive the real Typer command, not the function body it wraps."""
    from typer.testing import CliRunner  # noqa: PLC0415

    from nornyx_forge.cli import app  # noqa: PLC0415

    return CliRunner().invoke(
        app, ["provision-ledger", "--root", str(root), "--reset-replay-history"]
    )


def test_a35_the_reset_runs_on_a_ledger_the_boundary_calls_unusable(tmp_path: Path):
    """The recovery must work on the state that needs recovering.

    A trigger on `consumed_approvals` is refused at CONSTRUCTION with
    APPROVAL_LEDGER_UNREADABLE, and the reset used to build an `ApprovalLedger`
    to find the sidecar beside it -- so the repair inherited the refusal of the
    thing it was repairing and died with a traceback, deleting nothing.
    """
    from nornyx_forge.nornyx_runtime import approval_ledger_path  # noqa: PLC0415

    root = tmp_path / "repo"
    root.mkdir()
    location = approval_ledger_path(root.resolve())
    location.parent.mkdir(parents=True, exist_ok=True)
    ApprovalLedger.provision(location)

    hostile = sqlite3.connect(location)
    try:
        hostile.execute(
            "CREATE TRIGGER block_inserts BEFORE INSERT ON consumed_approvals "
            "BEGIN SELECT RAISE(IGNORE); END"
        )
        hostile.commit()
    finally:
        hostile.close()

    with pytest.raises(NornyxRuntimeUnavailable):
        ApprovalLedger(location)

    result = _run_reset(root)
    assert result.exit_code == 0, (
        "the remedy a security refusal names could not run on the ledger it "
        f"exists to repair: exit {result.exit_code}\n{result.output}"
    )
    # It is usable again, which is the point of a destructive repair.
    assert ApprovalLedger(location)


def test_a35_the_reset_clears_the_mark_beside_the_ledger(tmp_path: Path):
    """Both files, or the refusal survives its own remedy.

    `LEDGER_ROLLED_BACK` compares the row count against the mark. Clearing the
    ledger alone would leave a mark above zero and re-raise the same refusal on
    the next consumption -- which is exactly what re-provisioning did before
    this flag existed, and why the refusal wording had to be corrected.
    """
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        LEDGER_WATERMARK_SUFFIX,
        approval_ledger_path,
    )

    root = tmp_path / "repo"
    root.mkdir()
    location = approval_ledger_path(root.resolve())
    location.parent.mkdir(parents=True, exist_ok=True)
    _established_ledger(location, LEDGER_ESTABLISHED)
    _race_consumers(location, 3)

    watermark = location.with_name(location.name + LEDGER_WATERMARK_SUFFIX)
    assert watermark.exists(), "no mark was written; this measures nothing"
    assert ApprovalLedger(location)._recorded_consumptions() == 3

    assert _run_reset(root).exit_code == 0
    assert ApprovalLedger(location)._recorded_consumptions() == 0, (
        "after the reset the mark must be a freshly PROVISIONED zero, not the "
        "count from the discarded history and not absent. `None` was the right "
        "answer while the mark appeared on first use; `provision` writes it "
        "now, so absence would mean the reset left the ledger unprovisioned"
    )
