"""An approval for mission A must never release mission B's callback.

The runtime checked that `request.capability` matched the capability actually
exercised, but every other field it validated the approval against still came
from the caller-supplied request. So a request naming mission A, with a valid
unspent approval for mission A, released the callback of whatever mission was
actually executing.

The fix is not another field comparison bolted on: the runtime now builds the
request from its own execution context and validates the approval against that.
A supplied request is treated as a claim to be checked, never as the thing the
approval is judged against.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from nornyx_forge.nornyx_runtime import (
    EXTERNAL_TRUST_ZONE,
    ActionDescriptor,
    ApprovalLedger,
    canonical_action_request,
    canonical_request_id,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from signing import signed_grant  # noqa: E402
from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: E402

NOW = "2026-08-03T00:00:00Z"
MISSION_A = "CASE-AAA"
MISSION_B = "CASE-BBB"


def _descriptor(**overrides: object) -> ActionDescriptor:
    return ActionDescriptor(
        operation=str(overrides.pop("operation", "issue refund")),
        resource=str(overrides.pop("resource", "customer:omar")),
        destination=str(overrides.pop("destination", EXTERNAL_TRUST_ZONE)),
        parameters=overrides.pop("parameters", {"amount": 5000, "currency": "USD"}),  # type: ignore[arg-type]
    )


def _request(mission_id: str, **overrides: object):
    """Exactly what the runtime will authorize for that mission."""
    return canonical_action_request(
        mission_id=mission_id,
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=_descriptor(**overrides),
    )


def _grant(request, approval_id: str = "ACT-A") -> dict[str, object]:
    """A complete, correctly signed grant for the given request."""
    return signed_grant(request, approval_id=approval_id)
def _execute(boundary, mission_id: str, *, approval, request=None, descriptor=None):
    executed: list[str] = []
    decision, result = boundary.evaluate_and_execute(
        mission_id=mission_id,
        risk="high",
        action=lambda: executed.append("ran") or "ran",
        action_approval=approval,
        action_request=request,
        action_descriptor=descriptor if request is None else None,
    )
    return decision, result, executed


def test_an_approval_for_mission_a_cannot_release_mission_b(tmp_path: Path):
    """The reported escalation, driven end to end.

    Nothing is malformed: the grant matches its request perfectly, is unspent,
    and is inside its window. The only disagreement is which mission is actually
    executing.
    """
    approved = _request(MISSION_A)
    boundary = _permissive_boundary(tmp_path, as_of=NOW)

    decision, result, executed = _execute(
        boundary, MISSION_B, approval=_grant(approved), request=approved
    )

    assert decision.effect == "DENY", decision.evidence.get("action_binding")
    assert result is None
    assert executed == [], "mission A's approval released mission B's callback"


def test_the_same_request_id_under_a_different_mission_is_refused(tmp_path: Path):
    """A request id is only meaningful inside its own mission."""
    smuggled = canonical_action_request(
        mission_id=MISSION_B,
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=_descriptor(),
    )
    # Same canonical id as mission A's request, but presented under mission B.
    forged = type(smuggled)(
        request_id=canonical_request_id(MISSION_A),
        attempt_id=smuggled.attempt_id,
        mission_id=MISSION_B,
        subject_revision=smuggled.subject_revision,
        capability=smuggled.capability,
        action=smuggled.action,
    )
    boundary = _permissive_boundary(tmp_path, as_of=NOW)

    decision, _, executed = _execute(
        boundary, MISSION_B, approval=_grant(forged), request=forged
    )

    assert decision.effect == "DENY"
    assert executed == []
    assert "request_id" in decision.evidence["action_binding"]


def test_the_refusal_does_not_consume_the_approval(tmp_path: Path):
    """A grant spent on a request that was never judged is a grant destroyed.

    Consumption is deliberately at-most-once, so refusing after consuming would
    let mission B permanently burn mission A's approval.
    """
    approved = _request(MISSION_A)
    ledger = tmp_path / "ledger.sqlite3"
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    boundary.approval_ledger = ApprovalLedger.provision(ledger)

    _execute(boundary, MISSION_B, approval=_grant(approved), request=approved)

    claimed, reason = ApprovalLedger.provision(ledger).consume("ACT-A", approved.digest, at=NOW)
    assert claimed is True, f"the refused mission spent the approval: {reason}"


def test_the_original_mission_can_still_use_its_approval(tmp_path: Path):
    """The whole point: mission A's grant must survive B's attempt and work."""
    approved = _request(MISSION_A)
    grant = _grant(approved)
    ledger = tmp_path / "ledger.sqlite3"

    stolen = _permissive_boundary(tmp_path, as_of=NOW)
    stolen.approval_ledger = ApprovalLedger.provision(ledger)
    decision, _, executed = _execute(stolen, MISSION_B, approval=grant, request=approved)
    assert decision.effect == "DENY" and executed == []

    rightful = _permissive_boundary(tmp_path, as_of=NOW)
    rightful.approval_ledger = ApprovalLedger.provision(ledger)
    decision, result, executed = _execute(
        rightful, MISSION_A, approval=grant, descriptor=_descriptor()
    )
    assert decision.effect == "ALLOW", decision.evidence.get("action_binding")
    assert result == "ran"
    assert executed == ["ran"]


def test_the_mismatch_reason_reaches_the_evidence(tmp_path: Path):
    """A refusal nobody can audit is only half a control."""
    approved = _request(MISSION_A)
    boundary = _permissive_boundary(tmp_path, as_of=NOW)

    decision, _, _ = _execute(
        boundary, MISSION_B, approval=_grant(approved), request=approved
    )

    binding = decision.evidence["action_binding"]
    assert "mission_id" in binding, binding
    assert MISSION_A in binding and MISSION_B in binding, binding
    assert "action_withheld" in decision.evidence["observations"]
    assert "tool_invoked" not in decision.evidence["observations"]


@pytest.mark.parametrize(
    ("label", "field", "value"),
    [
        ("destination", "destination", "zone.somewhere_else"),
        ("capability", "capability", "execute_low_risk_action"),
        ("subject revision", "subject_revision", "git:" + "b" * 40),
    ],
)
def test_a_request_contradicting_the_runtime_is_refused(
    label: str, field: str, value: str, tmp_path: Path
):
    """Fields the runtime knows for itself cannot be overridden by a caller.

    Built directly rather than through `canonical_action_request`, because that
    helper pins these very fields — which is the point of it, and the reason an
    attacker would not use it.
    """
    honest = _request(MISSION_A)
    descriptor = (
        ActionDescriptor(
            operation=honest.action.operation,
            resource=honest.action.resource,
            destination=value,
            parameters=honest.action.parameters,
        )
        if field == "destination"
        else honest.action
    )
    forged = type(honest)(
        request_id=honest.request_id,
        attempt_id=honest.attempt_id,
        mission_id=honest.mission_id,
        subject_revision=value if field == "subject_revision" else honest.subject_revision,
        capability=value if field == "capability" else honest.capability,
        action=descriptor,
    )

    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    decision, _, executed = _execute(
        boundary, MISSION_A, approval=_grant(forged), request=forged
    )

    assert decision.effect == "DENY", label
    assert executed == [], label
    assert field in decision.evidence["action_binding"], decision.evidence["action_binding"]


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("different operation", {"operation": "close account"}),
        ("different target", {"resource": "customer:amina"}),
        ("different amount", {"parameters": {"amount": 1, "currency": "USD"}}),
    ],
)
def test_a_request_describing_another_operation_is_refused(
    label: str, overrides: dict, tmp_path: Path
):
    """The descriptor a grant is bound to must be the act being executed.

    Both are supplied here: the descriptor is what the runtime is actually
    running, and the request claims something else. The grant matches the claim
    perfectly, which is exactly why the claim cannot be what it is judged
    against.
    """
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    claimed = _request(MISSION_A, **overrides)

    executed: list[str] = []
    decision, _ = boundary.evaluate_and_execute(
        mission_id=MISSION_A,
        risk="high",
        action=lambda: executed.append("ran") or "ran",
        action_approval=_grant(claimed),
        action_request=claimed,
        action_descriptor=_descriptor(),
    )

    assert decision.effect == "DENY", label
    assert executed == [], label
    assert "different operation" in decision.evidence["action_binding"], label


def test_binding_survives_boundary_reconstruction_and_ledger_reopen(tmp_path: Path):
    """Restarting must not forget either the binding or the spend."""
    approved = _request(MISSION_A)
    grant = _grant(approved)
    ledger = tmp_path / "ledger.sqlite3"

    def run(mission_id: str, *, request=None, descriptor=None):
        boundary = _permissive_boundary(tmp_path, as_of=NOW)
        boundary.approval_ledger = ApprovalLedger.provision(ledger)
        return _execute(
            boundary, mission_id, approval=grant, request=request, descriptor=descriptor
        )

    # A fresh process cannot launder the mismatch.
    decision, _, executed = run(MISSION_B, request=approved)
    assert decision.effect == "DENY" and executed == []

    # The rightful mission still succeeds, once.
    decision, _, executed = run(MISSION_A, descriptor=_descriptor())
    assert decision.effect == "ALLOW" and executed == ["ran"]

    # And the spend is durable across reconstruction.
    decision, _, executed = run(MISSION_A, descriptor=_descriptor())
    assert decision.effect == "DENY", "a spent grant released again after restart"
    assert executed == []

    # A later attempt by B is still refused, and still on binding grounds.
    decision, _, _ = run(MISSION_B, request=approved)
    assert "mission_id" in decision.evidence["action_binding"]
