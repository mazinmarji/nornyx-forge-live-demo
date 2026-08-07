"""The capability an approval is checked against must be the one being exercised.

`_official` derives the capability from the risk of the act, but it used to
validate the grant against whatever capability the caller put in the request.
So a caller could label a high-risk request `execute_low_risk_action`, obtain a
grant bound to that label, and every field would match — including the digest,
because the digest is computed over the same mislabelled request — while the
high-risk effect is what actually ran.
"""

from __future__ import annotations

import sys
from pathlib import Path

from nornyx_forge.nornyx_runtime import (
    ActionDescriptor,
    ActionRequest,
    canonical_attempt_id,
    canonical_request_id,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: E402

NOW = "2026-08-03T00:00:00Z"


def _request(capability: str) -> ActionRequest:
    return ActionRequest(
        request_id=canonical_request_id("CASE-MISLABELLED"),
        attempt_id=canonical_attempt_id("CASE-MISLABELLED", 1),
        mission_id="CASE-MISLABELLED",
        subject_revision=TEST_REVISION,
        capability=capability,
        action=ActionDescriptor(
            operation="issue refund",
            resource="customer:omar",
            destination="zone.external_customer",
            parameters={"amount": 5000, "currency": "USD"},
        ),
    )


def _grant(request: ActionRequest) -> dict[str, object]:
    """A grant that is internally consistent with the request it names."""
    return {
        "granted": True,
        "approval_id": "ACT-MISLABELLED",
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


def test_a_low_risk_grant_cannot_release_a_high_risk_effect(tmp_path: Path) -> None:
    """The reported escalation, driven end to end.

    Nothing here is malformed: the grant matches its request perfectly. The only
    disagreement is between the capability the caller declared and the one a
    high-risk act actually exercises, and that alone must withhold the effect.
    """
    request = _request("execute_low_risk_action")
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)

    decision, result = boundary.evaluate_and_execute(
        mission_id=request.mission_id,
        risk="high",
        action=lambda: executed.append("ran") or "ran",
        action_approval=_grant(request),
        action_request=request,
    )

    assert decision.effect == "DENY", decision.evidence.get("action_binding")
    assert result is None
    assert executed == [], "a mislabelled request released the high-risk effect"
    assert "execute_high_risk_effect" in decision.evidence["action_binding"]


def test_the_matching_capability_still_releases(tmp_path: Path) -> None:
    """The check must not break the legitimate case it guards."""
    request = _request("execute_high_risk_effect")
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)

    decision, _ = boundary.evaluate_and_execute(
        mission_id=request.mission_id,
        risk="high",
        action=lambda: executed.append("ran") or "ran",
        action_approval=_grant(request),
        action_request=request,
    )

    assert decision.effect == "ALLOW", decision.evidence.get("action_binding")
    assert executed == ["ran"]


def test_the_mismatch_is_refused_before_the_approval_is_spent(tmp_path: Path) -> None:
    """A refusal on this path must not consume the grant.

    Consumption is deliberately at-most-once, so spending a grant on a request
    that was never evaluated would destroy a legitimate approval.
    """
    mislabelled = _request("execute_low_risk_action")
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    boundary.evaluate_and_execute(
        mission_id=mislabelled.mission_id,
        risk="high",
        action=lambda: "ran",
        action_approval=_grant(mislabelled),
        action_request=mislabelled,
    )

    claimed, reason = boundary.approval_ledger.consume(
        "ACT-MISLABELLED", mislabelled.digest, at=NOW
    )
    assert claimed is True, f"the refused request spent the approval: {reason}"
