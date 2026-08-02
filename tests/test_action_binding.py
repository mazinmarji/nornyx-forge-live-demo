"""An action approval releases one exact operation, once, and nothing else."""

from __future__ import annotations

import pytest

from nornyx_forge.nornyx_runtime import (
    ActionDescriptor,
    ActionRequest,
    validate_action_approval,
)

NOW = "2026-08-03T00:00:00Z"


def _request(**overrides: object) -> ActionRequest:
    action = ActionDescriptor(
        operation=str(overrides.pop("operation", "issue refund")),
        resource=str(overrides.pop("resource", "customer:omar")),
        destination=str(overrides.pop("destination", "zone.external_customer")),
        parameters=overrides.pop(  # type: ignore[arg-type]
            "parameters", {"amount": 100, "currency": "USD", "account": "acct-1"}
        ),
    )
    return ActionRequest(
        request_id=str(overrides.pop("request_id", "REQ-001")),
        mission_id=str(overrides.pop("mission_id", "CASE-001")),
        subject_revision=str(overrides.pop("subject_revision", "git:" + "a" * 40)),
        capability=str(overrides.pop("capability", "execute_high_risk_effect")),
        action=action,
    )


def _grant(request: ActionRequest, **overrides: object) -> dict[str, object]:
    grant: dict[str, object] = {
        "granted": True,
        "approval_id": "ACT-0001",
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
    grant.update(overrides)
    return grant


def test_a_complete_grant_releases_its_own_request():
    request = _request()
    released, reason = validate_action_approval(_grant(request), request, as_of=NOW)
    assert released is True, reason


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("different request id", {"request_id": "REQ-002"}),
        ("different mission", {"mission_id": "CASE-999"}),
        ("different revision", {"subject_revision": "git:" + "b" * 40}),
        ("different capability", {"capability": "execute_low_risk_action"}),
        ("different operation", {"operation": "close account"}),
        ("different target", {"resource": "customer:amina"}),
        ("different destination", {"destination": "zone.other_customer"}),
        ("different amount", {"parameters": {"amount": 5000, "currency": "USD", "account": "acct-1"}}),
        ("different account", {"parameters": {"amount": 100, "currency": "USD", "account": "acct-9"}}),
        ("different currency", {"parameters": {"amount": 100, "currency": "EUR", "account": "acct-1"}}),
        ("extra parameter", {"parameters": {"amount": 100, "currency": "USD", "account": "acct-1", "expedite": True}}),
        ("dropped parameter", {"parameters": {"amount": 100}}),
    ],
)
def test_a_grant_never_releases_a_different_operation(label: str, overrides: dict):
    """One grant, one operation.

    Each element of the consequential act is varied independently, so a single
    shared check cannot give false confidence that all of them are bound. The
    amount and account cases are the ones that matter most: same mission, same
    request id, different money.
    """
    approved = _request()
    grant = _grant(approved)
    released, reason = validate_action_approval(grant, _request(**overrides), as_of=NOW)
    assert released is False, f"{label} was released: {reason}"


def test_same_mission_and_request_id_but_different_payload_is_refused():
    """The reviewer's exact concern: identity alone must not be enough."""
    approved = _request(parameters={"amount": 100, "currency": "USD"})
    escalated = _request(parameters={"amount": 1_000_000, "currency": "USD"})
    assert approved.request_id == escalated.request_id
    assert approved.mission_id == escalated.mission_id
    released, reason = validate_action_approval(_grant(approved), escalated, as_of=NOW)
    assert released is False, reason


def test_payload_digest_is_order_and_type_stable():
    """Equal operations must digest equally, or grants break for no reason."""
    a = _request(parameters={"amount": 100, "currency": "USD"})
    b = _request(parameters={"currency": "USD", "amount": 100.0})
    assert a.payload_digest == b.payload_digest
    assert a.digest == b.digest


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("not granted", {"granted": False}),
        ("granted is truthy not True", {"granted": 1}),
        ("no approval id", {"approval_id": ""}),
        ("no approver", {"approver": "  "}),
        ("machine approver", {"approver_type": "tool"}),
        ("approver type missing", {"approver_type": None}),
        ("ineligible role", {"approver_role": "intake_agent"}),
        ("role missing", {"approver_role": ""}),
        ("tampered request digest", {"request_digest": "sha256:" + "0" * 64}),
        ("tampered payload digest", {"payload_digest": "sha256:" + "0" * 64}),
        ("naive timestamps", {"generated_at": "2026-08-02T00:00:00"}),
        ("expiry before issue", {"expires_at": "2026-08-01T00:00:00Z"}),
        ("window longer than seven days", {"expires_at": "2026-09-30T00:00:00Z"}),
    ],
)
def test_defective_grants_are_refused(label: str, overrides: dict[str, object]):
    request = _request()
    released, reason = validate_action_approval(
        _grant(request, **overrides), request, as_of=NOW
    )
    assert released is False, f"{label} was released: {reason}"


def test_grant_outside_its_window_is_refused():
    request = _request()
    grant = _grant(request)
    early, reason = validate_action_approval(grant, request, as_of="2026-08-01T00:00:00Z")
    assert early is False and "not yet valid" in reason
    late, reason = validate_action_approval(grant, request, as_of="2026-08-06T00:00:00Z")
    assert late is False and "expired" in reason


def test_absent_approval_is_refused():
    request = _request()
    assert validate_action_approval(None, request, as_of=NOW)[0] is False
    assert validate_action_approval({}, request, as_of=NOW)[0] is False


def test_request_digest_covers_every_bound_field():
    """Changing any part of the consequential act must change the digest."""
    base = _request().digest
    for other in (
        _request(request_id="REQ-002"),
        _request(mission_id="CASE-999"),
        _request(subject_revision="git:" + "b" * 40),
        _request(capability="execute_low_risk_action"),
        _request(operation="close account"),
        _request(resource="customer:amina"),
        _request(destination="zone.other_customer"),
        _request(parameters={"amount": 5000, "currency": "USD", "account": "acct-1"}),
    ):
        assert other.digest != base


def test_descriptor_does_not_depend_on_a_callable():
    """The approved thing is the operation, not the function performing it."""
    request = _request()
    canonical = request.action.canonical()
    assert set(canonical) == {"operation", "resource", "destination", "parameters"}
    assert "callable" not in json_dumps(canonical)
    assert "function" not in json_dumps(canonical)


def json_dumps(value: object) -> str:
    import json

    return json.dumps(value, sort_keys=True)
