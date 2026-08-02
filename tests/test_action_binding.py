"""An action approval releases one exact request, once, and nothing else."""

from __future__ import annotations

import pytest

from nornyx_forge.nornyx_runtime import (
    ActionRequest,
    validate_action_approval,
)

NOW = "2026-08-03T00:00:00Z"


def _request(**overrides: str) -> ActionRequest:
    fields = {
        "request_id": "REQ-001",
        "mission_id": "CASE-001",
        "subject_revision": "git:" + "a" * 40,
        "capability": "execute_high_risk_effect",
        "destination": "zone.external_customer",
        "effect": "execute_high_risk_action",
    }
    fields.update(overrides)
    return ActionRequest(**fields)  # type: ignore[arg-type]


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


def test_a_grant_never_releases_a_different_action():
    """The core property: one grant, one action.

    Each field is varied independently so a single shared check cannot give a
    false sense that all of them are bound.
    """
    approved = _request()
    grant = _grant(approved)
    for label, other in {
        "different request id": _request(request_id="REQ-002"),
        "different mission": _request(mission_id="CASE-999"),
        "different revision": _request(subject_revision="git:" + "b" * 40),
        "different capability": _request(capability="execute_low_risk_action"),
        "different destination": _request(destination="zone.other_customer"),
        "different effect": _request(effect="wire_transfer"),
    }.items():
        released, reason = validate_action_approval(grant, other, as_of=NOW)
        assert released is False, f"{label} was released: {reason}"


def test_a_grant_is_single_use():
    request = _request()
    grant = _grant(request)
    spent: set[str] = set()
    assert validate_action_approval(grant, request, as_of=NOW, spent=spent)[0] is True
    spent.add("ACT-0001")
    released, reason = validate_action_approval(grant, request, as_of=NOW, spent=spent)
    assert released is False
    assert "replay" in reason


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
        ("tampered digest", {"request_digest": "sha256:" + "0" * 64}),
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
    early, reason = validate_action_approval(
        grant, request, as_of="2026-08-01T00:00:00Z"
    )
    assert early is False and "not yet valid" in reason
    late, reason = validate_action_approval(
        grant, request, as_of="2026-08-06T00:00:00Z"
    )
    assert late is False and "expired" in reason


def test_absent_approval_is_refused():
    request = _request()
    assert validate_action_approval(None, request, as_of=NOW)[0] is False
    assert validate_action_approval({}, request, as_of=NOW)[0] is False


def test_request_digest_covers_every_bound_field():
    """Changing any bound field must change the digest."""
    base = _request().digest
    for other in (
        _request(request_id="REQ-002"),
        _request(mission_id="CASE-999"),
        _request(subject_revision="git:" + "b" * 40),
        _request(capability="execute_low_risk_action"),
        _request(destination="zone.other_customer"),
        _request(effect="wire_transfer"),
    ):
        assert other.digest != base
