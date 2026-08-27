"""An action approval releases one exact operation, once, and nothing else."""

from __future__ import annotations

from pathlib import Path

import pytest

from nornyx_forge.nornyx_runtime import (
    ActionDescriptor,
    ActionRequest,
    _bind_action_approval,
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
    released, reason = _bind_action_approval(_grant(request), request, as_of=NOW)
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
    released, reason = _bind_action_approval(grant, _request(**overrides), as_of=NOW)
    assert released is False, f"{label} was released: {reason}"


def test_same_mission_and_request_id_but_different_payload_is_refused():
    """The reviewer's exact concern: identity alone must not be enough."""
    approved = _request(parameters={"amount": 100, "currency": "USD"})
    escalated = _request(parameters={"amount": 1_000_000, "currency": "USD"})
    assert approved.request_id == escalated.request_id
    assert approved.mission_id == escalated.mission_id
    released, reason = _bind_action_approval(_grant(approved), escalated, as_of=NOW)
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
    released, reason = _bind_action_approval(
        _grant(request, **overrides), request, as_of=NOW
    )
    assert released is False, f"{label} was released: {reason}"


def test_grant_outside_its_window_is_refused():
    request = _request()
    grant = _grant(request)
    early, reason = _bind_action_approval(grant, request, as_of="2026-08-01T00:00:00Z")
    assert early is False and "not yet valid" in reason
    late, reason = _bind_action_approval(grant, request, as_of="2026-08-06T00:00:00Z")
    assert late is False and "expired" in reason


def test_absent_approval_is_refused():
    request = _request()
    assert _bind_action_approval(None, request, as_of=NOW)[0] is False
    assert _bind_action_approval({}, request, as_of=NOW)[0] is False


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


# --------------------------------------------------------------------------
# A-P2-4. A claimed zone crossing must be authorized, at every risk level.
# --------------------------------------------------------------------------


def test_every_risk_level_claims_the_external_destination():
    """The premise, measured rather than assumed.

    If low-risk requests did not name the external zone, there would be no
    unauthorized claim and nothing to fix. They do: the destination is pinned
    canonically, so it is part of what the digest binds and what an approver
    would sign.
    """
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        EXTERNAL_TRUST_ZONE,
        ActionDescriptor,
        canonical_action_request,
    )

    descriptor = ActionDescriptor(
        operation="send guidance", resource="customer:amina",
        destination=EXTERNAL_TRUST_ZONE, parameters={},
    )
    for risk in ("low", "medium", "high"):
        request = canonical_action_request(
            mission_id="CASE-ZONE", risk=risk,
            subject_revision="sha256:" + "a" * 64,
            descriptor=descriptor, attempt=1,
        )
        assert request.destination == EXTERNAL_TRUST_ZONE, (
            f"{risk} risk does not claim the external zone, so this finding "
            "would not apply to it"
        )


def test_the_crossing_is_evaluated_at_every_risk_level():
    """Risk selects which capability is exercised. It does not decide whether a
    boundary between trust zones is real.

    Read from the source because the authorizer does not load in this tree
    (the runtime contract does not currently pass governance validation), so the
    decision itself cannot be driven here. Stated as a structural assertion and
    labelled as one rather than dressed up as a behavioural proof.
    """
    from nornyx_forge import nornyx_runtime  # noqa: PLC0415

    source = Path(nornyx_runtime.__file__).read_text(encoding="utf-8")
    crossing = source[source.index("        decision = capability"):]
    crossing = crossing[: crossing.index("ZoneCrossingRequest(")]

    assert "if capability.allowed and high_risk:" not in crossing, (
        "the zone crossing is evaluated only for high risk, while every request "
        "claims the external destination regardless of risk"
    )
    assert "if capability.allowed:" in crossing, crossing


# --------------------------------------------------------------------------
# Canonicalization must be injective, not merely deterministic.
# --------------------------------------------------------------------------


def test_two_different_descriptors_cannot_share_a_digest():
    """`str(key)` mapped {1: ...} and {"1": ...} onto one canonical form.

    Determinism and injectivity are different requirements and only the first
    was met. Two DIFFERENT requests shared a payload_digest, so an approval
    bound to either would release the other -- the whole point of binding an
    approval to a digest is that this cannot happen.

    Refused rather than resolved: coercing the key silently picks a winner
    between two distinct requests.
    """
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        NornyxRuntimeUnavailable,
    )

    string_keyed = ActionDescriptor(
        operation="refund", resource="customer:amina",
        destination="zone.external_customer", parameters={"1": 10},
    )
    int_keyed = ActionDescriptor(
        operation="refund", resource="customer:amina",
        destination="zone.external_customer", parameters={1: 10},
    )

    # The string-keyed one is ordinary and must still canonicalize.
    assert string_keyed.canonical()["parameters"] == {"1": 10}

    with pytest.raises(NornyxRuntimeUnavailable, match="not strings"):
        int_keyed.canonical()


def test_the_refusal_names_the_offending_keys():
    """A refusal a caller cannot act on is a crash with better manners."""
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        NornyxRuntimeUnavailable,
    )

    descriptor = ActionDescriptor(
        operation="refund", resource="customer:amina",
        destination="zone.external_customer", parameters={7: "a", None: "b"},
    )
    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        descriptor.canonical()

    message = str(refusal.value)
    assert "7" in message and "None" in message, message


def test_the_deliberate_numeric_normalisation_survives():
    """100 and 100.0 are the same AMOUNT, and must still digest identically.

    That collapse is between two spellings of one value. The one removed was
    between two different values. Keeping them apart is the point of this test:
    a stricter canonicaliser that also split 100 from 100.0 would break the
    property the numeric branch exists to provide.
    """
    from nornyx_forge.nornyx_runtime import ActionDescriptor  # noqa: PLC0415

    def descriptor(amount):
        return ActionDescriptor(
            operation="refund", resource="customer:amina",
            destination="zone.external_customer", parameters={"amount": amount},
        )

    assert descriptor(100).canonical() == descriptor(100.0).canonical()


def test_nested_mappings_are_checked_too():
    """A collision one level down is still a collision."""
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        NornyxRuntimeUnavailable,
    )

    descriptor = ActionDescriptor(
        operation="refund", resource="customer:amina",
        destination="zone.external_customer",
        parameters={"outer": {2: "deep"}},
    )
    with pytest.raises(NornyxRuntimeUnavailable, match="not strings"):
        descriptor.canonical()
