"""Authentication proves who signed. Authorization proves what they may do.

Governance approval and consequential action approval currently share one
`ApprovalTrustStore` and one overlapping role, `network_governance_owner`.
Measured end to end, the consequential boundary DOES refuse a governance-only
principal -- so this is not an exploitable release bypass. But the property
rests on every caller composing a generic authenticator with the correct
authority-specific role check, which is weaker than independent provisioning.

These tests lock what is true today so a refactor to domain-bound trust changes
it deliberately rather than preserving it by accident. Three are permanent
properties; one is a CHARACTERIZATION test, marked as such, that the refactor is
expected to invert.

THE RULE these exist to keep separate:

    authentication   "this trusted key signed this artifact"
    authorization    "this key may exercise THIS authority"

No generic authenticator result may be read as an authority grant.
"""

from __future__ import annotations

import sys
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from signing import trust_store  # noqa: E402

from nornyx_forge.approval_trust import (  # noqa: E402
    GOVERNANCE_APPROVAL_SCHEMA,
    GOVERNANCE_APPROVER_ROLES,
    canonical_governance_payload,
    verify_signed_approval,
    verify_signed_governance_approval,
)
from nornyx_forge.nornyx_runtime import (  # noqa: E402
    ACTION_APPROVER_ROLES,
    ActionDescriptor,
    canonical_action_request,
)

DESCRIPTOR = ActionDescriptor(
    operation="issue refund",
    resource="customer:omar",
    destination="zone.external_customer",
    parameters={"amount": 100, "currency": "USD"},
)

#: A window around the real clock: the governance verifier evaluates it.
_NOW = datetime.now(timezone.utc)
FROM = (_NOW - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
UNTIL = (_NOW + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
AS_OF = _NOW.strftime("%Y-%m-%dT%H:%M:%SZ")


def _governance_approval(role: str) -> dict:
    """A correctly signed governance approval claiming `role`."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PrivateKey,
    )
    from signing import KEY_ID, SUBJECT, _keypair  # noqa: PLC0415

    record = {
        "schema": GOVERNANCE_APPROVAL_SCHEMA,
        "approval": "granted",
        "producer": {"id": f"{SUBJECT}:{role}", "type": "human"},
        "status": "pass",
        "subject_revision": "sha256:" + "a" * 64,
        "generated_at": FROM,
        "expires_at": UNTIL,
        "signer_key_id": KEY_ID,
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    raw, _ = _keypair()
    record["signature"] = b64encode(
        Ed25519PrivateKey.from_private_bytes(raw).sign(
            canonical_governance_payload(record)
        )
    ).decode("ascii")
    return record


def _release(tmp_path: Path, role: str):
    """Drive the REAL consequential boundary with a grant claiming `role`."""
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: PLC0415

    boundary = _permissive_boundary(tmp_path, as_of="2026-08-03T00:00:00Z")
    request = canonical_action_request(
        mission_id="CASE-DOMAIN", risk="high",
        subject_revision=TEST_REVISION, descriptor=DESCRIPTOR, attempt=1,
    )
    calls: list[str] = []
    decision, _detail = boundary.evaluate_and_execute(
        mission_id="CASE-DOMAIN",
        risk="high",
        action=lambda: (calls.append("released"), "done")[1],
        # `role=`, not `approver_role=`. The latter lands in **overrides as an
        # unsigned extra field, so the grant carries the DEFAULT role under a
        # signature that no longer matches -- and every case would then refuse
        # for a broken signature while appearing to test authority. Caught by
        # reading the refusal text instead of the boolean.
        action_approval=signed_grant(request, approval_id="ACT-DOMAIN", role=role),
        action_descriptor=DESCRIPTOR,
        attempt=1,
    )
    spent = boundary.approval_ledger.lookup(request_digest=request.digest) is not None
    return decision, calls, spent


# --------------------------------------------------------------------------
# Permanent properties
# --------------------------------------------------------------------------


def test_a_governance_role_cannot_release_a_consequential_effect(tmp_path: Path):
    """`architecture_reviewer` approves content; it does not release effects.

    Asserted at the CONSEQUENTIAL BOUNDARY, not at the authenticator. The
    authenticator accepts this artifact -- it is correctly signed by a trusted
    human -- and reading that as an action-authority success would be exactly
    the confusion this file exists to prevent.
    """
    assert "architecture_reviewer" in GOVERNANCE_APPROVER_ROLES
    assert "architecture_reviewer" not in ACTION_APPROVER_ROLES

    decision, calls, spent = _release(tmp_path, "architecture_reviewer")

    assert decision.effect == "DENY"
    assert calls == [], "a governance-only role released a consequential effect"
    assert spent is False, "the grant was consumed by a run that must not start"


def test_an_action_role_cannot_approve_governed_content():
    """The mirror: `operations_owner` releases effects, it does not approve content."""
    assert "operations_owner" in ACTION_APPROVER_ROLES
    assert "operations_owner" not in GOVERNANCE_APPROVER_ROLES

    ok, reason, _evidence = verify_signed_governance_approval(
        _governance_approval("operations_owner"),
        trust_store=trust_store(roles=("operations_owner",)),
        as_of=AS_OF,
    )
    assert ok is False
    assert "APPROVER_ROLE_UNAUTHORIZED" in reason


def test_an_action_role_does_release_with_an_otherwise_valid_grant(tmp_path: Path):
    """The benign control. Without it the refusals above could be 'always refuses'."""
    decision, calls, spent = _release(tmp_path, "operations_owner")

    assert decision.effect == "ALLOW", decision.reason
    assert len(calls) == 1
    assert spent is True, "the grant must be spent exactly once"


def test_cryptographic_authentication_is_not_authority_authorization():
    """The distinction, named and pinned.

    `verify_signed_approval` answers "a trusted human key signed this artifact".
    It does NOT answer "this principal may release a consequential effect" --
    `validate_action_approval` does, and the boundary calls both.

    This asserts the generic primitive ACCEPTS a governance-only role, which is
    correct for what it measures and dangerous only if a caller stops there. The
    architectural test below is what stops that.
    """
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION  # noqa: PLC0415

    request = canonical_action_request(
        mission_id="CASE-PRIMITIVE", risk="high",
        subject_revision=TEST_REVISION, descriptor=DESCRIPTOR, attempt=1,
    )
    grant = signed_grant(
        request, approval_id="ACT-PRIM", role="architecture_reviewer"
    )
    authentic, _reason, _evidence = verify_signed_approval(
        grant, trust_store=trust_store()
    )

    assert authentic is True, (
        "the primitive should authenticate a correctly signed artifact from a "
        "trusted key regardless of which authority the role belongs to"
    )
    # And the same artifact is refused where authority is actually decided --
    # asserted in test_a_governance_role_cannot_release_a_consequential_effect.


def test_no_authority_consumer_calls_the_generic_authenticator_alone():
    """Structural: authentication alone must never gate a consequential effect.

    The property currently rests on the boundary composing
    `verify_signed_approval` with `validate_action_approval`. A future caller
    that used only the first would authenticate a governance principal into an
    action release, and no behavioural test would notice because the boundary
    still behaves.
    """
    import ast  # noqa: PLC0415

    source = (ROOT / "src/nornyx_forge/nornyx_runtime.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        called = {
            inner.func.id
            for inner in ast.walk(node)
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
        }
        if "verify_signed_approval" in called:
            assert "validate_action_approval" in called, (
                f"{node.name} authenticates a grant without authorizing it: "
                "authentication proves who signed, not what they may do"
            )


# --------------------------------------------------------------------------
# CHARACTERIZATION -- expected to change
# --------------------------------------------------------------------------


@pytest.mark.xfail(
    reason=(
        "CHARACTERIZATION of the shared-trust model, not the intended end state. "
        "`network_governance_owner` appears in BOTH role vocabularies and both "
        "authorities read one ApprovalTrustStore, so provisioning a principal "
        "once grants both. The intended model is independent provisioning per "
        "domain: this xfail becomes an xpass when that lands, which is the "
        "signal to convert it into a permanent directionality assertion rather "
        "than to delete it."
    ),
    strict=False,
)
def test_one_provisioning_should_not_grant_both_authorities(tmp_path: Path):
    """Today a single provisioning spans both domains. It should not.

    The comment in `approval_trust.py` claims the vocabularies are disjoint
    "so one key cannot do both by accident". That is false as written --
    `network_governance_owner` is in both -- and this test records the
    consequence rather than the wording.
    """
    assert "network_governance_owner" in GOVERNANCE_APPROVER_ROLES
    assert "network_governance_owner" in ACTION_APPROVER_ROLES

    governance_ok, _reason, _evidence = verify_signed_governance_approval(
        _governance_approval("network_governance_owner"),
        trust_store=trust_store(roles=("network_governance_owner",)),
        as_of=AS_OF,
    )
    decision, calls, _spent = _release(tmp_path, "network_governance_owner")

    # The assertion is the DESIRED property, so it fails today by design.
    assert not (governance_ok and decision.effect == "ALLOW"), (
        "one provisioning of network_governance_owner exercised BOTH governance "
        f"approval and consequential release (calls={len(calls)}); the domains "
        "are not independently provisioned"
    )
