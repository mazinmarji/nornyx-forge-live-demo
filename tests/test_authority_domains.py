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
    authenticate_action_grant,
    verify_governance_approval,
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

    # PREREQUISITES, so the refusal can only be the authority clause:
    #   signature ✓  trust ✓  identity ✓  subject ✓  time ✓
    # The authenticator accepting this artifact is what makes the test
    # meaningful -- if it refused earlier, the boundary result would prove
    # nothing about authority.
    from signing import signed_grant, trust_store  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION  # noqa: PLC0415

    prerequisite = canonical_action_request(
        mission_id="CASE-PREREQ", risk="high",
        subject_revision=TEST_REVISION, descriptor=DESCRIPTOR, attempt=1,
    )
    signer = authenticate_action_grant(
        signed_grant(prerequisite, approval_id="ACT-PRE", role="architecture_reviewer"),
        trust_store=trust_store(),
    )
    assert signer.signer_authenticated is True, (
        f"the artifact failed an EARLIER clause: {signer.reason}"
    )

    decision, calls, spent = _release(tmp_path, "architecture_reviewer")

    assert decision.effect == "DENY"
    # The exact clause. A boolean-only assertion passed for a broken signature
    # once already in this very file, so the reason is pinned.
    assert "may not release a high-risk effect" in decision.reason, (
        f"refused, but not on the authority clause: {decision.reason}"
    )
    assert "architecture_reviewer" in decision.reason
    assert calls == [], "a governance-only role released a consequential effect"
    assert spent is False, "the grant was consumed by a run that must not start"


def test_a_governance_role_is_authoritative_in_the_governance_domain():
    """The positive half, without which the matrix is only "one side denied".

    Every governance prerequisite is satisfied deliberately -- signature,
    trusted key, human subject type, matching identity, authorized role,
    subject binding, and a live temporal window -- so this asserts ACCEPTANCE
    rather than the absence of one particular refusal.
    """
    ok, reason, evidence = verify_governance_approval(
        _governance_approval("architecture_reviewer"),
        trust_store=trust_store(roles=("architecture_reviewer",)),
        as_of=AS_OF,
    )
    assert ok is True, reason
    assert evidence["signature_verified"] is True
    assert evidence["identity_verified"] is True
    assert evidence["subject_type_verified"] is True
    assert evidence["role_verified"] is True
    assert evidence["validity_verified"] is True
    assert evidence["approver_role"] == "architecture_reviewer"


def test_an_action_role_cannot_approve_governed_content():
    """The mirror: `operations_owner` releases effects, it does not approve content."""
    assert "operations_owner" in ACTION_APPROVER_ROLES
    assert "operations_owner" not in GOVERNANCE_APPROVER_ROLES

    ok, reason, evidence = verify_governance_approval(
        _governance_approval("operations_owner"),
        trust_store=trust_store(roles=("operations_owner",)),
        as_of=AS_OF,
    )
    assert ok is False
    # PREREQUISITES reached, then the role clause failed -- proven by the
    # evidence flags rather than asserted in prose.
    assert evidence["signature_verified"] is True, "refused before the signature check"
    assert evidence["identity_verified"] is True, "refused before the identity check"
    assert evidence["subject_type_verified"] is True
    assert evidence.get("role_verified") is not True
    assert "APPROVER_ROLE_UNAUTHORIZED" in reason, reason
    assert "operations_owner" in reason


def test_an_action_role_does_release_with_an_otherwise_valid_grant(tmp_path: Path):
    """The benign control. Without it the refusals above could be 'always refuses'."""
    decision, calls, spent = _release(tmp_path, "operations_owner")

    assert decision.effect == "ALLOW", decision.reason
    assert len(calls) == 1
    assert spent is True, "the grant must be spent exactly once"

def test_the_primitive_result_cannot_be_read_as_a_decision():
    """The structural fix, asserted at the language level.

    `authenticate_action_grant` answers "a trusted human key signed this
    artifact". It does NOT answer "this principal may release a consequential
    effect". Previously that separation rested on every caller remembering to
    compose a second check -- and a caller that forgets is exactly the bug.

    Now the primitive returns evidence that REFUSES to be a boolean, so the
    single likeliest misuse is a TypeError at the call site:

        if authenticate_action_grant(grant, ...):   ->  TypeError
        released = evidence                          ->  TypeError when tested

    This test authenticates a governance-only role deliberately. The primitive
    ACCEPTING it is correct for what it measures -- the artifact is genuinely
    signed by a trusted human key -- and is dangerous only if a caller can stop
    there. It no longer can.
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
    signer = authenticate_action_grant(grant, trust_store=trust_store())

    assert signer.signer_authenticated is True, (
        "the primitive should authenticate a correctly signed artifact from a "
        f"trusted key regardless of authority: {signer.reason}"
    )
    with pytest.raises(TypeError, match="not an authority decision"):
        bool(signer)
    with pytest.raises(TypeError, match="not an authority decision"):
        # The shape a careless caller actually writes.
        if signer:  # noqa: SIM103
            pass

    # No field in the evidence may name an authority it did not decide.
    forbidden = {"authorized", "approved", "granted", "authenticated", "released"}
    fields = set(vars(signer)) | set(signer.as_evidence())
    assert not (fields & forbidden), (
        f"the primitive exposes an authority-shaped field: {sorted(fields & forbidden)}"
    )


def test_an_authority_decision_is_a_decision():
    """The mirror. A type that refused to be a boolean everywhere would be
    unusable, so the distinction has to cut in both directions: the authority
    API returns something whose truth value IS the grant."""
    from nornyx_forge.approval_trust import AuthorityDecision  # noqa: PLC0415

    assert bool(AuthorityDecision("action", True, "r", {})) is True
    assert bool(AuthorityDecision("action", False, "r", {})) is False


def test_no_consequential_consumer_reaches_past_the_authority_api():
    """Structural, and this time it constrains something real.

    The old version of this test looked for two symbols in one function and
    passed for two live bypasses -- discarding the validator's result, and
    validating on an unreachable branch. It proved that two names appeared
    together, which is not composition.

    What replaced it is not a better grep: the composition moved INTO
    `verify_action_approval`, so there is no longer a call site that could
    compose it wrongly. This asserts that arrangement holds -- the primitive
    has exactly one caller in the runtime, and it is the authority verifier.
    """
    import ast  # noqa: PLC0415

    source = (ROOT / "src/nornyx_forge/nornyx_runtime.py").read_text(encoding="utf-8")
    callers = [
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Name)
            and inner.func.id == "authenticate_action_grant"
            for inner in ast.walk(node)
        )
    ]
    assert callers == ["verify_action_approval"], (
        "the authentication primitive is reachable from somewhere other than the "
        f"action authority verifier: {callers}"
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
    # STRICT. A non-strict xfail turns into a silent xpass the moment the
    # refactor lands, and a migration alarm nobody hears is not an alarm. With
    # strict=True the run FAILS when the characterized defect stops holding,
    # which is the signal to convert this into a permanent directionality
    # assertion rather than to delete it.
    strict=True,
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

    governance_ok, _reason, _evidence = verify_governance_approval(
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
