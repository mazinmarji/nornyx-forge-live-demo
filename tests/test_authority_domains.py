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

import inspect
import json
import sys
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from signing import (  # noqa: E402
    KEY_ID,
    OTHER_KEY_ID,
    other_signer,
    trust_store,
    write_trust_store,
)

from nornyx_forge.approval_trust import (  # noqa: E402
    ACTION_TRUST_DOMAIN,
    GOVERNANCE_APPROVAL_SCHEMA,
    GOVERNANCE_APPROVER_ROLES,
    GOVERNANCE_TRUST_DOMAIN,
    authenticate_action_grant,
    canonical_governance_payload,
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


def _provision(tmp_path: Path, *, governance=(), action=(),
               governance_extra=(), action_extra=()):
    """Provision the two authority domains THROUGH THE REAL DOCUMENT.

    Not two hand-built in-memory stores. The distinction decided this file's
    own migration: the characterization below kept xfailing after the domains
    were split, because its fixtures constructed stores directly and so never
    exercised provisioning at all. A test about what one provisioning grants
    has to provision.
    """
    from signing import write_trust_store  # noqa: PLC0415

    from nornyx_forge.approval_trust import ApprovalTrustDomains  # noqa: PLC0415

    path = write_trust_store(
        tmp_path / "trusted_approvers.json",
        governance_roles=tuple(governance),
        action_roles=tuple(action),
        governance_extra=tuple(governance_extra),
        action_extra=tuple(action_extra),
    )
    return ApprovalTrustDomains.load(path)


def _grant(tmp_path: Path, role: str) -> dict:
    """The exact grant `_release` presents, for prerequisite checks."""
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION  # noqa: PLC0415

    return signed_grant(
        canonical_action_request(
            mission_id="CASE-DOMAIN", risk="high",
            subject_revision=TEST_REVISION, descriptor=DESCRIPTOR, attempt=1,
        ),
        approval_id="ACT-DOMAIN",
        role=role,
    )


def _release(tmp_path: Path, role: str, *, action_trust=None):
    """Drive the REAL consequential boundary with a grant claiming `role`."""
    from signing import signed_grant, trust_store  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: PLC0415

    # The consequential boundary IS the action authority, so its store says so.
    # The domain guard is total: an unlabelled store cannot answer a
    # domain-scoped question, and defaulting to one here made these tests refuse
    # on TRUST_DOMAIN_MISMATCH instead of on the role clause they are named for.
    if action_trust is None:
        action_trust = trust_store(domain=ACTION_TRUST_DOMAIN)
    boundary = _permissive_boundary(
        tmp_path, as_of="2026-08-03T00:00:00Z", action_trust=action_trust
    )
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
        trust_store=trust_store(domain=ACTION_TRUST_DOMAIN),
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


#: The subject the governance fixture in this module actually names.
GOVERNANCE_SUBJECT = "sha256:" + "a" * 64
def test_a_governance_role_is_authoritative_in_the_governance_domain():
    """The positive half, without which the matrix is only "one side denied".

    Every governance prerequisite is satisfied deliberately -- signature,
    trusted key, human subject type, matching identity, authorized role,
    subject binding, and a live temporal window -- so this asserts ACCEPTANCE
    rather than the absence of one particular refusal.
    """
    ok, reason, evidence = verify_governance_approval(
        _governance_approval("architecture_reviewer"),
        trust_store=trust_store(
            roles=("architecture_reviewer",), domain=GOVERNANCE_TRUST_DOMAIN
        ),
        as_of=AS_OF,
        expected_subject_revision=GOVERNANCE_SUBJECT,
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
        trust_store=trust_store(
            roles=("operations_owner",), domain=GOVERNANCE_TRUST_DOMAIN
        ),
        as_of=AS_OF,
        expected_subject_revision=GOVERNANCE_SUBJECT,
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
    signer = authenticate_action_grant(
        grant, trust_store=trust_store(domain=ACTION_TRUST_DOMAIN)
    )

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
# THE DIRECTIONALITY MATRIX
#
# Replaces a strict xfail that characterized the shared-trust model. That alarm
# was observed doing its job: after the domains were split it reported
# [XPASS(strict)] and failed the run, which is the signal these permanent tests
# exist to answer. It is recorded rather than deleted quietly, and the sequence
# is worth keeping because the FIRST run after the split still xfailed -- the
# characterization built its stores in memory and so never exercised
# provisioning at all. A test about what one provisioning grants has to
# provision. Only once its fixture went through the real trust document did the
# alarm fire.
#
#   G  governance-only principal
#   A  action-only principal
#   R  reviewer-only principal
#   D  principal explicitly provisioned in BOTH approval domains
#
# Every negative below establishes its prerequisites first, so a refusal can
# only be the domain or role clause. Reading the boolean alone once let a
# whole file pass on broken signatures while appearing to test authority.
# --------------------------------------------------------------------------

#: In GOVERNANCE_APPROVER_ROLES only.
GOVERNANCE_ROLE = "architecture_reviewer"
#: In ACTION_APPROVER_ROLES only.
ACTION_ROLE = "operations_owner"
#: In BOTH vocabularies, deliberately. The matrix is only decisive because of
#: it: a shared role name must bridge nothing.
SHARED_ROLE = "network_governance_owner"


def _prerequisites_met(grant, store) -> None:
    """Assert everything EARLIER than authority succeeded, or say which failed.

    Without this a cross-domain refusal is indistinguishable from a broken
    fixture. That is not hypothetical: a mis-spelled keyword once made every
    grant in this file carry an unsigned role under a non-matching signature,
    so each case refused for an invalid signature while appearing to prove
    something about authority.
    """
    from nornyx_forge.approval_trust import authenticate_action_grant  # noqa: PLC0415

    signer = authenticate_action_grant(grant, trust_store=store)
    assert signer.signer_authenticated is True, (
        f"the grant failed a clause EARLIER than authority: {signer.reason}"
    )
    assert signer.signature_verified is True
    assert signer.identity_verified is True
    assert signer.subject_type_verified is True




def _governance(domains, role: str, as_of: str = AS_OF):
    return verify_governance_approval(
        _governance_approval(role), trust_store=domains.governance, as_of=as_of,
        expected_subject_revision=GOVERNANCE_SUBJECT,
    )


def _refused_effect(decision, calls, spent, *, clause: str) -> None:
    """A negative action case is proven by the EFFECT, not by the verdict.

    effect DENY, callback never invoked, grant unconsumed -- and the refusal
    naming the clause the test is about.
    """
    assert decision.effect == "DENY", decision.reason
    assert clause in decision.reason, (
        f"refused, but not on the clause under test: {decision.reason}"
    )
    assert calls == [], "the effect ran despite a DENY"
    assert spent is False, "a run that must not start consumed the grant"


def test_G_a_governance_only_principal_cannot_release_an_effect(tmp_path: Path):
    """G: governance ✓, action ✗ -- proven at the effect boundary."""
    domains = _provision(
        tmp_path,
        governance=(GOVERNANCE_ROLE,),
        action_extra=(other_signer((ACTION_ROLE,)),),
    )

    granted = _governance(domains, GOVERNANCE_ROLE)
    assert granted.granted is True, granted.reason
    assert granted.evidence["role_verified"] is True
    assert granted.evidence["validity_verified"] is True

    # The ACTION domain is provisioned -- with somebody else. So the refusal
    # has to be about this key, not about an empty store.
    assert domains.action.signers, "the action domain must not be empty here"
    decision, calls, spent = _release(
        tmp_path, GOVERNANCE_ROLE, action_trust=domains.action
    )
    _refused_effect(decision, calls, spent, clause="not in the action approver")


def test_A_an_action_only_principal_cannot_approve_governance(tmp_path: Path):
    """A: action ✓, governance ✗."""
    domains = _provision(
        tmp_path,
        action=(ACTION_ROLE,),
        governance_extra=(other_signer((GOVERNANCE_ROLE,)),),
    )

    _prerequisites_met(_grant(tmp_path, ACTION_ROLE), domains.action)
    decision, calls, spent = _release(tmp_path, ACTION_ROLE, action_trust=domains.action)
    assert decision.effect == "ALLOW", decision.reason
    assert len(calls) == 1
    assert spent is True, "the grant must be spent exactly once"

    assert domains.governance.signers, "the governance domain must not be empty"
    refused = _governance(domains, ACTION_ROLE)
    assert refused.granted is False
    assert "not in the governance approver trust store" in refused.reason, refused.reason


def test_R_a_reviewer_is_not_an_approver_in_either_domain(tmp_path: Path):
    """R: reviewer attestation ✓, governance ✗, action ✗.

    Reviewer trust is a SEPARATE document with its own schema, so the direction
    is enforced by the parser rather than by a role check: an approver store
    handed to the reviewer loader is refused for being the wrong kind of thing,
    and the reverse holds too.
    """
    from nornyx_forge.approval_trust import (  # noqa: PLC0415
        ApprovalTrustDomains,
        TrustStoreUnavailable,
    )
    from nornyx_forge.reviewer_trust import (  # noqa: PLC0415
        ReviewerStoreUnavailable,
        ReviewerTrustStore,
    )

    approver = write_trust_store(tmp_path / "approvers.json", roles=(SHARED_ROLE,))
    reviewer = tmp_path / "reviewers.json"
    reviewer.write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.reviewer_trust_store.v1",
                "reviewers": [
                    {
                        "key_id": "reviewer-only-01",
                        "reviewer": "human.reviewer",
                        "roles": ["architecture_inspector"],
                        "public_key": "AAAA",
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReviewerStoreUnavailable, match="not a reviewer trust store"):
        ReviewerTrustStore.load(approver)
    with pytest.raises(TrustStoreUnavailable, match="declares no authority domains"):
        ApprovalTrustDomains.load(reviewer)

    # And the reviewer identity is in neither approval domain.
    domains = ApprovalTrustDomains.load(approver)
    assert "reviewer-only-01" not in domains.governance.signers
    assert "reviewer-only-01" not in domains.action.signers


def test_D_a_dual_domain_principal_holds_both_because_it_was_provisioned_twice(
    tmp_path: Path,
):
    """D: both authorities, and ONLY because both were granted explicitly.

    The same key, the same identity, the same role name throughout. What makes
    the difference is provisioning, which is the whole claim.
    """
    domains = _provision(tmp_path, governance=(SHARED_ROLE,), action=(SHARED_ROLE,))

    granted = _governance(domains, SHARED_ROLE)
    assert granted.granted is True, granted.reason

    decision, calls, spent = _release(tmp_path, SHARED_ROLE, action_trust=domains.action)
    assert decision.effect == "ALLOW", decision.reason
    assert len(calls) == 1
    assert spent is True


def test_D_removing_only_the_governance_grant_leaves_action_intact(tmp_path: Path):
    """Losing one authority must not collapse the other.

    The mirror of the bridging tests, and the one most likely to be got wrong
    by a "simplification" that reads both domains from one place.
    """
    domains = _provision(
        tmp_path,
        action=(SHARED_ROLE,),
        governance_extra=(other_signer((SHARED_ROLE,)),),
    )

    refused = _governance(domains, SHARED_ROLE)
    assert refused.granted is False
    assert "not in the governance approver trust store" in refused.reason

    decision, calls, spent = _release(tmp_path, SHARED_ROLE, action_trust=domains.action)
    assert decision.effect == "ALLOW", (
        f"withdrawing GOVERNANCE trust withdrew ACTION authority too: "
        f"{decision.reason}"
    )
    assert len(calls) == 1
    assert spent is True


def test_D_removing_only_the_action_grant_leaves_governance_intact(tmp_path: Path):
    """The other direction, with the effect boundary as the witness."""
    domains = _provision(
        tmp_path,
        governance=(SHARED_ROLE,),
        action_extra=(other_signer((ACTION_ROLE,)),),
    )

    granted = _governance(domains, SHARED_ROLE)
    assert granted.granted is True, (
        f"withdrawing ACTION trust withdrew GOVERNANCE authority too: "
        f"{granted.reason}"
    )

    decision, calls, spent = _release(tmp_path, SHARED_ROLE, action_trust=domains.action)
    _refused_effect(decision, calls, spent, clause="not in the action approver")


def test_nothing_about_the_key_bridges_a_domain_it_was_not_granted(tmp_path: Path):
    """Same public key, same key id, same identity, same role spelling.

    Every property an implementation might be tempted to treat as sufficient is
    held constant across the two domains; only the provisioning differs. If any
    of them bridged, this would pass in both directions.
    """
    domains = _provision(
        tmp_path,
        governance=(SHARED_ROLE,),
        action_extra=(other_signer((SHARED_ROLE,)),),
    )

    trusted = domains.governance.signers[KEY_ID]
    other = domains.action.signers[OTHER_KEY_ID]
    # The bridging candidates, stated so the test says what it holds constant.
    assert other.public_key == trusted.public_key, "same key material"
    assert SHARED_ROLE in trusted.roles and SHARED_ROLE in other.roles, "same role"
    assert trusted.subject_type == other.subject_type == "human"
    assert KEY_ID not in domains.action.signers, "only the provisioning differs"

    decision, calls, spent = _release(tmp_path, SHARED_ROLE, action_trust=domains.action)
    _refused_effect(decision, calls, spent, clause="not in the action approver")


def test_the_governance_store_is_refused_by_the_action_authority(tmp_path: Path):
    """Wiring the wrong domain in is a refusal, not a silent cross-domain grant.

    Every signature in the governance store is valid, so nothing about the
    artifact is wrong. What is wrong is the question being asked of it, and the
    authenticator says so rather than leaving it to whoever wired the call.
    """
    domains = _provision(tmp_path, governance=(SHARED_ROLE,), action=(SHARED_ROLE,))

    decision, calls, spent = _release(
        tmp_path, SHARED_ROLE, action_trust=domains.governance
    )
    _refused_effect(decision, calls, spent, clause="TRUST_DOMAIN_MISMATCH")


def test_the_action_store_is_refused_by_the_governance_authority(tmp_path: Path):
    """The mirror, at the governance verifier."""
    domains = _provision(tmp_path, governance=(SHARED_ROLE,), action=(SHARED_ROLE,))

    refused = verify_governance_approval(
        _governance_approval(SHARED_ROLE), trust_store=domains.action, as_of=AS_OF,
        expected_subject_revision=GOVERNANCE_SUBJECT,
    )
    assert refused.granted is False
    assert "TRUST_DOMAIN_MISMATCH" in refused.reason, refused.reason


def test_every_prerequisite_holds_before_the_domain_clause_refuses(tmp_path: Path):
    """The false-green audit, made an assertion instead of a habit.

    A cross-domain negative is only evidence if execution REACHED the domain
    clause. Here the key IS trusted in the action domain -- it simply holds a
    governance role there -- so signature, identity, subject type and trust all
    succeed and are asserted from the evidence, and the refusal can only be the
    authority clause.

    Written because the opposite happened in this very file: a mis-spelled
    keyword put the role into an UNSIGNED field, every grant carried the default
    role under a signature that no longer matched, and each case refused for a
    broken signature while reporting a clean authority test.
    """
    domains = _provision(tmp_path, action=(GOVERNANCE_ROLE,))

    from nornyx_forge.approval_trust import authenticate_action_grant  # noqa: PLC0415

    grant = _grant(tmp_path, GOVERNANCE_ROLE)
    signer = authenticate_action_grant(grant, trust_store=domains.action)
    assert signer.signer_authenticated is True, signer.reason
    assert signer.signature_verified is True
    assert signer.identity_verified is True
    assert signer.subject_type_verified is True
    assert signer.claimed_role == GOVERNANCE_ROLE
    assert GOVERNANCE_ROLE in signer.trusted_roles, (
        "the action domain does not trust this key in the claimed role, so the "
        "refusal below would be the membership clause rather than the role one"
    )

    decision, calls, spent = _release(
        tmp_path, GOVERNANCE_ROLE, action_trust=domains.action
    )
    _refused_effect(decision, calls, spent, clause="may not release a high-risk effect")
    assert GOVERNANCE_ROLE in decision.reason


# --------------------------------------------------------------------------
# The domain guard is opt-in for unlabelled stores. Recorded, and bounded.
# --------------------------------------------------------------------------


def test_no_production_path_can_build_an_unlabelled_store():
    """The property the runtime clause relies on, asserted directly.

    `authenticate_action_grant` skips the domain clause for a store carrying no
    domain, so separation is opt-in there. That is only safe while nothing in
    production can produce one -- which is a claim about `src/`, and is
    therefore checked in `src/`.

    Making the runtime clause TOTAL was implemented and measured instead, and
    reverted on the evidence: it broke thirteen call sites across five modules,
    and two were security proofs whose MECHANISM it changed. Removing the frozen
    store to show a decision moves stops proving that if a domain refusal
    arrives first.
    """
    import ast  # noqa: PLC0415

    from nornyx_forge.approval_trust import ApprovalTrustStore  # noqa: PLC0415

    # `load` cannot be called without naming a domain: keyword-only, no default.
    signature = inspect.signature(ApprovalTrustStore.load)
    domain = signature.parameters["domain"]
    assert domain.kind is inspect.Parameter.KEYWORD_ONLY, domain.kind
    assert domain.default is inspect.Parameter.empty, (
        "ApprovalTrustStore.load has a default domain, so a production caller "
        "can build a store that answers every authority that asks"
    )

    # And no constructor call under src/ omits it.
    unlabelled: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name not in {"ApprovalTrustStore", "for_test"}:
                continue
            if not any(kw.arg == "domain" for kw in node.keywords):
                relative = str(path.relative_to(ROOT)).replace("\\", "/")
                unlabelled.append(f"{relative}:{node.lineno}")

    assert unlabelled == [], (
        "these production sites build an approver trust store without naming "
        f"its authority domain, so it would satisfy every domain: {unlabelled}"
    )


def test_absence_is_decided_before_domain():
    """An absent store must refuse as ABSENT, not as a domain mismatch.

    Found while measuring the total guard: with the domain clause first, a store
    that was simply not provisioned reported TRUST_DOMAIN_MISMATCH -- invalidity
    standing in for absence, which sends an operator to the wrong fix. The
    ordering fix was kept even though the totality change was reverted.
    """
    from nornyx_forge.approval_trust import (  # noqa: PLC0415
        ACTION_TRUST_DOMAIN,
        ApprovalTrustStore,
        authenticate_action_grant,
    )

    absent = ApprovalTrustStore(source="<no store>", domain=GOVERNANCE_TRUST_DOMAIN)
    assert not absent.available and not absent.signers

    signer = authenticate_action_grant({}, trust_store=absent)
    assert "APPROVER_TRUST_UNAVAILABLE" in signer.reason, signer.reason
    assert "TRUST_DOMAIN_MISMATCH" not in signer.reason, (
        "an unprovisioned store refused as a domain mismatch, so absence is "
        f"being reported as invalidity: {signer.reason}"
    )
    assert ACTION_TRUST_DOMAIN  # the authority that was asking
