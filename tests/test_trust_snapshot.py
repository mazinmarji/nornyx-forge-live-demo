"""Runtime authority consumes trust frozen at bootstrap, not files reopened.

`TrustConfiguration` carried LOCATIONS, and a location is not authority. The
action boundary is constructed per flow -- which is per request -- and it called
`ApprovalTrustStore.load(path)` each time, so editing the file between two
requests changed who the second one trusted while the same security context
served both.

Measured before this control existed:

    request 1 -> signers ['test-approval-01']
    (trust file replaced on disk)
    request 2 -> signers ['attacker-key']

Anyone able to write the store gained authority over a running process with no
restart and nothing in the evidence to show for it.

THE PROPERTY:

    trust is parsed and frozen once at bootstrap
    an existing context answers from that snapshot forever
    only an explicit new bootstrap observes a changed file

The last clause matters as much as the first: a snapshot that could never be
refreshed would be a different bug, so the deliberate-rebootstrap path is
asserted too.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from nornyx_forge.approval_trust import (  # noqa: E402
    ACTION_TRUST_DOMAIN,
    ApprovalTrustStore,
)
from nornyx_forge.governed_subject import TrustConfiguration  # noqa: E402
from nornyx_forge.nornyx_runtime import (  # noqa: E402
    ApprovalLedger,
    NornyxActionBoundary,
    RuntimeContext,
    approval_ledger_path,
)

#: A hostile replacement, in the domained shape. Written into the ACTION
#: domain only: an attacker who could add a key to the action store is the
#: threat this file reproduces, and provisioning both domains would prove
#: something weaker -- that a totally replaced document is observed -- while
#: hiding whether one domain can be attacked without the other.
ATTACKER = {
    "domains": {
        "governance": {"signers": []},
        "action": {"signers": [
        {
            "key_id": "attacker-key",
            "algorithm": "Ed25519",
            "subject": "human.attacker",
            "subject_type": "human",
            "roles": ["operations_owner"],
            "public_key": "AAAA",
            "status": "active",
        }
    ]},
    }
}


def _anchored(tmp_path: Path):
    """A trust file, a matching configuration, and a provisioned ledger."""
    from signing import LEDGER_ESTABLISHED, write_trust_store  # noqa: PLC0415

    store_path = write_trust_store(tmp_path / "trust.json")
    ApprovalLedger.provision(approval_ledger_path(tmp_path), established_at=LEDGER_ESTABLISHED)
    trust = TrustConfiguration(
        approver_store=str(store_path),
        reviewer_store="",
        approval_ledger=str(approval_ledger_path(tmp_path)),
        builder_identities=frozenset(),
    )
    return store_path, trust


def _signers(root: Path, trust: TrustConfiguration, frozen) -> list[str]:
    """Who a boundary built now would trust."""
    from test_governance_failure import TEST_REVISION, TEST_SUBJECT  # noqa: PLC0415

    boundary = NornyxActionBoundary(
        root,
        allow_fallback=True,
        trust=trust,
        runtime_context=RuntimeContext.for_test(
            root, at="2026-08-03T00:00:00Z", revision=TEST_REVISION
        ),
        runtime_subject=TEST_SUBJECT,
        frozen_action_trust=frozen,
    )
    return sorted(boundary.action_trust_store.signers)


def test_two_requests_through_one_context_see_the_same_trust(tmp_path: Path):
    """The exploit, reproduced and closed.

    The file is genuinely replaced between the two requests, so this fails if
    anything downstream reopens it.
    """
    store_path, trust = _anchored(tmp_path)
    frozen = ApprovalTrustStore.load(store_path, domain=ACTION_TRUST_DOMAIN)

    first = _signers(tmp_path, trust, frozen)
    store_path.write_text(json.dumps(ATTACKER), encoding="utf-8")
    second = _signers(tmp_path, trust, frozen)

    assert first == ["test-approval-01"]
    assert second == first, (
        "replacing the trust file changed who a running context trusted"
    )
    assert "attacker-key" not in second


def test_an_explicit_new_bootstrap_observes_the_change(tmp_path: Path):
    """A snapshot that could never be refreshed would be its own defect.

    Rotating a key must still work; it must take a deliberate restart rather
    than happening under a running process.
    """
    store_path, _trust = _anchored(tmp_path)
    store_path.write_text(json.dumps(ATTACKER), encoding="utf-8")

    assert sorted(ApprovalTrustStore.load(store_path, domain=ACTION_TRUST_DOMAIN).signers) == ["attacker-key"]


def test_deleting_the_trust_file_leaves_an_existing_context_intact(tmp_path: Path):
    """Absence after bootstrap must not silently empty a live snapshot.

    Distinguishing the two states the absence rule names: the SNAPSHOT is
    immutable and unaffected, while a NEW bootstrap over a missing file has no
    trust to offer and says so.
    """
    store_path, trust = _anchored(tmp_path)
    frozen = ApprovalTrustStore.load(store_path, domain=ACTION_TRUST_DOMAIN)
    store_path.unlink()

    assert _signers(tmp_path, trust, frozen) == ["test-approval-01"]
    assert ApprovalTrustStore.load(store_path, domain=ACTION_TRUST_DOMAIN).signers == {}, (
        "a new bootstrap over a missing store must offer no trusted signer"
    )


def test_corrupting_the_trust_file_leaves_an_existing_context_intact(tmp_path: Path):
    """Same distinction, for invalid rather than absent material."""
    from nornyx_forge.approval_trust import TrustStoreUnavailable  # noqa: PLC0415

    store_path, trust = _anchored(tmp_path)
    frozen = ApprovalTrustStore.load(store_path, domain=ACTION_TRUST_DOMAIN)
    store_path.write_text("{ this is not json", encoding="utf-8")

    assert _signers(tmp_path, trust, frozen) == ["test-approval-01"]
    with pytest.raises(TrustStoreUnavailable):
        ApprovalTrustStore.load(store_path, domain=ACTION_TRUST_DOMAIN)


def test_the_established_context_carries_the_frozen_store(tmp_path: Path):
    """PROPAGATED: the frozen object reaches the boundary.

    Scoped honestly. This proves possession travels from the context to the
    boundary -- a control built and not connected is a defect this repository
    has produced three times -- and it proves nothing about the authority
    DECISION consulting it. That is the pair of tests at the end of this module,
    and the distinction is the permanent rule H01 produced.
    """
    from demo_app.agentic import CustomerCaseFlow, application_security_context  # noqa: PLC0415

    context = application_security_context()
    flow = CustomerCaseFlow(
        {
            "id": "CASE-TRUST",
            "customer": "Omar",
            "summary": "Issue a high-value external refund",
            "risk": "high",
            "requested_action": "issue refund",
        },
        root=ROOT,
        security_context=context,
    )
    assert context.action_approval_trust is not None, (
        "bootstrap parsed no action approval trust at all"
    )
    assert flow.boundary.action_trust_store is context.action_approval_trust, (
        "the boundary is answering from a store the application did not freeze"
    )


def test_no_authorization_path_reopens_the_trust_file():
    """Structural: the decision path must not reach the filesystem for trust.

    A behavioural test passes while a second, unused load site sits in the
    module waiting to be called. This asserts the shape -- the boundary's
    constructor may load only as the last resort when nothing was injected.
    """
    import ast  # noqa: PLC0415

    source = (ROOT / "src/nornyx_forge/nornyx_runtime.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name in {"__init__"}:
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "load"
                and isinstance(inner.func.value, ast.Name)
                and inner.func.value.id == "ApprovalTrustStore"
            ):
                offenders.append(f"{node.name}:{inner.lineno}")
    assert offenders == [], (
        "these functions load the trust store outside construction, so an "
        f"authorization decision could reopen it: {offenders}"
    )


def test_the_probe_would_notice_a_stale_snapshot(tmp_path: Path):
    """The assertions above must be capable of failing.

    Passing `None` takes the old path -- the boundary resolves trust from the
    configured location -- and that path must still see the replaced file.
    Without this, every assertion above could be passing because nothing was
    reloaded under any circumstances.
    """
    store_path, trust = _anchored(tmp_path)
    store_path.write_text(json.dumps(ATTACKER), encoding="utf-8")

    assert _signers(tmp_path, trust, None) == ["attacker-key"], (
        "the unfrozen path no longer observes the file, so the frozen tests "
        "prove nothing about freezing"
    )


def test_a_missing_snapshot_is_not_an_empty_trust_store(tmp_path: Path):
    """The absence rule, applied here.

    A context that never parsed trust must not present as "nobody is trusted"
    without saying so -- that reads as a deployment with no approvers rather
    than one whose trust material was never established.
    """
    _store_path, trust = _anchored(tmp_path)
    store = ApprovalTrustStore(source="not established")
    assert store.signers == {}
    assert store.available is False
    _ = trust


def test_a_broken_store_at_bootstrap_says_why(tmp_path: Path, monkeypatch):
    """"Nobody is trusted" and "the trust material is broken" are not the same.

    Both authorize exactly nothing, so no test comparing signer sets can tell
    them apart -- a mutation replacing the diagnostic with an empty string
    survived until this existed. They call for different operator actions: one
    means provision an approver, the other means the file on disk is damaged.
    """
    from nornyx_forge import subject_bootstrap  # noqa: PLC0415

    broken = tmp_path / "broken.json"
    broken.write_text("{ not json", encoding="utf-8")
    monkeypatch.setenv("FORGE_APPROVER_TRUST_STORE", str(broken))

    loaded = subject_bootstrap._load_approval_domains(tmp_path)
    # BOTH domains must report the damage. One of them silently reading as
    # "no approvers provisioned" would be the absence-reads-as-configured
    # confusion in the half nobody looked at.
    assert set(loaded) == {"governance_approval_trust", "action_approval_trust"}
    for name, store in loaded.items():
        assert store.signers == {}, f"a broken store must vouch for nobody: {name}"
        assert store.domain, f"{name} does not say which authority it is for"
    store = loaded["action_approval_trust"]
    assert store.source, (
        "the context carries no reason the trust material is unusable, so an "
        "operator cannot tell a damaged file from an unprovisioned one"
    )
    assert "broken.json" in store.source or "json" in store.source.lower()


# --------------------------------------------------------------------------
# The other trust domains, and where each is actually consumed
# --------------------------------------------------------------------------
#
# Task 4 asks that every runtime trust domain follow the bootstrap model. That
# is answerable only after establishing which domains HAVE a runtime consumer,
# and the answer is not symmetrical:
#
#   action-approval trust   consumed by the action boundary, per request
#                           -> must be frozen, and is
#   reviewer trust          consumed by the assurance derivation in the CLI
#                           tooling, once per invocation
#                           -> each invocation is its own bootstrap
#
# Measured rather than assumed: `ReviewerTrustStore.load` is called exactly once
# per `derive_assurance_state()`, and nothing under `src/` consumes reviewer
# trust at all. Freezing it into `RuntimeSecurityContext` would add a field with
# no consumer, which is the shape of defect this programme keeps finding rather
# than a fix for one.
#
# So the property asserted here is the honest one: reviewer trust has no runtime
# authorization consumer, and if that ever changes the change has to be
# deliberate because this test fails.
#
# THE STANDING RULE, for whoever reads that failure:
#
#   If reviewer trust gains a long-lived runtime consumer, that consumer must
#   establish an immutable reviewer-trust snapshot at its composition boundary.
#
# It is the rule the approval domains already follow, and it is written here
# rather than applied pre-emptively: a snapshot with no consumer is unused
# security state, and this programme has found that shape to be a defect more
# often than a fix. The rule costs nothing until it is needed, and the test
# below is what makes sure it is read at the moment it becomes needed.


def test_reviewer_trust_has_no_runtime_authorization_consumer():
    """If this fails, reviewer trust gained a runtime consumer and must freeze.

    The action boundary reads approver trust and must be handed a snapshot,
    because it runs per request. Reviewer trust is consumed by the assurance
    derivation, which is a tool invocation -- its own bootstrap. Those need
    different treatments, and the difference is only defensible while it is
    true, so this pins it.
    """
    import ast  # noqa: PLC0415

    runtime_modules = [
        "src/nornyx_forge/nornyx_runtime.py",
        "src/demo_app/agentic.py",
        "src/demo_app/main.py",
    ]
    offenders: list[str] = []
    for relative in runtime_modules:
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "ReviewerTrustStore", "reviewer_store_path",
            }:
                offenders.append(f"{relative}:{node.lineno}")
            if isinstance(node, ast.Name) and node.id in {
                "ReviewerTrustStore", "reviewer_store_path",
            }:
                offenders.append(f"{relative}:{node.lineno}")
    assert offenders == [], (
        "reviewer trust is now consumed by a runtime path, so it must be "
        f"frozen at bootstrap like approver trust: {offenders}"
    )


def test_the_assurance_derivation_reads_reviewer_trust_once():
    """One load per invocation, so there is no window to swap it mid-run.

    A second load inside one derivation would be the same defect approver trust
    had, at a smaller scale: the file could change between them and the two
    halves of one answer would disagree.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    import nornyx_forge.reviewer_trust as reviewer_trust  # noqa: PLC0415

    loads: list[object] = []
    original = reviewer_trust.ReviewerTrustStore.load

    def counting(*args, **kwargs):
        loads.append(args[0] if args else None)
        return original(*args, **kwargs)

    reviewer_trust.ReviewerTrustStore.load = counting  # type: ignore[assignment]
    try:
        refresh.derive_assurance_state()
    finally:
        reviewer_trust.ReviewerTrustStore.load = original  # type: ignore[assignment]

    assert len(loads) <= 1, (
        f"the assurance derivation read reviewer trust {len(loads)} times; the "
        "file could change between them and one answer would rest on two "
        "different roots of trust"
    )


# --------------------------------------------------------------------------
# POSSESSION IS NOT CONSUMPTION
#
# `test_the_established_context_carries_the_frozen_store` proves the frozen
# object REACHES the boundary. That is propagation, and its name once implied
# more. The standing rule this repository now works to:
#
#     ESTABLISHED -> PROPAGATED -> CONSUMED BY THE CONSEQUENTIAL DECISION
#                 -> REMOVAL CHANGES THAT DECISION
#
# A security object present in RuntimeSecurityContext proves only possession.
# The two tests below close the last two arrows for action trust.
# --------------------------------------------------------------------------


def _release_under(tmp_path, store, *, workspace: str = "run"):
    """Drive the REAL consequential boundary with a chosen frozen store.

    Each call gets its OWN workspace. Sharing one would share the ledger, and a
    later refusal would then observe the grant spent by an earlier successful
    release -- which is exactly what the first version of these tests reported,
    a contaminated observation rather than a real consumption.
    """
    tmp_path = tmp_path / workspace
    tmp_path.mkdir(parents=True, exist_ok=True)
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import (  # noqa: PLC0415
        TEST_REVISION,
        _permissive_boundary,
    )

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        canonical_action_request,
    )

    descriptor = ActionDescriptor(
        operation="issue refund",
        resource="customer:omar",
        destination="zone.external_customer",
        parameters={"amount": 100, "currency": "USD"},
    )
    boundary = _permissive_boundary(
        tmp_path, as_of="2026-08-03T00:00:00Z", action_trust=store
    )
    request = canonical_action_request(
        mission_id="CASE-CONSUME", risk="high",
        subject_revision=TEST_REVISION, descriptor=descriptor, attempt=1,
    )
    calls: list[str] = []
    decision, _detail = boundary.evaluate_and_execute(
        mission_id="CASE-CONSUME",
        risk="high",
        action=lambda: (calls.append("released"), "done")[1],
        action_approval=signed_grant(
            request, approval_id="ACT-CONSUME", role="operations_owner"
        ),
        action_descriptor=descriptor,
        attempt=1,
    )
    spent = boundary.approval_ledger.lookup(request_digest=request.digest) is not None
    return decision, calls, spent


def test_the_frozen_store_is_what_the_authority_decision_consults(tmp_path: Path):
    """CONSUMED, not merely carried.

    The same grant is judged against two different frozen stores. One trusts the
    signer; the other is provisioned and does not. If the boundary consulted
    anything other than the object it was handed, both would decide alike.
    """
    from signing import other_signer, trust_store  # noqa: PLC0415

    from nornyx_forge.approval_trust import ApprovalTrustStore  # noqa: PLC0415

    trusting = trust_store()
    stranger = ApprovalTrustStore.for_test([other_signer(("operations_owner",))])
    assert stranger.signers, "the control store must be provisioned, just not with this key"

    allowed, released, spent = _release_under(tmp_path, trusting, workspace="trusting")
    assert allowed.effect == "ALLOW", allowed.reason
    assert released == ["released"]
    assert spent is True

    refused, not_released, not_spent = _release_under(tmp_path, stranger, workspace="stranger")
    assert refused.effect == "DENY", (
        "the boundary released an effect against a store that does not trust "
        "the signer, so it is not consulting the store it was handed"
    )
    assert "not in the action approver trust store" in refused.reason, refused.reason
    assert not_released == []
    assert not_spent is False


def test_removing_the_frozen_store_changes_the_consequential_decision(tmp_path: Path):
    """The last arrow: REMOVAL CHANGES THE DECISION.

    An empty store is not "no opinion" -- it is an authority that vouches for
    nobody, and the effect must not occur. Without this, a boundary that ignored
    its store entirely would still pass the positive case above.
    """
    from signing import trust_store  # noqa: PLC0415

    from nornyx_forge.approval_trust import ApprovalTrustStore  # noqa: PLC0415

    allowed, released, _spent = _release_under(tmp_path, trust_store(), workspace="trusting")
    assert allowed.effect == "ALLOW" and released == ["released"]

    refused, not_released, not_spent = _release_under(
        tmp_path, ApprovalTrustStore(source="deliberately empty"), workspace="empty"
    )
    assert refused.effect == "DENY"
    assert not_released == [], "an empty trust store released a consequential effect"
    assert not_spent is False, "the grant was spent by a run that must not start"


# --------------------------------------------------------------------------
# P1-1. ONE question, asked once. Reporting is a view of the snapshot.
# --------------------------------------------------------------------------


def _context_with(action_store, governance_store=None):
    """A stand-in context carrying exactly the two frozen approval domains."""
    from dataclasses import replace  # noqa: PLC0415

    from demo_app import agentic  # noqa: PLC0415

    # The established object itself, not the accessor: these tests replace the
    # accessor, and reading it here would call back into this function.
    return replace(
        agentic._SECURITY_CONTEXT,  # noqa: SLF001
        action_approval_trust=action_store,
        governance_approval_trust=governance_store
        if governance_store is not None
        else action_store,
    )


def test_the_reported_state_never_reads_the_trust_store(monkeypatch):
    """The defect itself: a second consumer that re-opens the file.

    `assurance_state()` called `ApprovalTrustDomains.load()` again, so the
    interface answered from the filesystem while the boundary answered from a
    snapshot taken at startup. Counting the loads is the direct measurement --
    zero, because the answer is already held.
    """
    from demo_app import agentic  # noqa: PLC0415
    from nornyx_forge import approval_trust  # noqa: PLC0415

    loads: list[int] = []
    original = approval_trust.ApprovalTrustDomains.load

    def counting(*args, **kwargs):
        loads.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(approval_trust.ApprovalTrustDomains, "load", counting)
    agentic.assurance_state()

    assert loads == [], (
        f"the reported assurance state read the trust store {len(loads)} time(s); "
        "it must be a view of the established snapshot, or the interface and the "
        "boundary can answer the same question differently"
    )


def test_reporting_cannot_claim_authority_the_boundary_lacks(monkeypatch):
    """The dangerous direction, and the reason this was a P1.

    Measured before the fix, bootstrapping against no store and provisioning one
    afterwards:

        boundary   action_signers=[]  available=False   -- refuses
        reported   consequential_authority="available"  -- claims it can

    Nothing was released; only the reporting path re-read. But a deployment that
    misdescribes its own authority is what an operator plans against.
    """
    from demo_app import agentic  # noqa: PLC0415
    from nornyx_forge.approval_trust import (  # noqa: PLC0415
        ACTION_TRUST_DOMAIN,
        ApprovalTrustStore,
    )

    empty = ApprovalTrustStore(source="<absent>", domain=ACTION_TRUST_DOMAIN)
    assert not empty.available and not empty.signers  # the boundary would refuse

    monkeypatch.setattr(
        agentic, "application_security_context", lambda: _context_with(empty)
    )
    reported = agentic.assurance_state()

    assert reported["consequential_authority"] != "available", reported
    assert reported["trusted_approvers_loaded"] is False, reported


def test_absent_and_unusable_stay_different_states(monkeypatch):
    """Both authorize nothing. They send an operator to different fixes.

    Collapsing them would trade one truthfulness defect for another, so the
    third state is carried ON the snapshot rather than re-derived by reopening
    the file -- which is the only other way to answer it later.
    """
    from demo_app import agentic  # noqa: PLC0415
    from nornyx_forge.approval_trust import (  # noqa: PLC0415
        ACTION_TRUST_DOMAIN,
        ApprovalTrustStore,
    )

    absent = ApprovalTrustStore(source="<no such file>", domain=ACTION_TRUST_DOMAIN)
    broken = ApprovalTrustStore(
        source="store is unreadable: JSONDecodeError",
        domain=ACTION_TRUST_DOMAIN,
        unusable=True,
    )

    monkeypatch.setattr(
        agentic, "application_security_context", lambda: _context_with(absent)
    )
    absent_state = agentic.assurance_state()["action_approval_authentication"]

    monkeypatch.setattr(
        agentic, "application_security_context", lambda: _context_with(broken)
    )
    broken_state = agentic.assurance_state()["action_approval_authentication"]

    assert absent_state == "unavailable", absent_state
    assert broken_state == "unusable", broken_state
    assert absent_state != broken_state


def test_a_provisioned_snapshot_is_reported_available(monkeypatch):
    """The control. A reporter that said "unavailable" always would also pass
    every test above and describe nothing."""
    from signing import trust_store  # noqa: PLC0415

    from demo_app import agentic  # noqa: PLC0415
    from nornyx_forge.approval_trust import (  # noqa: PLC0415
        ACTION_TRUST_DOMAIN,
        GOVERNANCE_TRUST_DOMAIN,
    )

    action = trust_store()
    action = type(action)(
        signers=action.signers, digest=action.digest, source=action.source,
        available=True, domain=ACTION_TRUST_DOMAIN,
    )
    governance = type(action)(
        signers=action.signers, digest=action.digest, source=action.source,
        available=True, domain=GOVERNANCE_TRUST_DOMAIN,
    )
    assert action.signers, "the control needs a genuinely provisioned domain"

    monkeypatch.setattr(
        agentic, "application_security_context", lambda: _context_with(action, governance)
    )
    reported = agentic.assurance_state()

    assert reported["consequential_authority"] == "available", reported
    assert reported["trusted_approvers_loaded"] is True, reported


def _store_with_status(status: str, domain: str):
    from signing import trust_store  # noqa: PLC0415

    from nornyx_forge.approval_trust import ApprovalTrustStore  # noqa: PLC0415

    base = trust_store(status=status)
    return ApprovalTrustStore(
        signers=base.signers, digest=base.digest, source="<test>",
        available=True, domain=domain,
    )


def test_a_revoked_store_is_not_reported_as_available(monkeypatch):
    """A-P2-3. Membership is not authority.

    A revoked key stays in the store on purpose, so a refusal can say "that key
    is revoked" rather than "unknown key", and `authenticate_action_grant`
    refuses it. Counting raw membership reported `consequential_authority:
    available` for a deployment whose every key was revoked -- measured through
    `/api/health`, which is what an operator reads.
    """
    from demo_app import agentic  # noqa: PLC0415
    from nornyx_forge.approval_trust import (  # noqa: PLC0415
        ACTION_TRUST_DOMAIN,
        GOVERNANCE_TRUST_DOMAIN,
    )

    action = _store_with_status("revoked", ACTION_TRUST_DOMAIN)
    governance = _store_with_status("revoked", GOVERNANCE_TRUST_DOMAIN)
    assert action.signers, "the store must carry the revoked keys, not drop them"
    assert not action.active_signers, "none of them may count as active"

    monkeypatch.setattr(
        agentic, "application_security_context",
        lambda: _context_with(action, governance),
    )
    reported = agentic.assurance_state()

    assert reported["consequential_authority"] != "available", reported
    assert reported["trusted_approvers_loaded"] is False, reported


def test_an_active_store_is_still_reported_as_available(monkeypatch):
    """The control. Filtering everything out would also satisfy the case above."""
    from demo_app import agentic  # noqa: PLC0415
    from nornyx_forge.approval_trust import (  # noqa: PLC0415
        ACTION_TRUST_DOMAIN,
        GOVERNANCE_TRUST_DOMAIN,
    )

    action = _store_with_status("active", ACTION_TRUST_DOMAIN)
    governance = _store_with_status("active", GOVERNANCE_TRUST_DOMAIN)
    assert action.active_signers

    monkeypatch.setattr(
        agentic, "application_security_context",
        lambda: _context_with(action, governance),
    )
    assert agentic.assurance_state()["consequential_authority"] == "available"


def test_the_report_and_the_authenticator_use_one_rule():
    """Two spellings of "active" is how these drift apart again.

    `active_signers` and the authenticator's refusal must consult the same
    constant, so a change to what counts as usable cannot move one without the
    other.
    """
    from nornyx_forge import approval_trust  # noqa: PLC0415

    source = Path(approval_trust.__file__).read_text(encoding="utf-8")
    assert source.count('!= ACTIVE_SIGNER_STATUS') >= 1, (
        "the authenticator no longer consults the shared constant"
    )
    assert source.count('== ACTIVE_SIGNER_STATUS') >= 1, (
        "active_signers no longer consults the shared constant"
    )
    assert 'status != "active"' not in source, (
        "a second spelling of the active rule has appeared, which is how the "
        "report and the authenticator drift onto different answers"
    )


def test_la03_the_frozen_store_cannot_be_repointed_in_place():
    """`frozen=True` freezes the reference, not what it points at.

    A review inserted an attacker key directly into
    `context.action_approval_trust.signers` and turned a DENY
    (APPROVER_NOT_TRUSTED) into an ALLOW with the effect executed -- while
    `store.digest` stayed unchanged, so the audit projection could not detect
    it afterwards either. The docstring claimed "a variable changed after
    startup cannot re-point the root of trust"; the mapping was a plain dict.
    """
    from nornyx_forge.approval_trust import ApprovalTrustStore  # noqa: PLC0415

    store = ApprovalTrustStore.for_test(
        [{"key_id": "k1", "public_key": "AAAA", "algorithm": "Ed25519",
          "subject": "human.reviewer", "subject_type": "human",
          "roles": ["operations_owner"], "status": "active"}],
        domain="action",
    )
    with pytest.raises(TypeError):
        store.signers["attacker-key"] = object()
    with pytest.raises(TypeError):
        del store.signers["k1"]
    assert "attacker-key" not in store.signers
