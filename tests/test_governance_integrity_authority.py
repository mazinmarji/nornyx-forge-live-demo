"""An integrity-compromised runtime must not reach a consequential effect.

Derived governance state -- an evidence record's `status`, a recorded
`content_hash` -- sits outside the inspection subject. That exclusion is
necessary (binding an inspection to values the tooling rewrites made
authenticated inspection unreachable) but it is admissible only while
compromising those values withdraws EVERY authority that could depend on them.

Runtime authority did not. Measured before this control existed, with a valid
signed grant and a permissive authorizer so integrity was the only variable:

    baseline (intact)        effect=ALLOW callbacks=1 ledger_spent=True
    derived status upgraded  effect=ALLOW callbacks=1 ledger_spent=True
    content_hash mutated     effect=ALLOW callbacks=1 ledger_spent=True

The effect ran and the approval was spent while the governance evidence the
decision rested on did not match what the contracts recorded.

THE PROPERTY:

    integrity compromised
      -> callback count 0
      -> approval not consumed
      -> structured GOVERNANCE_INTEGRITY_COMPROMISED diagnostic

asked before the request is built, so no grant is spent discovering it, and
before the authorizer is consulted, because a compromised contract is what the
authorizer would be reading.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nornyx_forge.governed_subject import (  # noqa: E402
    INTEGRITY_COMPROMISED,
    INTEGRITY_INTACT,
    INTEGRITY_UNAVAILABLE,
    GovernanceIntegrityState,
)
from nornyx_forge.nornyx_runtime import (  # noqa: E402
    GOVERNANCE_INTEGRITY_COMPROMISED,
    ActionDescriptor,
    canonical_action_request,
)
from nornyx_forge.subject_observer import observe_governance_integrity  # noqa: E402

DESCRIPTOR = ActionDescriptor(
    operation="issue refund",
    resource="customer:omar",
    destination="zone.external_customer",
    parameters={"amount": 100, "currency": "USD"},
)


def _release(tmp_path: Path, integrity: GovernanceIntegrityState | None):
    """Drive the real boundary with a valid grant. Integrity is the only variable."""
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: PLC0415

    boundary = _permissive_boundary(tmp_path, as_of="2026-08-03T00:00:00Z")
    boundary.governance_integrity = integrity

    request = canonical_action_request(
        mission_id="CASE-INTEGRITY", risk="high",
        subject_revision=TEST_REVISION, descriptor=DESCRIPTOR, attempt=1,
    )
    calls: list[str] = []
    decision, _detail = boundary.evaluate_and_execute(
        mission_id="CASE-INTEGRITY",
        risk="high",
        action=lambda: (calls.append("released"), "done")[1],
        action_approval=signed_grant(request, approval_id="ACT-INTEGRITY"),
        action_descriptor=DESCRIPTOR,
        attempt=1,
    )
    spent = boundary.approval_ledger.lookup(request_digest=request.digest) is not None
    return decision, calls, spent


def test_an_intact_runtime_still_releases(tmp_path: Path):
    """The benign control. Without it every refusal below could be 'always refuses'."""
    decision, calls, spent = _release(
        tmp_path, GovernanceIntegrityState(status=INTEGRITY_INTACT, verified_claims=8)
    )
    assert decision.effect == "ALLOW", decision.reason
    assert len(calls) == 1
    assert spent is True


def test_a_compromised_runtime_releases_nothing(tmp_path: Path):
    decision, calls, spent = _release(
        tmp_path,
        GovernanceIntegrityState(
            status=INTEGRITY_COMPROMISED,
            verified_claims=8,
            problems=("architecture_governance.nyx records X",),
        ),
    )

    assert decision.effect == "DENY"
    assert decision.code == GOVERNANCE_INTEGRITY_COMPROMISED
    assert calls == [], "a consequential effect ran under compromised governance evidence"
    assert spent is False, "the approval was spent by a run that must not have started"
    assert "does not match what the contracts record" in decision.reason


def test_the_refusal_precedes_the_approval_being_spent(tmp_path: Path):
    """Order matters: a grant must not be consumed discovering the compromise.

    If integrity were checked after consumption, an attacker could burn a
    victim's outstanding approval by tampering with an artifact.
    """
    _decision, _calls, spent = _release(
        tmp_path,
        GovernanceIntegrityState(
            status=INTEGRITY_COMPROMISED, problems=("problem",)
        ),
    )
    assert spent is False


# --------------------------------------------------------------------------
# The observation itself
# --------------------------------------------------------------------------


def test_the_real_repository_reports_intact_governance_integrity():
    """The benign control for the observer: it must not flag a healthy tree."""
    state = observe_governance_integrity(ROOT / ".nornyx/contracts")
    assert state.status == INTEGRITY_INTACT, state.problems
    assert state.verified_claims > 0, (
        "intact with nothing verified would mean the observer checked nothing"
    )


@pytest.mark.parametrize(
    ("label", "relative", "find", "replace"),
    [
        (
            "recorded digest",
            ".nornyx/contracts/runtime_network.nyx",
            b"content_hash: sha256:",
            b"content_hash: sha256:dead",
        ),
        (
            "status upgraded past its own artifact",
            ".nornyx/contracts/architecture_governance.nyx",
            b"status: observed",
            b"status: pass",
        ),
    ],
)
def test_a_tampered_derived_field_is_observed(
    label: str, relative: str, find: bytes, replace: bytes, tmp_path: Path
):
    """Both measured attacks, at the observation that feeds the boundary.

    The status case is the upgrade, deliberately: a record claiming LESS than
    its artifact supports is not an integrity failure, and testing the downgrade
    would assert nothing. A status is derived, so it is checked against the
    derivation -- an artifact reporting no authenticated inspection cannot back
    a passing independent review.

    Against a copy. This tampered the REAL contracts and restored them in
    `finally`, which holds until a run does not reach the restore. The identical
    pattern in test_artifact_authority.py did not: forged inspection records
    survived an interrupted run and were committed, and a governed artifact in
    this repository asserted three authenticated inspections that never
    happened. A `finally` is not isolation.
    """
    from mutation_workspace import faithful_copy  # noqa: PLC0415

    tree = faithful_copy(tmp_path)
    target = tree / relative
    original = target.read_bytes()
    assert find in original, f"{label}: the fixture no longer matches the contract"

    target.write_bytes(original.replace(find, replace, 1))
    state = observe_governance_integrity(tree / ".nornyx/contracts")

    assert state.status == INTEGRITY_COMPROMISED, f"{label}: the tamper was not observed"
    assert state.problems, f"{label}: compromised with no diagnostic"
    assert (ROOT / relative).read_bytes() != target.read_bytes(), (
        "the tamper reached the real contract"
    )


def test_the_established_context_carries_integrity_to_the_boundary():
    """Wired, not merely available.

    The same defect has now appeared twice in this repository -- a control built
    and then not connected -- so this asserts the object identity at the edge
    rather than that the mechanism exists.
    """
    from demo_app.agentic import CustomerCaseFlow, application_security_context  # noqa: PLC0415

    context = application_security_context()
    flow = CustomerCaseFlow(
        {
            "id": "CASE-WIRE",
            "customer": "Omar",
            "summary": "Issue a high-value external refund",
            "risk": "high",
            "requested_action": "issue refund",
        },
        root=ROOT,
        security_context=context,
    )
    assert flow.boundary.governance_integrity is context.governance_integrity


# --------------------------------------------------------------------------
# "I could not look" is not "I looked and it is sound"
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "location", "because"),
    [
        ("a missing contracts directory", "no/such/directory", "is not a directory"),
        ("a directory holding no contracts", "tests", "holds no contracts"),
    ],
)
def test_an_unobservable_governance_surface_is_not_intact(
    tmp_path: Path, label: str, location: str, because: str
):
    """The fail-open this state type exists to remove.

    The first version returned a list of problems, so "nothing to check" and
    "everything matched" were the same empty value. Measured then: a missing
    contracts directory reported intact, which would have authorized a
    consequential effect on a tree with no governance surface at all.
    """
    state = observe_governance_integrity(ROOT / location)
    assert state.status == INTEGRITY_UNAVAILABLE, label
    assert state.verified_claims == 0
    assert state.authorizes_consequential_action is False, label
    # The DISTINGUISHING diagnostic, not merely "unavailable". The two branches
    # cover each other otherwise -- delete the directory check and the empty-glob
    # check still returns unavailable, so a mutation removing either survived a
    # test that asked only for the status. An operator also needs to know which
    # of the two happened: one is a deployment error, the other an empty tree.
    assert any(because in problem for problem in state.problems), (
        f"{label}: refused, but not because it {because}: {state.problems}"
    )


def test_an_unavailable_observation_denies_at_the_boundary(tmp_path: Path):
    """Checked where authority is consumed, not only where it is observed."""
    decision, calls, spent = _release(
        tmp_path,
        GovernanceIntegrityState(
            status=INTEGRITY_UNAVAILABLE, problems=("could not observe",)
        ),
    )
    assert decision.effect == "DENY"
    assert decision.code == GOVERNANCE_INTEGRITY_COMPROMISED
    assert calls == []
    assert spent is False


def test_no_established_observation_denies(tmp_path: Path):
    """A boundary handed no observation must not treat that as permission."""
    decision, calls, spent = _release(tmp_path, None)
    assert decision.effect == "DENY"
    assert calls == []
    assert spent is False


def test_the_state_refuses_to_be_constructed_dishonestly():
    """The type will not hold a contradiction.

    `intact` with problems, or a refusal with no reason, are both states a
    caller could otherwise build and then act on.
    """
    from nornyx_forge.governed_subject import GovernedSubjectError

    with pytest.raises(GovernedSubjectError):
        GovernanceIntegrityState(status=INTEGRITY_INTACT, problems=("x",))
    with pytest.raises(GovernedSubjectError):
        GovernanceIntegrityState(status=INTEGRITY_COMPROMISED)
    with pytest.raises(GovernedSubjectError):
        GovernanceIntegrityState(status="probably_fine", problems=("x",))


def test_intact_with_nothing_verified_is_refused():
    """The refusal the docstring described and the code never performed.

    `verified_claims` exists precisely because "no problems found" can mean
    every claim was checked and matched, or that nothing was checked at all.
    The class docstring said a count of zero with status `intact` "is refused at
    construction rather than left for a caller to notice" -- and `__post_init__`
    contained no such check, so the state most worth refusing was the one state
    it would accept, and it authorizes consequential action.

    `observe_governance_integrity` returns `unavailable` on that path already,
    so this is a backstop on the type rather than a change of behaviour: the
    invariant now holds for every construction site, including future ones.
    """
    from nornyx_forge.governed_subject import GovernedSubjectError

    with pytest.raises(GovernedSubjectError, match="nothing was checked"):
        GovernanceIntegrityState(status=INTEGRITY_INTACT, verified_claims=0)
    with pytest.raises(GovernedSubjectError, match="nothing was checked"):
        GovernanceIntegrityState(status=INTEGRITY_INTACT)  # the default is zero


def test_intact_with_verified_claims_is_still_accepted():
    """The control. A type that refused every intact state would also pass
    the case above while making the sound outcome unrepresentable."""
    state = GovernanceIntegrityState(status=INTEGRITY_INTACT, verified_claims=1)

    assert state.authorizes_consequential_action is True
    assert state.problems == ()


# --------------------------------------------------------------------------
# A refusal for compromised governance must leave a record.
# --------------------------------------------------------------------------


def _compromised_boundary(root):
    from test_governance_failure import _permissive_boundary  # noqa: PLC0415

    from nornyx_forge.governed_subject import (  # noqa: PLC0415
        INTEGRITY_COMPROMISED,
        GovernanceIntegrityState,
    )

    return _permissive_boundary(
        root,
        as_of="2026-08-03T00:00:00Z",
        governance_integrity=GovernanceIntegrityState(
            status=INTEGRITY_COMPROMISED,
            verified_claims=8,
            problems=("architecture_approval_record.json does not match",),
        ),
    )


def test_a_compromised_refusal_is_recorded(tmp_path: Path):
    """The attempt most worth finding afterwards produced the least evidence.

    A consequential act attempted against a runtime whose own governance state
    is compromised used to return DENY and write nothing at all -- no stream, no
    report, no case record -- so nothing showed an operator that it had
    happened.
    """
    from signing import LEDGER_ESTABLISHED, signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        ApprovalLedger,
        approval_ledger_path,
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
    request = canonical_action_request(
        mission_id="CASE-COMPROMISED", risk="high", subject_revision=TEST_REVISION,
        descriptor=descriptor, attempt=1,
    )
    grant = signed_grant(request, approval_id="ACT-C1", role="operations_owner")

    calls: list[str] = []
    decision, _result = _compromised_boundary(tmp_path).evaluate_and_execute(
        mission_id="CASE-COMPROMISED", risk="high",
        action=lambda: (calls.append("ran"), "done")[1],
        action_approval=grant, action_descriptor=descriptor, attempt=1,
    )

    assert decision.effect == "DENY"
    assert calls == [], "a compromised runtime released the effect"

    written = sorted((tmp_path / "evidence/runtime/refused").glob("*.refused.json"))
    assert written, "the refusal left no record at all"

    record = json.loads(written[0].read_text(encoding="utf-8"))
    assert record["schema"] == "nornyx.forge.refused_action_attempt.v1"
    assert record["effect_released"] is False
    assert record["approval_consumed"] is False
    assert record["integrity_status"] == "compromised"
    assert record["integrity_problems"], "the record does not say what was wrong"


def test_the_refusal_record_is_not_a_governance_decision(tmp_path: Path):
    """It must not imitate an evidence stream it never had.

    This path runs BEFORE the authorizer is consulted -- deliberately, because a
    compromised contract is what the authorizer would be reading. So there is no
    Nornyx decision to report, and the record carries its own schema rather than
    borrowing one that would imply a verdict nobody reached.
    """
    from signing import LEDGER_ESTABLISHED, signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        ApprovalLedger,
        approval_ledger_path,
        canonical_action_request,
    )

    descriptor = ActionDescriptor(
        operation="wire transfer", resource="customer:omar",
        destination="zone.external_customer", parameters={"amount": 1},
    )
    ApprovalLedger.provision(
        approval_ledger_path(tmp_path), established_at=LEDGER_ESTABLISHED
    )
    request = canonical_action_request(
        mission_id="CASE-NO-VERDICT", risk="high", subject_revision=TEST_REVISION,
        descriptor=descriptor, attempt=1,
    )
    grant = signed_grant(request, approval_id="ACT-C2", role="operations_owner")

    _compromised_boundary(tmp_path).evaluate_and_execute(
        mission_id="CASE-NO-VERDICT", risk="high", action=lambda: "done",
        action_approval=grant, action_descriptor=descriptor, attempt=1,
    )

    record = json.loads(
        next((tmp_path / "evidence/runtime/refused").glob("*.refused.json"))
        .read_text(encoding="utf-8")
    )
    assert "nornyx_decision" not in record, (
        "the refusal record claims a Nornyx verdict, but the authorizer was "
        "never consulted on this path"
    )
    # And it must not land among the real evidence streams.
    assert not (tmp_path / "evidence/runtime/nornyx").exists() or not list(
        (tmp_path / "evidence/runtime/nornyx").glob("*.events.json")
    ), "a refusal before the authorizer wrote an event stream"


def test_an_intact_runtime_writes_no_refusal_record(tmp_path: Path):
    """The control. A record written unconditionally would distinguish nothing."""
    from signing import LEDGER_ESTABLISHED, signed_grant  # noqa: PLC0415
    from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        ApprovalLedger,
        approval_ledger_path,
        canonical_action_request,
    )

    descriptor = ActionDescriptor(
        operation="wire transfer", resource="customer:omar",
        destination="zone.external_customer", parameters={"amount": 1},
    )
    ApprovalLedger.provision(
        approval_ledger_path(tmp_path), established_at=LEDGER_ESTABLISHED
    )
    request = canonical_action_request(
        mission_id="CASE-INTACT", risk="high", subject_revision=TEST_REVISION,
        descriptor=descriptor, attempt=1,
    )
    grant = signed_grant(request, approval_id="ACT-C3", role="operations_owner")

    _permissive_boundary(tmp_path, as_of="2026-08-03T00:00:00Z").evaluate_and_execute(
        mission_id="CASE-INTACT", risk="high", action=lambda: "done",
        action_approval=grant, action_descriptor=descriptor, attempt=1,
    )

    refused = tmp_path / "evidence/runtime/refused"
    assert not refused.exists() or not list(refused.glob("*.refused.json")), (
        "an intact runtime wrote a compromised-governance refusal record"
    )


# --------------------------------------------------------------------------
# A10 -- the integrity gate ran AFTER the authorizer it protects, and was
# skipped when the compromised contract's own verdict was DENY.
#
# The block carried the comment "before the authorizer is consulted, because a
# compromised contract is what the authorizer would be reading" while sitting
# inside `if high_risk and decision.allowed:`, three `authorizer.evaluate`
# calls later. Measured: 3 calls made first, and with the contract denying, the
# `refused_action_attempt.v1` record was never written -- so whether an
# operator learned the governance state was compromised was decided BY the
# compromised material.
# --------------------------------------------------------------------------


NOW = "2026-08-03T00:00:00Z"


def _compromised(boundary):
    from nornyx_forge.governed_subject import (  # noqa: PLC0415
        INTEGRITY_COMPROMISED,
        GovernanceIntegrityState,
    )

    boundary.governance_integrity = GovernanceIntegrityState(
        status=INTEGRITY_COMPROMISED,
        verified_claims=3,
        problems=("architecture_governance.nyx records X, but it digests to Y",),
    )
    return boundary


def _counting_authorizer(boundary, *, allow: bool = True):
    """Count evaluations, and optionally make every one of them DENY."""
    calls: list[str] = []
    real = boundary.authorizer.evaluate

    def counted(*args, **kwargs):
        calls.append("evaluate")
        outcome = real(*args, **kwargs)
        if not allow:
            # The compromised contract denying is the case that used to write
            # no refusal record at all.
            try:
                object.__setattr__(outcome, "allowed", False)
            except (AttributeError, TypeError):  # pragma: no cover - shape guard
                pass
        return outcome

    boundary.authorizer.evaluate = counted
    return calls


@pytest.mark.parametrize("contract_allows", [True, False],
                         ids=["contract allows", "contract denies"])
def test_a10_integrity_is_decided_before_the_authorizer_reads_the_contract(
    tmp_path: Path, contract_allows: bool
):
    """No evaluation may precede the refusal, in either direction.

    The parametrisation is the finding: the refusal used to exist only in the
    first case, because the branch guarding it required the contract to have
    ALLOWED. A control that a compromised contract can switch off is not a
    control over that contract.
    """
    from test_governance_failure import _permissive_boundary  # noqa: PLC0415

    boundary = _compromised(_permissive_boundary(tmp_path, as_of=NOW))
    calls = _counting_authorizer(boundary, allow=contract_allows)

    released: list[str] = []
    verdict, _ = boundary.evaluate_and_execute(
        mission_id="CASE-A10", risk="high",
        action=lambda: released.append("released"),
        action_approval=None,
        action_descriptor=ActionDescriptor(
            operation="issue refund", resource="customer:omar",
            destination="zone.external_customer",
            parameters={"amount": 100, "currency": "USD"},
        ),
        attempt=1,
    )

    assert verdict.code == "GOVERNANCE_INTEGRITY_COMPROMISED", verdict.reason
    assert released == [], "a compromised runtime released the effect"
    assert calls == [], (
        "the authorizer read the contract before the integrity of that "
        f"contract was decided, {len(calls)} times: the comment on this gate "
        "says it runs first precisely because a compromised contract is what "
        "the authorizer would be reading"
    )

    written = sorted((tmp_path / "evidence/runtime/refused").glob("*.refused.json"))
    assert len(written) == 1, (
        "no refusal record was written, so an operator cannot see that a "
        "consequential act was attempted against a compromised runtime -- and "
        "this is the case that used to write nothing at all"
    )
    record = json.loads(written[0].read_text(encoding="utf-8"))
    assert record["code"] == "GOVERNANCE_INTEGRITY_COMPROMISED"
    assert record["effect_released"] is False
    assert record["approval_consumed"] is False


def test_a10_a_sound_runtime_still_reaches_the_authorizer(tmp_path: Path):
    """The positive control. Without it, hoisting the gate could refuse
    everything and every test above would still pass."""
    from test_governance_failure import _permissive_boundary  # noqa: PLC0415

    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    calls = _counting_authorizer(boundary)

    boundary.evaluate_and_execute(
        mission_id="CASE-A10-OK", risk="high",
        action=lambda: None,
        action_approval=None,
        action_descriptor=ActionDescriptor(
            operation="issue refund", resource="customer:omar",
            destination="zone.external_customer",
            parameters={"amount": 100, "currency": "USD"},
        ),
        attempt=1,
    )
    assert calls, (
        "the authorizer was never consulted on a runtime whose governance "
        "state is sound, so the gate now refuses everything"
    )


#: The demonstration case the shipped path runs first, and its risk.
#:
#: LOW, deliberately. The gate's own comment says `high_risk` is not a
#: precondition -- "a compromised governance state is not more acceptable for a
#: low-risk act, it simply has less to release" -- and the fallback already
#: denies high and critical for a different reason, so a high-risk specimen
#: would have gone green whether this gate ran or not.
SHIPPED_CASE = {
    "id": "CASE-INTEGRITY",
    "customer": "Amina",
    "summary": "Update delivery instructions",
    "risk": "low",
    "requested_action": "send guidance",
}


def _shipped_run(root: Path, integrity: GovernanceIntegrityState | None):
    """Drive `CustomerCaseFlow` the way `run_case` does, on the fallback path.

    Not a boundary in isolation: the point of this pair is that the gate is
    reached by the configuration that SHIPS, and the shipped configuration is
    `deterministic_fallback` because the authorizer cannot load without a human
    approval.
    """
    from demo_app.agentic import (  # noqa: PLC0415
        CustomerCaseFlow,
        application_security_context,
    )

    flow = CustomerCaseFlow(
        dict(SHIPPED_CASE), root=root, worker_mode="deterministic",
        allow_policy_fallback=True,
        security_context=application_security_context(),
    )
    assert flow.boundary.mode == "deterministic_fallback", (
        "this specimen is about the fallback path and the boundary took "
        f"another one: {flow.boundary.mode}"
    )
    if integrity is not None:
        flow.boundary.governance_integrity = integrity
    flow.run_sequential()
    refusals = sorted((root / "evidence/runtime/refused").glob("*.json"))
    return flow.case, refusals


def test_the_shipped_fallback_refuses_under_compromised_governance(tmp_path: Path):
    """The gate lived only where the shipped configuration never goes.

    `_official` carries this check, and `_official` is entered only when the
    Nornyx authorizer loaded -- which needs the human approval this repository
    does not have. So on every path a reader can actually run, the property the
    gate's comment states in as many words was dead code.

    Measured on `CustomerCaseFlow.run_sequential` before the repair, with the
    integrity state injected as compromised and again as unavailable:

        fallback, integrity=compromised   ALLOW/ALLOWED, callable ran, 0 records
        fallback, integrity=unavailable   ALLOW/ALLOWED, callable ran, 0 records

    No refusal record either, so an operator could not find the attempt.
    """
    case, refusals = _shipped_run(
        tmp_path,
        GovernanceIntegrityState(
            status=INTEGRITY_COMPROMISED,
            verified_claims=8,
            problems=("architecture_governance.nyx records X",),
        ),
    )
    assert case["action_status"] == "prevented", (
        "a low-risk effect was released against a runtime whose own governance "
        f"evidence does not match its contracts: {case['decision']}"
    )
    assert case["decision"]["code"] == GOVERNANCE_INTEGRITY_COMPROMISED
    assert len(refusals) == 1, (
        "the attempt left no refusal record, so an operator cannot see that a "
        "consequential act was attempted against a compromised runtime"
    )
    record = json.loads(refusals[0].read_text(encoding="utf-8"))
    assert record["schema"] == "nornyx.forge.refused_action_attempt.v1"
    assert record["effect_released"] is False
    assert record["approval_consumed"] is False
    assert record["integrity_status"] == INTEGRITY_COMPROMISED


def test_an_unavailable_observation_also_refuses_on_the_shipped_path(tmp_path: Path):
    """`unavailable` is not `intact`, on this path as on the other one."""
    case, refusals = _shipped_run(
        tmp_path,
        GovernanceIntegrityState(
            status=INTEGRITY_UNAVAILABLE,
            problems=("the governance surface could not be read",),
        ),
    )
    assert case["action_status"] == "prevented", case["decision"]
    assert case["decision"]["code"] == GOVERNANCE_INTEGRITY_COMPROMISED
    assert len(refusals) == 1


def test_the_shipped_fallback_still_releases_when_integrity_is_intact(tmp_path: Path):
    """The benign control, and it carries the two refusals above.

    Both are satisfied by a gate that refuses everything, and a gate that
    refused everything would have stopped the demonstration this repository
    ships. The observation is the one the application really establishes --
    nothing is injected here.
    """
    case, refusals = _shipped_run(tmp_path, None)
    assert case["action_status"] == "executed", (
        "the shipped low-risk demonstration no longer runs: " + repr(case["decision"])
    )
    assert case["decision"]["effect"] == "ALLOW"
    assert refusals == [], "an intact runtime wrote a refusal record"
