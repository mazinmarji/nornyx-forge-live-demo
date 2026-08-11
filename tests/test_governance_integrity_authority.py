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
    label: str, relative: str, find: bytes, replace: bytes
):
    """Both measured attacks, at the observation that feeds the boundary.

    The status case is the upgrade, deliberately: a record claiming LESS than
    its artifact supports is not an integrity failure, and testing the downgrade
    would assert nothing. A status is derived, so it is checked against the
    derivation -- an artifact reporting no authenticated inspection cannot back
    a passing independent review.
    """
    target = ROOT / relative
    original = target.read_bytes()
    try:
        target.write_bytes(original.replace(find, replace, 1))
        state = observe_governance_integrity(ROOT / ".nornyx/contracts")
    finally:
        target.write_bytes(original)

    assert state.status == INTEGRITY_COMPROMISED, f"{label}: the tamper was not observed"
    assert state.problems, f"{label}: compromised with no diagnostic"
    assert target.read_bytes() == original, "the test did not restore the contract"


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
