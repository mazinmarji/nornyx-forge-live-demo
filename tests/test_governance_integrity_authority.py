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


def _release(tmp_path: Path, integrity: tuple[str, ...]):
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
    decision, calls, spent = _release(tmp_path, ())
    assert decision.effect == "ALLOW", decision.reason
    assert len(calls) == 1
    assert spent is True


def test_a_compromised_runtime_releases_nothing(tmp_path: Path):
    decision, calls, spent = _release(tmp_path, ("architecture_governance.nyx records X",))

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
    _decision, _calls, spent = _release(tmp_path, ("problem",))
    assert spent is False


# --------------------------------------------------------------------------
# The observation itself
# --------------------------------------------------------------------------


def test_the_real_repository_reports_intact_governance_integrity():
    """The benign control for the observer: it must not flag a healthy tree."""
    assert observe_governance_integrity(ROOT / ".nornyx/contracts") == ()


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
        problems = observe_governance_integrity(ROOT / ".nornyx/contracts")
    finally:
        target.write_bytes(original)

    assert problems, f"{label}: the tamper was not observed"
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
