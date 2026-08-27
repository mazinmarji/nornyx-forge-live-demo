"""Every structural refusal in `verify_action_approval`, driven and measured.

R3. A declared proof guard must be a REAL, VERDICT-SENSITIVE production check.
A guard that never executes the production branch it names cannot be sensitive
to it, and a branch nothing executes is a control in name only.

MEASURED BEFORE THIS MODULE EXISTED. Coverage over the security modules put
`nornyx_runtime.py` at 85%, and the uncovered lines included most of this
function's structural clauses. So the check was made directly: the
human-approver clause was replaced with `if False:` -- deleting the control that
stops a NON-HUMAN approver releasing a high-risk effect -- and

    118 passed

across `tests/test_approval_authentication.py`,
`tests/test_governance_approval_verifier.py` and
`tests/test_production_security_context.py`. Nothing in the repository was
sensitive to it.

Each case below drives the real production entry point with one field spoiled
and requires the refusal that clause produces. Because each asserts the SPECIFIC
reason, removing the clause changes the outcome -- the approval is either
accepted or refused for a different reason -- so these are verdict-sensitive by
construction rather than by assertion.

THE POSITIVE CONTROL IS LOAD-BEARING. Without
`test_a_well_formed_approval_is_accepted`, every case here is satisfied by a
verifier that refuses everything, which would be a guard that proves nothing
while looking thorough.
"""

from __future__ import annotations

from typing import Any

import pytest
from signing import signed_grant, trust_store  # noqa: E402

from nornyx_forge.nornyx_runtime import (
    ActionDescriptor,
    canonical_action_request,
    verify_action_approval,
)

#: Inside the signed window used by `signed_grant`.
NOW = "2026-08-03T00:00:00Z"
DESCRIPTOR = ActionDescriptor(
    operation="issue refund",
    resource="customer:omar",
    destination="zone.external_customer",
    parameters={"amount": 5000, "currency": "USD"},
)
TEST_REVISION = "sha256:" + "0" * 64


def _request():
    return canonical_action_request(
        mission_id="CASE-R3",
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=DESCRIPTOR,
        attempt=1,
    )


def _grant(**overrides: Any):
    request = _request()
    approval = signed_grant(request, **overrides)
    return request, approval


def test_a_well_formed_approval_is_accepted() -> None:
    """THE CONTROL. Every refusal below is free without it."""
    request, approval = _grant()
    decision = verify_action_approval(
        approval, request, trust_store=trust_store(), as_of=NOW
    )
    assert decision.granted is True, (
        f"a correctly signed, well-formed grant was refused: {decision.reason!r}. "
        "Every refusal case in this module is satisfied by a verifier that "
        "refuses everything, so this failing makes them all meaningless."
    )


#: WHICH CLAUSE FIRES IS MEASURED, NOT ASSUMED -- and measuring it corrected me.
#:
#: I expected each of these to be caught by the structural clause that names it
#: (`approval does not carry an explicit granted decision`, `approval names no
#: human approver`, `approver role ... may not release`). Driven against the
#: real verifier, most are caught EARLIER: the signature covers those fields, so
#: spoiling one invalidates the grant before any structural clause is reached,
#: and `approver_type` has its own authenticated clause.
#:
#: That is defence in depth and the security property holds -- every one is
#: refused. But it means those structural clauses are SHADOWED for a signed
#: grant, and a claim that they are the operative check would be false. They can
#: only fire for an approval that is correctly signed and still structurally
#: invalid, which is why `approval_id` (outside the signed payload) is the one
#: that reaches its own clause.
#:
#: Recorded per case so a change in WHICH control catches these is visible,
#: rather than absorbed by a test that only asks whether something refused.
STRUCTURAL_CASES = [
    ("no approval at all", None, "no action approval was supplied"),
    ("granted is not True", {"granted": False}, "APPROVAL_NOT_AUTHENTICATED"),
    ("granted is truthy but not True", {"granted": 1},
     "APPROVAL_NOT_AUTHENTICATED"),
    ("no identifier", {"approval_id": ""}, "approval has no identifier"),
    ("identifier is whitespace", {"approval_id": "   "},
     "approval has no identifier"),
    ("no approver named", {"approver": ""}, "APPROVAL_NOT_AUTHENTICATED"),
    ("approver is not human", {"approver_type": "service"},
     "APPROVAL_PRODUCER_NOT_HUMAN"),
    ("approver type absent", {"approver_type": ""},
     "APPROVAL_PRODUCER_NOT_HUMAN"),
    ("role may not release", {"approver_role": "observer"},
     "APPROVAL_NOT_AUTHENTICATED"),
]


@pytest.mark.parametrize(
    ("label", "spoil", "expected"), STRUCTURAL_CASES,
    ids=[case[0] for case in STRUCTURAL_CASES],
)
def test_a_structurally_invalid_approval_is_refused(
    label: str, spoil: dict | None, expected: str
) -> None:
    """One spoiled field per case, through the real production entry point.

    `verify_action_approval` is documented as THE ONLY entry point a
    consequential boundary may use, precisely so the clauses cannot stop being
    composed at a call site. Each case is driven through it rather than by
    reaching past it into a helper.

    THE PROPERTY is `granted is False`. The reason is asserted too, because a
    refusal arriving from a DIFFERENT control than last time is a change worth
    seeing -- it is how a clause becomes shadowed without anyone noticing.
    """
    if spoil is None:
        request = _request()
        approval: Any = None
    else:
        request, approval = _grant(**spoil)

    decision = verify_action_approval(
        approval, request, trust_store=trust_store(), as_of=NOW
    )
    assert decision.granted is False, (
        f"{label}: a structurally invalid approval was GRANTED. "
        f"reason={decision.reason!r}"
    )
    assert expected in decision.reason, (
        f"{label}: refused as {decision.reason[:90]!r}, but the control that "
        f"caught it was recorded as {expected!r}. Either a clause changed or "
        "one control is now shadowing another."
    )


def test_a_non_human_approver_cannot_release_a_high_risk_effect() -> None:
    """Named separately because it is the one that was measured unguarded.

    Disabling this clause left 118 tests passing. It is the difference between
    "a human approved this" and "something approved this", which is the whole
    subject of the approval path.
    """
    request, approval = _grant(approver_type="automation")
    decision = verify_action_approval(
        approval, request, trust_store=trust_store(), as_of=NOW
    )
    assert decision.granted is False
    assert "APPROVAL_PRODUCER_NOT_HUMAN" in decision.reason, decision.reason
