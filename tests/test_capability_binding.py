"""The capability an approval is checked against must be the one being exercised.

`_official` derives the capability from the risk of the act, but it used to
validate the grant against whatever capability the caller put in the request.
So a caller could label a high-risk request `execute_low_risk_action`, obtain a
grant bound to that label, and every field would match — including the digest,
because the digest is computed over the same mislabelled request — while the
high-risk effect is what actually ran.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from nornyx_forge.nornyx_runtime import (
    RISK_LEVELS,
    ActionDescriptor,
    ActionRequest,
    canonical_attempt_id,
    canonical_request_id,
    exercised_capability,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutation_validity import check_python_mutation  # noqa: E402
from signing import GRANT_ISSUED, signed_grant  # noqa: E402
from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: E402

NOW = "2026-08-03T00:00:00Z"

#: The tree the production flow is imported from.
SRC = Path(__file__).resolve().parent.parent / "src"


def _request(capability: str) -> ActionRequest:
    return ActionRequest(
        request_id=canonical_request_id("CASE-MISLABELLED"),
        attempt_id=canonical_attempt_id("CASE-MISLABELLED", 1),
        mission_id="CASE-MISLABELLED",
        subject_revision=TEST_REVISION,
        capability=capability,
        action=ActionDescriptor(
            operation="issue refund",
            resource="customer:omar",
            destination="zone.external_customer",
            parameters={"amount": 5000, "currency": "USD"},
        ),
    )


def _grant(request, approval_id: str = "ACT-A") -> dict[str, object]:
    """A complete, correctly signed grant for the given request."""
    return signed_grant(request, approval_id=approval_id)
def test_a_low_risk_grant_cannot_release_a_high_risk_effect(tmp_path: Path) -> None:
    """The reported escalation, driven end to end.

    Nothing here is malformed: the grant matches its request perfectly. The only
    disagreement is between the capability the caller declared and the one a
    high-risk act actually exercises, and that alone must withhold the effect.
    """
    request = _request("execute_low_risk_action")
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)

    decision, result = boundary.evaluate_and_execute(
        mission_id=request.mission_id,
        risk="high",
        action=lambda: executed.append("ran") or "ran",
        action_approval=_grant(request),
        action_request=request,
    )

    assert decision.effect == "DENY", decision.evidence.get("action_binding")
    assert result is None
    assert executed == [], "a mislabelled request released the high-risk effect"
    assert "execute_high_risk_effect" in decision.evidence["action_binding"]


def test_the_matching_capability_still_releases(tmp_path: Path) -> None:
    """The check must not break the legitimate case it guards."""
    request = _request("execute_high_risk_effect")
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)

    decision, _ = boundary.evaluate_and_execute(
        mission_id=request.mission_id,
        risk="high",
        action=lambda: executed.append("ran") or "ran",
        action_approval=_grant(request),
        action_request=request,
    )

    assert decision.effect == "ALLOW", decision.evidence.get("action_binding")
    assert executed == ["ran"]


def test_the_mismatch_is_refused_before_the_approval_is_spent(tmp_path: Path) -> None:
    """A refusal on this path must not consume the grant.

    Consumption is deliberately at-most-once, so spending a grant on a request
    that was never evaluated would destroy a legitimate approval.
    """
    mislabelled = _request("execute_low_risk_action")
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    boundary.evaluate_and_execute(
        mission_id=mislabelled.mission_id,
        risk="high",
        action=lambda: "ran",
        action_approval=_grant(mislabelled),
        action_request=mislabelled,
    )

    claimed, reason = boundary.approval_ledger.consume(
        "ACT-MISLABELLED", mislabelled.digest, at=NOW
    , grant_issued_at=GRANT_ISSUED)
    assert claimed is True, f"the refused request spent the approval: {reason}"


# What the evidence stream RECORDS was exercised, not only what was requested.
#
# Everything above is about the REQUEST: a caller may not label a high-risk act
# `execute_low_risk_action` and have a grant validated against the label. The
# boundary refuses that now. Nothing constrained the RECORD written afterwards,
# and the demonstration flow named the capability from the branch it was in:
#
#     if decision.allowed:   capability="execute_low_risk_action"
#     else:                  capability="execute_high_risk_action"
#
# Measured on `CustomerCaseFlow.run_sequential`, with a real signed grant
# releasing a high-value external refund, before the repair:
#
#     act risk               high
#     decision               ALLOW / ALLOWED, effect released
#     recorded capability    execute_low_risk_action
#
# `execute_low_risk_action` is declared `risk: low`, with no required gates and no
# required approvals. The single record of a released high-risk effect said the
# capability in play was the one that needs no human -- at the moment a human
# approval was spent. The same substitution as the request-side defect this module
# was written for, one layer out and in the direction nobody was watching.
#
# The other branch was wrong too, and that half ships on the default path:
# `execute_high_risk_action` is an ACTION CLASS. No capability of that name exists
# anywhere in this system; the declared one is `execute_high_risk_effect`. So every
# high-risk case in the shipped demonstration wrote a capability name the
# authorizer has never heard of.

DRIVER = Path(__file__).resolve().parent / "capability_record_driver.py"


def _drive(src: Path, risk: str, approve: str) -> dict:
    """Run the production flow under `src` and return what it recorded.

    A subprocess, so the pristine module and the reverted one are exercised by
    byte-identical driver code and an import of one cannot satisfy the other.
    """
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(DRIVER), str(src), risk, approve],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONPATH": str(src)},
    )
    assert completed.returncode == 0, (
        "the flow did not run to completion, so nothing was measured: "
        + completed.stderr[-600:]
    )
    observed = json.loads(completed.stdout.strip().splitlines()[-1])
    # WHICH TREE ANSWERED. The driver refuses to run against a module outside
    # the tree it was given, and this repeats the check here so a result can
    # never be attributed to a tree that did not produce it. `ruff --fix` once
    # sorted the driver's imports, `demo_app` fell below a module that inserts
    # the real `src` at `sys.path[0]`, and the revert control below started
    # measuring the pristine repository under a mutant's name.
    assert Path(observed["module"]).is_relative_to(Path(src).resolve()), (
        "asked for " + str(src) + " and got " + observed["module"]
    )
    return observed


@pytest.mark.parametrize(
    ("risk", "approve", "expect_status"),
    [
        # THE HOSTILE SPECIMEN: a high-risk effect genuinely released.
        ("high", "grant", "executed"),
        # The shipped default: the same act, withheld for want of an approval.
        ("high", "none", "prevented"),
        # The documented two-tier mapping, recorded the same way.
        ("medium", "none", "executed"),
        ("low", "none", "executed"),
    ],
    ids=["high released", "high withheld", "medium", "low"],
)
def test_the_recorded_capability_is_the_one_the_act_exercised(
    risk: str, approve: str, expect_status: str,
) -> None:
    """The record names the capability the RISK exercises, in both branches.

    Both directions on purpose. Reading the released case alone would leave the
    withheld branch free to keep its invented name, and reading the withheld
    case alone is what let a released high-risk effect be filed under the
    no-approval capability.
    """
    observed = _drive(SRC, risk, approve)
    assert observed["action_status"] == expect_status, observed
    recorded = {entry["capability"] for entry in observed["capabilities"]}
    assert recorded == {exercised_capability(risk)}, (
        "a " + risk + "-risk act whose effect was " + observed["action_status"]
        + " was recorded against " + repr(sorted(recorded)) + ", and the "
        "capability such an act exercises is " + repr(exercised_capability(risk))
    )


def test_no_recorded_capability_is_a_name_the_authorizer_never_issues() -> None:
    """Whatever is recorded must be a capability, not an action class.

    Stated over the derivation's whole range rather than against the two names
    spelled out above, so inventing a THIRD name is caught by the same guard.
    `execute_high_risk_action` passed every other check in this repository for
    exactly one reason: nothing ever asked whether it was a capability.
    """
    declared = {exercised_capability(level) for level in RISK_LEVELS}
    for risk, approve in (("high", "grant"), ("high", "none"), ("low", "none")):
        observed = _drive(SRC, risk, approve)
        for entry in observed["capabilities"]:
            assert entry["capability"] in declared, (
                entry["event"] + " recorded " + repr(entry["capability"])
                + ", which is not a capability this system issues. The declared "
                "set is " + repr(sorted(declared))
            )


#: The repair, and the decision-derived code it replaced.
DECISION_DERIVED = (
    "                capability=exercised,",
    '                capability="execute_low_risk_action",',
)


def test_reverting_the_derivation_restores_the_mislabelled_record(
    tmp_path: Path,
) -> None:
    """Removing the fix must bring the specimen back, for its own reason.

    Only the ALLOW branch is reverted -- the anchor appears twice and exactly
    the first occurrence is replaced. That is the branch the hostile specimen
    runs through, so reverting it alone shows the specimen is decided by this
    derivation and not by something else that moved with it.
    """
    destination = tmp_path / "src"
    shutil.copytree(SRC, destination,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    module = destination / "demo_app" / "agentic.py"
    before = module.read_text(encoding="utf-8")
    anchor, replacement = DECISION_DERIVED
    after = before.replace(anchor, replacement, 1)
    check_python_mutation("src/demo_app/agentic.py", before, after, anchor, 2)
    module.write_text(after, encoding="utf-8", newline="")

    reverted = _drive(destination, "high", "grant")
    assert reverted["action_status"] == "executed", (
        "the reverted run did not release the effect, so it is not the "
        "specimen: " + repr(reverted)
    )
    recorded = {entry["capability"] for entry in reverted["capabilities"]}
    assert recorded == {"execute_low_risk_action"}, (
        "reverting the derivation did not restore the mislabelled record, so "
        "the derivation is not what the guard above measures: " + repr(recorded)
    )
    # Stated against the derivation as well, so a future edit that made
    # `exercised_capability('high')` return the low-risk name would break
    # this control instead of quietly making it agree with the defect.
    assert recorded != {exercised_capability("high")}, (
        "the reverted module records exactly what the specimen requires, so"
        " the specimen cannot fail: " + repr(recorded)
    )
    # And the same driver on the repaired module does not.
    assert {entry["capability"] for entry in _drive(SRC, "high", "grant")["capabilities"]} == {
        "execute_high_risk_effect"
    }
