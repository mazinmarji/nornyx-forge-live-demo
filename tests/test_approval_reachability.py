"""A control the shipped application cannot reach is not a control.

The approval apparatus is complete and correct: signature verification, trust
domains, role vocabulary, request binding, temporal window, single-use ledger.
A review then asked the only question that matters about it -- can the running
product ever USE it? -- and the answer was no.

    src/demo_app/agentic.py:393    evaluate_and_execute(mission_id, risk,
                                   action, action_descriptor, attempt)
    run_case(...)                  no parameter for a grant
    CaseInput                      no field for a grant

So every high-risk outcome is HUMAN_APPROVAL_REQUIRED whether or not a valid
signed approval exists, and every green result about approval semantics comes
from the test harness only. It fails CLOSED, which is why this is not a
release-of-effect defect -- but it means the whole authority chain sits on a
path the product never takes.

The runtime emits `evidence/runtime/pending/<attempt>.request.json` telling an
operator to sign that exact digest with `scripts/issue_action_approval.py`.
That instruction terminated in nothing: the signed artifact had no return path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from human_authority import (  # noqa: E402
    APPROVAL_NAMED_DIRECTLY,
    LOCK_ABSENT,
    RefusalNotFromAbsentApproval,
    assert_absent_human_authority,
    human_approval_granted,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))



#: Kept as the published name; the membership test now lives in
#: tests/human_authority.py because set membership alone was too weak. A
#: review measured two trees with identical contracts and identical (absent)
#: approval state reporting different codes purely because one had a lock
#: file -- so "RUNTIME_LOCK_MISSING is in the set" is satisfied by someone
#: deleting the lock, which says nothing about human authority.
HUMAN_AUTHORITY_ABSENT = APPROVAL_NAMED_DIRECTLY | {LOCK_ABSENT}

def _accepts_a_grant(function) -> bool:
    import inspect  # noqa: PLC0415

    return "action_approval" in inspect.signature(function).parameters


def test_the_shipped_case_entry_can_receive_an_approval():
    """The reachability property, stated as the narrowest thing that matters.

    Not "the HTTP body carries a grant" -- that is a product decision with its
    own risks. This asks whether the consequential entry point the application
    calls has any route at all by which a genuine human approval can arrive.
    """
    from demo_app.agentic import run_case  # noqa: PLC0415

    assert _accepts_a_grant(run_case), (
        "run_case has no parameter through which a signed approval can reach "
        "the action boundary, so the entire approval apparatus is unreachable "
        "from the shipped application and every high-risk outcome is "
        "HUMAN_APPROVAL_REQUIRED regardless of what a human decided"
    )


def test_the_flow_passes_the_grant_to_the_boundary():
    """FG32. Possession must travel. A parameter that is accepted and dropped is worse
    than none, because it looks like a route."""
    import ast  # noqa: PLC0415

    source = (ROOT / "src/demo_app/agentic.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    call = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "evaluate_and_execute"
    )
    supplied = {kw.arg for kw in call.keywords}
    assert "action_approval" in supplied, (
        "the flow calls evaluate_and_execute without action_approval, so a "
        f"grant cannot reach the boundary. supplied: {sorted(supplied)}"
    )


# --------------------------------------------------------------------------
# Both directions, executed. A route that cannot release is not reachability,
# and a route that releases twice is not single use.
# --------------------------------------------------------------------------


def _high_risk_case() -> dict:
    return {
        "id": "CASE-R6",
        "customer": "Omar",
        "summary": "Issue a high-value external refund",
        "risk": "high",
        "requested_action": "issue refund",
    }


def test_without_an_approval_the_high_risk_effect_is_suppressed(tmp_path: Path):
    """Fail-closed, unchanged. Wiring a route must not make approval optional."""
    from demo_app.agentic import demonstration_authority, run_case  # noqa: PLC0415

    out = run_case(_high_risk_case(), root=ROOT, config=demonstration_authority())
    decision = out.get("action_decision") or out.get("decision") or {}
    effect = decision.get("effect") if isinstance(decision, dict) else None
    assert effect != "ALLOW", (
        f"a high-risk effect was released with no approval presented: {decision}"
    )
    assert out.get("execution_result") in (None, "", "prevented") or effect == "DENY", (
        f"the effect appears to have run without an approval: {out.get('execution_result')!r}"
    )


def test_the_grant_route_stops_where_human_authority_begins(tmp_path: Path):
    """MEASURED, and the answer bounds what R6 may claim.

    Wiring the parameter was necessary and not sufficient. On the SHIPPED
    demonstration path the deterministic fallback refuses every high-risk
    effect categorically, before any approval is consulted, so a presented
    grant changes nothing:

        effect DENY, code HUMAN_APPROVAL_REQUIRED
        "Autonomous demonstration mode cannot grant human production approval."

    On the GOVERNED path the authorizer cannot load at all:

        NornyxRuntimeUnavailable: AuthorizerLoadError: CONTRACT_INVALID:
        AN_APPROVAL_RECORD_MISSING

    So end-to-end release cannot be demonstrated in this repository, and
    manufacturing the approval that would demonstrate it is forbidden. This
    test pins the boundary itself: both paths refuse, for their own reasons,
    and neither refusal depends on the grant being absent.
    """
    from demo_app.agentic import (  # noqa: PLC0415
        RuntimeAuthorityConfig,
        demonstration_authority,
        run_case,
    )
    from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable  # noqa: PLC0415

    grant = {"approval": "granted", "producer": {"id": "unsigned:test"}}

    shipped = run_case(_high_risk_case(), root=ROOT,
                       config=demonstration_authority(), action_approval=grant)
    decision = shipped.get("action_decision") or shipped.get("decision") or {}
    assert decision.get("effect") == "DENY", decision
    assert decision.get("code") == "HUMAN_APPROVAL_REQUIRED", decision

    with pytest.raises(NornyxRuntimeUnavailable) as refusal:
        run_case(
            _high_risk_case(), root=ROOT, action_approval=grant,
            config=RuntimeAuthorityConfig(policy_backend="nornyx",
                                          execution_backend="sequential"),
        )
    # THE DIAGNOSTIC DEPENDS ON THE ENVIRONMENT; THE PROPERTY DOES NOT.
    # This asserted AN_APPROVAL_RECORD_MISSING alone and so passed only in a
    # tree that already holds `.nornyx/runtime/nornyx.agentic_network.lock`.
    # That path is gitignored and a reader cannot produce it: prepare_runtime
    # exits 2 without a human approval, and the only file it leaves behind is
    # `preparation-report.json` -- measured, not assumed. So on every clean
    # checkout the proximate refusal is RUNTIME_LOCK_MISSING.
    #
    # Widening this to a SET of codes was the first repair, and a second review
    # showed the set admits a lock that someone simply deleted. The depth is
    # not the property; the CAUSE is. The helper establishes it from the tree.
    assert_absent_human_authority(str(refusal.value), ROOT)

def test_an_unsigned_grant_is_refused(tmp_path: Path):
    """The route must not become a way in. An unauthenticated grant is refused."""
    from demo_app.agentic import demonstration_authority, run_case  # noqa: PLC0415

    out = run_case(
        _high_risk_case(), root=ROOT, config=demonstration_authority(),
        action_approval={"approval": "granted", "producer": {"id": "attacker"}},
    )
    decision = out.get("action_decision") or out.get("decision") or {}
    effect = decision.get("effect") if isinstance(decision, dict) else None
    assert effect != "ALLOW", (
        f"an unsigned, unauthenticated grant released a high-risk effect: {decision}"
    )


# --------------------------------------------------------------------------
# Controls for the cause check itself.
#
# The first repair of this property widened an assertion to a SET of codes and
# was accepted because the suite went green. A review then measured that the
# set admits a deleted lock. So the replacement gets hostile and positive
# controls of its own, in both directions, rather than a green suite.
# --------------------------------------------------------------------------


def _tree_with_approval(root: Path, **record) -> Path:
    where = root / ".nornyx/contracts/evidence"
    where.mkdir(parents=True, exist_ok=True)
    (where / "architecture_approval_record.json").write_bytes(
        (json.dumps(record, indent=2, sort_keys=True) + chr(10)).encode("utf-8")
    )
    return root


def test_a_refusal_naming_the_approval_is_accepted(tmp_path: Path):
    """The positive control at the deeper depth."""
    tree = _tree_with_approval(tmp_path, approval="not_granted",
                               production_approval="not_granted")
    assert assert_absent_human_authority(
        "AuthorizerLoadError: CONTRACT_INVALID: AN_APPROVAL_RECORD_MISSING",
        tree,
    ) == "AN_APPROVAL_RECORD_MISSING"


def test_a_missing_lock_is_accepted_only_with_no_granted_approval(tmp_path: Path):
    """The positive control at the shallower depth -- the clean-checkout state."""
    tree = _tree_with_approval(tmp_path, approval="not_granted",
                               production_approval="not_granted")
    assert assert_absent_human_authority(
        "RuntimeError: RUNTIME_LOCK_MISSING: ...lock does not exist", tree
    ) == LOCK_ABSENT


def test_a_missing_lock_is_refused_when_an_approval_stands(tmp_path: Path):
    """THE CONTROL THAT MAKES THE SET-MEMBERSHIP VERSION WRONG.

    A review measured two trees with identical contracts and identical absent
    approval state reporting different codes purely because one had a lock
    file. The mirror of that is this: a tree where a human approval EXISTS and
    the lock was deleted also reports RUNTIME_LOCK_MISSING, and the previous
    assertion accepted it as proof that human authority is absent.

    It is not. It is proof that a file is missing.
    """
    tree = _tree_with_approval(tmp_path, approval="granted",
                               production_approval="not_granted")
    with pytest.raises(RefusalNotFromAbsentApproval, match="GRANTED"):
        assert_absent_human_authority(
            "RuntimeError: RUNTIME_LOCK_MISSING: ...lock does not exist", tree
        )


def test_a_missing_lock_is_refused_when_the_lock_is_actually_present(tmp_path: Path):
    """Diagnostic and tree must agree, or the diagnostic is describing something else."""
    tree = _tree_with_approval(tmp_path, approval="not_granted",
                               production_approval="not_granted")
    lock = tree / ".nornyx/runtime/nornyx.agentic_network.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_bytes(b"{}")
    with pytest.raises(RefusalNotFromAbsentApproval, match="present on disk"):
        assert_absent_human_authority(
            "RuntimeError: RUNTIME_LOCK_MISSING: ...lock does not exist", tree
        )


@pytest.mark.parametrize("reason", [
    "ImportError: No module named 'nornyx'",
    "RuntimeError: CONTRACT_INVALID: SYNTAX_ERROR at line 4",
    "",
])
def test_a_refusal_for_any_other_reason_is_refused(reason: str, tmp_path: Path):
    """The hostile control: a broken install must not read as the honest state.

    This is the whole point of naming the cause. A generic unavailability would
    otherwise certify that the strict path fails closed for want of a human
    approval, when it actually fails closed for want of a dependency.
    """
    tree = _tree_with_approval(tmp_path, approval="not_granted",
                               production_approval="not_granted")
    with pytest.raises(RefusalNotFromAbsentApproval):
        assert_absent_human_authority(reason, tree)


@pytest.mark.parametrize(("record", "granted"), [
    ({"approval": "granted", "production_approval": "not_granted"}, True),
    ({"approval": "not_granted", "production_approval": "granted"}, True),
    ({"approval": "not_granted", "production_approval": "not_granted"}, False),
    ({}, False),
])
def test_the_approval_record_is_read_for_either_kind_of_grant(
    record: dict, granted: bool, tmp_path: Path
):
    assert human_approval_granted(_tree_with_approval(tmp_path, **record)) is granted


def test_an_unreadable_approval_record_is_not_authority(tmp_path: Path):
    """Absence of the record is absence of authority, never a grant.

    Reading a missing or corrupt record as `granted` would make the hostile
    control above pass on a tree that proves nothing.
    """
    assert human_approval_granted(tmp_path) is False
    where = tmp_path / ".nornyx/contracts/evidence"
    where.mkdir(parents=True, exist_ok=True)
    (where / "architecture_approval_record.json").write_bytes(b"{not json")
    assert human_approval_granted(tmp_path) is False


def test_this_repository_records_no_granted_human_approval():
    """The premise the two governed-path tests rest on, asserted rather than assumed.

    If this ever goes true, those tests stop measuring what they claim and must
    be revisited -- so it fails here rather than passing quietly there.
    """
    assert human_approval_granted(ROOT) is False
