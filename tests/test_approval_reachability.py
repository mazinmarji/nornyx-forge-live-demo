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

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))


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
    """Possession must travel. A parameter that is accepted and dropped is worse
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
    assert "AN_APPROVAL_RECORD_MISSING" in str(refusal.value), (
        "the governed path failed for a reason other than the absent human "
        f"approval record: {refusal.value}"
    )

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
