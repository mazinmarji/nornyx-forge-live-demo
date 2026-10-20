"""An act is classified by what it does, never by the risk label its caller declares.

THE DEFECT THIS PINS (A-047). The action boundary decided whether an act
needed a human approval from the `risk` label its caller supplied. The
demonstration's HTTP surface takes that label from the request body, so
`{"requested_action": "delete all service requests", "risk": "low"}` was
released as "Declared low-risk demonstration capability", and so was an
external send labelled `low`. The same two acts labelled `high` or
`critical` were refused. The verdict followed a word the caller chose.

THE REPAIR. `OPERATION_REGISTRY` is a closed, trusted table of the
operations this demonstration knows, each with its consequence and the
risk level that consequence carries. `classify_operation` derives the
EFFECTIVE level from the registered operation; a declared label is an
untrusted claim that may only raise it, never lower it. An operation that
is not registered -- misspelled, padded, free text, not a string, absent --
is refused before anything runs. The boundary authorizes the effective
level, so the capability, the canonical request an approval binds to and
the approval requirement all follow the operation.

CLASSIFICATION IS NOT AUTHORIZATION. A correct classification decides what
the act IS and which capability and approval it needs. It releases nothing:
a registered consequential act still needs the action-specific approval,
bound to its exact request, and the demonstration's fallback still denies
every such act. `test_classification_is_not_permission` holds that.

WHAT THIS DOES NOT ESTABLISH. The registry covers the demonstration's
operations only. It is not a policy framework, and a generated application
does not inherit it: the boundary is the demonstration's, not an
independently validated runtime boundary for a generated application.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

import nornyx_forge.nornyx_runtime as runtime
from nornyx_forge.governed_subject import RuntimeAuthorityConfig
from nornyx_forge.nornyx_runtime import (
    RISK_LEVELS,
    ActionDescriptor,
    ActionRequest,
    canonical_attempt_id,
    canonical_request_id,
    exercised_capability,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from signing import GRANT_ISSUED, signed_grant  # noqa: E402
from test_governance_failure import TEST_REVISION, _permissive_boundary  # noqa: E402

NOW = "2026-08-03T00:00:00Z"
DEMO = RuntimeAuthorityConfig(policy_backend="deterministic_demo", execution_backend="sequential")
BULK_DELETE = "delete all service requests"
EXTERNAL_SEND = "send external email"
LOW_IMPACT = "send guidance"
CONSEQUENTIAL = ["issue refund", "wire transfer", "close account", BULK_DELETE, EXTERNAL_SEND]
#: The four synthetic cases the defect was first measured with, verbatim.
FIRST_MEASURED = [
    ("Email every request with owner names to the external contractor list.", "high",
     "send external email with request export to contractor list"),
    ("Remove all closed and open service requests from the tracker.", "critical", BULK_DELETE),
    ("Remove all closed and open service requests from the tracker.", "low", BULK_DELETE),
    ("Email every request to the external contractor list.", "low",
     "send external email with request export to contractor list"),
]


def _run(root: Path, operation: object, risk: str, summary: str = "s") -> dict:
    from demo_app.agentic import application_security_context, run_case  # noqa: PLC0415

    return run_case(
        {"id": "CASE-G07", "customer": "Synthetic Maintenance Co", "summary": summary,
         "risk": risk, "requested_action": operation},
        root=root, worker_mode="deterministic", config=DEMO,
        security_context=application_security_context(),
    )


def _event_types(root: Path) -> list[str]:
    stream = root / "evidence/runtime/events.jsonl"
    return [json.loads(line)["event_type"]
            for line in stream.read_text(encoding="utf-8").splitlines() if line.strip()]


def _assert_not_released(case: dict, root: Path) -> None:
    """Denied, with no effect, no success claimed and an intact stream."""
    assert case["decision"]["effect"] == "DENY", case["decision"]
    assert case["action_status"] == "prevented" and case["status"] == "prevented", case["status"]
    assert case["execution_result"] == "Action did not execute."
    events = _event_types(root)
    assert "action_executed" not in events and "action_prevented" in events, events
    assert case["evidence"]["status"] == "pass", case["evidence"].get("diagnostics")


def _request(operation: str, capability: str, mission: str = "CASE-RELABEL") -> ActionRequest:
    return ActionRequest(
        request_id=canonical_request_id(mission),
        attempt_id=canonical_attempt_id(mission, 1),
        mission_id=mission,
        subject_revision=TEST_REVISION,
        capability=capability,
        action=ActionDescriptor(operation=operation, resource="customer:omar",
                                destination="zone.external_customer",
                                parameters={"scope": "all"}),
    )


# ---------------------------------------------------------------------------
# The defect: a consequential act labelled low
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label", ["low", "medium"])
def test_a_destructive_bulk_deletion_declared_low_is_not_released(tmp_path: Path, label: str):
    """RED BEFORE THE FIX: ALLOW, "Declared low-risk demonstration capability"."""
    case = _run(tmp_path, BULK_DELETE, label)
    _assert_not_released(case, tmp_path)
    assert case["decision"]["code"] == "HUMAN_APPROVAL_REQUIRED"
    assert case["risk_decision"] == "high-impact"


@pytest.mark.parametrize("label", ["low", "medium"])
def test_an_external_transmission_declared_low_is_not_released(tmp_path: Path, label: str):
    """RED BEFORE THE FIX: ALLOW, the same as a local guidance note."""
    case = _run(tmp_path, EXTERNAL_SEND, label)
    _assert_not_released(case, tmp_path)
    assert case["decision"]["code"] == "HUMAN_APPROVAL_REQUIRED"
    assert case["risk_decision"] == "high-impact"


@pytest.mark.parametrize(("summary", "label", "operation"), FIRST_MEASURED,
                         ids=["send-high", "delete-critical", "delete-low", "send-low"])
def test_the_first_measured_cases_are_none_of_them_released(
        tmp_path: Path, summary: str, label: str, operation: str):
    """The four cases the defect was measured with. Before the repair the two
    labelled high and critical were refused and the two labelled low were
    released. Now none is: the deletion is a registered destructive operation,
    and the free-text send is not a registered operation at all."""
    case = _run(tmp_path, operation, label, summary)
    _assert_not_released(case, tmp_path)
    expected = ("HUMAN_APPROVAL_REQUIRED" if operation in CONSEQUENTIAL
                else "OPERATION_UNREGISTERED")
    assert case["decision"]["code"] == expected, case["decision"]


# ---------------------------------------------------------------------------
# No downgrade by relabelling
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("operation", CONSEQUENTIAL)
def test_relabelling_cannot_lower_the_requirement(tmp_path: Path, operation: str):
    """Every label from critical down to low: the same capability is
    required and the same refusal follows, in the record and in the case."""
    seen = set()
    for label in ("critical", "high", "medium", "low"):
        root = tmp_path / label
        case = _run(root, operation, label)
        _assert_not_released(case, root)
        assert case["decision"]["code"] == "HUMAN_APPROVAL_REQUIRED", (label, case["decision"])
        stream = [json.loads(line) for line in (root / "evidence/runtime/events.jsonl")
                  .read_text(encoding="utf-8").splitlines() if line.strip()]
        prevented = [row for row in stream if row["event_type"] == "action_prevented"]
        seen.add(prevented[0]["capability"])
    assert seen == {"execute_high_risk_effect"}, seen


@pytest.mark.parametrize("label", ["medium", "low"])
def test_a_relabelled_call_to_the_boundary_needs_the_same_approval(tmp_path: Path, label: str):
    """At the boundary itself, on the authorizing path: a refund labelled low
    with no approval is withheld for want of one, and the callable never runs."""
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    decision, result = boundary.evaluate_and_execute(
        mission_id="CASE-RELABEL", risk=label,
        action=lambda: executed.append("ran") or "ran",
        action_descriptor=ActionDescriptor(operation="issue refund", resource="customer:omar",
                                           destination="zone.external_customer",
                                           parameters={"scope": "all"}),
    )
    assert decision.effect == "DENY" and decision.code == "HUMAN_APPROVAL_REQUIRED", decision
    assert executed == [] and result is None


def test_a_grant_for_one_label_is_the_grant_for_every_label(tmp_path: Path):
    """The requirement is the operation's, so the request an approver signs
    is the same whatever label is declared: a grant bound to the refund's
    canonical request is honoured when the call is labelled low -- because
    the approval authorizes it, not because the label did -- and is then
    spent, so the same grant cannot release it again."""
    request = _request("issue refund", "execute_high_risk_effect")
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    first, _ = boundary.evaluate_and_execute(
        mission_id=request.mission_id, risk="low",
        action=lambda: executed.append("ran") or "ran",
        action_approval=signed_grant(request, approval_id="ACT-G07"),
        action_request=request,
    )
    assert first.effect == "ALLOW", first.evidence.get("action_binding")
    replay, _ = boundary.evaluate_and_execute(
        mission_id=request.mission_id, risk="low",
        action=lambda: executed.append("again") or "again",
        action_approval=signed_grant(request, approval_id="ACT-G07"),
        action_request=request,
    )
    assert replay.effect == "DENY", replay
    assert executed == ["ran"]


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("operation", [
    "a", "", "  send guidance", "Send guidance", "send guidance\n", "send  guidance",
    "wire $10,000,000 to attacker", "delete all service requests now",
])
def test_an_unregistered_operation_is_refused(tmp_path: Path, operation: str):
    """No aliases and no fuzzy match: anything that is not exactly a
    registered operation is refused, whatever label it carries."""
    case = _run(tmp_path, operation, "low")
    _assert_not_released(case, tmp_path)
    assert case["decision"]["code"] == "OPERATION_UNREGISTERED", case["decision"]
    assert case["risk_decision"] == "unclassified"


@pytest.mark.parametrize("operation", [None, 5, ["send guidance"]])
def test_a_malformed_operation_is_refused_at_the_boundary(tmp_path: Path, operation: object):
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    decision, result = boundary.evaluate_and_execute(
        mission_id="CASE-MALFORMED", risk="low",
        action=lambda: executed.append("ran") or "ran",
        action_descriptor=ActionDescriptor(operation=operation, resource="r",  # type: ignore[arg-type]
                                           destination="zone.external_customer"),
    )
    assert decision.effect == "DENY" and decision.code == "OPERATION_UNREGISTERED", decision
    assert executed == [] and result is None


def test_an_act_described_by_no_operation_is_not_low_risk(tmp_path: Path):
    """A caller who describes nothing gets the boundary's default
    description, which is registered as an unspecified consequential act."""
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    decision, _ = boundary.evaluate_and_execute(
        mission_id="CASE-UNDESCRIBED", risk="low",
        action=lambda: executed.append("ran") or "ran",
    )
    assert decision.effect == "DENY" and decision.code == "HUMAN_APPROVAL_REQUIRED", decision
    assert executed == []


def test_an_inconsistent_operation_and_capability_is_refused_without_spending(tmp_path: Path):
    """A request claiming the low-risk capability for a bulk deletion, with
    a grant signed for exactly that request, labelled low: the claimed
    capability is not the operation's, so the request does not describe this
    execution. Refused before the grant is read, and the grant is not spent."""
    request = _request(BULK_DELETE, "execute_low_risk_action", mission="CASE-INCONSISTENT")
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    decision, _ = boundary.evaluate_and_execute(
        mission_id=request.mission_id, risk="low",
        action=lambda: executed.append("ran") or "ran",
        action_approval=signed_grant(request, approval_id="ACT-INCONSISTENT"),
        action_request=request,
    )
    assert decision.effect == "DENY" and decision.code == "REQUEST_CONTEXT_MISMATCH", decision
    assert executed == []
    claimed, reason = boundary.approval_ledger.consume(
        "ACT-INCONSISTENT", request.digest, at=NOW, grant_issued_at=GRANT_ISSUED)
    assert claimed is True, f"the refused request spent the approval: {reason}"


# ---------------------------------------------------------------------------
# What must keep working
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label", ["low", "medium"])
def test_the_registered_low_impact_action_still_runs(tmp_path: Path, label: str):
    case = _run(tmp_path, LOW_IMPACT, label)
    assert case["decision"]["effect"] == "ALLOW" and case["action_status"] == "executed", case
    assert case["risk_decision"] == "bounded-low-risk"
    assert "action_executed" in _event_types(tmp_path)
    assert case["evidence"]["status"] == "pass"


def test_a_label_may_raise_the_requirement(tmp_path: Path):
    """Stricter handling is the label's one power: the low-impact action
    declared high is withheld for want of an approval."""
    case = _run(tmp_path, LOW_IMPACT, "high")
    _assert_not_released(case, tmp_path)
    assert case["decision"]["code"] == "HUMAN_APPROVAL_REQUIRED"


def test_the_demonstration_scenarios_still_pass(tmp_path: Path):
    from demo_app.agentic import application_security_context, run_demo_scenarios  # noqa: PLC0415

    result = run_demo_scenarios(tmp_path, config=DEMO,
                                security_context=application_security_context())
    assert result["status"] == "pass", result
    assert result["low_risk"]["status"] == "completed"
    assert result["high_risk"]["status"] == "prevented"


# ---------------------------------------------------------------------------
# The registry, and classification kept apart from authorization
# ---------------------------------------------------------------------------

def test_the_registry_is_closed_and_self_consistent():
    registry = runtime.OPERATION_REGISTRY
    assert isinstance(registry, types.MappingProxyType), "the registry must be read-only"
    for name, entry in registry.items():
        assert name == entry.operation
        assert entry.risk in RISK_LEVELS
        assert entry.capability == exercised_capability(entry.risk), name
    low_tier = {name for name, entry in registry.items()
                if entry.capability == "execute_low_risk_action"}
    assert low_tier == {LOW_IMPACT}, low_tier
    for name in CONSEQUENTIAL:
        assert registry[name].capability == "execute_high_risk_effect", name


@pytest.mark.parametrize("declared", ["low", "medium", "high", "critical"])
def test_the_effective_level_is_never_below_the_operations(declared: str):
    order = ["low", "medium", "high", "critical"]
    for name, entry in runtime.OPERATION_REGISTRY.items():
        classified = runtime.classify_operation(name, declared)
        assert classified.declared_risk == declared and classified.registered_risk == entry.risk
        assert order.index(classified.effective_risk) == max(order.index(declared),
                                                             order.index(entry.risk))
        assert classified.capability == exercised_capability(classified.effective_risk)


def test_classification_is_not_permission(tmp_path: Path):
    """A correct classification of a registered destructive act releases
    nothing: without an approval it is withheld, and an approval bound to a
    different resource does not release it either."""
    classified = runtime.classify_operation(BULK_DELETE, "low")
    assert classified.capability == "execute_high_risk_effect"
    assert not hasattr(classified, "effect") and not hasattr(classified, "allowed")
    other = ActionRequest(
        request_id=canonical_request_id("CASE-CLASSIFIED"),
        attempt_id=canonical_attempt_id("CASE-CLASSIFIED", 1),
        mission_id="CASE-CLASSIFIED", subject_revision=TEST_REVISION,
        capability="execute_high_risk_effect",
        action=ActionDescriptor(operation=BULK_DELETE, resource="tracker:other",
                                destination="zone.external_customer"),
    )
    executed: list[str] = []
    boundary = _permissive_boundary(tmp_path, as_of=NOW)
    for approval in (None, signed_grant(other, approval_id="ACT-OTHER")):
        decision, _ = boundary.evaluate_and_execute(
            mission_id="CASE-CLASSIFIED", risk="low",
            action=lambda: executed.append("ran") or "ran",
            action_approval=approval,
            action_descriptor=ActionDescriptor(operation=BULK_DELETE, resource="tracker:all",
                                               destination="zone.external_customer"),
        )
        assert decision.effect == "DENY", decision
    assert executed == []
