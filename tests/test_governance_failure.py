"""The strict governance path must fail closed legibly, not crash.

When the Nornyx authorization path cannot be established and the deterministic
fallback is refused, nothing may execute — and the refusal has to be reported as
a governed decision rather than an unhandled traceback.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from nornyx_forge.nornyx_runtime import (
    NornyxActionBoundary,
    NornyxRuntimeUnavailable,
    RuntimeContext,
)


def test_strict_boundary_refuses_instead_of_crashing(tmp_path: Path) -> None:
    """No contract in the tree + fallback refused => typed governed refusal."""
    with pytest.raises(NornyxRuntimeUnavailable) as raised:
        NornyxActionBoundary(tmp_path, allow_fallback=False)
    assert raised.value.detail


def test_fallback_boundary_denies_high_risk_without_executing(tmp_path: Path) -> None:
    """The fallback is allowed to run, but must still deny high-risk actions."""
    boundary = NornyxActionBoundary(tmp_path, allow_fallback=True)
    executed: list[str] = []

    def action() -> str:
        executed.append("ran")
        return "ran"

    decision, result = boundary.evaluate_and_execute(
        mission_id="TEST-HIGH", risk="high", action=action
    )
    assert decision.effect == "DENY"
    assert decision.code == "HUMAN_APPROVAL_REQUIRED"
    assert result is None
    assert executed == [], "a denied action must never reach its callable"


def test_fallback_boundary_allows_low_risk(tmp_path: Path) -> None:
    boundary = NornyxActionBoundary(tmp_path, allow_fallback=True)
    decision, result = boundary.evaluate_and_execute(
        mission_id="TEST-LOW", risk="low", action=lambda: "done"
    )
    assert decision.effect == "ALLOW"
    assert result == "done"


class _Effect:
    name = "ALLOW"


class _Code:
    value = "ALLOWED"


class _AllowDecision:
    """Stands in for a Nornyx decision that permits the action."""

    allowed = True
    effect = _Effect()
    code = _Code()
    reason = "ALLOWED"


class _PermissiveAuthorizer:
    subject_revision = "git:test"

    def evaluate(self, *_args: object, **_kwargs: object) -> _AllowDecision:
        return _AllowDecision()


class _Recorder:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.observations: list[str] = []

    def record_decision(self, *_args: object, **_kwargs: object) -> None:
        return None

    def record_observation(self, name: str, **_kwargs: object) -> None:
        self.observations.append(name)

    def stream(self) -> list[dict[str, object]]:
        return [{"event_type": name} for name in self.observations]

    def validate(self) -> dict[str, object]:
        return {"status": "pass", "observations": list(self.observations)}


#: A pinned revision for tests whose subject is the action binding, not the
#: revision gate. Without it every such test would deny UNVERIFIED first, since
#: a tmp_path has no git metadata to derive an actual revision from.
TEST_REVISION = "git:" + "0" * 40


def _permissive_boundary(
    root: Path,
    as_of: str | None = None,
    *,
    runtime_context: RuntimeContext | None = None,
) -> NornyxActionBoundary:
    """A boundary whose authorizer allows everything, to isolate our control.

    Determinism arrives through an explicit ``RuntimeContext.for_test``. The
    ``as_of`` shorthand here is a *test helper* convenience that builds one; the
    production constructor has no such parameter and no environment route.
    """
    boundary = NornyxActionBoundary(
        root,
        allow_fallback=True,
        runtime_context=runtime_context
        or RuntimeContext.for_test(root, at=as_of, revision=TEST_REVISION),
    )
    boundary.authorizer = _PermissiveAuthorizer()
    boundary.context = object()
    boundary._imports = {
        "CapabilityRequest": lambda *a, **k: None,
        "ZoneCrossingRequest": lambda *a, **k: None,
        "EvidenceRecorder": _Recorder,
    }
    return boundary


def test_high_risk_is_withheld_even_when_nornyx_allows(tmp_path: Path) -> None:
    """Contract approval must not release a high-risk action on its own.

    In the live run Nornyx blocked the trust-zone crossing first, so this control
    never engaged. That leaves it unproven exactly where it matters, so this
    drives the case where Nornyx permits and only our control stands between the
    approval and the effect.
    """
    boundary = _permissive_boundary(tmp_path)
    executed: list[str] = []
    decision, result = boundary.evaluate_and_execute(
        mission_id="TEST-WITHHELD",
        risk="high",
        action=lambda: executed.append("ran") or "ran",
    )
    assert decision.effect == "DENY"
    assert decision.code == "HUMAN_APPROVAL_REQUIRED"
    assert result is None
    assert executed == [], "a withheld action must never reach its callable"
    assert "action_withheld" in decision.evidence["observations"]
    assert "tool_invoked" not in decision.evidence["observations"]


def test_high_risk_runs_only_with_an_action_specific_approval(tmp_path: Path) -> None:
    """The separate action approval is what releases it, nothing else.

    The grant has to be bound to this exact request, so it is built from the
    same ActionRequest the boundary constructs. A loose "granted: true" is no
    longer sufficient, which is the point of the binding.
    """
    from nornyx_forge.nornyx_runtime import (
        ActionDescriptor,
        ActionRequest,
        runtime_as_of,
    )

    boundary = _permissive_boundary(tmp_path)
    request = ActionRequest(
        request_id="REQ-TEST-RELEASED",
        attempt_id="REQ-TEST-RELEASED#attempt-1",
        mission_id="TEST-RELEASED",
        subject_revision=TEST_REVISION,
        capability="execute_high_risk_effect",
        action=ActionDescriptor(
            operation="issue refund",
            resource="customer:test",
            destination="zone.external_customer",
            parameters={"amount": 100},
        ),
    )
    now = datetime.fromisoformat(runtime_as_of().replace("Z", "+00:00"))
    executed: list[str] = []
    decision, result = boundary.evaluate_and_execute(
        mission_id="TEST-RELEASED",
        risk="high",
        action=lambda: executed.append("ran") or "ran",
        action_request=request,
        action_approval={
            "granted": True,
            "approval_id": "ACT-TEST-0001",
            "approver": "human:operations_owner",
            "approver_type": "human",
            "approver_role": "operations_owner",
            "request_id": request.request_id,
            "subject_revision": request.subject_revision,
            "capability": request.capability,
            "destination": request.destination,
            "payload_digest": request.payload_digest,
            "request_digest": request.digest,
            "generated_at": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )
    assert decision.effect == "ALLOW", decision.reason
    assert result == "ran"
    assert executed == ["ran"]


def test_low_risk_needs_no_action_approval(tmp_path: Path) -> None:
    boundary = _permissive_boundary(tmp_path)
    decision, result = boundary.evaluate_and_execute(
        mission_id="TEST-LOW-OFFICIAL", risk="low", action=lambda: "done"
    )
    assert decision.effect == "ALLOW"
    assert result == "done"


def test_action_approval_is_not_satisfied_by_a_contract_approval() -> None:
    """Approving the network contract must not authorize an individual action.

    _action_approval_present is the gate that keeps the two separate, so it must
    reject anything that is not an explicit, human, granted action approval.
    """
    from nornyx_forge.nornyx_runtime import _action_approval_present

    assert _action_approval_present(None) is False
    assert _action_approval_present({}) is False
    # A contract-level approval record must not count as an action approval.
    assert _action_approval_present({"approver": "human:network_governance_owner"}) is False
    assert _action_approval_present({"granted": True}) is False
    assert _action_approval_present({"granted": "yes", "approver": "someone"}) is False
    assert _action_approval_present({"granted": True, "approver": "   "}) is False
    # A machine may not stand in for the human approver.
    assert (
        _action_approval_present(
            {"granted": True, "approver": "tool:forge", "approver_type": "tool"}
        )
        is False
    )
    assert (
        _action_approval_present(
            {"granted": True, "approver": "human:operations_owner"}
        )
        is True
    )


def test_fallback_denies_high_risk_even_with_an_action_approval(tmp_path: Path) -> None:
    """The fallback never releases a high-risk action, approval or not.

    An action approval is an additional control on top of Nornyx authorization,
    not a substitute for it. With no authorization path established, nothing may
    execute.
    """
    boundary = NornyxActionBoundary(tmp_path, allow_fallback=True)
    executed: list[str] = []
    decision, result = boundary.evaluate_and_execute(
        mission_id="TEST-HIGH-APPROVED",
        risk="high",
        action=lambda: executed.append("ran") or "ran",
        action_approval={"granted": True, "approver": "human:operations_owner"},
    )
    assert decision.effect == "DENY"
    assert decision.code == "HUMAN_APPROVAL_REQUIRED"
    assert result is None
    assert executed == []


def test_demo_scenarios_honour_the_fail_closed_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FORGE_ALLOW_POLICY_FALLBACK=false must fail closed for the demo run too.

    /api/cases honoured this via run_case; run_demo_scenarios used to hard-default
    the fallback to True and silently degrade.
    """
    from demo_app.agentic import run_demo_scenarios

    monkeypatch.setenv("FORGE_ALLOW_POLICY_FALLBACK", "false")
    with pytest.raises(NornyxRuntimeUnavailable):
        run_demo_scenarios(tmp_path)


def test_demo_scenarios_run_when_fallback_is_permitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from demo_app.agentic import run_demo_scenarios

    monkeypatch.setenv("FORGE_ALLOW_POLICY_FALLBACK", "true")
    result = run_demo_scenarios(tmp_path)
    assert result["low_risk"]["status"] == "completed"
    assert result["high_risk"]["status"] == "prevented"


def test_api_reports_governance_unavailable_as_503(monkeypatch: pytest.MonkeyPatch) -> None:
    """The API surfaces a governed refusal, not a 500 traceback."""
    pytest.importorskip("fastapi", reason="requires the demo extra")
    from fastapi.testclient import TestClient

    import demo_app.main as api

    def _unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NornyxRuntimeUnavailable("AN_APPROVAL_RECORD_MISSING")

    monkeypatch.setattr(api, "run_case", _unavailable)
    client = TestClient(api.app, raise_server_exceptions=False)
    response = client.post(
        "/api/cases",
        json={
            "customer": "Amina",
            "summary": "Update delivery instructions",
            "risk": "low",
            "requested_action": "send guidance",
        },
    )
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["error"] == "governance_unavailable"
    assert detail["human_review"] == "not_performed"
    assert detail["production_approval"] == "not_granted"


def test_health_declares_assurance_limits() -> None:
    pytest.importorskip("fastapi", reason="requires the demo extra")
    from fastapi.testclient import TestClient

    import demo_app.main as api

    payload = TestClient(api.app).get("/api/health").json()
    assert payload["assurance_mode"] == "autonomous_demonstration"
    assert payload["human_review"] == "not_performed"
    assert payload["production_approval"] == "not_granted"
