"""The strict governance path must fail closed legibly, not crash.

When the Nornyx authorization path cannot be established and the deterministic
fallback is refused, nothing may execute — and the refusal has to be reported as
a governed decision rather than an unhandled traceback.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nornyx_forge.nornyx_runtime import NornyxActionBoundary, NornyxRuntimeUnavailable


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
