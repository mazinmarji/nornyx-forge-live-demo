"""The strict governance path must fail closed legibly, not crash.

When the Nornyx authorization path cannot be established and the deterministic
fallback is refused, nothing may execute — and the refusal has to be reported as
a governed decision rather than an unhandled traceback.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from signing import LEDGER_ESTABLISHED  # noqa: E402

from nornyx_forge.governed_subject import (
    INTEGRITY_INTACT,
    GovernanceIntegrityState,
    RuntimeSubject,
)
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
#: The fixture subject's identity. Named TEST_REVISION for continuity with
#: the callers that build requests from it; it is a content digest now,
#: because a git revision no longer decides anything.
TEST_REVISION = "sha256:" + "f" * 64


#: The subject these fixtures authorize against.
TEST_SUBJECT = RuntimeSubject(
    scope_id="forge.test-fixture.v1",
    scope_definition_digest="sha256:" + "c" * 64,
    runtime_authority_config_digest="sha256:" + "d" * 64,
    governed_revision_digest="sha256:" + "e" * 64,
    governed_subject_digest="sha256:" + "f" * 64,
    subject_verified=True,
)


def _permissive_boundary(
    root: Path,
    as_of: str | None = None,
    *,
    runtime_context: RuntimeContext | None = None,
    runtime_subject: RuntimeSubject | None = None,
    action_trust: object | None = None,
    governance_integrity: object | None = None,
) -> NornyxActionBoundary:
    """A boundary whose authorizer allows everything, to isolate our control.

    Determinism arrives through an explicit ``RuntimeContext.for_test``. The
    ``as_of`` shorthand here is a *test helper* convenience that builds one; the
    production constructor has no such parameter and no environment route.
    """
    from signing import trust_store  # noqa: PLC0415

    from nornyx_forge.approval_trust import ACTION_TRUST_DOMAIN  # noqa: PLC0415

    # Provisioned deliberately, because these tests are about other controls and
    # need a boundary that can actually record a consumption. A boundary no
    # longer creates its own replay state; absence of a ledger is its own test,
    # in tests/test_approval_ledger.py.
    from nornyx_forge.nornyx_runtime import ApprovalLedger, approval_ledger_path  # noqa: PLC0415

    ApprovalLedger.provision(approval_ledger_path(root), established_at=LEDGER_ESTABLISHED)

    boundary = NornyxActionBoundary(
        root,
        allow_fallback=True,
        runtime_context=runtime_context
        or RuntimeContext.for_test(root, at=as_of, revision=TEST_REVISION),
        # A real trust store holding a real ephemeral key. Tests about refusal
        # supply a defective grant; they do not rely on trust being absent.
        # Labelled ACTION, because that is the authority a consequential
        # boundary exercises. The domain guard is total: an unlabelled store
        # cannot answer a domain-scoped question, so a bare `trust_store()` here
        # made every test resting on this helper refuse with
        # TRUST_DOMAIN_MISMATCH instead of reaching the clause it was written
        # for. One default, rather than a domain argument at each call site.
        action_trust_store=(
            action_trust
            if action_trust is not None
            else trust_store(domain=ACTION_TRUST_DOMAIN)
        ),
        # An established subject. Authority is content identity now, so a test
        # states one explicitly rather than letting the boundary discover it —
        # a boundary that could discover its own subject is the ambient
        # re-resolution the model removes.
        runtime_subject=runtime_subject or TEST_SUBJECT,
    )
    boundary.authorizer = _PermissiveAuthorizer()
    boundary.context = object()
    # Integrity is a prerequisite, not the property these tests are about. A
    # boundary handed no observation refuses -- correctly, since "nobody looked"
    # must not read as "sound" -- so a fixture that omitted this would exercise
    # the integrity gate while claiming to test approval semantics, and every
    # refusal below would pass for the wrong reason.
    boundary.governance_integrity = (
        governance_integrity
        if governance_integrity is not None
        else GovernanceIntegrityState(status=INTEGRITY_INTACT, verified_claims=8)
    )
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

    The grant is bound to this exact request and signed by a key the trust store
    vouches for. A loose "granted: true" is no longer sufficient, and neither is
    a correctly-shaped grant nobody signed.
    """
    from signing import signed_grant  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        canonical_action_request,
        runtime_as_of,
    )

    boundary = _permissive_boundary(tmp_path)
    request = canonical_action_request(
        mission_id="TEST-RELEASED",
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=ActionDescriptor(
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
        action_approval=signed_grant(
            request,
            generated_at=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=(now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    assert decision.effect == "ALLOW", decision.reason
    assert result == "ran"
    assert executed == ["ran"]
    assert decision.evidence["approval_authentication"]["signature_verified"] is True


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
    from nornyx_forge.governed_subject import RuntimeAuthorityConfig

    # The retired variable is set hostile to prove it no longer decides. The
    # deterministic backend is now selected by naming it, so a run cannot claim
    # Nornyx governance while executing the fallback.
    monkeypatch.setenv("FORGE_ALLOW_POLICY_FALLBACK", "true")
    result = run_demo_scenarios(
        tmp_path, config=RuntimeAuthorityConfig("deterministic_demo", "sequential")
    )
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


# --------------------------------------------------------------------------
# A-P2-2. A released effect must leave evidence, especially when it fails.
# --------------------------------------------------------------------------


def _released_grant(tmp_path, *, effect):
    """Drive one high-risk grant all the way to release, with `effect` as the act."""
    from signing import LEDGER_ESTABLISHED, signed_grant  # noqa: PLC0415

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
        mission_id="CASE-EVIDENCE", risk="high", subject_revision=TEST_REVISION,
        descriptor=descriptor, attempt=1,
    )
    grant = signed_grant(request, approval_id="ACT-EVIDENCE", role="operations_owner")
    boundary = _permissive_boundary(tmp_path, as_of="2026-08-03T00:00:00Z")
    return boundary.evaluate_and_execute(
        mission_id="CASE-EVIDENCE", risk="high", action=effect,
        action_approval=grant, action_descriptor=descriptor, attempt=1,
    )


def _evidence_files(tmp_path):
    directory = tmp_path / "evidence/runtime/nornyx"
    return sorted(p.name for p in directory.glob("*.json")) if directory.is_dir() else []


def test_an_effect_that_raises_still_leaves_evidence(tmp_path: Path):
    """The finding. The grant is spent either way; the record was not written.

    `consume` runs BEFORE the effect, deliberately, because at-most-once is the
    safe direction for something that may already have happened. But the
    exception propagated past the recorder and past both writes, so the one
    situation where an operator most needs to know what was attempted produced
    the least evidence of any path through this method: a ledger row, and
    nothing else.
    """
    def explodes() -> str:
        raise RuntimeError("the payment rail timed out")

    with pytest.raises(RuntimeError, match="payment rail"):
        _released_grant(tmp_path, effect=explodes)

    files = _evidence_files(tmp_path)
    assert files, (
        "a consequential effect was released, the grant is spent, and no "
        "evidence was written at all"
    )
    report = json.loads(
        next(p for p in (tmp_path / "evidence/runtime/nornyx").glob("*.report.json"))
        .read_text(encoding="utf-8")
    )
    release = report.get("effect_release")
    assert release, f"the report does not record the failed release: {sorted(report)}"
    assert release["released"] is True
    assert release["completed"] is False
    assert release["outcome"] == "unknown"
    assert "payment rail" in release["error"]


def test_the_failed_release_is_not_recorded_as_a_successful_invocation(tmp_path: Path):
    """`tool_invoked` is a SUCCESS terminal in the evidence vocabulary.

    Recording it for an effect that raised would make the stream say the tool
    completed. The failure belongs in the report, where it can be stated without
    inventing an event type the schema does not define -- an unvalidatable
    stream is not evidence.
    """
    def explodes() -> str:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        _released_grant(tmp_path, effect=explodes)

    events = json.loads(
        next(p for p in (tmp_path / "evidence/runtime/nornyx").glob("*.events.json"))
        .read_text(encoding="utf-8")
    )
    kinds = [
        event.get("event_type") or event.get("type")
        for event in (events if isinstance(events, list) else events.get("events", []))
    ]
    assert "tool_invoked" not in kinds, (
        f"the stream claims the tool completed after it raised: {kinds}"
    )


def test_a_successful_release_still_records_the_invocation(tmp_path: Path):
    """The control. Both artifacts, and no failure record on a clean run."""
    calls: list[str] = []
    decision, _result = _released_grant(
        tmp_path, effect=lambda: (calls.append("ran"), "done")[1]
    )

    assert calls == ["ran"], "the control did not release the effect"
    assert decision.effect == "ALLOW", decision.reason
    files = _evidence_files(tmp_path)
    assert any(name.endswith(".events.json") for name in files), files
    assert any(name.endswith(".report.json") for name in files), files

    report = json.loads(
        next(p for p in (tmp_path / "evidence/runtime/nornyx").glob("*.report.json"))
        .read_text(encoding="utf-8")
    )
    assert "effect_release" not in report, (
        "a clean run recorded a release failure, so the field does not "
        "distinguish the two states"
    )
