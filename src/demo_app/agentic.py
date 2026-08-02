from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

from nornyx_forge.claude_worker import ClaudeCodeWorker
from nornyx_forge.evidence import EvidenceLedger
from nornyx_forge.nornyx_runtime import (
    ActionDescriptor,
    ActionRequest,
    NornyxActionBoundary,
    NornyxRuntimeUnavailable,
    runtime_revision,
)

# Re-exported so the interface layer can handle a governed refusal without
# importing the governance module directly.
__all__ = ["CustomerCaseFlow", "NornyxRuntimeUnavailable", "run_case", "run_demo_scenarios"]

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("CREWAI_TESTING", "true")

try:
    from crewai.flow.flow import Flow, listen, start

    CREWAI_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    CREWAI_AVAILABLE = False
    Flow = object  # type: ignore[assignment]

    def start(*_args: Any, **_kwargs: Any):
        return lambda fn: fn

    def listen(*_args: Any, **_kwargs: Any):
        return lambda fn: fn


STAGES = ("intake", "knowledge", "resolution", "risk", "execution", "audit")


class CustomerCaseFlow(Flow):  # type: ignore[misc]
    """A live CrewAI Flow with Nornyx-governed consequential execution.

    Reasoning stages can invoke local Claude Code workers. The final action is
    always evaluated through the Nornyx action boundary first; the callable is
    unreachable on a denial.
    """

    def __init__(
        self,
        case: dict[str, Any],
        *,
        root: Path,
        worker_mode: str = "deterministic",
        allow_policy_fallback: bool = True,
    ) -> None:
        try:
            super().__init__()
        except Exception:
            pass
        self.case = case
        self.root = root
        self.worker_mode = worker_mode
        self.mission_id = case.get("mission_id") or f"CASE-{uuid.uuid4().hex[:10]}"
        self.case["mission_id"] = self.mission_id
        self.ledger = EvidenceLedger(
            root / "evidence/runtime/events.jsonl",
            subject_revision=runtime_revision(root),
        )
        self.boundary = NornyxActionBoundary(root, allow_fallback=allow_policy_fallback)
        self.worker = ClaudeCodeWorker()
        self.execution_backend = "sequential"

    def _stage(self, name: str, summary: str) -> dict[str, Any]:
        self.case.setdefault("timeline", []).append(
            {"stage": name, "status": "complete", "summary": summary}
        )
        self.ledger.append(
            "stage_completed",
            mission_id=self.mission_id,
            actor=f"agent.{name}",
            stage=name,
            summary=summary,
        )
        return self.case

    @start()
    def intake(self) -> dict[str, Any]:
        return self._stage("intake", "Case normalized and assigned a mission identity.")

    @listen(intake)
    def knowledge(self, _previous: Any = None) -> dict[str, Any]:
        if self.worker_mode == "claude-code" and self.worker.available():
            result = self.worker.run(
                role="knowledge-agent",
                goal=(
                    "Analyze this customer case without editing files. Use only declared "
                    f"demo policy and return a bounded summary: {self.case['summary']}"
                ),
                workspace=self.root,
                allowed_tools=("Read", "Glob", "Grep"),
                max_turns=8,
                timeout_seconds=180,
            )
            summary = (
                result.output[:600]
                if result.success
                else "Claude worker failed; deterministic policy knowledge was used."
            )
        else:
            summary = "Matched the case to the demonstration support and remediation policy."
        return self._stage("knowledge", summary)

    @listen(knowledge)
    def resolution(self, _previous: Any = None) -> dict[str, Any]:
        requested = self.case.get("requested_action", "send guidance")
        self.case["proposal"] = f"Proposed action: {requested}."
        return self._stage("resolution", self.case["proposal"])

    @listen(resolution)
    def risk(self, _previous: Any = None) -> dict[str, Any]:
        risk = str(self.case.get("risk", "low")).lower()
        self.case["risk_decision"] = (
            "high-impact" if risk in {"high", "critical"} else "bounded-low-risk"
        )
        return self._stage("risk", f"Risk classified as {self.case['risk_decision']}.")

    @listen(risk)
    def execution(self, _previous: Any = None) -> dict[str, Any]:
        def execute_local_demo_action() -> str:
            return "Low-risk demonstration action executed in the local sandbox."

        # Describe the operation, not the callable. Two refunds share a closure
        # but are different consequential acts, so the approval must bind to the
        # requested operation, target and parameters rather than to the function.
        request = ActionRequest(
            request_id=f"REQ-{self.mission_id}",
            mission_id=self.mission_id,
            subject_revision=runtime_revision(self.root),
            capability="execute_high_risk_effect",
            action=ActionDescriptor(
                operation=str(self.case.get("requested_action", "unspecified")),
                resource=str(self.case.get("customer", "unknown")),
                destination="zone.external_customer",
                parameters={
                    "case_id": self.case.get("id"),
                    "risk": self.case.get("risk"),
                    "summary": self.case.get("summary"),
                },
            ),
        )
        self.case["action_request"] = {
            "request_id": request.request_id,
            "payload_digest": request.payload_digest,
            "request_digest": request.digest,
        }
        decision, result = self.boundary.evaluate_and_execute(
            mission_id=self.mission_id,
            risk=str(self.case.get("risk", "low")),
            action=execute_local_demo_action,
            action_request=request,
        )
        self.case["decision"] = {
            "effect": decision.effect,
            "code": decision.code,
            "reason": decision.reason,
            "source": decision.source,
        }
        self.case["nornyx_evidence"] = decision.evidence
        self.case["governance_mode"] = self.boundary.mode
        self.case["status"] = "completed" if decision.allowed else "prevented"
        if decision.allowed:
            self.case["execution_result"] = result or "Action completed."
            self.ledger.append(
                "action_executed",
                mission_id=self.mission_id,
                actor="agent.execution",
                capability="execute_low_risk_action",
                decision=decision.effect,
                reason=decision.reason,
                governance_source=decision.source,
            )
        else:
            self.case["execution_result"] = "Action did not execute."
            self.ledger.append(
                "action_prevented",
                mission_id=self.mission_id,
                actor="agent.execution",
                capability="execute_high_risk_action",
                decision=decision.effect,
                reason=decision.reason,
                code=decision.code,
                governance_source=decision.source,
            )
        return self._stage("execution", self.case["execution_result"])

    @listen(execution)
    def audit(self, _previous: Any = None) -> dict[str, Any]:
        report = self.ledger.validate(report_path=self.root / "evidence/runtime/report.json")
        self.case["evidence"] = report
        self.case["framework"] = (
            "CrewAI Flow kickoff"
            if self.execution_backend == "crewai"
            else "CrewAI Flow-compatible sequential execution"
        )
        return self._stage("audit", f"Evidence status: {report['status']}.")

    def run_sequential(self) -> dict[str, Any]:
        self.execution_backend = "sequential"
        self.intake()
        self.knowledge()
        self.resolution()
        self.risk()
        self.execution()
        return self.audit()


def run_case(
    case: dict[str, Any],
    *,
    root: Path,
    worker_mode: str | None = None,
    allow_policy_fallback: bool | None = None,
) -> dict[str, Any]:
    mode = worker_mode or os.getenv("FORGE_WORKER_MODE", "deterministic")
    fallback = (
        allow_policy_fallback
        if allow_policy_fallback is not None
        else os.getenv("FORGE_ALLOW_POLICY_FALLBACK", "true").lower() == "true"
    )
    flow = CustomerCaseFlow(case, root=root, worker_mode=mode, allow_policy_fallback=fallback)
    use_kickoff = (
        CREWAI_AVAILABLE
        and os.getenv("FORGE_USE_CREWAI_KICKOFF", "true").lower() == "true"
    )
    if use_kickoff:
        try:
            flow.execution_backend = "crewai"
            result = flow.kickoff()  # type: ignore[attr-defined]
            return result if isinstance(result, dict) else flow.case
        except Exception as exc:
            if os.getenv("FORGE_STRICT_CREWAI", "false").lower() == "true":
                raise
            flow.case.setdefault("limitations", []).append(
                f"CrewAI kickoff failed ({type(exc).__name__}); sequential fallback used."
            )
    return flow.run_sequential()


def run_demo_scenarios(
    root: Path,
    *,
    worker_mode: str | None = None,
    allow_policy_fallback: bool | None = None,
) -> dict[str, Any]:
    """Run both demonstration cases.

    ``worker_mode`` and ``allow_policy_fallback`` default to the same environment
    resolution as :func:`run_case`, so a deployment that disables the fallback
    fails closed here too instead of silently degrading.
    """
    worker_mode = worker_mode or os.getenv("FORGE_WORKER_MODE", "deterministic")
    if allow_policy_fallback is None:
        allow_policy_fallback = (
            os.getenv("FORGE_ALLOW_POLICY_FALLBACK", "true").lower() == "true"
        )
    runtime_dir = root / "evidence/runtime"
    for file in (runtime_dir / "events.jsonl", runtime_dir / "report.json"):
        if file.exists():
            file.unlink()
    low = run_case(
        {
            "id": "DEMO-LOW",
            "customer": "Amina",
            "summary": "Update delivery instructions",
            "risk": "low",
            "requested_action": "send guidance",
        },
        root=root,
        worker_mode=worker_mode,
        allow_policy_fallback=allow_policy_fallback,
    )
    high = run_case(
        {
            "id": "DEMO-HIGH",
            "customer": "Omar",
            "summary": "Issue a high-value external refund",
            "risk": "high",
            "requested_action": "issue refund",
        },
        root=root,
        worker_mode=worker_mode,
        allow_policy_fallback=allow_policy_fallback,
    )
    final_report = EvidenceLedger(
        runtime_dir / "events.jsonl",
        subject_revision=runtime_revision(root),
    ).validate(report_path=runtime_dir / "report.json")
    status = (
        "pass"
        if low["status"] == "completed"
        and high["status"] == "prevented"
        and final_report["status"] == "pass"
        else "fail"
    )
    return {
        "status": status,
        "low_risk": low,
        "high_risk": high,
        "evidence": final_report,
        "governance_modes": sorted(
            {str(low.get("governance_mode")), str(high.get("governance_mode"))}
        ),
    }
