from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

from nornyx_forge.claude_worker import ClaudeCodeWorker
from nornyx_forge.evidence import EvidenceLedger
from nornyx_forge.governed_subject import RuntimeAuthorityConfig
from nornyx_forge.nornyx_runtime import (
    EXTERNAL_TRUST_ZONE,
    ActionDescriptor,
    NornyxActionBoundary,
    NornyxRuntimeUnavailable,
    canonical_action_request,
)
from nornyx_forge.subject_bootstrap import RuntimeSecurityContext

# Re-exported so the interface layer can handle a governed refusal without
# importing the governance module directly.
__all__ = [
    "CustomerCaseFlow",
    "NornyxRuntimeUnavailable",
    "assurance_state",
    "run_case",
    "run_demo_scenarios",
]

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


def demonstration_authority() -> RuntimeAuthorityConfig:
    """The mode this demonstration runs in, named rather than defaulted.

    Exposed here so the HTTP surface never imports `nornyx_forge`: the
    architecture gate forbids that edge by path, because the API reaching the
    governance package directly is how the action boundary stops being the only
    route to a consequential effect.

    A deployment wanting governed authorization selects "nornyx" and receives a
    refusal when Nornyx cannot authorize — which is the honest outcome while no
    human approval exists.
    """
    return RuntimeAuthorityConfig(
        policy_backend="deterministic_demo",
        execution_backend="sequential",
    )


class ExecutionBackendUnavailable(RuntimeError):
    """The requested execution backend cannot actually run."""


STAGES = ("intake", "knowledge", "resolution", "risk", "execution", "audit")


def assurance_state() -> dict[str, Any]:
    """What this deployment can actually do, for the interface to report.

    Lives here rather than in the API module because the interface layer may not
    reach into the governance domain — and the answer is a governance fact, not
    a presentation one. A packaged image ships no approver trust store, so
    consequential authority is genuinely unavailable there, and saying so is the
    point: "no approval has been sought" and "no approval could be
    authenticated" are different states.

    Carries no store path and no key material.
    """
    from nornyx_forge.approval_trust import ApprovalTrustStore, TrustStoreUnavailable

    try:
        store = ApprovalTrustStore.load()
        loaded = store.available and bool(store.signers)
        state = "available" if loaded else "unavailable"
    except TrustStoreUnavailable:
        loaded, state = False, "unusable"
    return {
        "action_approval_authentication": state,
        "trusted_approvers_loaded": loaded,
        "consequential_authority": "available" if loaded else "unavailable",
    }


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
        subject_revision: str | None = None,
        security_context: RuntimeSecurityContext | None = None,
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
        self.case.setdefault("orchestration_status", "not_started")
        self.case.setdefault("action_status", "not_reached")
        # Which attempt at this mission's consequential action this run is. A
        # retry is a new attempt needing its own approval; it is not a second
        # release of the previous one.
        self.attempt = int(case.get("attempt", 1))
        self.case["attempt"] = self.attempt
        self.ledger = EvidenceLedger(
            root / "evidence/runtime/events.jsonl",
            # Evidence provenance, not authority. It used to come from a
            # contract read per flow; recomputing an identity here is the
            # ambient re-resolution the subject model removes. R1-D supplies it
            # from the injected RuntimeSubject; until then it is unset rather
            # than guessed.
            subject_revision=subject_revision,
        )
        # Injected, never discovered. A flow that established its own subject
        # would let a file changed between two cases silently re-aim the second
        # one, which is the ambient re-resolution this model removes.
        self.security_context = security_context
        # Trust anchors come from the established context, not from a fresh
        # environment read per boundary. The context resolved them once at
        # startup; handing them down is what makes that resolution binding.
        self.boundary = NornyxActionBoundary(
            root,
            allow_fallback=allow_policy_fallback,
            trust=security_context.trust if security_context is not None else None,
        )
        #: Whether the consequential stage has been entered on this flow. One
        #: way: never reset, so no recovery path can re-arm it.
        self._execution_entered = False
        # Set by the sequential driver only. A stage that runs without it was
        # driven by CrewAI's Flow machinery, so the observed backend is derived
        # from the path that actually executed rather than restated from the
        # configuration — a marker copied from config would make any test of it
        # tautological.
        self._sequential_driver = False
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

    def _record_observed_backend(self) -> None:
        """Record which driver actually ran this flow.

        Derived from the execution path, not restated from the configuration.
        A marker copied out of `RuntimeAuthorityConfig` would make any test of
        backend binding tautological — it would assert the config equals
        itself. `_sequential_driver` is set only by `run_sequential`, so a
        stage reaching here without it was driven by CrewAI's Flow machinery.
        """
        self.case["observed_execution_backend"] = (
            "sequential" if self._sequential_driver else "crewai_flow"
        )

    @start()
    def intake(self) -> dict[str, Any]:
        self._record_observed_backend()
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
        # One-way, per flow instance. The approval ledger is not the replay
        # mechanism here: a low-risk action consumes no approval, so nothing
        # downstream would stop the callable running twice. This guard is the
        # thing that does, and it refuses before the boundary is consulted, so
        # no evaluation, no callable and no consumption occur on a second entry.
        if self._execution_entered:
            self.case["action_status"] = self.case.get("action_status", "unknown")
            self.ledger.append(
                "execution_stage_replay_refused",
                mission_id=self.mission_id,
                actor="agent.execution",
                detail=(
                    "the consequential stage was entered twice on one flow; a "
                    "retry is an explicit new attempt"
                ),
            )
            self.case.setdefault("limitations", []).append(
                "EXECUTION_STAGE_REPLAY refused: the consequential stage may be "
                "entered once per flow."
            )
            return self.case
        self._execution_entered = True

        def execute_local_demo_action() -> str:
            return "Low-risk demonstration action executed in the local sandbox."

        # Describe the operation, not the callable. Two refunds share a closure
        # but are different consequential acts, so the approval must bind to the
        # requested operation, target and parameters rather than to the function.
        #
        # Only the descriptor is supplied. Which mission, capability, revision and
        # destination this execution is happens to be exactly what the runtime
        # already knows, so it derives those itself: a caller cannot name someone
        # else's mission and have an approval validated against the name it gave.
        descriptor = ActionDescriptor(
            operation=str(self.case.get("requested_action", "unspecified")),
            resource=str(self.case.get("customer", "unknown")),
            destination=EXTERNAL_TRUST_ZONE,
            parameters={
                "case_id": self.case.get("id"),
                "risk": self.case.get("risk"),
                "summary": self.case.get("summary"),
            },
        )
        decision, result = self.boundary.evaluate_and_execute(
            mission_id=self.mission_id,
            risk=str(self.case.get("risk", "low")),
            action=execute_local_demo_action,
            action_descriptor=descriptor,
            attempt=self.attempt,
        )
        # Reported from the runtime's own canonical request, so the evidence
        # describes what was actually authorized rather than what was asked for.
        request = canonical_action_request(
            mission_id=self.mission_id,
            risk=str(self.case.get("risk", "low")),
            # The boundary's own subject, not a second lookup that could
            # disagree with the one authority is actually judged against. A
            # pending request describes the exact attempt an approver would be
            # signing, so it must carry the identity the boundary will compare.
            subject_revision=(
                self.boundary.runtime_subject.governed_subject_digest
                if self.boundary.runtime_subject is not None
                else ""
            ),
            subject_scope_id=(
                self.boundary.runtime_subject.scope_id
                if self.boundary.runtime_subject is not None
                else ""
            ),
            governed_revision_digest=(
                self.boundary.runtime_subject.governed_revision_digest
                if self.boundary.runtime_subject is not None
                else ""
            ),
            descriptor=descriptor,
            attempt=self.attempt,
        )
        self.case["action_request"] = {
            "request_id": request.request_id,
            "attempt_id": request.attempt_id,
            "payload_digest": request.payload_digest,
            "request_digest": request.digest,
        }
        self.case["decision"] = {
            "effect": decision.effect,
            "code": decision.code,
            "reason": decision.reason,
            "source": decision.source,
        }
        self.case["nornyx_evidence"] = decision.evidence
        self.case["governance_mode"] = self.boundary.mode
        # What happened to the *act*, recorded separately from what happened to
        # the workflow. An orchestration failure later must not be able to erase
        # the fact that an effect was released, and an effect being released must
        # not let a failed run claim it completed.
        self.case["action_status"] = "executed" if decision.allowed else "prevented"
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
        self.case["orchestration_status"] = "completed"
        report = self.ledger.validate(report_path=self.root / "evidence/runtime/report.json")
        self.case["evidence"] = report
        self.case["framework"] = (
            "CrewAI Flow kickoff"
            if self.execution_backend == "crewai"
            else "CrewAI Flow-compatible sequential execution"
        )
        return self._stage("audit", f"Evidence status: {report['status']}.")

    def run_sequential(self) -> dict[str, Any]:
        self._sequential_driver = True
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
    config: RuntimeAuthorityConfig | None = None,
    security_context: RuntimeSecurityContext | None = None,
) -> dict[str, Any]:
    # The authority configuration is the single source of truth for governance
    # and execution mode. It used to be read from the environment here, which
    # would now be strictly worse than before: the subject digest binds the
    # mode, so a downstream environment read would let the subject attest to
    # `crewai` while the process actually ran `sequential`. A signature over a
    # configuration the runtime does not follow is a false attestation.
    authority = config if config is not None else RuntimeAuthorityConfig()
    mode = worker_mode or "deterministic"
    fallback = authority.policy_backend == "deterministic_demo"
    flow = CustomerCaseFlow(
        case,
        root=root,
        worker_mode=mode,
        allow_policy_fallback=fallback,
        security_context=security_context,
    )
    flow.case["configured_execution_backend"] = authority.execution_backend
    flow.case["configured_policy_backend"] = authority.policy_backend
    use_kickoff = authority.execution_backend == "crewai"
    # The backend is chosen once, before any stage runs. Falling back *after*
    # kickoff re-ran every stage including the consequential one: the reviewer
    # drove a kickoff that failed after execution and watched the action happen
    # twice from a single call, with the case still reporting "completed".
    #
    # The reason this cannot be repaired by resuming is that completion position
    # is unknowable. An effect may have been released immediately before the
    # process failed to record that it had been — so a timeline missing the
    # execution stage is not evidence the execution did not happen. Inspecting
    # the timeline and continuing from there would just be the same assumption
    # written more carefully.
    if not use_kickoff:
        flow.execution_backend = "sequential"
        return flow.run_sequential()

    if not CREWAI_AVAILABLE:
        # `execution_backend=crewai` is a claim about what runs. If CrewAI
        # cannot execute, the honest outcome is that this backend is
        # unavailable — not a silent downgrade to sequential under an unchanged
        # label, which is how the whole suite stayed green with CrewAI absent.
        raise ExecutionBackendUnavailable(
            "execution_backend=crewai was requested but CrewAI could not be "
            "imported. Refusing to run a different backend under that name."
        )

    try:
        flow.execution_backend = "crewai"
        result = flow.kickoff()  # type: ignore[attr-defined]
        return result if isinstance(result, dict) else flow.case
    except ExecutionBackendUnavailable:
        raise
    except Exception as exc:
        if authority.policy_backend == "nornyx":
            raise
        # Two independent truths, deliberately not collapsed: the workflow did
        # not complete, and an effect may already have been released.
        flow.case["orchestration_status"] = "failed"
        flow.case["status"] = "failed"
        flow.case["orchestration_error"] = f"{type(exc).__name__}: {exc}"
        flow.case.setdefault("limitations", []).append(
            f"CrewAI orchestration failed ({type(exc).__name__}). The run was "
            "terminated rather than replayed: after kickoff begins, how far it "
            "got is unknown, and re-running the flow could release a "
            "consequential effect a second time. A retry is an explicit new "
            "attempt, not something recovery code performs."
        )
        return flow.case


def run_demo_scenarios(
    root: Path,
    *,
    worker_mode: str | None = None,
    allow_policy_fallback: bool | None = None,
    config: RuntimeAuthorityConfig | None = None,
) -> dict[str, Any]:
    """Run both demonstration cases.

    Governance mode comes from the authority configuration bound into the
    subject, never from the environment. A second resolution path here would
    have been the exact hazard binding the mode was meant to remove: the
    subject would attest to one governance backend while this entry point ran
    another.
    """
    authority = config if config is not None else RuntimeAuthorityConfig()
    worker_mode = worker_mode or "deterministic"
    if allow_policy_fallback is None:
        allow_policy_fallback = authority.policy_backend == "deterministic_demo"
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
        config=authority,
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
        config=authority,
        allow_policy_fallback=allow_policy_fallback,
    )
    final_report = EvidenceLedger(
        runtime_dir / "events.jsonl",
        subject_revision=None,
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
