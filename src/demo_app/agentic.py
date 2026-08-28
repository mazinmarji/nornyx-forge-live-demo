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
    HIGH_RISK_LEVELS,
    ActionDescriptor,
    NornyxActionBoundary,
    NornyxRuntimeUnavailable,
    UnknownRiskLevel,
    canonical_action_request,
    exercised_capability,
    normalize_risk,
)
from nornyx_forge.subject_bootstrap import (
    RuntimeSecurityContext,
    bootstrap_security_context,
)

# Re-exported so the interface layer can handle a governed refusal without
# importing the governance module directly.
__all__ = [
    "CustomerCaseFlow",
    "NornyxRuntimeUnavailable",
    "application_security_context",
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


#: The one security context this process runs under.
#:
#: Established at import, which is the application's startup: module import
#: happens once per process under the interpreter's own lock, so there is no
#: window in which two requests could each establish one and no lazy accessor
#: that a request could be the first to reach.
#:
#: This existed as a parameter that production never filled. `bootstrap_
#: security_context()` had no caller outside the tests, so every real flow ran
#: with `security_context=None` and the boundary fell back to resolving its own
#: trust anchors — the per-use ambient resolution the whole subject model exists
#: to remove. The tests proved the mechanism worked; nothing proved it was used.
#:
#: Failure is a context with an unavailable subject, never an exception and
#: never a fabricated digest: the application may start and serve read-only work
#: while consequential authority is simply not on offer. An import that raised
#: would turn "this deployment cannot authorize effects" into "this deployment
#: does not start", which are different outcomes.
_SECURITY_CONTEXT = bootstrap_security_context(config=demonstration_authority())


def application_security_context() -> RuntimeSecurityContext:
    """Return the established context. The same object every time.

    Identity is the property, not equality. Handing back an equal copy would
    satisfy any digest comparison while still allowing each request to observe
    the tree afresh, which is exactly what this prevents.
    """
    return _SECURITY_CONTEXT


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

    READ FROM THE ESTABLISHED CONTEXT, never re-loaded. This called
    `ApprovalTrustDomains.load()` again, which made it a second consumer of a
    question the boundary already had a frozen answer to -- so the same question
    got two answers whenever the store changed after startup. Measured, with the
    process bootstrapped against no store and one provisioned afterwards:

        boundary   action_signers=[]  action_available=False   (refuses)
        reported   consequential_authority="available"         (claims it can)

    The interface told an operator this deployment could release consequential
    effects while the boundary that releases them held an empty trust domain.
    Nothing was released -- only the reporting path re-read, so this was never
    an action-release bypass -- but a deployment that misdescribes its own
    authority is the thing an operator plans against.

    The snapshot is now the only source, so what is reported and what is
    enforced cannot drift apart: they are the same object.
    """
    context = application_security_context()
    stores = (context.governance_approval_trust, context.action_approval_trust)

    # BOTH domains, reported together. Saying "trust is available" while only
    # one authority is provisioned would describe a deployment that cannot do
    # what the word implies.
    # ACTIVE signers, not raw membership. A revoked key stays in the store so a
    # refusal can name it, and the boundary refuses it -- but counting it here
    # reported `consequential_authority: available` for a deployment whose every
    # key was revoked. Measured, and the same defect as the live re-read above:
    # the report described an authority that was not in force.
    loaded = all(
        getattr(s, "available", False) and getattr(s, "active_signers", None)
        for s in stores
    )
    if loaded:
        state = "available"
    elif any(getattr(s, "unusable", False) for s in stores):
        # Present and broken. Distinct from absent, and it stays distinct:
        # both authorize nothing, and they send an operator to different fixes.
        state = "unusable"
    else:
        state = "unavailable"
    return {
        "action_approval_authentication": state,
        "trusted_approvers_loaded": loaded,
        # RENAMED TO WHAT IT MEASURES. This was `consequential_authority`, and
        # a review measured `/api/health` publishing it as `available` while
        # the boundary IN THE SAME PROCESS refused every consequential act with
        # SUBJECT_UNVERIFIED -- against a document asserting that what the
        # interface says and what the boundary enforces "cannot disagree".
        #
        # The boundary consults five things for a high-risk release: the
        # integrity verdict, the runtime subject, the action trust store, the
        # approval ledger and the authorizer. This function reads ONE. Rather
        # than have the name promise the other four, it now names the trust
        # store, which is what it actually establishes.
        #
        # `consequential_authority` is retained as an explicit refusal to
        # answer, so a reader is not left to infer it from a field that never
        # meant it. Deriving it honestly would mean threading all five inputs
        # here, which is a design change and belongs in its own diff.
        "approver_trust_authentication": "available" if loaded else "unavailable",
        "consequential_authority": "not_derived_here",
    }


def _canonical_request_or_none(**arguments: Any):
    """The request the runtime authorized, or None when there is no such thing.

    An unrecognised risk label has no capability, so there is no canonical
    request to report -- and the boundary has already refused it by the time
    this is reached. Returning None lets the refusal be recorded and
    returned; raising made a correct refusal unobservable.
    """
    try:
        return canonical_action_request(**arguments)
    except UnknownRiskLevel:
        return None


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
        action_approval: dict[str, Any] | None = None,
    ) -> None:
        try:
            super().__init__()
        except Exception:
            pass
        self.case = case
        # A grant the CALLER obtained from a human. Nothing here creates,
        # adopts, infers or backdates one: `None` means no approval was
        # presented, and the boundary denies every high-risk effect.
        self.action_approval = action_approval
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
        # Trust anchors AND the established subject come from the context, not
        # from a fresh environment read per boundary. The context resolved them
        # once at startup; handing them down is what makes that resolution
        # binding.
        #
        # `runtime_subject` was the half that never arrived. The boundary
        # defaulted it to None and refused every release with
        # SUBJECT_UNVERIFIED, so the whole approval path -- signature
        # verification, window validation, fingerprinting, ledger consumption --
        # was unreachable in the running application. Worse than unreachable:
        # the refusal LOOKED like governance working, while it was really the
        # boundary saying it did not know what it was governing.
        #
        # This is the same defect as the one above it, one level down. The
        # context was wired into the flow and then not out of it, which is why
        # `test_the_flow_hands_the_established_subject_to_the_boundary` asserts
        # the object identity at this edge rather than trusting the wiring to
        # have been carried through.
        self.boundary = NornyxActionBoundary(
            root,
            allow_fallback=allow_policy_fallback,
            trust=security_context.trust if security_context is not None else None,
            runtime_subject=(
                security_context.runtime_subject if security_context is not None else None
            ),
            # Established with the subject and injected with it. A boundary
            # that observed its own integrity would be deciding whether to
            # trust itself.
            governance_integrity=(
                security_context.governance_integrity
                if security_context is not None
                else None
            ),
            # The store parsed at startup, not its path. Reopening the file
            # per boundary meant an edit between two requests changed who
            # the second one trusted.
            frozen_action_trust=(
                security_context.action_approval_trust
                if security_context is not None
                else None
            ),
            # So a boundary rooted at a different tree than the one this context
            # describes refuses, instead of judging tree A's policy against tree
            # B's identity.
            established_root=(
                getattr(security_context, "established_root", "")
                if security_context is not None
                else ""
            ),
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
        # THE SAME VOCABULARY THE BOUNDARY USES. This did bare `.lower()`
        # membership, so `"bogus"` and `" high "` both classified as
        # `bounded-low-risk` and that classification went into the evidence
        # stream -- while the boundary answered RISK_LEVEL_UNKNOWN, whose
        # own text reads "An unclassified act is not a low-risk act", and
        # for `" high "` named the high-risk effect capability. One
        # mission's stream carried a stage record calling the act
        # bounded-low-risk beside an `action_prevented` record naming
        # `execute_high_risk_effect`. `normalize_risk` exists precisely to
        # end that fall-through and its docstring names `"High" + newline`
        # by hand; it was simply not used one stage upstream.
        raw = str(self.case.get("risk", "low"))
        try:
            level = normalize_risk(raw)
        except UnknownRiskLevel:
            self.case["risk_decision"] = "unclassified"
            return self._stage(
                "risk",
                "Risk could not be classified: " + repr(raw) + " is not a "
                "declared level, and an unclassified act is not a low-risk "
                "act.",
            )
        self.case["risk_decision"] = (
            "high-impact" if level in HIGH_RISK_LEVELS else "bounded-low-risk"
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
            action_approval=self.action_approval,
        )
        # Reported from the runtime's own canonical request, so the evidence
        # describes what was actually authorized rather than what was asked for.
        #
        # BUILT ONLY IF THERE IS ONE TO BUILD. `canonical_action_request`
        # derives the capability, and an unrecognised risk label has no
        # capability -- so it raised here, one statement after the boundary
        # had already REFUSED that label with `RISK_LEVEL_UNKNOWN`. The
        # refusal was constructed and could not be observed: no case, no
        # ledger record, no response, just an exception out of `run_case`.
        # A guard that refuses correctly and then crashes before anyone can
        # see it has not refused anything a reader can act on.
        #
        # Not reachable from the HTTP surface today -- `CaseInput.risk`
        # rejects anything outside the four levels -- but reachable from the
        # library API, which is how the boundary's own guard is reached too.
        request = _canonical_request_or_none(
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
        if request is not None:
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
        # The capability the act EXERCISED, from the single derivation the
        # runtime authorizes against -- never from the branch we are in.
        #
        # These two appends used to name the capability from `decision.allowed`:
        # `execute_low_risk_action` when the effect was released and
        # `execute_high_risk_action` when it was withheld. Measured on the
        # production flow, with a real signed grant releasing a high-value
        # external refund:
        #
        #     act risk               high
        #     decision               ALLOW / ALLOWED, effect released
        #     recorded capability    execute_low_risk_action
        #
        # The contract declares `execute_low_risk_action` as `risk: low` with no
        # required gates and NO REQUIRED APPROVALS. So the one record of a
        # released high-risk effect said the capability in play was the one that
        # needs no human -- at the exact moment a human approval was spent.
        # This module's own suite, `tests/test_capability_binding.py`, exists
        # because a caller once labelled a high-risk REQUEST that way; the
        # boundary refuses that now, and the record was still free to say it
        # afterwards.
        #
        # `execute_high_risk_action` was not the right name for the other branch
        # either: it is an action class, and no capability by that name exists in
        # this system. The declared one is `execute_high_risk_effect`, and the
        # shipped demonstration wrote the non-existent name on every high-risk
        # case.
        # AND NONE WHEN THERE IS NO CAPABILITY. An unrecognised risk label
        # exercises nothing -- the boundary has already refused it -- so
        # the record says so rather than the derivation raising and taking
        # the refusal down with it. The ledger's `capability` is already
        # optional; `None` is the honest value for an act that was
        # refused before any capability was in play.
        try:
            exercised = exercised_capability(str(self.case.get("risk", "low")))
        except UnknownRiskLevel:
            exercised = None
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
                capability=exercised,
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
                capability=exercised,
                decision=decision.effect,
                reason=decision.reason,
                code=decision.code,
                governance_source=decision.source,
            )
        return self._stage("execution", self.case["execution_result"])

    @listen(execution)
    def audit(self, _previous: Any = None) -> dict[str, Any]:
        self.case["orchestration_status"] = "completed"
        # THE STAGE RECORD IS APPENDED FIRST, so the report describes the
        # whole stream. Validating before the final append left
        # `report.json` permanently one record behind the stream it names
        # on the single-case path -- two artifacts disagreeing about how
        # long the evidence is.
        self._stage("audit", "Evidence stream sealed.")
        report = self.ledger.validate(
            report_path=self.root / "evidence/runtime/report.json",
        )
        self.case["evidence"] = report
        self.case["framework"] = (
            "CrewAI Flow kickoff"
            if self.execution_backend == "crewai"
            else "CrewAI Flow-compatible sequential execution"
        )
        for entry in reversed(self.case.get("timeline", [])):
            if entry["stage"] == "audit":
                entry["summary"] = "Evidence status: " + report["status"] + "."
                break
        return self.case

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
    config: RuntimeAuthorityConfig | None = None,
    security_context: RuntimeSecurityContext | None = None,
    action_approval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # NO `allow_policy_fallback` PARAMETER. It used to be accepted here and
    # discarded: `fallback` below is computed from the authority configuration
    # regardless, so a caller asking for `False` got `True` and no error. A
    # review measured exactly that. Deleting it is the fix rather than
    # honouring it -- see `run_demo_scenarios`, which explains why a second
    # resolution path for the governance mode is the hazard the subject
    # binding exists to remove.
    # The authority configuration is the single source of truth for governance
    # and execution mode. It used to be read from the environment here, which
    # would now be strictly worse than before: the subject digest binds the
    # mode, so a downstream environment read would let the subject attest to
    # `crewai` while the process actually ran `sequential`. A signature over a
    # configuration the runtime does not follow is a false attestation.
    authority = config if config is not None else RuntimeAuthorityConfig()
    mode = worker_mode or "deterministic"
    fallback = authority.policy_backend == "deterministic_demo"
    # The established context, unless a caller deliberately supplied another.
    # `None` used to mean "no context at all", so the production path — which
    # passes nothing — ran every flow unestablished and let the boundary resolve
    # its own trust anchors per use. An omitted argument now means "the one this
    # application established", which is what a request should never get to
    # choose.
    context = (
        security_context if security_context is not None else application_security_context()
    )
    flow = CustomerCaseFlow(
        case,
        root=root,
        worker_mode=mode,
        allow_policy_fallback=fallback,
        security_context=context,
        action_approval=action_approval,
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
    config: RuntimeAuthorityConfig | None = None,
    security_context: RuntimeSecurityContext | None = None,
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
    runtime_dir = root / "evidence/runtime"
    # THROUGH THE LEDGER, under the lock every reader and writer holds.
    #
    # Three bare `unlink()` calls here raced `EvidenceLedger.append` in the
    # threadpool FastAPI dispatches these handlers into: measured over 300
    # iterations against a concurrent case, 5 legitimate runs reported
    # `fail` and 172 OSErrors escaped `append` as unhandled 500s. The mark
    # still goes with the stream it marks -- removing the events and leaving
    # the high-water file behind orphaned the pair -- but both now happen
    # where nothing else can be mid-write.
    EvidenceLedger(runtime_dir / "events.jsonl").reset(
        runtime_dir / "report.json",
    )

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
        security_context=security_context,
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
        security_context=security_context,
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
