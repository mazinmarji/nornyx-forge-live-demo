from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .models import GateResult
from .util import write_json

RUNTIME_AS_OF = "2026-08-01T12:00:00Z"
RUNTIME_REVISION = "git:e9f554892ba8d070bfa14acf75896e032d3c75ec"


@dataclass(frozen=True)
class RuntimeDecision:
    effect: str
    code: str
    reason: str
    source: str
    evidence: dict[str, Any] | None = None

    @property
    def allowed(self) -> bool:
        return self.effect == "ALLOW"


def prepare_runtime_contract(root: Path) -> list[GateResult]:
    """Validate, generate, lock, and verify the runtime contract with Nornyx.

    The generated artifacts are intentionally outside tracked source. When the
    CLI is unavailable the caller receives a failed gate rather than a fabricated
    success.
    """

    executable = shutil.which("nornyx")
    if not executable:
        return [GateResult("nornyx runtime preparation", False, "nornyx CLI not installed", (), 127)]
    contract = root / ".nornyx/contracts/runtime_network.nyx"
    out = root / ".nornyx/runtime"
    artifacts = out / "control_artifacts"
    lock = out / "nornyx.agentic_network.lock"
    out.mkdir(parents=True, exist_ok=True)
    commands = [
        (executable, "check", str(contract)),
        (
            executable,
            "agentic-network",
            "generate",
            str(contract),
            "--out",
            str(artifacts),
            "--as-of",
            RUNTIME_AS_OF,
        ),
        (
            executable,
            "agentic-network",
            "lock",
            str(contract),
            "--artifacts",
            str(artifacts),
            "--out",
            str(lock),
            "--as-of",
            RUNTIME_AS_OF,
        ),
        (
            executable,
            "agentic-network",
            "lock-check",
            str(contract),
            "--lock",
            str(lock),
            "--artifacts",
            str(artifacts),
            "--as-of",
            RUNTIME_AS_OF,
        ),
    ]
    results: list[GateResult] = []
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        detail = (completed.stdout + completed.stderr).strip()
        result = GateResult(
            name=" ".join(command[1:3]),
            passed=completed.returncode == 0,
            detail=detail,
            command=tuple(command),
            returncode=completed.returncode,
        )
        results.append(result)
        if not result.passed:
            break
    write_json(out / "preparation-report.json", [item.__dict__ for item in results])
    return results


class NornyxActionBoundary:
    """Official Nornyx authorization path with an explicit fallback boundary.

    If the Nornyx package and a verified lock are present, decisions and evidence
    come from `nornyx.agentic`. A deterministic fallback is available only for
    offline CI and is always labelled as fallback evidence.
    """

    def __init__(self, root: Path, *, allow_fallback: bool = True) -> None:
        self.root = root
        self.allow_fallback = allow_fallback
        self.authorizer: Any | None = None
        self.context: Any | None = None
        self._imports: dict[str, Any] = {}
        self.load_error: str | None = None
        try:
            from nornyx.agentic import (  # type: ignore[import-not-found]
                CapabilityRequest,
                EvaluationContext,
                EvidenceRecorder,
                ZoneCrossingRequest,
                load_authorizer,
            )

            contract = root / ".nornyx/contracts/runtime_network.nyx"
            lock = root / ".nornyx/runtime/nornyx.agentic_network.lock"
            if not lock.exists():
                prepared = prepare_runtime_contract(root)
                if not prepared or not all(item.passed for item in prepared):
                    detail = prepared[-1].detail if prepared else "no preparation result"
                    raise RuntimeError(detail)
            authorizer = load_authorizer(contract, lock, validation_as_of=RUNTIME_AS_OF)
            context = EvaluationContext(
                decision_at=RUNTIME_AS_OF,
                observed_subject_revision=authorizer.subject_revision,
            )
            self.authorizer = authorizer
            self.context = context
            self._imports = {
                "CapabilityRequest": CapabilityRequest,
                "EvidenceRecorder": EvidenceRecorder,
                "ZoneCrossingRequest": ZoneCrossingRequest,
            }
        except Exception as exc:  # optional dependency / contract preparation boundary
            self.load_error = f"{type(exc).__name__}: {exc}"
            if not allow_fallback:
                raise

    @property
    def mode(self) -> str:
        return "nornyx.agentic" if self.authorizer is not None else "deterministic_fallback"

    def _official(
        self,
        *,
        mission_id: str,
        risk: str,
        action: Callable[[], str],
    ) -> RuntimeDecision:
        assert self.authorizer is not None and self.context is not None
        capability_name = (
            "execute_high_risk_action"
            if risk.lower() in {"high", "critical"}
            else "execute_low_risk_action"
        )
        CapabilityRequest = self._imports["CapabilityRequest"]
        ZoneCrossingRequest = self._imports["ZoneCrossingRequest"]
        EvidenceRecorder = self._imports["EvidenceRecorder"]
        recorder = EvidenceRecorder(
            self.authorizer,
            self.context,
            producer_id="nornyx-forge-live-demo",
            producer_version="0.2.0",
            producer_type="external_runtime",
        )
        capability = self.authorizer.evaluate(
            CapabilityRequest("identity.execution", capability_name),
            context=self.context,
        )
        recorder.record_decision(capability, mission_id=mission_id)
        decision = capability
        if capability.allowed and risk.lower() in {"high", "critical"}:
            decision = self.authorizer.evaluate(
                ZoneCrossingRequest(
                    "identity.execution",
                    "zone.local_demo",
                    "zone.external_customer",
                    None,
                ),
                context=self.context,
            )
            recorder.record_decision(decision, mission_id=mission_id)
        if decision.allowed:
            action()
            recorder.record_observation(
                "tool_invoked",
                mission_id=mission_id,
                actor_ref="identity.execution",
                capability_ref=capability_name,
            )
        stream = recorder.stream()
        report = recorder.validate()
        evidence_dir = self.root / "evidence/runtime/nornyx"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        write_json(evidence_dir / f"{mission_id}.events.json", stream)
        write_json(evidence_dir / f"{mission_id}.report.json", report)
        return RuntimeDecision(
            effect=getattr(decision.effect, "name", str(decision.effect)),
            code=decision.code.value,
            reason=decision.reason or decision.code.value,
            source="nornyx.agentic",
            evidence=report,
        )

    def evaluate_and_execute(
        self,
        *,
        mission_id: str,
        risk: str,
        action: Callable[[], str],
    ) -> tuple[RuntimeDecision, str | None]:
        if self.authorizer is not None:
            result: str | None = None

            def capture() -> str:
                nonlocal result
                result = action()
                return result

            return self._official(mission_id=mission_id, risk=risk, action=capture), result
        if not self.allow_fallback:
            raise RuntimeError(self.load_error or "Nornyx runtime unavailable")
        if risk.lower() in {"high", "critical"}:
            decision = RuntimeDecision(
                "DENY",
                "HUMAN_APPROVAL_REQUIRED",
                "Autonomous demonstration mode cannot grant human production approval.",
                "deterministic_fallback",
                {"status": "fallback", "load_error": self.load_error},
            )
            return decision, None
        result = action()
        decision = RuntimeDecision(
            "ALLOW",
            "ALLOWED",
            "Declared low-risk demonstration capability.",
            "deterministic_fallback",
            {"status": "fallback", "load_error": self.load_error},
        )
        return decision, result
