from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .evidence import EvidenceLedger


@dataclass(frozen=True)
class PolicyDecision:
    effect: str
    code: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.effect == "ALLOW"


class DemoPolicyEngine:
    """Transparent demonstration policy bridge.

    The bridge validates Nornyx contracts through the official CLI when present,
    then makes a deliberately small local decision for the UI demonstration.

    NO PRODUCTION CALLER. `grep -rn DemoPolicyEngine src/ scripts/` finds
    only this definition; the shipped path decides through
    `NornyxActionBoundary.evaluate_and_execute`. It is kept because the
    demonstration's own tests exercise it as a worked example of the
    shape, and it is documented as dead so nobody reads its verdicts as
    the system's.

    WHAT ITS RISK TEST ACTUALLY MEASURES. This said "high-risk actions
    never execute in autonomous-demo mode" and tested
    `risk.lower() in {"high", "critical"}`, so `"HIGH-RISK"`, `"severe"`
    or `""` fell through to ALLOW under a sentence promising they could
    not. What it measures is: an act whose risk is SPELLED `high` or
    `critical` does not execute here. That is narrower than the claim, and
    the claim is now the measurement.

    IT IS NOT REPAIRED TO MATCH THE BOUNDARY, deliberately.
    `NornyxActionBoundary` refuses an unrecognised label outright through
    `normalize_risk`, and importing that here is a dependency the
    architecture contract does not declare for `policy_adapter` -- the gate
    refuses it, correctly. Copying the vocabulary instead would create the
    second implementation FG40 is the class about. So the honest outcome
    for a class with no production caller is an accurate docstring, and
    the boundary remains the only thing that decides a real act.
    """

    def __init__(self, ledger: EvidenceLedger, *, autonomous_demo: bool = True) -> None:
        self.ledger = ledger
        self.autonomous_demo = autonomous_demo

    @staticmethod
    def validate_contract(contract: Path) -> tuple[bool, str]:
        executable = shutil.which("nornyx")
        if not executable:
            return False, "nornyx CLI not installed"
        result = subprocess.run(
            [executable, "check", str(contract)],
            text=True,
            capture_output=True,
            check=False,
        )
        detail = (result.stdout + result.stderr).strip()
        return result.returncode == 0, detail

    def evaluate(self, *, mission_id: str, actor: str, capability: str, risk: str) -> PolicyDecision:
        if risk.lower() in {"high", "critical"} and self.autonomous_demo:
            decision = PolicyDecision(
                "DENY",
                "HUMAN_APPROVAL_REQUIRED",
                "Autonomous demonstration mode cannot grant human production approval.",
            )
        else:
            decision = PolicyDecision("ALLOW", "ALLOWED", "Declared low-risk demo capability.")
        self.ledger.append(
            "policy_decision",
            mission_id=mission_id,
            actor=actor,
            capability=capability,
            decision=decision.effect,
            reason=decision.reason,
            code=decision.code,
            risk=risk,
        )
        return decision
