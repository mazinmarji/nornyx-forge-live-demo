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
    High-risk actions never execute in autonomous-demo mode.
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
