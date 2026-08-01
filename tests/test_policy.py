from pathlib import Path

from nornyx_forge.evidence import EvidenceLedger
from nornyx_forge.policy import DemoPolicyEngine


def test_low_risk_allowed_and_high_risk_prevented(tmp_path: Path):
    engine = DemoPolicyEngine(EvidenceLedger(tmp_path / "events.jsonl"))
    assert engine.evaluate(mission_id="L", actor="agent.execution", capability="execute", risk="low").allowed
    denied = engine.evaluate(mission_id="H", actor="agent.execution", capability="execute", risk="high")
    assert not denied.allowed
    assert denied.code == "HUMAN_APPROVAL_REQUIRED"
