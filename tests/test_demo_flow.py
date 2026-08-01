from pathlib import Path

from demo_app.agentic import run_demo_scenarios


def test_offline_demo_proves_allow_and_prevent(tmp_path: Path):
    result = run_demo_scenarios(tmp_path, worker_mode="deterministic")
    assert result["status"] == "pass"
    assert result["low_risk"]["status"] == "completed"
    assert result["high_risk"]["status"] == "prevented"
    assert result["high_risk"]["decision"]["code"] == "HUMAN_APPROVAL_REQUIRED"
