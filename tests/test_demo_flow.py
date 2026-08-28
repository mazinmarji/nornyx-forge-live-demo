from pathlib import Path

from demo_app.agentic import run_demo_scenarios
from nornyx_forge.governed_subject import RuntimeAuthorityConfig


def test_offline_demo_proves_allow_and_prevent(tmp_path: Path):
    result = run_demo_scenarios(
        tmp_path,
        worker_mode="deterministic",
        config=RuntimeAuthorityConfig("deterministic_demo", "sequential"),
    )
    assert result["status"] == "pass"
    assert result["low_risk"]["status"] == "completed"
    assert result["high_risk"]["status"] == "prevented"
    assert result["high_risk"]["decision"]["code"] == "HUMAN_APPROVAL_REQUIRED"
