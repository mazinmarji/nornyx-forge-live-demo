from pathlib import Path

import yaml

from nornyx_forge.contract_generator import generate_brd_contract
from nornyx_forge.requirements import parse_brd


def test_brd_generates_traceable_nornyx_contract(tmp_path: Path) -> None:
    brd = tmp_path / "BRD.md"
    brd.write_text(
        """## BRD-001 Purpose

Build a governed service.

### BRD-F-001 Intake

Accept requests.

## BRD-002 Acceptance

- Tests pass.
""",
        encoding="utf-8",
    )
    model = parse_brd(brd)

    path = generate_brd_contract(tmp_path, model)
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert payload["project"]["profile"] == "agentic_repo_harness"
    assert [goal["id"] for goal in payload["goals"]] == [
        "BRD-001",
        "BRD-F-001",
        "BRD-002",
    ]
    assert payload["goals"][1]["goal"] == "Accept requests."
