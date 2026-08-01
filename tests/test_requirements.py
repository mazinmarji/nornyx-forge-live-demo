from pathlib import Path

from nornyx_forge.requirements import parse_brd


def test_brd_sections_are_separate_requirements(tmp_path: Path) -> None:
    brd = tmp_path / "BRD.md"
    brd.write_text(
        """# Product

## BRD-001 Purpose

Build the product.

## BRD-002 Functional requirements

### BRD-F-001 Intake

Accept a request.

### BRD-F-002 Decision

Make a decision.

## BRD-003 Non-functional requirements

- Run offline.
- Use Docker.

## BRD-004 Acceptance criteria

- Tests pass.
""",
        encoding="utf-8",
    )

    model = parse_brd(brd)

    assert [item.id for item in model.requirements] == [
        "BRD-001",
        "BRD-F-001",
        "BRD-F-002",
        "BRD-003",
        "BRD-004",
    ]
    statements = {item.id: item.statement for item in model.requirements}
    assert statements["BRD-F-002"] == "Make a decision."
    assert "Run offline." in statements["BRD-003"]
    assert "Tests pass." in statements["BRD-004"]
    assert "Non-functional" not in statements["BRD-F-002"]
