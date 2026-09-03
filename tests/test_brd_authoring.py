"""The BRD derivation: confirmed words in, a parseable BRD out.

THE ROUND TRIP IS AGAINST THE REAL PARSER: every test that checks what
the derived BRD says reads it back through `parse_brd` -- the same
function the build flow uses -- so what is proven is that the flow will
build from exactly the statements a human confirmed. The hostile
specimens are the authority line (a proposal-only capsule refuses; open
proposals author nothing) and the heading grammar (words that would change
what a parser reads back are refused, not escaped into ambiguity).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nornyx_forge.brd_authoring import (
    BrdAuthoringError,
    brd_from_capsule,
    confirmed_requirement_texts,
)
from nornyx_forge.capsule import Actor, confirm, create_document, propose
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.requirements import parse_brd

ROOT = Path(__file__).resolve().parents[1]
HUMAN = Actor(kind="human", ident="casey")
MODEL = Actor(kind="model", ident="builder-model")

INTENT = "Build a customer support portal with case tracking."
PROPOSED_ONLY = "Also mine cryptocurrency in the background."


def _document(*, confirm_intent: bool = True, with_requirements: bool = False,
              with_open_proposal: bool = False) -> dict:
    document = create_document("proj-1", "Support Portal", HUMAN,
                               "2026-08-30T12:00:00Z")
    document, intent_id = propose(document, "intent", INTENT, MODEL,
                                  "2026-08-30T12:01:00Z")
    if confirm_intent:
        document = confirm(document, intent_id, HUMAN, "2026-08-30T12:02:00Z")
    if with_requirements:
        rows = [{"id": "RQ-1", "text": "Cases are created from a web form."},
                {"id": "RQ-2", "text": "Every action is evidence-logged."}]
        document, req_id = propose(document, "requirements", rows, HUMAN,
                                   "2026-08-30T12:03:00Z")
        document = confirm(document, req_id, HUMAN, "2026-08-30T12:04:00Z")
    if with_open_proposal:
        document, _ = propose(
            document, "requirements",
            [{"id": "RQ-9", "text": PROPOSED_ONLY}], MODEL,
            "2026-08-30T12:05:00Z",
        )
    return document


def _parse(tmp_path: Path, rendered: str):
    target = tmp_path / "BRD.md"
    target.write_text(rendered, encoding="utf-8", newline="")
    return parse_brd(target)


# ---------------------------------------------------------------------------
# The round trip against the real parser
# ---------------------------------------------------------------------------

def test_the_confirmed_intent_is_what_the_flow_would_build_from(tmp_path: Path):
    model = _parse(tmp_path, brd_from_capsule(_document()))
    assert [item.id for item in model.requirements] == ["BRD-001"]
    assert model.requirements[0].statement == INTENT


def test_confirmed_requirements_come_back_in_order(tmp_path: Path):
    document = _document(with_requirements=True)
    model = _parse(tmp_path, brd_from_capsule(document))
    statements = [item.statement for item in model.requirements]
    assert statements == list(confirmed_requirement_texts(document))
    assert [item.id for item in model.requirements] == [
        "BRD-001", "BRD-F-001", "BRD-F-002",
    ]


def test_the_document_names_its_own_derivation(tmp_path: Path):
    rendered = brd_from_capsule(_document())
    assert "DERIVED from the project capsule's confirmed" in rendered
    assert "# BRD — Support Portal" in rendered.splitlines()[0]


# ---------------------------------------------------------------------------
# The authority line
# ---------------------------------------------------------------------------

def test_a_proposal_only_capsule_refuses_to_author_a_brd():
    with pytest.raises(BrdAuthoringError, match="no confirmed intent"):
        brd_from_capsule(_document(confirm_intent=False))


def test_open_proposals_author_nothing(tmp_path: Path):
    """The proposal sits in the capsule, visible and open, and the BRD
    carries not one word of it."""
    document = _document(with_requirements=True, with_open_proposal=True)
    rendered = brd_from_capsule(document)
    assert PROPOSED_ONLY not in rendered
    model = _parse(tmp_path, rendered)
    assert all(PROPOSED_ONLY not in item.statement for item in model.requirements)


def test_words_that_would_change_the_parse_are_refused():
    document = _document(confirm_intent=False)
    document["authoritative"]["intent"] = "## BRD-999 injected heading"
    with pytest.raises(BrdAuthoringError, match="heading grammar"):
        brd_from_capsule(document)
    document["authoritative"]["intent"] = "line one\nline two"
    with pytest.raises(BrdAuthoringError, match="heading grammar"):
        brd_from_capsule(document)


# ---------------------------------------------------------------------------
# The route: derived into the project directory, refusals passed through
# ---------------------------------------------------------------------------

def test_the_route_writes_the_brd_beside_the_capsule(tmp_path: Path):
    CapsuleStore(tmp_path / "capsule").initialize(_document(with_requirements=True))
    client = TestClient(create_app(tmp_path / "capsule",
                                   ROOT / ".nornyx" / "contracts",
                                   seal_dir=tmp_path / "seals"))
    response = client.post("/api/brd")
    assert response.status_code == 200, response.text
    written = Path(response.json()["written"])
    assert written == tmp_path / "BRD.md"
    model = parse_brd(written)
    assert model.requirements[0].statement == INTENT


def test_the_route_refuses_a_proposal_only_capsule(tmp_path: Path):
    CapsuleStore(tmp_path / "capsule").initialize(_document(confirm_intent=False))
    client = TestClient(create_app(tmp_path / "capsule",
                                   ROOT / ".nornyx" / "contracts",
                                   seal_dir=tmp_path / "seals"))
    response = client.post("/api/brd")
    assert response.status_code == 409
    assert "no confirmed intent" in response.json()["refused"]
    assert not (tmp_path / "BRD.md").exists(), "a refused BRD was still written"


def test_the_route_refuses_without_a_project(tmp_path: Path):
    client = TestClient(create_app(tmp_path / "capsule",
                                   ROOT / ".nornyx" / "contracts",
                                   seal_dir=tmp_path / "seals"))
    response = client.post("/api/brd")
    assert response.status_code == 409