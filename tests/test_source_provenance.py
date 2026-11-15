"""Source-specification provenance (A-060): what the requirements came from.

Each test drives the real capsule, the real BRD derivation, the real parser,
the real contract generator or the real receipt. The hostile specimens are
the losses Forge could not see before this record existed: a requirement
whose source part was rewritten, a source sentence no requirement carried
across, and a capsule with no source at all, from which a BRD and a contract
were derived anyway.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
import yaml

from nornyx_forge.brd_authoring import (
    BrdAuthoringError,
    brd_from_capsule,
    contract_from_capsule,
    proposal_entry_refusal,
)
from nornyx_forge.capsule import (
    AUTHORITATIVE_FIELDS,
    Actor,
    CapsuleValidationError,
    confirm,
    create_document,
    propose,
)
from nornyx_forge.contract_generator import render_brd_contract
from nornyx_forge.journey_receipt import _consistency_problems, source_projection
from nornyx_forge.requirements import SOURCE_BINDING_PREFIX, brd_source_binding, parse_brd_text
from nornyx_forge.source_provenance import (
    binding_problems,
    provenance_report,
    source_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
HUMAN = Actor(kind="human", ident="casey")
MODEL = Actor(kind="model", ident="builder-model")

INTENT = "Book meeting rooms for a small office."
SOURCE = (
    "# Room booking\n"
    "Book meeting rooms for a small office.\n"
    "A person books a room for a date and an hour.\n"
    "Two bookings of one room never overlap.\n"
    "A person cancels their own booking.\n"
    "Bookings are kept for one year and then deleted.\n"
)
ROWS = [
    {"id": "RQ-1", "text": "A person books a room for a date and an hour."},
    {"id": "RQ-2", "text": "A person cancels their own booking or one an administrator names."},
    {"id": "RQ-3", "text": "Every booking change is logged."},
]
RECORDS = [
    {"requirement": "RQ-1", "kind": "verbatim",
     "excerpt": "A person books a room for a date and an hour.", "change": ""},
    {"requirement": "RQ-2", "kind": "changed",
     "excerpt": "A person cancels their own booking.",
     "change": "Added cancellation by an administrator."},
    {"requirement": "RQ-3", "kind": "added", "excerpt": "",
     "change": "Not in the specification; added so changes can be audited."},
]
_CLOCK = (f"2026-11-05T{tick // 3600 % 24:02d}:{tick // 60 % 60:02d}:{tick % 60:02d}Z"
          for tick in itertools.count())


def _confirmed(document: dict, field: str, value) -> dict:
    document, proposal_id = propose(document, field, value, MODEL, next(_CLOCK))
    return confirm(document, proposal_id, HUMAN, next(_CLOCK))


def _document(*, source: str | None = SOURCE, rows=ROWS, records=RECORDS) -> dict:
    document = create_document("proj-1", "Room Booking", HUMAN, next(_CLOCK))
    document = _confirmed(document, "intent", INTENT)
    if rows is not None:
        document = _confirmed(document, "requirements", rows)
    if source is not None:
        document = _confirmed(document, "source_specification", {"text": source})
    if records is not None:
        document = _confirmed(document, "requirement_sources", records)
    return document


# ---------------------------------------------------------------------------
# The capsule holds both facts, shape-checked at the door
# ---------------------------------------------------------------------------

def test_the_capsule_registers_the_two_provenance_fields():
    assert "source_specification" in AUTHORITATIVE_FIELDS
    assert "requirement_sources" in AUTHORITATIVE_FIELDS


@pytest.mark.parametrize("value, reason", [
    ({"text": ""}, "must not be empty"),
    ({"text": "x", "sha256": "0" * 64}, "exactly {text}"),
    ("the spec", "exactly {text}"),
    ({"text": "a\x00b"}, "control characters"),
    ({"text": "Track \ud800 requests."}, "cannot be written as UTF-8"),
])
def test_a_malformed_source_specification_is_refused(value, reason):
    with pytest.raises(CapsuleValidationError, match=reason):
        AUTHORITATIVE_FIELDS["source_specification"](value)


@pytest.mark.parametrize("record, reason", [
    ({"requirement": "RQ-1", "kind": "copied", "excerpt": "x", "change": ""}, "not one of"),
    ({"requirement": "RQ-1", "kind": "verbatim", "excerpt": "x", "change": "edited"},
     "records no change"),
    ({"requirement": "RQ-1", "kind": "changed", "excerpt": "x", "change": ""}, "must not be empty"),
    ({"requirement": "RQ-1", "kind": "added", "excerpt": "x", "change": "new"}, "names no source part"),
    ({"requirement": "RQ-1", "kind": "verbatim", "excerpt": "", "change": ""}, "must not be empty"),
    ({"requirement": "R1", "kind": "added", "excerpt": "", "change": "new"}, "must match RQ-"),
    ({"requirement": "RQ-1", "kind": "added", "excerpt": "", "change": "new", "extra": 1},
     "exactly"),
])
def test_a_malformed_requirement_source_is_refused(record, reason):
    with pytest.raises(CapsuleValidationError, match=reason):
        AUTHORITATIVE_FIELDS["requirement_sources"]([record])


def test_two_records_for_one_requirement_are_refused_at_the_door():
    record = {"requirement": "RQ-1", "kind": "added", "excerpt": "", "change": "new"}
    with pytest.raises(CapsuleValidationError, match="duplicated"):
        AUTHORITATIVE_FIELDS["requirement_sources"]([record, dict(record)])


# ---------------------------------------------------------------------------
# No source, no BRD, no contract
# ---------------------------------------------------------------------------

def test_a_capsule_with_no_confirmed_source_derives_no_brd_and_no_contract():
    document = _document(source=None, records=None)
    with pytest.raises(BrdAuthoringError, match="no source specification has been confirmed"):
        brd_from_capsule(document)
    with pytest.raises(BrdAuthoringError, match="not bound to a confirmed source"):
        contract_from_capsule(document)


def test_a_proposed_source_binds_nothing_until_a_human_confirms_it():
    document = _document(source=None, records=None)
    document, _ = propose(document, "source_specification", {"text": SOURCE}, MODEL, next(_CLOCK))
    assert binding_problems(document) == ["no source specification has been confirmed"]
    with pytest.raises(BrdAuthoringError):
        brd_from_capsule(document)


def test_requirements_with_no_source_records_derive_nothing():
    with pytest.raises(BrdAuthoringError, match="no requirement sources have been confirmed"):
        brd_from_capsule(_document(records=None))


def test_an_intent_only_capsule_needs_its_source_and_no_records():
    document = _document(rows=None, records=None)
    assert binding_problems(document) == []
    assert SOURCE_BINDING_PREFIX + source_sha256(SOURCE) in brd_from_capsule(document)


@pytest.mark.parametrize("records, problem", [
    (RECORDS[:2], "RQ-3 has no confirmed source record"),
    ([*RECORDS, {"requirement": "RQ-9", "kind": "added", "excerpt": "", "change": "new"}],
     "names RQ-9, which is not a confirmed requirement"),
    ([{**RECORDS[0], "excerpt": "A person books a desk for a date."}, *RECORDS[1:]],
     "does not occur in the confirmed source"),
    ([{**RECORDS[1], "kind": "verbatim", "change": ""}, RECORDS[0], RECORDS[2]],
     "RQ-2 is recorded as verbatim but its text is not exactly its source part"),
    ([{**RECORDS[1], "excerpt": "An administrator cancels any booking."}, RECORDS[0], RECORDS[2]],
     "does not occur in the confirmed source"),
])
def test_a_record_that_does_not_match_the_source_or_the_requirements_is_refused(records, problem):
    document = _document(records=records)
    assert any(problem in item for item in binding_problems(document))
    with pytest.raises(BrdAuthoringError, match="not bound"):
        brd_from_capsule(document)


def test_a_proposal_is_still_judged_on_its_words_alone():
    """The binding is a relation between confirmed fields; a proposed intent
    or requirement set is not refused for lacking a source (A-048 holds)."""
    assert proposal_entry_refusal("intent", INTENT) is None
    assert proposal_entry_refusal("requirements", ROWS) is None


# ---------------------------------------------------------------------------
# The binding travels: BRD, parser, contract
# ---------------------------------------------------------------------------

def test_a_bound_brd_declares_the_specification_and_still_reads_back_exactly():
    rendered = brd_from_capsule(_document())
    assert brd_source_binding(rendered) == source_sha256(SOURCE)
    model = parse_brd_text(rendered, "BRD.md")
    assert model.specification_digest == source_sha256(SOURCE)
    assert [item.statement for item in model.requirements] == [INTENT, *(row["text"] for row in ROWS)]


def test_the_contract_names_the_brd_revision_and_the_specification():
    document = _document()
    rendered = brd_from_capsule(document)
    goal = yaml.safe_load(contract_from_capsule(document))["intents"][0]["goal"]
    model = parse_brd_text(rendered, "BRD.md")
    assert model.source_digest in goal
    assert "sha256:" + source_sha256(SOURCE) in goal


def test_a_brd_that_declares_no_specification_keeps_the_contract_it_always_had():
    text = "# BRD — Demo\n\n## BRD-001 Purpose\n\nShip it.\n"
    model = parse_brd_text(text, "BRD.md")
    assert model.specification_digest is None
    contract = yaml.safe_load(render_brd_contract(model, template="certified"))
    assert contract["intents"][0]["goal"] == (
        "Convert the exact BRD revision into a tested, architecture-conformant, "
        "evidence-backed application.")


@pytest.mark.parametrize("text", [
    # Under a heading, a declaration is a requirement's words, not the BRD's.
    "# BRD — Demo\n\n## BRD-001 Purpose\n\n" + SOURCE_BINDING_PREFIX + "a" * 64 + "\n",
    # Two declarations that disagree declare nothing.
    "# BRD — Demo\n\n" + SOURCE_BINDING_PREFIX + "a" * 64 + "\n"
    + SOURCE_BINDING_PREFIX + "b" * 64 + "\n\n## BRD-001 Purpose\n\nShip it.\n",
    # Not 64 lower-case hex digits.
    "# BRD — Demo\n\n" + SOURCE_BINDING_PREFIX + "A" * 64 + "\n\n## BRD-001 Purpose\n\nShip it.\n",
])
def test_only_one_well_formed_declaration_above_the_first_section_counts(text):
    assert brd_source_binding(text) is None


# ---------------------------------------------------------------------------
# Losses become visible
# ---------------------------------------------------------------------------

def test_the_report_shows_the_source_no_requirement_carries_across():
    report = provenance_report(_document())
    assert report["bound"] is True
    assert report["source_sha256"] == source_sha256(SOURCE)
    uncovered = [part["excerpt"] for part in report["uncovered"]]
    assert "# Room booking" in uncovered
    assert "Two bookings of one room never overlap." in uncovered
    assert "Bookings are kept for one year and then deleted." in uncovered
    assert not any("books a room" in part for part in uncovered)
    assert not any("Book meeting rooms" in part for part in uncovered)
    assert report["intent"]["found_verbatim"] is True
    assert report["uncovered_characters"] == sum(part["characters"] for part in report["uncovered"])


def test_the_report_carries_each_transformation_and_the_persons_note():
    entries = {entry["requirement"]: entry for entry in provenance_report(_document())["requirements"]}
    assert entries["RQ-1"]["kind"] == "verbatim" and entries["RQ-1"]["change"] == ""
    assert entries["RQ-2"]["kind"] == "changed"
    assert entries["RQ-2"]["change"] == "Added cancellation by an administrator."
    assert entries["RQ-3"]["kind"] == "added" and entries["RQ-3"]["start"] is None
    start = entries["RQ-1"]["start"]
    assert SOURCE[start:entries["RQ-1"]["end"]] == ROWS[0]["text"]


def test_a_part_that_occurs_twice_says_so():
    source = SOURCE + "A person books a room for a date and an hour.\n"
    entries = {entry["requirement"]: entry
               for entry in provenance_report(_document(source=source))["requirements"]}
    assert entries["RQ-1"]["occurrences"] == 2


def test_a_document_with_no_source_reports_nothing_measured():
    report = provenance_report(_document(source=None, records=None))
    assert report["bound"] is False and report["source_sha256"] is None
    assert report["uncovered"] == [] and report["uncovered_characters"] is None


# ---------------------------------------------------------------------------
# The receipt carries digests and offsets, never the text
# ---------------------------------------------------------------------------

def test_the_receipt_section_carries_no_source_text_and_no_change_note():
    section = source_projection(_document())
    dumped = json.dumps(section)
    assert "booking" not in dumped and "administrator" not in dumped
    assert section["specification_sha256"] == source_sha256(SOURCE)
    changed = next(entry for entry in section["requirements"] if entry["requirement"] == "RQ-2")
    assert len(changed["change_sha256"]) == 64
    assert section["bound"] is True and section["problems"] == 0


def _body_with(source: dict) -> dict:
    """A receipt body whose only questionable section is `source`: the other
    sections take the values an untracked, provider-less project has."""
    return {
        "forge": {"version": __import__("nornyx_forge").__version__,
                  "exporter": "nornyx_forge.journey_receipt"},
        "generated_at": "2026-11-05T12:00:00Z",
        "brd": {"present": False, "derived": False, "digest": None},
        "source": source,
        "journey": {"tracking": "absent", "stage": None, "status": None,
                    "lifecycle_digest": None, "events": [], "failure": None},
        "evidence": [],
        "provider": {"name": None, "platform": "windows", "eligible": None,
                     "confinement": None, "reason": None},
        "build": {"outcome": "none", "refusal": None, "recorded": False},
        "classification": {"execution": "none", "runnable_application": False,
                           "basis": ("no governed build is recorded for this project; no "
                                     "receipt establishes a runnable application, because "
                                     "Forge records no runnable verification of a produced "
                                     "application")},
    }


def test_a_consistent_source_section_passes_the_verifier():
    assert [p for p in _consistency_problems(_body_with(source_projection(_document())))
            if p.startswith("source")] == []


@pytest.mark.parametrize("edit, problem", [
    (lambda s: s.update(bound=False), "'bound' is exactly the absence"),
    (lambda s: s["requirements"][0].update(change_sha256="0" * 64), "change note exactly"),
    (lambda s: s["requirements"][0].update(end=10 ** 9), "impossible location"),
    (lambda s: s.update(uncovered_characters=1), "sum of the uncovered parts"),
    (lambda s: s["uncovered"].reverse(), "ordered, disjoint"),
    (lambda s: s.update(specification_sha256=None), "nothing is bound"),
    (lambda s: s.update(problems=-1), "not negative"),
])
def test_an_inconsistent_source_section_is_refused(edit, problem):
    section = source_projection(_document())
    edit(section)
    assert any(problem in p for p in _consistency_problems(_body_with(section)))


def test_the_page_offers_the_specification_and_renders_the_uncovered_parts():
    from nornyx_forge.onboarding_app import _PAGE

    for needle in ('id="source_spec"', "proposeSource()", "proposeRequirementSources()",
                   "renderProvenance(s.source_provenance)", "renderSourceRows(s.authoritative"):
        assert needle in _PAGE
    script = _PAGE[_PAGE.index("function renderProvenance"):]
    script = script[:script.index("\nfunction act(")]
    assert "innerHTML" not in script and "textContent" in script


def test_the_served_state_carries_the_provenance_report(tmp_path: Path):
    from session_client import authed_client

    from nornyx_forge.capsule_store import CapsuleStore
    from nornyx_forge.onboarding_app import create_app

    document = _document()
    CapsuleStore(tmp_path / "capsule").initialize(document)
    client = authed_client(create_app(tmp_path / "capsule", ROOT / ".nornyx" / "contracts",
                                      seal_dir=tmp_path / "seals"))
    state = client.get("/api/state").json()
    assert state["source_provenance"] == provenance_report(document)
    response = client.post("/api/brd")
    assert response.status_code == 200, response.text
    assert brd_source_binding(Path(response.json()["written"]).read_text(encoding="utf-8")) \
        == source_sha256(SOURCE)


def test_the_route_refuses_an_unbound_capsule_and_writes_nothing(tmp_path: Path):
    from session_client import authed_client

    from nornyx_forge.capsule_store import CapsuleStore
    from nornyx_forge.onboarding_app import create_app

    CapsuleStore(tmp_path / "capsule").initialize(_document(source=None, records=None))
    client = authed_client(create_app(tmp_path / "capsule", ROOT / ".nornyx" / "contracts",
                                      seal_dir=tmp_path / "seals"))
    response = client.post("/api/brd")
    assert response.status_code == 409
    assert "not bound to a confirmed source" in response.json()["refused"]
    assert not (tmp_path / "BRD.md").exists()


# ---------------------------------------------------------------------------
# Review of the first head: text with no UTF-8 form, records left behind by
# removed requirements, and a source editor that outlived its requirements
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("record", [
    {"requirement": "RQ-1", "kind": "changed", "excerpt": "x", "change": "Reason \ud800"},
    {"requirement": "RQ-1", "kind": "added", "excerpt": "", "change": "Reason \ud800"},
    {"requirement": "RQ-1", "kind": "changed", "excerpt": "x \udfff", "change": "Reason"},
    {"requirement": "RQ-1", "kind": "verbatim", "excerpt": "x \ud800", "change": ""},
])
def test_source_record_text_with_no_utf8_form_is_refused_at_the_door(record):
    with pytest.raises(CapsuleValidationError, match="cannot be written as UTF-8"):
        AUTHORITATIVE_FIELDS["requirement_sources"]([record])


def test_a_change_note_with_no_utf8_form_is_never_proposed_so_the_receipt_still_projects():
    document = _document()
    records = [dict(record) for record in RECORDS]
    records[1]["change"] = "Reason \ud800"
    with pytest.raises(CapsuleValidationError, match="UTF-8"):
        propose(document, "requirement_sources", records, MODEL, next(_CLOCK))
    assert source_projection(document)["bound"] is True


def test_records_left_by_removed_requirements_are_cleared_by_an_empty_record_list():
    document = _confirmed(_document(), "requirements", [])
    assert any("not a confirmed requirement" in p for p in binding_problems(document))
    with pytest.raises(BrdAuthoringError, match="not bound"):
        brd_from_capsule(document)
    document = _confirmed(document, "requirement_sources", [])
    assert binding_problems(document) == []
    assert SOURCE_BINDING_PREFIX + source_sha256(SOURCE) in brd_from_capsule(document)


def test_the_routes_accept_the_empty_record_list_that_clears_them(tmp_path: Path):
    from session_client import authed_client

    from nornyx_forge.capsule_store import CapsuleStore
    from nornyx_forge.onboarding_app import create_app

    CapsuleStore(tmp_path / "capsule").initialize(_confirmed(_document(), "requirements", []))
    client = authed_client(create_app(tmp_path / "capsule", ROOT / ".nornyx" / "contracts",
                                      seal_dir=tmp_path / "seals"))
    assert client.get("/api/state").json()["source_provenance"]["bound"] is False
    human = {"kind": "human", "ident": "casey"}
    response = client.post("/api/proposals", json={"field": "requirement_sources", "value": [],
                                                   "actor": human})
    assert response.status_code == 200, response.text
    response = client.post(f"/api/proposals/{response.json()['proposal_id']}/confirm",
                           json={"actor": human})
    assert response.status_code == 200, response.text
    assert client.get("/api/state").json()["source_provenance"]["bound"] is True
    assert client.post("/api/brd").status_code == 200


def _source_rows_script() -> str:
    from nornyx_forge.onboarding_app import _PAGE

    script = _PAGE[_PAGE.index("let sourcesEdited"):]
    return script[:script.index("\nfunction proposeRequirementSources(")]


def test_the_source_editor_keeps_a_draft_only_while_the_requirements_are_unchanged():
    script = _source_rows_script()
    # The early return that kept a draft is taken only for the requirement set
    # it was built for; a changed set rebuilds the rows, and a draft is carried
    # only to the requirement whose id and text it was written for.
    assert "if(sourcesEdited && rowsFor === sourceRowsFor){ return; }" in script
    assert "if(sourcesEdited){ return; }" not in script
    assert "drafts.get(JSON.stringify([row.id, row.text]))" in script


def test_the_record_proposal_is_offered_while_records_are_held_and_no_requirement_is():
    script = _source_rows_script()
    assert "!(source !== undefined && (rows.length || recorded.size))" in script


# ---------------------------------------------------------------------------
# Unmapped source text, one entry per Markdown block (A-061)
# ---------------------------------------------------------------------------

from nornyx_forge import source_provenance  # noqa: E402

#: A specification shaped the way real ones are: a section that is one list
#: with no blank line inside it, a nested list, an item that runs on to a
#: second line, a fenced example holding a blank line, and a numbered list.
BLOCKS_SOURCE = (
    "# Library loans\n"
    "\n"
    "Status: draft for review.\n"
    "\n"
    "## 1. Interface\n"
    "\n"
    "    loans --books BOOKS.csv --out OUTDIR\n"
    "\n"
    "- Input files:\n"
    "  - `BOOKS.csv`: `book_id,title`\n"
    "  - `LOANS.csv`: `loan_id,book_id,due`\n"
    "- Files are UTF-8; a field may contain commas inside quotes.\n"
    "- On invalid input it prints one line `ERROR <CODE> <file>:<line>` and\n"
    "  writes nothing to standard output.\n"
    "- OUTDIR is created with any missing parents.\n"
    "\n"
    "## 2. Requirements\n"
    "\n"
    "R1. A loan names exactly one book that exists.\n"
    "\n"
    "R2. A book is on loan to at most one person at a time.\n"
    "\n"
    "## 3. Worked example\n"
    "\n"
    "```\n"
    "book_id,title\n"
    "\n"
    "B-1,Atlas\n"
    "```\n"
    "\n"
    "1. Run it.\n"
    "2. Compare the output.\n"
)
BLOCKS_INTENT = "Track library loans."
BLOCKS_ROWS = [
    {"id": "RQ-1", "text": "A loan names exactly one book that exists."},
    {"id": "RQ-2", "text": "A book is on loan to at most one person at a time."},
]
BLOCKS_RECORDS = [
    {"requirement": "RQ-1", "kind": "changed",
     "excerpt": "R1. A loan names exactly one book that exists.",
     "change": "Dropped the R-number label."},
    {"requirement": "RQ-2", "kind": "changed",
     "excerpt": "R2. A book is on loan to at most one person at a time.",
     "change": "Dropped the R-number label."},
]


def _blocks_document(source: str = BLOCKS_SOURCE, records=None) -> dict:
    document = create_document("proj-2", "Library Loans", HUMAN, next(_CLOCK))
    document = _confirmed(document, "intent", BLOCKS_INTENT)
    document = _confirmed(document, "requirements", BLOCKS_ROWS)
    document = _confirmed(document, "source_specification", {"text": source})
    return _confirmed(document, "requirement_sources",
                      BLOCKS_RECORDS if records is None else records)


def _blocks_report(source: str = BLOCKS_SOURCE, records=None) -> dict:
    return provenance_report(_blocks_document(source, records))


def _entry(report: dict, starting: str) -> dict:
    found = [part for part in report["uncovered"] if part["excerpt"].startswith(starting)]
    assert len(found) == 1, (starting, [part["excerpt"][:40] for part in report["uncovered"]])
    return found[0]


def _line_of(text: str) -> int:
    return BLOCKS_SOURCE[:BLOCKS_SOURCE.index(text)].count("\n") + 1


def test_unmapped_text_is_one_entry_per_list_item_even_with_no_blank_line_between():
    report = _blocks_report()
    for item in ("- Files are UTF-8", "- On invalid input", "- OUTDIR is created"):
        entry = _entry(report, item)
        assert entry["block"] == "list item"
        assert entry["line"] == _line_of(item)


def test_each_entry_names_its_line_its_positions_and_its_text():
    report = _blocks_report()
    assert report["uncovered"]
    for part in report["uncovered"]:
        text = BLOCKS_SOURCE[part["start"]:part["end"]]
        assert text and text == text.strip()
        assert part["characters"] == part["end"] - part["start"]
        assert part["line"] == BLOCKS_SOURCE[:part["start"]].count("\n") + 1
        assert part["excerpt"] == text[:source_provenance.EXCERPT_PREVIEW]
        assert part["block"] in source_provenance.BLOCK_KINDS


def test_a_list_item_runs_on_through_its_continuation_line_and_nested_items_stand_alone():
    report = _blocks_report()
    entry = _entry(report, "- On invalid input")
    assert BLOCKS_SOURCE[entry["start"]:entry["end"]].endswith("writes nothing to standard output.")
    for nested in ("- `BOOKS.csv`", "- `LOANS.csv`"):
        assert _entry(report, nested)["block"] == "list item"
    assert _entry(report, "- Input files:")["excerpt"] == "- Input files:"


def test_headings_paragraphs_fenced_blocks_and_numbered_items_are_each_their_own_entry():
    report = _blocks_report()
    assert _entry(report, "# Library loans")["block"] == "heading"
    assert _entry(report, "## 3. Worked example")["block"] == "heading"
    assert _entry(report, "Status: draft")["block"] == "paragraph"
    fenced = _entry(report, "```")
    assert fenced["block"] == "fenced block"
    assert BLOCKS_SOURCE[fenced["start"]:fenced["end"]] == "```\nbook_id,title\n\nB-1,Atlas\n```"
    assert _entry(report, "1. Run it.")["block"] == "list item"
    assert _entry(report, "2. Compare")["block"] == "list item"


def test_mapped_blocks_are_not_reported_and_a_partly_mapped_block_reports_only_the_rest():
    assert not any("A loan names" in part["excerpt"] for part in _blocks_report()["uncovered"])
    records = [dict(BLOCKS_RECORDS[0], excerpt="A loan names exactly one book"),
               BLOCKS_RECORDS[1]]
    report = _blocks_report(records=records)
    head = _entry(report, "R1.")
    assert head["excerpt"] == "R1." and head["block"] == "paragraph"
    tail = _entry(report, "that exists.")
    assert tail["block"] == "paragraph" and tail["line"] == _line_of("R1. A loan")


def test_the_total_counts_the_unmapped_text_not_the_blank_lines_between_blocks():
    report = _blocks_report()
    parts = report["uncovered"]
    assert report["uncovered_characters"] == sum(part["characters"] for part in parts)
    assert all(a["end"] < b["start"] for a, b in zip(parts, parts[1:]))
    for part in parts:
        # A blank line separates blocks; only a fenced block may hold one.
        if "\n\n" in BLOCKS_SOURCE[part["start"]:part["end"]]:
            assert part["block"] == "fenced block"


@pytest.mark.parametrize("text, kind", [
    ("#hashtag is not a heading", "paragraph"),
    ("####### seven marks is not a heading", "paragraph"),
    ("+ a plus item", "list item"),
    ("3) a numbered item", "list item"),
    ("-not an item", "paragraph"),
])
def test_only_markdown_block_openers_open_a_block(text, kind):
    assert [block[2] for block in source_provenance._blocks(text)] == [kind]


def test_an_unclosed_fence_runs_to_the_end_of_the_text():
    text = "Intro.\n\n```\ncode\n\nmore code"
    assert [(text[s:e], k) for s, e, k in source_provenance._blocks(text)] == [
        ("Intro.", "paragraph"), ("```\ncode\n\nmore code", "fenced block")]


def test_block_entries_still_make_a_receipt_section_the_verifier_accepts():
    section = source_projection(_blocks_document())
    assert len(section["uncovered"]) > 10
    assert [p for p in _consistency_problems(_body_with(section)) if p.startswith("source")] == []


def test_the_page_calls_it_unmapped_source_text_and_claims_nothing_is_missing():
    from nornyx_forge.onboarding_app import _PAGE

    script = _PAGE[_PAGE.index("function renderProvenance"):]
    script = script[:script.index("\nfunction act(")]
    assert "Unmapped source text" in script
    assert "part.line" in script and "part.block" in script
    assert "carries across" not in script
    assert "missing" not in script.lower()


def _line_breaks_inside_js_strings(script: str) -> list[int]:
    """The lines on which a quoted JavaScript string holds a raw line break.

    `_PAGE` is an ordinary Python string, so a `\\n` written inside a page
    string reaches the browser as a real line break, and a quoted JavaScript
    string cannot hold one: the whole script then fails to parse and no
    control on the page works. A small scan, not a JavaScript parser: it
    skips comments, template literals and regular-expression literals, and
    reports where a '...' or "..." string meets a line break."""
    found: list[int] = []
    index, line, quote, previous = 0, 1, None, ""
    while index < len(script):
        char = script[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == "\n":
                found.append(line)
                quote = None
            elif char == quote:
                quote = None
        elif script.startswith("//", index):
            index = script.find("\n", index)
            index = len(script) if index < 0 else index
            continue
        elif script.startswith("/*", index):
            end = script.find("*/", index + 2)
            end = len(script) if end < 0 else end + 2
            line += script.count("\n", index, end)
            index = end
            continue
        elif char in "'\"":
            quote = char
        elif char == "`":
            end = index + 1
            while end < len(script) and script[end] != "`":
                end += 2 if script[end] == "\\" else 1
            line += script.count("\n", index, end)
            index = end + 1
            continue
        elif char == "/" and previous in "(,=:[!&|?{};+-*%<>~^" + "\n":
            end, in_class = index + 1, False
            while end < len(script) and script[end] != "\n":
                if script[end] == "\\":
                    end += 2
                    continue
                if script[end] == "[":
                    in_class = True
                elif script[end] == "]":
                    in_class = False
                elif script[end] == "/" and not in_class:
                    break
                end += 1
            index = end + 1
            previous = "x"
            continue
        if char == "\n":
            line += 1
        if not char.isspace():
            previous = char
        elif char == "\n":
            previous = previous if previous else "\n"
        index += 1
    return found


def test_the_page_script_has_no_line_break_inside_a_string_literal():
    import re

    from nornyx_forge.onboarding_app import _PAGE

    scripts = re.findall(r"<script[^>]*>(.*?)</script>", _PAGE, re.S)
    assert scripts
    for script in scripts:
        assert _line_breaks_inside_js_strings(script) == []
    # The scan sees the defect it exists for: the separator the source editor
    # once wrote reached the browser as a real line break.
    assert _line_breaks_inside_js_strings('const a = [1].join("\n");\nlet b = 1;')[:1] == [1]
    assert _line_breaks_inside_js_strings('const a = [1].join("\\n"); // "\nx = `\n`;') == []


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["LF", "CRLF"])
def test_a_closing_fence_ends_its_block_whatever_the_line_ending(newline):
    # A CRLF line kept its carriage return, so its closing fence was never
    # recognised and the fence swallowed what followed (Codex P2 4492746866).
    text = newline.join(["```", "code", "```", "- first item", "- second item", ""])
    blocks = source_provenance._blocks(text)
    assert [kind for _, _, kind in blocks] == ["fenced block", "list item", "list item"]
    assert [text[start:end] for start, end, _ in blocks] == [
        newline.join(["```", "code", "```"]), "- first item", "- second item"]


def test_a_crlf_source_reports_the_lf_entries_at_its_own_exact_offsets():
    crlf = BLOCKS_SOURCE.replace("\n", "\r\n")
    lf_entries = source_provenance._unmapped(BLOCKS_SOURCE, [])
    crlf_entries = source_provenance._unmapped(crlf, [])
    assert [(entry["block"], entry["line"]) for entry in crlf_entries] == [
        (entry["block"], entry["line"]) for entry in lf_entries]
    for lf, cr in zip(lf_entries, crlf_entries):
        text = crlf[cr["start"]:cr["end"]]
        assert text == BLOCKS_SOURCE[lf["start"]:lf["end"]].replace("\n", "\r\n")
        assert text == text.strip() and cr["characters"] == cr["end"] - cr["start"]
    after = [entry for entry in crlf_entries if crlf[entry["start"]:].startswith("1. Run it.")]
    assert after and after[0]["block"] == "list item"


def test_a_confirmed_specification_cannot_hold_a_carriage_return():
    # The capsule refuses a CR in the text, so CRLF reaches the report only
    # if that rule changes; the block reader handles it anyway.
    with pytest.raises(CapsuleValidationError, match="control characters"):
        AUTHORITATIVE_FIELDS["source_specification"]({"text": "line one\r\nline two"})
