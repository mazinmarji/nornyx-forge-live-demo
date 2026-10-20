"""One requirement-identity rule for the BRD derivation, the parser and the verifier.

THE DEFECT THIS PINS (A-045). The BRD that `brd_from_capsule` derives from a
capsule carrying confirmed requirements puts them under a section heading,
`## BRD-002 Functional requirements`, with the requirements as `### BRD-F-*`
headings beneath it. `parse_brd`, which the flow builds from, treated that
empty section heading as no requirement; the trusted greenfield verifier
counted every `BRD-*` heading of levels 2 to 6 as one and refused the build
with "tests do not reference BRD-002". So a build from confirmed requirements
was always refused by Forge's own acceptance profile, whatever was built.
Three readers of one document held three rules, and they disagreed on other
shapes too: an identifier heading at level 4, an untitled one, one whose
identifier runs into punctuation, a duplicated one, and a line break that
`str.splitlines` honours and a multi-line regular expression does not.

THE RULE, ONCE. `requirements.brd_requirement_identity` decides what a
requirement is. The parser reads requirements through it, the derivation
checks its own rendering against it, and the verifier -- which executes from
a digest-verified snapshot and imports no first-party code -- carries a
verbatim copy that `test_the_verifier_carries_the_rule_verbatim` holds
character for character. A section is an identifier heading with no
statement of its own and at least one requirement beneath it; it needs no
test of its own because it states nothing to test. Every requirement still
needs one. An identifier heading that is neither -- untitled, duplicated, a
malformed identifier, or empty with nothing beneath it -- is REFUSED by the
verifier rather than silently dropped, which the old rule could not do.

WHAT IS NOT WEAKENED, measured both ways here: a confirmed requirement no
test names is refused, the purpose requirement no test names is refused, and
every identifier heading the old verifier demanded a reference for is still
either demanded or refused, except a section that states nothing.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from nornyx_forge import greenfield_verifier, requirements
from nornyx_forge.brd_authoring import BrdAuthoringError, brd_from_capsule
from nornyx_forge.capsule import Actor, confirm, create_document, propose
from nornyx_forge.gates import trusted_greenfield_gates
from nornyx_forge.requirements import parse_brd

HUMAN = Actor(kind="human", ident="casey")
INTENT = "Build a customer support portal with case tracking."
#: Forge's own synthetic specimen, not anyone's product requirements.
ROWS = [
    {"id": "RQ-1", "text": "A support agent opens a case with a title and a priority."},
    {"id": "RQ-2", "text": "A support agent assigns a case to a colleague."},
    {"id": "RQ-3", "text": "A support agent closes a case with a resolution note."},
]


def _document(rows: list[dict[str, str]] | None = None) -> dict:
    document = create_document("proj-1", "Support Portal", HUMAN, "2026-08-30T12:00:00Z")
    document, intent_id = propose(document, "intent", INTENT, HUMAN, "2026-08-30T12:01:00Z")
    document = confirm(document, intent_id, HUMAN, "2026-08-30T12:02:00Z")
    if rows:
        document, req_id = propose(document, "requirements", rows, HUMAN, "2026-08-30T12:03:00Z")
        document = confirm(document, req_id, HUMAN, "2026-08-30T12:04:00Z")
    return document


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def _project(root: Path, brd: str, referenced: list[str]) -> Path:
    """A project the verifier accepts on every gate but traceability, which
    is decided by which identifiers the tests name."""
    _write(root / "BRD.md", brd)
    _write(root / "src/app.py", "def add(left: int, right: int) -> int:\n    return left + right\n")
    _write(root / "tests/test_app.py", "from src.app import add\n" + "".join(
        f"\n\ndef test_{index}():\n    # {ident}\n    assert add(1, {index}) == {index + 1}\n"
        for index, ident in enumerate(referenced, start=1)))
    return root


def _gates(root: Path) -> dict[str, tuple[bool, str]]:
    gates, _provenance = trusted_greenfield_gates(root)
    return {gate.name.split(":", 1)[-1]: (gate.passed, gate.detail) for gate in gates}


def _ids(text: str, tmp_path: Path) -> list[str]:
    target = tmp_path / "parsed" / "BRD.md"
    _write(target, text)
    return [item.id for item in parse_brd(target).requirements]


# ---------------------------------------------------------------------------
# The defect, end to end: Forge's derived BRD against Forge's own verifier
# ---------------------------------------------------------------------------

def test_the_derived_brd_of_confirmed_requirements_passes_the_verifier(tmp_path: Path):
    """RED BEFORE THE FIX: refused with "tests do not reference BRD-002".
    Tests that name exactly what the flow's parser reads pass every gate."""
    brd = brd_from_capsule(_document(ROWS))
    assert "## BRD-002 Functional requirements" in brd.splitlines()
    ids = _ids(brd, tmp_path)
    assert ids == ["BRD-001", "BRD-F-001", "BRD-F-002", "BRD-F-003"]
    verdicts = _gates(_project(tmp_path / "project", brd, ids))
    assert all(passed for passed, _detail in verdicts.values()), verdicts
    assert verdicts["requirements-traceability"][1] == "tests reference all 4 BRD requirement headings"


@pytest.mark.parametrize("missing", ["BRD-F-002", "BRD-001"])
def test_a_confirmed_requirement_no_test_names_is_still_refused(tmp_path: Path, missing: str):
    """The negative control, held on both sides of the fix: one requirement
    left unnamed by every test -- a confirmed requirement or the purpose --
    is refused by name, and the build cannot be accepted."""
    brd = brd_from_capsule(_document(ROWS))
    referenced = [ident for ident in _ids(brd, tmp_path) if ident != missing]
    passed, detail = _gates(_project(tmp_path / "project", brd, referenced))["requirements-traceability"]
    assert passed is False
    assert f"tests do not reference {missing}" in detail


def test_a_section_with_no_requirement_beneath_it_is_refused_even_when_named(tmp_path: Path):
    """RED BEFORE THE FIX: the old verifier accepted it once a test named
    it. An identifier heading with no statement and nothing beneath it is
    neither a requirement nor a section, and naming it in a test states
    nothing; it is refused, and the parser reports it rather than dropping it."""
    brd = ("# BRD\n\n## BRD-001 Purpose\n\nTrack cases.\n\n## BRD-002 Payments\n\n"
           "## BRD-003 Reports\n\nShow a weekly report.\n")
    passed, detail = _gates(_project(tmp_path / "project", brd,
                                     ["BRD-001", "BRD-002", "BRD-003"]))["requirements-traceability"]
    assert passed is False
    assert "BRD-002 is neither a requirement nor a section" in detail
    target = tmp_path / "BRD.md"
    _write(target, brd)
    model = parse_brd(target)
    assert [item.id for item in model.requirements] == ["BRD-001", "BRD-003"]
    assert any("BRD-002" in note for note in model.assumptions), model.assumptions


@pytest.mark.parametrize("heading, reason", [
    ("## BRD-002", "an identifier followed by a space and a title"),
    ("## BRD-002: Exports", "an identifier followed by a space and a title"),
    ("## BRD-F--2 Exports", "an identifier followed by a space and a title"),
])
def test_an_identifier_heading_off_the_grammar_is_refused_even_when_named(
        tmp_path: Path, heading: str, reason: str):
    """RED BEFORE THE FIX: the old verifier demanded a reference to each of
    these and then accepted it, while the parser never read them as
    requirements -- so the flow built without them and acceptance passed."""
    brd = f"# BRD\n\n## BRD-001 Purpose\n\nTrack cases.\n\n{heading}\n\nExport cases as CSV.\n"
    candidate = heading.split()[1].rstrip(":")
    passed, detail = _gates(_project(tmp_path / "project", brd,
                                     ["BRD-001", candidate]))["requirements-traceability"]
    assert passed is False
    assert "is neither a requirement nor a section" in detail and reason in detail


def test_a_duplicated_identifier_is_refused(tmp_path: Path):
    brd = ("# BRD\n\n## BRD-001 Purpose\n\nTrack cases.\n\n## BRD-001 Again\n\nSomething else.\n")
    passed, detail = _gates(_project(tmp_path / "project", brd, ["BRD-001"]))["requirements-traceability"]
    assert passed is False
    assert "names more than one heading" in detail
    assert _ids(brd, tmp_path) == []


def test_a_deeper_identifier_heading_is_a_requirement_for_every_reader(tmp_path: Path):
    """RED BEFORE THE FIX: the parser folded a level-4 identifier heading
    into its parent's statement while the verifier demanded a test for it."""
    brd = ("# BRD\n\n## BRD-001 Purpose\n\nTrack cases.\n\n### BRD-F-001 Intake\n\nOpen a case.\n\n"
           "#### BRD-F-001-A Priority\n\nA case carries a priority.\n")
    assert _ids(brd, tmp_path) == ["BRD-001", "BRD-F-001", "BRD-F-001-A"]
    target = tmp_path / "BRD.md"
    _write(target, brd)
    statements = {item.id: item.statement for item in parse_brd(target).requirements}
    assert statements["BRD-F-001"] == "Open a case."
    passed, detail = _gates(_project(tmp_path / "project", brd,
                                     ["BRD-001", "BRD-F-001"]))["requirements-traceability"]
    assert passed is False and "tests do not reference BRD-F-001-A" in detail


# ---------------------------------------------------------------------------
# One rule: the verifier's copy is the parser's rule, character for character
# ---------------------------------------------------------------------------

CORPUS = [
    "# BRD\n\n## BRD-001 Purpose\n\nOne.\n",
    "# BRD\n\n## BRD-001 Purpose\n\nOne.\n\n## BRD-002 Functional requirements\n\n"
    "### BRD-F-001 A\n\nAlpha.\n\n### BRD-F-002 B\n\n- Beta.\n",
    "## BRD-002 Section\n\n### Notes\n\n#### BRD-F-001 Deep\n\nDeep text.\n",
    "## BRD-002 Section with intro\n\nIntro.\n\n### BRD-F-001 Child\n\nChild.\n",
    "## BRD-002 Empty\n\n## BRD-003 Next\n\nText.\n",
    "## BRD-002\n\nUntitled.\n",
    "## BRD-002: Colon\n\nText.\n",
    "## BRD-001 Twice\n\nOne.\n\n### BRD-001 Again\n\nTwo.\n",
    "## BRD-001 Purpose\r\n\r\nWindows line endings.\r\n",
    "## BRD-001 Purpose\n\nText ## BRD-009 Hidden\n\nInjected.\n",
    "##\nBRD-009 Split\n\nText.\n",
    "# BRD-001 Title level\n\nText.\n",
    "## Purpose\n\nNo identifier at all.\n",
]


def test_the_verifier_carries_the_rule_verbatim():
    """The verifier imports nothing first-party, so it carries the rule as
    a copy; the copy is the parser's function, character for character."""
    assert inspect.getsource(greenfield_verifier.brd_requirement_identity) == inspect.getsource(
        requirements.brd_requirement_identity)


@pytest.mark.parametrize("text", CORPUS)
def test_every_reader_takes_the_same_identities(tmp_path: Path, text: str):
    rule = requirements.brd_requirement_identity(text)
    assert greenfield_verifier.brd_requirement_identity(text) == rule
    assert _ids(text, tmp_path) == [entry["id"] for entry in rule["requirements"]]


# ---------------------------------------------------------------------------
# The derivation checks its own rendering against the rule
# ---------------------------------------------------------------------------

def test_the_derivation_reads_back_as_exactly_the_confirmed_identities():
    rule = requirements.brd_requirement_identity(brd_from_capsule(_document(ROWS)))
    assert [entry["id"] for entry in rule["requirements"]] == [
        "BRD-001", "BRD-F-001", "BRD-F-002", "BRD-F-003"]
    assert rule["sections"] == ["BRD-002"] and rule["malformed"] == []
    intent_only = requirements.brd_requirement_identity(brd_from_capsule(_document()))
    assert [entry["id"] for entry in intent_only["requirements"]] == ["BRD-001"]
    assert intent_only["sections"] == [] and intent_only["malformed"] == []


@pytest.mark.parametrize("text", [
    "Agents work. ## BRD-999 Injected requirement",
    "Agents work.\x85### BRD-F-999 Injected requirement",
])
def test_a_rendering_that_would_read_back_differently_is_refused(text: str):
    """RED BEFORE THE FIX: a confirmed text carrying a line separator that
    `str.splitlines` honours rendered a BRD whose parse held a requirement
    nobody confirmed. The derivation now refuses any rendering whose
    identities are not exactly the confirmed ones."""
    with pytest.raises(BrdAuthoringError, match="requirement-identity rule"):
        brd_from_capsule(_document([{"id": "RQ-1", "text": text}]))
