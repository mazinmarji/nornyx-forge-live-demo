"""A basic user enters requirements as rows on the page, and what would be
refused later is refused at proposal time, in plain language (A-048).

THE DEFECT. The onboarding page had one textarea. A need written over several
lines -- the natural way to list what an application must do -- was accepted
as a proposal and confirmed into the capsule's authority, and only then did
the BRD derivation refuse it, in the parser's terms: "the confirmed intent
collides with the BRD's heading grammar". The capsule's `requirements` field,
which the derivation renders one row per requirement, was reachable through
the API alone. Measured at 3e47ad9 through the app: a multi-line intent
proposal answered 200, its confirmation 200, and `POST /api/brd` 409.

WHAT THIS MODULE HOLDS.

* The rule, asked early. `proposal_entry_refusal` refuses an intent or a set
  of requirement rows that the derivation would refuse, or that the capsule's
  field schema refuses, and two kinds of row nobody means to confirm: an
  empty row and a row repeating another. Each refusal carries a plain-language
  explanation that says what to change and the verbatim technical reason.
* The doors. `POST /api/proposals` asks it before anything is stored, and
  `POST /api/proposals/{id}/confirm` asks it again before an open proposal
  that some other path stored is confirmed. A refusal stores nothing and
  moves no authority. Proposals that pass are unchanged: same route, same
  body, same answer, same capsule rule, same human confirmation.
* The page. A row editor on the existing page, built with the DOM APIs the
  page already uses: labelled rows, native buttons, an announced notice, the
  failing row marked and focused. It proposes the existing `requirements`
  field through the existing route. No JavaScript executes in this suite, so
  the page is pinned on its source text, as the session tests pin it.

What it does not hold, and the change it makes for intent-only API callers,
are stated once in A-048.
"""

from __future__ import annotations

import html.parser
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from session_client import authed_client

from nornyx_forge import brd_authoring
from nornyx_forge.brd_authoring import BrdAuthoringError, brd_from_capsule
from nornyx_forge.capsule import Actor, propose
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.onboarding_app import create_app

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / ".nornyx" / "contracts"
HUMAN = {"kind": "human", "ident": "casey"}
MODEL = Actor(kind="model", ident="builder-model")
NEED = "Build a customer support portal."
ROWS = [
    {"id": "RQ-1", "text": "A support agent opens a case with a title and a priority."},
    {"id": "RQ-2", "text": "A support agent assigns a case to a colleague."},
    {"id": "RQ-3", "text": "A support agent moves a case from open to resolved."},
]
#: The page's CSP at 3e47ad9, byte for byte: the row editor adds no source.
BASE_CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'"
)
#: The derivation's own refusal of a value that breaks the heading grammar.
HEADING_GRAMMAR = "collides with the BRD's heading grammar"


def _clock():
    ticks = iter(range(10_000))
    return lambda: f"2026-10-21T{(next(ticks) // 60) % 24:02d}:{next(ticks) % 60:02d}:00Z"


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(tmp_path / "capsule", CONTRACTS_DIR, clock=_clock(),
                      seal_dir=tmp_path / "seals")


@pytest.fixture()
def client(app) -> TestClient:
    client = authed_client(app)
    created = client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Support Portal", "actor": HUMAN})
    assert created.status_code == 200, created.text
    return client


def proposal_entry_refusal(field: str, value):
    """The rule under test, resolved when a test runs, so that each test
    fails on its own reason where the rule does not exist."""
    return brd_authoring.proposal_entry_refusal(field, value)


def _rows(*texts: str) -> list[dict[str, str]]:
    """Rows as the page composes them for a fresh editor: RQ-1, RQ-2, ..."""
    return [{"id": f"RQ-{index}", "text": text} for index, text in enumerate(texts, start=1)]


def _propose(client: TestClient, field: str, value):
    return client.post("/api/proposals", json={"field": field, "value": value, "actor": HUMAN})


def _confirm(client: TestClient, proposal_id: str):
    return client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": HUMAN})


def _state(client: TestClient) -> dict:
    return client.get("/api/state").json()


def _assert_refusal(refusal, *, row: str | None, explains: str,
                    reason: str) -> None:
    assert refusal is not None, "the entry was not refused"
    assert refusal.row == row
    assert explains in refusal.explanation, refusal.explanation
    assert reason in refusal.reason, refusal.reason
    # Plain language: the explanation never leads with the parser's vocabulary.
    for term in ("BRD", "heading grammar", "parser", "splitlines", "RQ-<n>"):
        assert term not in refusal.explanation, (term, refusal.explanation)


# ---------------------------------------------------------------------------
# The rule, asked at proposal time
# ---------------------------------------------------------------------------

def test_a_multi_line_need_is_refused_with_the_derivations_own_reason():
    """The defect's own input. The reason quotes the derivation verbatim --
    the same words `POST /api/brd` used to return after confirmation -- after
    a prefix saying when they would apply: the derivation speaks of "the
    confirmed intent", and at a proposal nothing is confirmed yet."""
    value = "I need a tracker.\n- It lists requests.\n- It exports them."
    with pytest.raises(BrdAuthoringError) as derived:
        brd_from_capsule({"authoritative": {"project_name": "P", "intent": value}})
    refusal = proposal_entry_refusal("intent", value)
    _assert_refusal(refusal, row=None, explains="one line", reason=HEADING_GRAMMAR)
    assert refusal.reason == brd_authoring.DERIVATION_WOULD_REFUSE + str(derived.value)
    assert refusal.reason.startswith("once confirmed, the BRD derivation would refuse this: ")
    assert "requirement" in refusal.explanation and "row" in refusal.explanation


@pytest.mark.parametrize("value, explains", [
    ("# My tracker", "“#”"),
    ("   # My tracker", "“#”"),
    ("## BRD-009 A tracker", "“#”"),
])
def test_a_need_the_heading_grammar_would_refuse_is_refused(value: str, explains: str):
    _assert_refusal(proposal_entry_refusal("intent", value), row=None,
                    explains=explains, reason=HEADING_GRAMMAR)


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\x85"])
def test_a_line_boundary_the_derivation_does_not_name_is_still_one(separator: str):
    """`str.splitlines` ends a line at these, so a reader of the rendered
    document sees two lines where the user typed one field. The line rule
    is the reader's, not the two characters the derivation spells."""
    refusal = proposal_entry_refusal("intent", f"A tracker{separator}that lists requests")
    _assert_refusal(refusal, row=None, explains="one line", reason="line boundary")


@pytest.mark.parametrize("value, explains, reason", [
    ("   ", "empty", "intent must not be empty"),
    ("x" * 4001, "4000", "intent exceeds 4000 characters"),
    ("A tracker\x07", "character", "intent contains control characters"),
    (42, "text", "intent must be a string"),
])
def test_a_need_the_capsule_refuses_is_explained(value, explains: str, reason: str):
    _assert_refusal(proposal_entry_refusal("intent", value), row=None,
                    explains=explains, reason=reason)


def test_a_single_line_need_and_every_other_field_pass_unchanged():
    assert proposal_entry_refusal("intent", NEED) is None
    assert proposal_entry_refusal("provider", {"name": "codex"}) is None
    assert proposal_entry_refusal("project_name", "Support Portal") is None
    assert proposal_entry_refusal("requirements", ROWS) is None
    assert proposal_entry_refusal("requirements", []) is None


@pytest.mark.parametrize("text, explains, reason", [
    ("", "empty", "requirement RQ-2 text must not be empty"),
    ("  ", "empty", "requirement RQ-2 text must not be empty"),
    ("x" * 2001, "2000", "requirement RQ-2 text exceeds 2000 characters"),
    ("Assigns\x1b a case", "character", "requirement RQ-2 text contains control characters"),
    ("Assigns a case.\nAnd closes it.", "one line", HEADING_GRAMMAR),
    ("# Assigns a case", "“#”", HEADING_GRAMMAR),
    ("Assigns a case\u2028to a colleague", "one line", "line boundary"),
])
def test_a_malformed_row_is_refused_and_named(text: str, explains: str, reason: str):
    rows = _rows("Opens a case.", text, "Resolves a case.")
    refusal = proposal_entry_refusal("requirements", rows)
    _assert_refusal(refusal, row="RQ-2", explains=explains, reason=reason)
    assert "RQ-2" in refusal.explanation


@pytest.mark.parametrize("repeat", [
    "Opens a case.", "opens a case.", "  Opens   a case.  ", "OPENS A CASE.",
])
def test_a_row_repeating_another_is_refused_and_the_later_one_named(repeat: str):
    refusal = proposal_entry_refusal("requirements", _rows("Opens a case.", "Assigns a case.", repeat))
    _assert_refusal(refusal, row="RQ-3", explains="RQ-1", reason="repeats requirement RQ-1")


@pytest.mark.parametrize("value, row, explains, reason", [
    ("RQ-1: opens a case", None, "list", "requirements must be a list"),
    ([{"id": "RQ-1"}], "row 1", "id and a text", "exactly {id, text}"),
    ([{"id": "R1", "text": "Opens a case."}], "row 1", "RQ-1", "must match RQ-<n>"),
    ([{"id": "RQ-1", "text": "Opens a case."}, {"id": "RQ-1", "text": "Assigns a case."}],
     "RQ-1", "same number", "requirement id RQ-1 is duplicated"),
    ([{"id": "RQ-1", "text": 7}], "RQ-1", "text", "requirement RQ-1 text must be a string"),
])
def test_a_set_an_api_caller_composed_wrongly_is_explained(value, row, explains: str, reason: str):
    refusal = proposal_entry_refusal("requirements", value)
    assert refusal is not None and refusal.row == row
    assert explains in refusal.explanation and reason in refusal.reason, refusal


def test_the_refusal_body_carries_the_reason_where_clients_already_read_it():
    body = proposal_entry_refusal("requirements", _rows("Opens a case.", "")).as_body()
    assert body == {
        "refused": "requirement RQ-2 text must not be empty",
        "explanation": body["explanation"],
        "field": "requirements",
        "row": "RQ-2",
    }


# ---------------------------------------------------------------------------
# The doors: proposal, and confirmation of what another path stored
# ---------------------------------------------------------------------------

def test_the_defect_is_refused_at_the_proposal_and_nothing_is_stored(client: TestClient):
    """Before: 200, then 200 on confirm, then 409 from `/api/brd`. Now: 422
    at the proposal, in plain words, with the parser's words beneath."""
    before = _state(client)
    response = _propose(client, "intent", "I need a tracker.\n- It lists requests.")
    assert response.status_code == 422, response.text
    body = response.json()
    assert HEADING_GRAMMAR in body["refused"] and "one line" in body["explanation"]
    assert body["field"] == "intent" and body["row"] is None
    after = _state(client)
    assert after["proposals"] == before["proposals"] == []
    assert after["authoritative"] == before["authoritative"]


@pytest.mark.parametrize("rows, row", [
    (_rows("Opens a case.", ""), "RQ-2"),
    (_rows("Opens a case.", "opens a case."), "RQ-2"),
    (_rows("Opens a case.\nAssigns it."), "RQ-1"),
    (_rows("# Opens a case."), "RQ-1"),
])
def test_malformed_rows_are_refused_before_any_confirmation_exists(
        client: TestClient, rows, row: str):
    response = _propose(client, "requirements", rows)
    assert response.status_code == 422, response.text
    assert response.json()["row"] == row
    assert _state(client)["proposals"] == []


def test_an_open_proposal_stored_before_this_run_is_refused_at_confirmation(
        client: TestClient, tmp_path: Path):
    """Any actor may propose through the capsule -- that is its design -- and a
    store can hold an open proposal written before this change, or by
    another path, before this run began. Such a value is refused at the
    human's confirmation, before it reaches authority, not after, at the BRD.
    The proposal is written through the sealed store between two runs, the
    way an earlier Forge would have left it; the second run serves it."""
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    updated, proposal_id = propose(store.load(), "intent", "Line one.\nLine two.", MODEL,
                                   "2026-10-21T00:00:00Z")
    store.save(updated, "test: a proposal stored before this run")
    second_run = authed_client(create_app(tmp_path / "capsule", CONTRACTS_DIR, clock=_clock(),
                                          seal_dir=tmp_path / "seals"))
    before = _state(second_run)
    assert "finding" not in before, before
    assert [(p["proposal_id"], p["status"]) for p in before["proposals"]] == [(proposal_id, "open")]
    response = _confirm(second_run, proposal_id)
    assert response.status_code == 422, response.text
    assert HEADING_GRAMMAR in response.json()["refused"]
    assert "one line" in response.json()["explanation"]
    after = _state(second_run)
    assert "intent" not in after["authoritative"]
    assert [p["status"] for p in after["proposals"]] == ["open"]


def test_a_confirmed_set_is_not_altered_by_editing_or_proposing_again(client: TestClient):
    """The rows on the page are a draft: what the capsule holds changes only
    by a new proposal AND its human confirmation. A second proposal leaves
    the confirmed set, and the BRD derived from it, exactly as confirmed."""
    assert _propose(client, "intent", NEED).status_code == 200
    assert _confirm(client, "P-1").status_code == 200
    assert _propose(client, "requirements", ROWS).json() == {"proposal_id": "P-2", "status": "open"}
    assert _confirm(client, "P-2").status_code == 200
    first = client.post("/api/brd")
    assert first.status_code == 200, first.text
    brd = Path(first.json()["written"]).read_text(encoding="utf-8")

    edited = [*ROWS[:1], {"id": "RQ-2", "text": "A support agent deletes every case."}]
    assert _propose(client, "requirements", edited).json() == {"proposal_id": "P-3", "status": "open"}
    held = _state(client)
    assert held["authoritative"]["requirements"] == ROWS
    again = client.post("/api/brd")
    assert again.status_code == 200
    assert Path(again.json()["written"]).read_text(encoding="utf-8") == brd
    assert "deletes every case" not in brd


def test_a_confirmed_set_edited_on_disk_is_named_tampered(client: TestClient, tmp_path: Path):
    """Out-of-band, not through a proposal: the seal and chain refuse it."""
    assert _propose(client, "intent", NEED).status_code == 200
    assert _confirm(client, "P-1").status_code == 200
    assert _propose(client, "requirements", ROWS).status_code == 200
    assert _confirm(client, "P-2").status_code == 200
    capsule = tmp_path / "capsule" / "capsule.json"
    text = capsule.read_text(encoding="utf-8")
    assert ROWS[1]["text"] in text
    capsule.write_text(text.replace(ROWS[1]["text"], "A support agent deletes every case."),
                       encoding="utf-8")
    state = _state(client)
    assert state.get("finding") == "TAMPERED", state
    refused = client.post("/api/brd")
    assert refused.status_code == 409 and refused.json().get("finding") == "TAMPERED"


def test_the_intent_only_path_answers_exactly_as_before(client: TestClient):
    assert _propose(client, "intent", NEED).json() == {"proposal_id": "P-1", "status": "open"}
    assert _confirm(client, "P-1").json() == {"proposal_id": "P-1", "status": "confirmed"}
    derived = client.post("/api/brd")
    assert derived.status_code == 200 and set(derived.json()) == {"written", "bytes"}


# ---------------------------------------------------------------------------
# The page: rows, composition, accessibility -- pinned on the served source
# ---------------------------------------------------------------------------

class _Page(html.parser.HTMLParser):
    """The served markup's elements and attributes, read with the stdlib."""

    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.legends: list[str] = []
        self._legend = False

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, {key: value or "" for key, value in attrs}))
        self._legend = tag == "legend"

    def handle_endtag(self, tag):
        if tag == "legend":
            self._legend = False

    def handle_data(self, data):
        if self._legend and data.strip():
            self.legends.append(data.strip())

    def by_id(self, ident: str) -> tuple[str, dict[str, str]]:
        found = [element for element in self.elements if element[1].get("id") == ident]
        assert len(found) == 1, f"the page has {len(found)} element(s) with id {ident!r}"
        return found[0]


@pytest.fixture()
def page(app) -> tuple[str, str, _Page]:
    served = TestClient(app).get("/")
    assert served.status_code == 200
    markup = served.text
    script = markup[markup.index("<script>"):markup.index("</script>")]
    parsed = _Page()
    parsed.feed(markup[:markup.index("<script>")])
    return markup, script, parsed


def test_the_page_offers_requirement_rows(page):
    """Enter, edit, remove: a list of rows, a button that adds one, a remove
    button per row, and a button that proposes the set."""
    _markup, script, parsed = page
    assert "List what the application must do" in " ".join(parsed.legends)
    assert parsed.by_id("rq_rows")[0] == "ol"
    for ident in ("b_rq_add", "b_rq_propose"):
        tag, attrs = parsed.by_id(ident)
        assert tag == "button" and attrs.get("type") == "button", (ident, attrs)
    assert "function addRequirementRow(" in script
    assert 'remove.textContent = "Remove"' in script and "item.remove()" in script
    assert 'input.type = "text"' in script


def test_the_page_proposes_the_existing_field_through_the_existing_route(page):
    """The composition: each row is `{id, text}`, ids `RQ-<n>` that a row
    keeps while it is edited, and a new row takes the next unused number;
    the value goes to `/api/proposals` as the `requirements` field, the
    same route, field and confirmation an API caller uses."""
    _markup, script, _parsed = page
    assert ('call("/api/proposals", {field: "requirements", value: requirementRows(), '
            "actor: actor()})") in script
    assert "({id: item.dataset.rqid, text: item.querySelector(\"input\").value})" in script
    assert 'item.dataset.rqid = id || ("RQ-" + nextRequirementNumber())' in script
    # Ids are the page's; nothing in the composition reads a stage or a gate.
    composition = script[script.index("function requirementRows("):]
    composition = composition[:composition.index("\n}") + 2]
    assert "stage" not in composition and "gate" not in composition


def test_the_rows_are_labelled_keyboard_usable_and_their_errors_announced(page):
    markup, script, parsed = page
    tag, attrs = parsed.by_id("notice")
    assert attrs.get("role") == "alert", attrs
    assert attrs.get("aria-live") in (None, "assertive")
    # Each row: a <label for> its input, a named remove button, an error
    # element the input is described by and that is marked when it fails.
    for pin in ("label.htmlFor = input.id",
                'remove.setAttribute("aria-label", "Remove requirement " + item.dataset.rqid)',
                'input.setAttribute("aria-describedby", error.id)',
                'input.setAttribute("aria-invalid", "true")',
                "input.focus()"):
        assert pin in script, pin
    # Native controls only: nothing clickable that the keyboard cannot reach.
    assert not re.search(r"<(div|span|li)[^>]*onclick", markup)
    assert 'createElement("button")' in script


def test_the_page_shows_the_plain_words_first_and_the_technical_reason_beneath(page):
    _markup, script, _parsed = page
    shown = script[script.index("function showRefusal("):]
    shown = shown[:shown.index("\n}") + 2]
    assert shown.index("data.explanation") < shown.index("data.refused")
    assert '"Technical reason: "' in shown
    assert "textContent" in shown and "innerHTML" not in shown


def test_the_row_editor_changes_neither_the_csp_nor_the_page_technology(page):
    markup, script, _parsed = page
    assert f'content="{BASE_CSP}"' in markup
    assert "<script src" not in markup and "import " not in script
    # A dynamic-evaluation call is not listed here: scripts/check_security.py
    # refuses that spelling anywhere in the source, the page string included,
    # and spelling it in this list would itself be a finding of that gate.
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                      "localStorage", "sessionStorage", "document.cookie", "new Function"):
        assert forbidden not in markup, forbidden
