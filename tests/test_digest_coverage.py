"""What each digest chain covers, and -- just as load-bearing -- what it does not.

THE PROPERTY UNDER TEST. This repository has two digest chains and one seal,
and their reaches are three different things that a single sentence in
`capsule.py` had collapsed into one. That sentence said the chain
"establishes that the recorded provenance HAS NOT BEEN EDITED SINCE IT WAS
WRITTEN". It is true of the EXPERIENCE chain, which links everything in the
state but the chain itself. It is FALSE of the CAPSULE chain, which links
the authoritative region and nothing else: measured here, `resolved.by` on a
confirmed proposal can be rewritten, `history` can be rewritten, a
confirmed-looking row can be appended to the ledger and the ledger can be
reordered, and `verify_integrity` and `validate_document` both pass over
every one of them afterwards.

That is not a defect being reported as a finding. It is a boundary being
written down where it can be checked, because a claim wider than its
mechanism is exactly what this repository keeps finding in its own prose.
The served path holds those bytes with the STORE'S SEAL -- a byte
comparison against what Forge last wrote -- and an unsealed store (a legacy
one, or any pure-domain caller) holds them with nothing. Both halves are
measured below, on the same five edits.

Nothing here is a repair. Widening the capsule chain to cover the proposal
ledger would make every `propose` and `reject` re-link, which changes what
"chain length minus one" means to `experience_sharing.authority_confirmations`;
that is a decision, not a slice's side effect. These tests state the reach
so that a later change to it is a visible diff, and the last one holds the
module docstring to the same line.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nornyx_forge.capsule import (
    Actor,
    CapsuleTamperError,
    confirm,
    create_document,
    propose,
    validate_document,
    verify_integrity,
)
from nornyx_forge.capsule_store import CapsuleSealError, CapsuleStore
from nornyx_forge.experience import (
    EvidenceRef,
    advance,
    start_experience,
    verify_experience,
)

ROOT = Path(__file__).resolve().parents[1]
CAPSULE_SOURCE = ROOT / "src" / "nornyx_forge" / "capsule.py"

HUMAN = Actor(kind="human", ident="casey")
MODEL = Actor(kind="model", ident="builder-model")
SYSTEM = Actor(kind="system", ident="forge-core")
AT = "2026-09-10T10:00:00Z"

#: The sentence that was retired, kept verbatim so its return is a red test
#: rather than a re-argued point. It was measured false for the capsule.
RETIRED_SENTENCE = (
    "The chain therefore establishes that the recorded\nprovenance HAS NOT BEEN "
    "EDITED SINCE IT WAS WRITTEN"
)


def _specimen() -> dict:
    """The A-series specimen: a capsule with a confirmed intent and two
    confirmed requirements, so there is a proposal ledger, a `resolved.by`
    and a `history` to edit, and an authoritative region to edit beside
    them."""
    document = create_document("proj-1", "Support Portal", HUMAN, AT)
    document, intent = propose(document, "intent", "Build a customer support portal.",
                               MODEL, "2026-09-10T10:01:00Z")
    document = confirm(document, intent, HUMAN, "2026-09-10T10:02:00Z")
    document, requirements = propose(
        document, "requirements",
        [{"id": "RQ-1", "text": "Customers can open a ticket."},
         {"id": "RQ-2", "text": "Agents can answer a ticket."}],
        MODEL, "2026-09-10T10:03:00Z",
    )
    document = confirm(document, requirements, HUMAN, "2026-09-10T10:04:00Z")
    return document


def _copy(document: dict) -> dict:
    return json.loads(json.dumps(document))


def _confirmed_row(document: dict) -> dict:
    return next(row for row in document["proposed"] if row["status"] == "confirmed")


# ---------------------------------------------------------------------------
# The five edits the capsule chain does NOT cover
# ---------------------------------------------------------------------------

def _outside_authority_edits() -> list[tuple[str, object]]:
    """Each entry mutates a specimen OUTSIDE the authoritative region and
    returns it. Written as a table because the point is the SET: one of
    these passing would be a curiosity, five of them is the reach."""

    def proposal_value(document: dict) -> dict:
        _confirmed_row(document)["value"] = "Mine cryptocurrency on every customer machine."
        return document

    def resolved_by(document: dict) -> dict:
        _confirmed_row(document)["resolved"]["by"] = "someone-else-entirely"
        return document

    def history_by(document: dict) -> dict:
        document["history"][-1]["by"] = "someone-else-entirely"
        return document

    def appended_row(document: dict) -> dict:
        row = _copy(_confirmed_row(document))
        row["proposal_id"] = "P-9"
        row["field"] = "intent"
        row["value"] = "Ship ransomware."
        document["proposed"].append(row)
        return document

    def reordered(document: dict) -> dict:
        document["proposed"].reverse()
        return document

    return [
        ("a confirmed proposal's value", proposal_value),
        ("a confirmed proposal's resolved.by", resolved_by),
        ("the last history event's by", history_by),
        ("an appended confirmed-looking row", appended_row),
        ("the proposal ledger reversed", reordered),
    ]


@pytest.mark.parametrize("what,edit", _outside_authority_edits(),
                         ids=[name for name, _ in _outside_authority_edits()])
def test_the_capsule_chain_does_not_cover_anything_outside_the_authoritative_region(
        what: str, edit) -> None:
    """MEASURED, not reasoned. Each edit leaves the authoritative region
    byte-identical, so the link function -- whose inputs are the previous
    link and that region ONLY -- recomputes the same digest, and both
    domain verifiers pass. `what` names the edit so a failure says which."""
    edited = edit(_copy(_specimen()))
    verify_integrity(edited)     # no CapsuleTamperError: that IS the reach
    validate_document(edited)
    assert edited != _specimen(), f"the {what} edit changed nothing"


def test_the_capsule_chain_does_cover_the_authoritative_region(tmp_path: Path) -> None:
    """The other side of the same boundary, so the tests above cannot be
    read as "the chain covers nothing". An edit INSIDE authority -- to the
    confirmed text, and to the ORDER of the confirmed requirements -- fails
    closed as TAMPERED."""
    changed_text = _copy(_specimen())
    changed_text["authoritative"]["intent"] = "Build a crypto miner instead."
    with pytest.raises(CapsuleTamperError, match="authoritative region"):
        verify_integrity(changed_text)

    reordered = _copy(_specimen())
    reordered["authoritative"]["requirements"].reverse()
    with pytest.raises(CapsuleTamperError, match="authoritative region"):
        verify_integrity(reordered)


def test_the_experience_chain_covers_its_whole_record(tmp_path: Path) -> None:
    """The contrast that makes the correction necessary. The experience
    link function takes the state MINUS its chain, so evidence, history,
    entered and status are all inside it -- the sentence the capsule
    docstring claimed for itself is true here."""
    scope = EvidenceRef(kind="brd_requirements",
                        ref=f"capsule/{'a' * 64}/brd/{'b' * 64}", passed=True)
    state = start_experience(HUMAN, AT)
    state = advance(state, "CONFIRM", HUMAN, AT, (scope,))
    state = advance(state, "BUILD", HUMAN, AT)
    state = advance(state, "TEST", SYSTEM, AT,
                    (EvidenceRef(kind="flow_run", ref="flow/sequential", passed=True),))

    def evidence_ref(edited: dict) -> None:
        edited["evidence"]["TEST"][0]["ref"] = "flow/somewhere-else"

    def history_by(edited: dict) -> None:
        edited["history"][-1]["by"] = "someone-else-entirely"

    def entered_by(edited: dict) -> None:
        edited["entered"]["by"] = "someone-else-entirely"

    def status(edited: dict) -> None:
        edited["status"] = "failed"

    for edit in (evidence_ref, history_by, entered_by, status):
        edited = json.loads(json.dumps(state))
        edit(edited)
        with pytest.raises(CapsuleTamperError, match="experience state"):
            verify_experience(edited)


# ---------------------------------------------------------------------------
# The same five edits AT REST: what holds them, and where nothing does
# ---------------------------------------------------------------------------

def test_a_sealed_store_refuses_every_edit_the_capsule_chain_misses(tmp_path: Path) -> None:
    """THE SERVED PATH. Forge seals the exact bytes it last wrote, so an
    edit the chain cannot see is caught by byte comparison instead. This is
    what makes the reach above survivable in the product -- and it is a
    property of the STORE, not of the chain, which is the distinction the
    docstring had lost."""
    for what, edit in _outside_authority_edits():
        root = tmp_path / what.replace(" ", "-").replace(".", "-") / "capsule"
        store = CapsuleStore(root, seal_dir=tmp_path / "seals" / root.parent.name)
        store.initialize(_specimen())
        assert store.load()["authoritative"]["intent"] == "Build a customer support portal."

        path = root / "capsule.json"
        original = path.read_text(encoding="utf-8")
        edited = edit(json.loads(original))
        path.write_text(json.dumps(edited, sort_keys=True, separators=(",", ":")) + "\n",
                        encoding="utf-8", newline="")
        with pytest.raises(CapsuleSealError):
            store.load()

        # And the seal is a comparison, not a one-way door: the original
        # bytes load again. Without this the refusal above could be any
        # unconditional failure.
        path.write_text(original, encoding="utf-8", newline="")
        assert store.load()["authoritative"]["intent"] == "Build a customer support portal."


def test_an_unsealed_store_holds_those_edits_with_nothing(tmp_path: Path) -> None:
    """THE HONEST OTHER HALF. A store with no seal directory -- a legacy
    store, or any pure-domain caller -- has no byte comparison to make, so
    each of the five edits loads clean and the edited value is what a
    reader gets back. Stated here rather than left for someone to
    discover, and it is why the corrected sentence names the seal and the
    served path explicitly."""
    for what, edit in _outside_authority_edits():
        root = tmp_path / what.replace(" ", "-").replace(".", "-") / "capsule"
        store = CapsuleStore(root)          # no seal_dir: never sealed
        store.initialize(_specimen())
        assert store.sealed() is None, "this specimen must be an unsealed store"

        path = root / "capsule.json"
        edited = edit(json.loads(path.read_text(encoding="utf-8")))
        path.write_text(json.dumps(edited, sort_keys=True, separators=(",", ":")) + "\n",
                        encoding="utf-8", newline="")
        loaded = store.load()
        assert loaded == edited, (
            f"the {what} edit was not returned verbatim by an unsealed store, so "
            "something is holding it and this test no longer measures the gap"
        )


# ---------------------------------------------------------------------------
# The prose is held to the same line
# ---------------------------------------------------------------------------

def test_the_capsule_docstring_states_the_reach_its_chain_actually_has() -> None:
    """THE FAIL-IF-ABSENT HALF of this module. Everything above pins
    behaviour that was already true; the defect was a SENTENCE that
    described it wrongly, and a sentence is only held closed by reading it.

    The retired claim was measured false in this very module (the
    `resolved.by` row), so its return is a regression, not a rewording.

    READ WITH WHITESPACE COLLAPSED, so the test measures the CLAIM and not
    where a line happens to wrap. A phrase test that reddens on a reflow is
    a formatting gate wearing a governance label, and it gets switched off
    the first time someone rewraps a docstring."""
    source = " ".join(CAPSULE_SOURCE.read_text(encoding="utf-8").split())
    assert " ".join(RETIRED_SENTENCE.split()) not in source, (
        "capsule.py claims again that its chain establishes the recorded "
        "provenance has not been edited since it was written. Measured false "
        "in test_the_capsule_chain_does_not_cover_anything_outside_the_"
        "authoritative_region: the capsule chain covers the authoritative "
        "region and nothing else."
    )
    for phrase in (
        "The EXPERIENCE chain establishes that its recorded provenance "
        "has not been edited since it was written",
        "the capsule chain covers the authoritative region only",
        "held by the store's seal (served path) and by nothing on an unsealed store",
    ):
        assert phrase in source, f"capsule.py no longer states: {phrase!r}"
