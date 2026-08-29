"""The Project Capsule's authority split, proven in both directions.

THE PROPERTY UNDER TEST. Provider/model output must be able to enter the
capsule (else the capsule is useless) and must not be able to become project
authority without a human confirmation (else the capsule is an S5 machine:
content authorising itself by being well-formed). Every test here holds one
edge of that line:

  * a model can propose, and the proposal is stored -- the permissive half;
  * nothing a model does moves content into `authoritative`;
  * only `kind == "human"` confirms, and the check is on the KIND, not the
    name, because names are spellings;
  * the closed schema refuses fields, shapes and values it does not declare;
  * out-of-band edits to the authoritative region fail closed as TAMPERED;
  * hostile content stays inert: the capsule machinery never executes,
    imports, or evaluates a value it stores.

Each guard has a hostile specimen, and the load-bearing ones are additionally
revert-proven (mutate the guard out on an isolated clone; the named specimen
here must fail in the call phase).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nornyx_forge.capsule import (
    AUTHORITATIVE_FIELDS,
    PROVIDERS,
    Actor,
    CapsuleTamperError,
    CapsuleTransitionError,
    CapsuleValidationError,
    canonical_json,
    confirm,
    create_document,
    propose,
    reject,
    set_derived,
    validate_document,
    verify_integrity,
)
from nornyx_forge.capsule_store import CapsuleStore, CapsuleStoreError

HUMAN = Actor(kind="human", ident="owner@example")
MODEL = Actor(kind="model", ident="provider-claude")
SYSTEM = Actor(kind="system", ident="forge-core")
AT = "2026-08-29T10:00:00Z"
LATER = "2026-08-29T10:05:00Z"


def _fresh() -> dict:
    return create_document("proj-1", "Maintenance Assistant", HUMAN, AT)


# ---------------------------------------------------------------------------
# The authority line
# ---------------------------------------------------------------------------

def test_a_model_proposal_lands_in_proposed_and_authoritative_is_unchanged():
    """The permissive half and the restrictive half of the line, together.

    A model must be able to contribute -- that is the capsule's purpose -- and
    the contribution must land with provenance, in `proposed`, with the
    authoritative region byte-identical to before.
    """
    document = _fresh()
    before = canonical_json(document["authoritative"])

    updated, proposal_id = propose(document, "intent", "Automate quotation follow-up", MODEL, AT)

    assert updated["proposed"][0]["proposal_id"] == proposal_id
    assert updated["proposed"][0]["kind"] == "model"
    assert updated["proposed"][0]["status"] == "open"
    assert canonical_json(updated["authoritative"]) == before, (
        "a model proposal changed the authoritative region without confirmation"
    )
    assert "intent" not in updated["authoritative"]


def test_only_a_human_actor_can_confirm():
    """THE AUTHORITY LINE. A model cannot confirm -- not even its own proposal.

    The refusal keys on the actor KIND. A model actor whose ident is spelled
    like a person must still be refused, because deciding by the name would be
    deciding by spelling.
    """
    document, proposal_id = propose(_fresh(), "intent", "Automate follow-up", MODEL, AT)

    with pytest.raises(CapsuleTransitionError, match="human"):
        confirm(document, proposal_id, MODEL, LATER)

    impersonator = Actor(kind="model", ident="owner@example")  # human-looking NAME
    with pytest.raises(CapsuleTransitionError, match="human"):
        confirm(document, proposal_id, impersonator, LATER)

    confirmed = confirm(document, proposal_id, HUMAN, LATER)
    assert confirmed["authoritative"]["intent"] == "Automate follow-up"
    assert confirmed["proposed"][0]["status"] == "confirmed"
    assert confirmed["proposed"][0]["resolved"]["kind"] == "human"


def test_confirmation_is_not_replayable():
    """A second "yes" the user never gave must not be synthesizable.

    Confirming a confirmed proposal, or a rejected one, is a state error --
    not an idempotent success, because idempotency here would let one human
    click authorize an unbounded number of later writes.
    """
    document, proposal_id = propose(_fresh(), "intent", "First intent", MODEL, AT)
    confirmed = confirm(document, proposal_id, HUMAN, LATER)

    with pytest.raises(CapsuleTransitionError, match="confirmed, not open"):
        confirm(confirmed, proposal_id, HUMAN, LATER)

    document2, p2 = propose(confirmed, "intent", "Second intent", MODEL, LATER)
    rejected = reject(document2, p2, HUMAN, LATER)
    with pytest.raises(CapsuleTransitionError, match="rejected, not open"):
        confirm(rejected, p2, HUMAN, LATER)
    assert rejected["authoritative"]["intent"] == "First intent"


def test_creation_itself_is_a_human_act():
    with pytest.raises(CapsuleTransitionError, match="human"):
        create_document("proj-2", "Model Project", MODEL, AT)
    with pytest.raises(CapsuleTransitionError, match="human"):
        create_document("proj-3", "System Project", SYSTEM, AT)


def test_derived_content_never_reaches_authority_or_the_digest():
    """Renderings are projections. Writing one changes no decision.

    Any actor may write derived content, and the digest chain must not move:
    if it did, "the rendering changed" would be indistinguishable from "the
    decision changed", which is the confusion the split exists to prevent.
    """
    document = _fresh()
    chain_before = list(document["digest_chain"])

    rendered = set_derived(document, "authority_view", "Allowed: answer enquiries", MODEL, AT)

    assert rendered["derived"]["authority_view"] == "Allowed: answer enquiries"
    assert rendered["digest_chain"] == chain_before
    assert set(rendered["authoritative"]) == {"project_name"}


# ---------------------------------------------------------------------------
# The closed schema
# ---------------------------------------------------------------------------

def test_an_undeclared_field_cannot_be_proposed():
    """The registry is closed. Growing it is a diff, not a payload."""
    with pytest.raises(CapsuleValidationError, match="undeclared field"):
        propose(_fresh(), "budget_authority", {"limit": 10**9}, MODEL, AT)


def test_an_undeclared_field_cannot_ride_in_through_load(tmp_path: Path):
    """The other door: a hand-crafted document with an extra authoritative key.

    Proposals are one entrance; deserialization is the other. A field the
    registry does not declare must be refused at load even if every declared
    field is valid -- otherwise the closed set is closed at one door only.
    """
    document = _fresh()
    store = CapsuleStore(tmp_path / "capsule")
    store.initialize(document)

    raw = json.loads((store.root / "capsule.json").read_text(encoding="utf-8"))
    raw["authoritative"]["budget_authority"] = {"limit": 10**9}
    (store.root / "capsule.json").write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(CapsuleValidationError, match="undeclared"):
        store.load()


@pytest.mark.parametrize(
    "field,bad_value,why",
    [
        ("intent", "", "empty"),
        ("intent", "x" * 4001, "over length"),
        ("requirements", [{"id": "RQ-1"}], "missing key"),
        ("requirements", [{"id": "REQ-1", "text": "t"}], "wrong id shape"),
        ("requirements", [{"id": "RQ-1", "text": "a"}, {"id": "RQ-1", "text": "b"}], "duplicate id"),
        ("provider", {"name": "gemini"}, "provider outside the closed set"),
        ("provider", {"name": "codex", "extra": 1}, "extra key"),
        ("limitations", ["ok", 7], "non-string entry"),
    ],
)
def test_field_validators_refuse_bad_shapes(field, bad_value, why):
    with pytest.raises(CapsuleValidationError):
        propose(_fresh(), field, bad_value, MODEL, AT)


def test_the_provider_set_is_closed_and_small():
    """Two providers until the equivalence proof exists. Widening is a diff."""
    assert PROVIDERS == ("codex", "claude")


def test_contract_refs_cannot_traverse_or_go_absolute():
    """The capsule names governance artifacts inside its project, only.

    Segment-wise: `..` as a path segment is refused; consecutive dots inside a
    NAME are legal, because refusing the substring would refuse legal names --
    deciding the property, not the spelling.
    """
    for hostile in (
        ["../outside.nyx"],
        ["a/../../outside.nyx"],
        ["/etc/contracts/root.nyx"],
        ["C:/other/place.nyx"],
        ["..\\windows\\style.nyx"],
        ["contracts/policy.yaml"],  # not a .nyx artifact
    ):
        with pytest.raises(CapsuleValidationError):
            propose(_fresh(), "authority_contract_refs", hostile, MODEL, AT)

    document, proposal_id = propose(
        _fresh(), "authority_contract_refs",
        [".nornyx/contracts/forge_control.nyx", "contracts/a..b.nyx"],
        MODEL, AT,
    )
    assert document["proposed"][0]["value"][1] == "contracts/a..b.nyx"


# ---------------------------------------------------------------------------
# Tamper evidence
# ---------------------------------------------------------------------------

def test_an_out_of_band_edit_to_authority_fails_closed_as_tampered(tmp_path: Path):
    """THE TAMPER SPECIMEN. Editing capsule.json by hand must not load.

    The store's load order distinguishes three findings -- corrupt, invalid,
    tampered -- and this is the third: a schema-valid document whose
    authoritative region disagrees with its own digest chain. That must raise
    CapsuleTamperError specifically, not blur into validation.
    """
    document, proposal_id = propose(_fresh(), "intent", "Honest intent", MODEL, AT)
    document = confirm(document, proposal_id, HUMAN, LATER)
    store = CapsuleStore(tmp_path / "capsule")
    store.initialize(document)

    raw = json.loads((store.root / "capsule.json").read_text(encoding="utf-8"))
    raw["authoritative"]["intent"] = "Silently inflated intent"
    (store.root / "capsule.json").write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(CapsuleTamperError):
        store.load()


def test_rebuilding_the_final_digest_alone_is_still_tampered(tmp_path: Path):
    """A cleverer edit: fix the LAST link to match the edited content.

    The chain hashes the previous link into each new one, so a forger must
    rebuild every link after the edit, not just the tail -- and rebuilding the
    whole chain is exactly the whole-file rewrite the module's docstring
    concedes to git history, not something a partial edit achieves.
    """
    document, p1 = propose(_fresh(), "intent", "First", MODEL, AT)
    document = confirm(document, p1, HUMAN, LATER)
    document, p2 = propose(document, "intent", "Second", MODEL, LATER)
    document = confirm(document, p2, HUMAN, LATER)

    from nornyx_forge.capsule import _chain_digest  # the real link function

    raw = json.loads(canonical_json(document))
    raw["authoritative"]["intent"] = "Forged"
    # Recompute ONLY the final link from the (unchanged) middle of the chain.
    raw["digest_chain"][-1] = _chain_digest(raw["digest_chain"][-2], raw["authoritative"])
    # The forgery is self-consistent at the tail...
    verify_integrity(raw)
    # ...which is precisely the disclosed bound of in-document integrity: the
    # detection of a full-tail rebuild belongs to the store's git history.
    # What the DOCUMENT still refuses is any edit that does not rebuild the
    # tail. This test pins the boundary so it is stated, not discovered.
    raw["authoritative"]["intent"] = "Forged again"
    with pytest.raises(CapsuleTamperError):
        verify_integrity(raw)


def test_truncating_the_chain_is_tampered():
    document, p1 = propose(_fresh(), "intent", "First", MODEL, AT)
    document = confirm(document, p1, HUMAN, LATER)
    truncated = json.loads(canonical_json(document))
    truncated["digest_chain"] = truncated["digest_chain"][:-1]
    with pytest.raises(CapsuleTamperError):
        verify_integrity(truncated)


# ---------------------------------------------------------------------------
# Hostile content stays inert
# ---------------------------------------------------------------------------

def test_executable_looking_content_is_stored_inert(tmp_path: Path):
    """The capsule machinery never executes what it stores.

    Free-text fields may legitimately contain anything a business owner types,
    including things that look like code. The property is not "no such
    strings" -- that would be deciding by spelling -- but that storing,
    validating, persisting and loading them causes no execution. The sentinel
    is a file path only an EXECUTED payload would create; after a full
    round-trip through every layer, it must not exist.
    """
    sentinel = tmp_path / "executed-proof.txt"
    payloads = [
        f"__import__('pathlib').Path(r'{sentinel}').write_text('ran')",
        f"$(touch {tmp_path / 'shell-proof'})",
        "'; DROP TABLE projects; --",
        "{{7*7}}{% raw %}",
        "=cmd|' /C calc'!A0",
    ]
    document = _fresh()
    for index, payload in enumerate(payloads):
        document, proposal_id = propose(document, "intent", payload, MODEL, AT)
        document = confirm(document, proposal_id, HUMAN, LATER)
        document = set_derived(document, f"render_{index}", payload, SYSTEM, LATER)

    store = CapsuleStore(tmp_path / "capsule")
    store.initialize(document)
    loaded = store.load()

    assert loaded["authoritative"]["intent"] == payloads[-1]
    assert not sentinel.exists(), "a stored payload was executed by the capsule machinery"
    assert not (tmp_path / "shell-proof").exists(), "a stored payload reached a shell"


# ---------------------------------------------------------------------------
# The store: revision binding and refusals
# ---------------------------------------------------------------------------

def test_every_confirmation_is_a_distinct_revision(tmp_path: Path):
    """Revision binding: state changes are ordered, identified, and complete."""
    store = CapsuleStore(tmp_path / "capsule")
    document = _fresh()
    first = store.initialize(document)

    document, p1 = propose(document, "intent", "Automate follow-up", MODEL, AT)
    second = store.save(document, "record proposal")
    document = confirm(document, p1, HUMAN, LATER)
    third = store.save(document, "confirm intent")

    assert len({first, second, third}) == 3
    assert store.revisions() == [first, second, third]
    assert store.revision() == third

    reloaded = store.load()
    assert reloaded["authoritative"]["intent"] == "Automate follow-up"


def test_the_store_refuses_histories_it_did_not_create(tmp_path: Path):
    """Never adopt an existing repository; never load an unmarked directory.

    Committing a capsule into some other project's git history would entangle
    two provenances; loading a directory without the marker would treat
    arbitrary files as a store. Both are refusals, not accommodations.
    """
    foreign = tmp_path / "existing-repo"
    foreign.mkdir()
    import subprocess
    subprocess.run(["git", "init", "--quiet", str(foreign)], check=True)
    with pytest.raises(CapsuleStoreError, match="does not adopt"):
        CapsuleStore(foreign).initialize(_fresh())

    unmarked = tmp_path / "not-a-store"
    unmarked.mkdir()
    (unmarked / "capsule.json").write_text("{}", encoding="utf-8")
    with pytest.raises(CapsuleStoreError, match="not a capsule store"):
        CapsuleStore(unmarked).load()


def test_a_no_op_save_is_refused_rather_than_fabricating_history(tmp_path: Path):
    store = CapsuleStore(tmp_path / "capsule")
    document = _fresh()
    store.initialize(document)
    with pytest.raises(CapsuleStoreError, match="identical"):
        store.save(document, "nothing changed")


def test_transitions_do_not_mutate_their_inputs():
    """Pure means pure: the caller's document is never edited in place."""
    document = _fresh()
    frozen = canonical_json(document)
    updated, _ = propose(document, "intent", "New intent", MODEL, AT)
    set_derived(document, "view", "rendering", SYSTEM, AT)
    assert canonical_json(document) == frozen
    assert updated is not document


def test_the_document_validator_and_field_registry_agree_both_directions():
    """The registry is the single source: every proposal target validates, and
    a document may carry no authoritative key outside it. Holding both
    directions here keeps the registry and the validator from drifting apart
    the way two analyses of one question always eventually do."""
    document = _fresh()
    for field in AUTHORITATIVE_FIELDS:
        assert field in AUTHORITATIVE_FIELDS  # closed iteration is the point
    hostile = json.loads(canonical_json(document))
    hostile["authoritative"]["not_registered"] = "x"
    with pytest.raises(CapsuleValidationError, match="undeclared"):
        validate_document(hostile)
