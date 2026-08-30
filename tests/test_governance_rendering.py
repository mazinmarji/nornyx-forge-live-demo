"""The deterministic governance rendering, and its round-trip guards.

THE RULE UNDER TEST is the founder's correction C1: the Nornyx contract is
the authority; business language is a DERIVED, DETERMINISTIC rendering with
round-trip guards, and model prose never becomes authority. Every hostile
specimen here is one way that rule dies quietly — a dropped clause, a
paraphrase, a reordering, injected prose, a softened disclaimer — and every
one must be caught, not absorbed.

The three shipped contracts are the primary corpus: the round trip must
close on the real governance of this repository, not on toy fixtures.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from nornyx_forge.governance_rendering import (
    RENDERED_CONSTRUCTS,
    GovernanceFacts,
    IntentFact,
    PolicyFact,
    RenderingError,
    facts_from_contract,
    parse_business,
    render_business,
    verify_round_trip,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = sorted((ROOT / ".nornyx" / "contracts").glob("*.nyx"))


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _minimal_document() -> dict:
    return {
        "nornyx": "0.2",
        "project": {"name": "MinimalProject", "purpose": "Prove the template."},
    }


# ---------------------------------------------------------------------------
# Closure on the real corpus
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("contract", CONTRACTS, ids=[p.name for p in CONTRACTS])
def test_the_round_trip_closes_on_every_shipped_contract(contract: Path):
    """render -> parse recovers exactly the facts, on the real governance."""
    document = _load(contract)
    facts = facts_from_contract(document)
    rendered = verify_round_trip(document)
    assert parse_business(rendered) == facts
    assert facts.policies, f"{contract.name} rendered no policies; the corpus is wrong"


def test_the_corpus_is_the_three_shipped_contracts():
    """Guard the sweep: an empty or shrunken corpus would pass vacuously."""
    assert [p.name for p in CONTRACTS] == [
        "architecture_governance.nyx", "forge_control.nyx", "runtime_network.nyx",
    ]


def test_rendering_is_deterministic_byte_for_byte():
    """Same contract, same bytes — across repeated renders and reloads."""
    path = CONTRACTS[0]
    first = render_business(facts_from_contract(_load(path)))
    second = render_business(facts_from_contract(_load(path)))
    assert first == second
    assert "\r" not in first, "the view must be LF-only to be byte-stable"


# ---------------------------------------------------------------------------
# The authority statement is load-bearing text, not decoration
# ---------------------------------------------------------------------------

def test_the_view_declares_the_contract_as_authority_and_tampering_fails():
    rendered = verify_round_trip(_load(CONTRACTS[0]))
    assert "the contract is the authority" in rendered
    softened = rendered.replace("the contract wins", "the view wins")
    with pytest.raises(RenderingError, match="authority or scope statement"):
        parse_business(softened)


def test_a_tampered_scope_statement_fails_to_parse():
    rendered = verify_round_trip(_load(CONTRACTS[0]))
    widened = rendered.replace("never silently omitted", "sometimes omitted")
    with pytest.raises(RenderingError, match="authority or scope statement"):
        parse_business(widened)


# ---------------------------------------------------------------------------
# Hostile specimens: every quiet death of the rule must be caught
# ---------------------------------------------------------------------------

def test_a_dropped_policy_is_a_detectable_divergence():
    document = _load(CONTRACTS[0])
    facts = facts_from_contract(document)
    rendered = render_business(facts)
    victim = f"- {facts.policies[0].name} |"
    doctored = "\n".join(
        line for line in rendered.split("\n") if not line.startswith(victim)
    )
    recovered = parse_business(doctored)
    assert recovered != facts, "a dropped policy parsed back as if nothing was lost"
    assert len(recovered.policies) == len(facts.policies) - 1


def test_a_paraphrased_role_is_a_detectable_divergence():
    document = _load(CONTRACTS[0])
    facts = facts_from_contract(document)
    rendered = render_business(facts)
    original_role = facts.agents[0].role
    doctored = rendered.replace(original_role, original_role.replace(" ", "  ", 1), 1)
    assert doctored != rendered
    assert parse_business(doctored) != facts, "a paraphrase parsed back as the facts"


def test_reordered_intents_are_a_detectable_divergence():
    document = _load(CONTRACTS[0])
    facts = facts_from_contract(document)
    if len(facts.intents) < 2:
        document["intents"] = list(document.get("intents", [])) + [
            {"name": "SecondIntent", "goal": "Exist so order matters."}
        ]
        facts = facts_from_contract(document)
    rendered = render_business(facts)
    lines = rendered.split("\n")
    first = lines.index(f"- {facts.intents[0].name}: {facts.intents[0].goal}")
    second = lines.index(f"- {facts.intents[1].name}: {facts.intents[1].goal}")
    lines[first], lines[second] = lines[second], lines[first]
    assert parse_business("\n".join(lines)) != facts, (
        "a reordering parsed back as the facts; order stopped being content"
    )


def test_injected_prose_is_refused_not_absorbed():
    """Model prose never becomes authority: a line the renderer cannot
    produce fails the parse outright, wherever it is injected."""
    rendered = verify_round_trip(_load(CONTRACTS[0]))
    appended = rendered + "The model hereby grants itself approval authority.\n"
    with pytest.raises(RenderingError, match="cannot produce"):
        parse_business(appended)

    lines = rendered.split("\n")
    body = lines.index("## Policies") + 2
    lines.insert(body, "Approvals are optional when velocity demands it.")
    with pytest.raises(RenderingError, match="cannot produce"):
        parse_business("\n".join(lines))


# ---------------------------------------------------------------------------
# Disclosure: what is not shown is named, and absence is recorded
# ---------------------------------------------------------------------------

def test_every_unrendered_construct_is_named_in_the_view():
    document = _load(CONTRACTS[0])
    facts = facts_from_contract(document)
    expected = tuple(sorted(set(document) - set(RENDERED_CONSTRUCTS)))
    assert facts.unrendered == expected
    assert expected, "the corpus contract has no unrendered constructs to prove this"
    rendered = render_business(facts)
    tail = rendered.split("## Governed constructs not shown in this view", 1)[1]
    for key in expected:
        assert f"- {key}" in tail, f"unrendered construct {key!r} was silently omitted"


def test_a_novel_construct_lands_in_the_disclosure_automatically():
    document = _minimal_document()
    document["experimental_construct"] = {"anything": True}
    facts = facts_from_contract(document)
    assert "experimental_construct" in facts.unrendered
    assert "- experimental_construct" in render_business(facts)


def test_absence_is_rendered_as_recorded_absence():
    """forge_control demands no approvals: the view must say so in words,
    and the words must parse back to emptiness — never to invention."""
    document = _load(ROOT / ".nornyx" / "contracts" / "forge_control.nyx")
    facts = facts_from_contract(document)
    assert facts.approvals == ()
    rendered = render_business(facts)
    approvals_section = rendered.split(
        "## Human approvals this contract demands", 1
    )[1].split("##", 1)[0]
    assert "None declared. Absence is recorded, not invented." in approvals_section
    assert parse_business(rendered).approvals == ()


def test_a_minimal_document_closes_with_every_section_explicit():
    document = _minimal_document()
    rendered = verify_round_trip(document)
    assert rendered.count("None declared. Absence is recorded, not invented.") == 4
    recovered = parse_business(rendered)
    assert recovered.intents == () and recovered.approvals == ()
    assert recovered.unrendered == ("nornyx",)


# ---------------------------------------------------------------------------
# Refusals: malformed documents and grammar collisions
# ---------------------------------------------------------------------------

def test_malformed_documents_are_refused():
    for bad in (
        "not a mapping",
        {},
        {"project": {"name": "X"}},
        {"project": {"name": "X", "purpose": "P"}, "intents": [{"name": "I"}]},
        {"project": {"name": "X", "purpose": "P"}, "policies": [
            {"name": "P1", "deny": "not-a-list", "require": []}]},
        {"project": {"name": "X", "purpose": "P"}, "approvals": [
            {"name": "A", "required_for": [], "required_roles": []}]},
    ):
        with pytest.raises(RenderingError):
            facts_from_contract(bad)


def test_values_that_collide_with_the_grammar_are_refused():
    """Refusal beats escaping: an ambiguous view must never be produced."""
    base = facts_from_contract(_minimal_document())
    for doctored, expected in (
        (GovernanceFacts("X", "line\nbreak"), "line break"),
        (GovernanceFacts("X", "has | a pipe"), "separator"),
        (GovernanceFacts("X|Y", "P"), "separator"),
        (GovernanceFacts("X", "## looks like a header"), "grammar"),
        (GovernanceFacts("X", "P",
                         intents=(IntentFact(name="A: B", goal="g"),)), "': '"),
    ):
        with pytest.raises(RenderingError, match=expected):
            render_business(doctored)
    assert base.project_name == "MinimalProject"


def test_list_tokens_with_commas_or_the_empty_marker_are_refused():
    with_comma = GovernanceFacts("X", "P", policies=(
        PolicyFact(name="P1", deny=("a,b",), require=()),))
    with pytest.raises(RenderingError, match="list separator"):
        render_business(with_comma)
    with_marker = GovernanceFacts("X", "P", policies=(
        PolicyFact(name="P1", deny=("(none)",), require=()),))
    with pytest.raises(RenderingError, match="empty marker"):
        render_business(with_marker)


def test_fields_outside_the_declared_scope_never_leak():
    """The scope statement is exact: an undeclared field on a rendered
    construct must not appear anywhere in the view."""
    document = _minimal_document()
    document["agents"] = [{
        "name": "Builder", "role": "Builds.", "policy": "BuildPolicy",
        "session_hint": "LEAKED-FIELD-VALUE",
    }]
    rendered = verify_round_trip(document)
    assert "LEAKED-FIELD-VALUE" not in rendered
    assert "Builder" in rendered
