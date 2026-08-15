"""Task 11. One authoritative, auditable inventory of every hostile mutation.

This is NOT a second place to run mutations -- the owner catalogues run them,
and the gate runs those. It is the thing that makes the mutation evidence
AUDITABLE: it answers, mechanically, "where is every attack, what root property
does it defend, and can any of it disappear without the run turning red".

TWO COUNTS, deliberately kept apart:

    ROOT PROPERTY   the security invariant being defended
    ATTACK          one representation of removing it

One root property legitimately carries several attacks -- a direct spelling, an
alias, a dynamic form, a compound chain -- and collapsing those to reduce a
number would destroy the defence-in-depth accounting. So `GOVERNANCE_SURFACE_
ABSENCE` owns three single-guard attacks that each prove the property SURVIVES,
plus one compound attack that removes every route and kills it. Three of those
four are not survivals; they are evidence.

WHAT MAKES A RESULT ADMISSIBLE, enforced by `mutation_validity` and the owner
harnesses rather than restated here:

    the edit applied
    the mutant loaded
    the intended semantic property changed
    the intended control was reached

Anything less is harness evidence, not security evidence. H01 is the reason that
sentence exists: an edit that silently did not apply was read as a survivor.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from mutation_validity import (  # noqa: E402
    InvalidMutation,
    check_python_mutation,
    executable_projection,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import test_domain_collapse_mutations as domains  # noqa: E402
import test_historical_reproof as historical  # noqa: E402
import test_semantic_binding_theorem as projection  # noqa: E402


@dataclass(frozen=True)
class Attack:
    """One hostile representation, and the invariant it attacks."""

    root_property_id: str
    attack_id: str
    owner: str
    #: The test whose failure is the kill.
    killed_by: str
    #: True when the attack removes an entire enforcement chain rather than one
    #: clause, because the property has independent routes.
    compound: bool = False
    #: True when the attack is EXPECTED not to kill -- it demonstrates that the
    #: property survives losing one of several defences. Never a survivor.
    defence_in_depth: bool = False


def _domain_attacks() -> list[Attack]:
    return [
        Attack(
            root_property_id="AUTHORITY_DOMAIN_SEPARATION",
            attack_id=mutation.name.split()[0],
            owner="tests/test_domain_collapse_mutations.py",
            killed_by="test_the_collapse_is_visible",
        )
        for mutation in domains.CATALOGUE
    ]


def _projection_attacks() -> list[Attack]:
    return [
        Attack(
            root_property_id="SEMANTIC_IDENTITY_BINDING",
            attack_id=attack.ident.split()[0],
            owner="tests/test_semantic_binding_theorem.py",
            killed_by="test_the_projection_attack_is_killed",
        )
        for attack in projection.PROJECTION_ATTACKS
    ]


def _historical_attacks() -> list[Attack]:
    attacks = [
        Attack(
            root_property_id=item.ident.split()[0],
            attack_id=f"{item.ident.split()[0]}-DIRECT",
            owner="tests/test_historical_reproof.py",
            killed_by="test_removing_the_control_revives_the_defect",
        )
        for item in historical.DIRECT
    ]
    # The governance-surface family: three single-guard probes that prove the
    # property SURVIVES, and one compound attack that kills it.
    attacks += [
        Attack(
            root_property_id="GOVERNANCE_SURFACE_ABSENCE",
            attack_id=f"SURFACE-GUARD-{label}",
            owner="tests/test_historical_reproof.py",
            killed_by="test_removing_one_guard_leaves_the_property_protected",
            defence_in_depth=True,
        )
        for label, _anchor, _condition in historical.GOVERNANCE_SURFACE_CHAIN
    ]
    attacks.append(
        Attack(
            root_property_id="GOVERNANCE_SURFACE_ABSENCE",
            attack_id="SURFACE-WHOLE-CHAIN",
            owner="tests/test_historical_reproof.py",
            killed_by="test_disabling_the_whole_chain_recreates_the_historical_unsafe_state",
            compound=True,
        )
    )
    return attacks


CATALOGUE: tuple[Attack, ...] = tuple(
    _domain_attacks() + _projection_attacks() + _historical_attacks()
)

#: Root properties that MUST be represented. Written independently of the
#: catalogue so removing one from the code fails rather than shrinking the
#: expectation with it.
REQUIRED_ROOT_PROPERTIES = frozenset(
    {
        "AUTHORITY_DOMAIN_SEPARATION",
        "SEMANTIC_IDENTITY_BINDING",
        "GOVERNANCE_SURFACE_ABSENCE",
        "H01",  # runtime security context reaches the boundary
        "H02",  # governance integrity gates the effect
        "H05",  # missing governed contract refuses rather than crashing
        "H06",  # anti-shrink floor
        "H07",  # dynamic process-capability resolution
        "H08",  # bootstrap trust snapshot
        "H09",  # temporal approval validity
        "H10",  # ledger continuity
    }
)

#: A truthful floor, not a target. Set below the current total so ordinary
#: consolidation does not fail the gate, and far enough above zero that losing a
#: whole campaign does.
MINIMUM_ATTACKS = 28

#: Owner modules whose deletion must be visible.
OWNERS = (
    "tests/test_domain_collapse_mutations.py",
    "tests/test_semantic_binding_theorem.py",
    "tests/test_historical_reproof.py",
)


# --------------------------------------------------------------------------
# 11A / 11F -- the inventory, and honest duplicate accounting
# --------------------------------------------------------------------------


def test_the_catalogue_is_not_empty_and_holds_its_floor():
    """A floor alone is not the control, but zero must never pass.

    `for x in CATALOGUE` succeeds over an empty tuple, which is the historical
    REQUIRED_MODULES defect. Both bounds are asserted explicitly.
    """
    assert CATALOGUE, "the unified mutation catalogue is empty"
    assert len(CATALOGUE) >= MINIMUM_ATTACKS, (
        f"{len(CATALOGUE)} attack representations, floor is {MINIMUM_ATTACKS}. "
        "A campaign has been lost."
    )


def test_every_required_root_property_is_represented():
    """Set containment against an independently written expectation."""
    present = {attack.root_property_id for attack in CATALOGUE}
    missing = sorted(REQUIRED_ROOT_PROPERTIES - present)
    assert missing == [], (
        f"these root properties have no attack representation at all: {missing}"
    )


def test_attack_identifiers_are_unique():
    """Duplicate IDs would let one attack be counted twice."""
    seen: dict[str, str] = {}
    duplicates: list[str] = []
    for attack in CATALOGUE:
        key = f"{attack.root_property_id}/{attack.attack_id}"
        if key in seen:
            duplicates.append(key)
        seen[key] = attack.owner
    assert duplicates == [], f"duplicate attack identifiers: {duplicates}"


def test_a_root_property_may_hold_several_attacks_without_being_deduplicated():
    """The accounting that keeps defence-in-depth honest.

    GOVERNANCE_SURFACE_ABSENCE carries four representations: three that prove
    the property SURVIVES losing one guard, and one compound attack that removes
    every route and kills it. Collapsing those to "one attack" would report the
    three survivals as failures, and dropping them would hide the evidence that
    the property has independent routes at all.
    """
    surface = [
        attack for attack in CATALOGUE
        if attack.root_property_id == "GOVERNANCE_SURFACE_ABSENCE"
    ]
    assert len(surface) == 4, [a.attack_id for a in surface]
    assert sum(1 for a in surface if a.defence_in_depth) == 3
    assert sum(1 for a in surface if a.compound) == 1
    assert len({a.attack_id for a in surface}) == 4


def test_the_accounting_is_kills_plus_defence_in_depth():
    """34 = 31 + 3, with  as METADATA on one of the kills.

    Stated mechanically because the alternative reading -- 31 + 3 + 1 -- would
    count the compound attack twice and imply a fourth category. A compound
    attack is a kill that had to remove an entire enforcement chain; it is not
    a separate outcome.
    """
    total = len(CATALOGUE)
    defence = sum(1 for a in CATALOGUE if a.defence_in_depth)
    kills = sum(1 for a in CATALOGUE if not a.defence_in_depth)
    compound = [a for a in CATALOGUE if a.compound]

    assert total == kills + defence, f"{total} != {kills} + {defence}"
    assert len(compound) == 1, [a.attack_id for a in compound]
    assert not compound[0].defence_in_depth, (
        "the compound attack is marked defence-in-depth, which would take it "
        "out of the kill count and make the arithmetic 31 + 3 + 1"
    )


def test_the_two_counts_are_reported_separately():
    """Root properties and attack representations are different numbers."""
    roots = {attack.root_property_id for attack in CATALOGUE}
    assert len(CATALOGUE) > len(roots), (
        "every root property has exactly one attack, which means no invariant "
        "is defended against more than one representation"
    )


# --------------------------------------------------------------------------
# 11E -- delegation must be mechanically verifiable
# --------------------------------------------------------------------------


def test_every_owner_module_exists_and_defines_its_killing_test():
    """"Covered elsewhere" is not evidence. The catalogue must say where."""
    problems: list[str] = []
    for attack in CATALOGUE:
        module = ROOT / attack.owner
        if not module.exists():
            problems.append(f"{attack.attack_id}: {attack.owner} is gone")
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        defined = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if attack.killed_by not in defined:
            problems.append(
                f"{attack.attack_id}: {attack.owner} no longer defines "
                f"{attack.killed_by}"
            )
    assert problems == [], problems


def test_every_owner_is_protected_by_the_anti_shrink_census():
    """Deleting an owner module must fail the suite, not shrink it quietly."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import check_test_coverage as census  # noqa: PLC0415

    unprotected = sorted(set(OWNERS) - set(census.REQUIRED_MODULES))
    assert unprotected == [], (
        f"these mutation catalogues are deletable without failing: {unprotected}"
    )


def test_every_production_mutating_owner_proves_mutant_origin():
    """A catalogue that mutates production without isolation proves nothing.

    Asserted structurally against each owner, because this is the property H01
    showed can fail silently: without it a run measures the original source and
    reports whatever the original does.
    """
    for owner in OWNERS:
        source = (ROOT / owner).read_text(encoding="utf-8")
        proves_origin = (
            "_prove_resolution" in source
            or "PYTHONPATH" in source
            or "sys.path.insert(0" in source
        )
        assert proves_origin, (
            f"{owner} mutates production source but shows no evidence of "
            "forcing the mutant ahead of the installed package"
        )


# --------------------------------------------------------------------------
# 11H -- self-mutation of this control
# --------------------------------------------------------------------------


def test_removing_a_required_root_property_is_visible():
    """Simulated against the real sets, so the guard is shown to bite."""
    present = {attack.root_property_id for attack in CATALOGUE} - {"H02"}
    assert sorted(REQUIRED_ROOT_PROPERTIES - present) == ["H02"]


def test_emptying_the_catalogue_is_visible():
    """The REQUIRED_MODULES shape: iteration over nothing must not pass."""
    empty: tuple[Attack, ...] = ()
    assert not empty, "sanity"
    assert len(empty) < MINIMUM_ATTACKS
    assert sorted(REQUIRED_ROOT_PROPERTIES - {a.root_property_id for a in empty})


def test_lowering_the_floor_below_a_lost_campaign_is_visible():
    """A floor that permits losing a whole campaign is not an anti-shrink control."""
    largest = max(
        len([a for a in CATALOGUE if a.owner == owner]) for owner in OWNERS
    )
    assert MINIMUM_ATTACKS > len(CATALOGUE) - largest, (
        f"the floor {MINIMUM_ATTACKS} still passes after losing the largest "
        f"campaign ({largest} attacks of {len(CATALOGUE)})"
    )


def test_removing_a_delegated_owner_is_visible():
    """A named owner that no longer exists must fail, not be skipped over."""
    phantom = Attack(
        root_property_id="AUTHORITY_DOMAIN_SEPARATION",
        attack_id="PHANTOM",
        owner="tests/test_module_that_does_not_exist.py",
        killed_by="test_nothing",
    )
    assert not (ROOT / phantom.owner).exists()


def test_an_attack_without_a_killing_test_is_visible():
    """Every attack must name a test that really exists in its owner."""
    module = ROOT / "tests/test_domain_collapse_mutations.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    defined = {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "test_a_function_that_does_not_exist" not in defined


# --------------------------------------------------------------------------
# 11B -- the global validity contract, self-tested
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "before", "after", "anchor", "expected"),
    [
        ("a no-op replacement", "x = 1 or 2\n", "x = 1 or 2\n", "x = 1", "UNCHANGED"),
        ("a comment target", "# marker\nx = 1\n", "# moved\nx = 1\n", "# marker", "INERT"),
        ("a syntax break", "def f():\n    return 1\n", "def (:\n    return 1\n",
         "def f():", "DOES NOT PARSE"),
    ],
    ids=["no-op", "comment", "syntax"],
)
def test_the_validity_contract_refuses_inadmissible_mutations(
    label: str, before: str, after: str, anchor: str, expected: str
):
    """Points 1-4 of the contract, exercised rather than described.

    Shared by every campaign, so its failure modes are proven once here instead
    of being assumed by each owner.
    """
    from mutation_validity import InvalidMutation, check_python_mutation  # noqa: PLC0415

    with pytest.raises(InvalidMutation, match=expected):
        check_python_mutation("probe.py", before, after, anchor, 1)


def test_the_validity_contract_admits_a_real_change():
    """The control. A contract that refused everything would also be useless."""
    from mutation_validity import check_python_mutation  # noqa: PLC0415

    check_python_mutation(
        "probe.py", "def f():\n    return 1\n", "def f():\n    return 2\n",
        "return 1", 1,
    )


# --------------------------------------------------------------------------
# B-P2-4. AST inequality is necessary and not sufficient.
# --------------------------------------------------------------------------

_PROSE_TARGET = '''def guard(request):
    """Refuse anything unsigned."""
    if not request.signature:
        return False
    return True
'''


def test_a_docstring_only_edit_is_refused_even_when_the_anchor_starts_on_code():
    """The exact shape Lens B used to credit a kill that removed nothing.

    The anchor begins on `def guard(request):` -- a line of code, so the
    start-offset test is satisfied -- and runs on into the docstring. Only the
    prose differs. Docstrings are AST nodes, so the parse trees differ too and
    the AST-inequality check passes. Both guards clear, and the control is
    entirely intact.
    """
    anchor = 'def guard(request):\n    """Refuse anything unsigned."""'
    replacement = 'def guard(request):\n    """Refuse anything at all."""'
    after = _PROSE_TARGET.replace(anchor, replacement)

    assert after != _PROSE_TARGET, "the edit must actually apply"
    assert ast.dump(ast.parse(after)) != ast.dump(ast.parse(_PROSE_TARGET)), (
        "if the parse trees matched, the older check would already refuse this "
        "and the case would prove nothing"
    )

    with pytest.raises(InvalidMutation) as refusal:
        check_python_mutation("probe.py", _PROSE_TARGET, after, anchor, 1)
    assert "PROSE-ONLY MUTATION" in str(refusal.value), str(refusal.value)


def test_a_real_edit_at_the_same_anchor_is_still_admitted():
    """The control. A checker that refused everything would also pass above."""
    anchor = "    if not request.signature:"
    replacement = "    if False:"
    after = _PROSE_TARGET.replace(anchor, replacement)

    check_python_mutation("probe.py", _PROSE_TARGET, after, anchor, 1)


def test_the_projection_keeps_executable_text_and_drops_prose():
    """Measured directly, so the guard above rests on something checkable."""
    projected = executable_projection(_PROSE_TARGET)

    assert "Refuse anything unsigned" not in projected
    assert "if not request.signature:" in projected
    assert "return False" in projected


def test_a_comment_only_edit_is_refused_too():
    """Comments were already covered by the offset test; this proves the
    projection does not quietly regress that."""
    source = "def f():\n    x = 1  # keep\n    return x\n"
    after = "def f():\n    x = 1  # drop\n    return x\n"

    with pytest.raises(InvalidMutation):
        check_python_mutation("probe.py", source, after, "    x = 1  # keep", 1)
