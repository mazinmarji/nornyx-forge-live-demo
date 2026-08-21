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
            # COMPOUND when the proof needs cumulative removal of more than one
            # enforcement route. H05 recorded `compound=False` while carrying two
            # edits and genuinely needing both: measured, R1 alone SURVIVES and
            # R1+R2 kills. The label disagreed with the semantics, which is the
            # mismatch this whole cycle exists to remove -- benign here, because
            # the kill itself is valid, but the same shape as the defects that
            # were not benign.
            compound=bool(item.extra_mutations),
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
        for label, _relative, _anchor, _condition in historical.GOVERNANCE_SURFACE_CHAIN
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

    GOVERNANCE_SURFACE_ABSENCE carries five representations: four that prove
    the property SURVIVES losing one guard, and one compound attack that removes
    every route and kills it. Collapsing those to "one attack" would report the
    three survivals as failures, and dropping them would hide the evidence that
    the property has independent routes at all.
    """
    surface = [
        attack for attack in CATALOGUE
        if attack.root_property_id == "GOVERNANCE_SURFACE_ABSENCE"
    ]
    assert len(surface) == 5, [a.attack_id for a in surface]
    assert sum(1 for a in surface if a.defence_in_depth) == 4
    assert sum(1 for a in surface if a.compound) == 1
    assert len({a.attack_id for a in surface}) == 5


#: The attacks that are DEFENCE-IN-DEPTH evidence rather than kills, BY NAME.
#:
#: An arithmetic identity cannot police this. `total == kills + defence` holds
#: for any labelling whatsoever, because `kills` is defined as "not defence" --
#: so Lens B marked all fourteen domain attacks defence-in-depth, restated the
#: campaign as 34 = 17 + 17, and every catalogue test stayed green. The numbers
#: 34/31/3 existed only in a docstring, where nothing executes them.
#:
#: Defence-in-depth is a claim about a specific property having independent
#: enforcement routes. It is therefore a fact about NAMED attacks, and it is
#: written here so that reclassifying one has to change this line, in the diff,
#: where a reviewer can see it.
#: Attacks whose proof needs CUMULATIVE removal of more than one enforcement
#: route. Named rather than counted, and each one's minimality is measured by
#: `test_every_compound_attack_is_proven_minimal` -- an extra edit could be
#: scaffolding, so needing two edits is a reason to check, never a proof.
COMPOUND_ATTACKS = frozenset({"H05-DIRECT", "SURFACE-WHOLE-CHAIN"})

DEFENCE_IN_DEPTH_ATTACKS = frozenset(
    {
        "SURFACE-GUARD-A",
        "SURFACE-GUARD-B",
        "SURFACE-GUARD-C",
        # Route D is the constructor refusal on GovernanceIntegrityState, added
        # when that refusal stopped being only a docstring. It lives in a
        # different module from A, B and C: the property is defended across a
        # file boundary.
        "SURFACE-GUARD-D",
    }
)

#: What the campaign actually measured. Pinned, because a floor is not a count.
EXPECTED_TOTAL_ATTACKS = 41
EXPECTED_KILLS = 37
EXPECTED_DEFENCE_IN_DEPTH = 4


def test_the_accounting_is_kills_plus_defence_in_depth():
    """41 = 37 + 4, with `compound` as METADATA on one of the kills.

    Not 37 + 4 + 1: that reading counts the compound attack twice and implies a
    fourth category. A compound attack is a kill that had to remove an entire
    enforcement chain.

    Every number here is asserted against a written constant rather than against
    another expression over the same data. The previous version asserted
    `total == kills + defence`, which is true of any labelling, and the real
    figures lived in prose.
    """
    total = len(CATALOGUE)
    defence = {a.attack_id for a in CATALOGUE if a.defence_in_depth}
    kills = [a for a in CATALOGUE if not a.defence_in_depth]
    compound = [a for a in CATALOGUE if a.compound]

    assert total == EXPECTED_TOTAL_ATTACKS, f"{total} attacks, expected 41"
    assert len(kills) == EXPECTED_KILLS, f"{len(kills)} kills, expected 37"
    assert len(defence) == EXPECTED_DEFENCE_IN_DEPTH, sorted(defence)
    assert total == len(kills) + len(defence), f"{total} != {len(kills)} + {len(defence)}"

    assert defence == DEFENCE_IN_DEPTH_ATTACKS, (
        "the set of attacks claimed as defence-in-depth has changed. That claim "
        "is about specific properties having independent enforcement routes, so "
        f"it is named, not counted.\n  expected {sorted(DEFENCE_IN_DEPTH_ATTACKS)}"
        f"\n  found    {sorted(defence)}"
    )
    # NAMED, not counted -- for the same reason the defence-in-depth set above
    # is. `len(compound) == 1` was true only while H05 was mislabelled: it
    # needs two cumulative edits and was recorded non-compound, so the count
    # agreed with the expectation by way of an error.
    assert {a.attack_id for a in compound} == COMPOUND_ATTACKS, (
        "the set of attacks needing cumulative removal has changed.\n"
        f"  expected {sorted(COMPOUND_ATTACKS)}\n"
        f"  found    {sorted(a.attack_id for a in compound)}"
    )
    assert not any(a.defence_in_depth for a in compound), (
        "a compound attack is marked defence-in-depth, which would take it out "
        "of the kill count and double-count the arithmetic"
    )


def test_relabelling_every_attack_as_defence_in_depth_is_refused():
    """The self-attack. This is the exact restatement Lens B performed.

    Marking all fourteen domain attacks defence-in-depth produced 34 = 17 + 17
    with the whole catalogue green. It must now fail on the identity check, not
    on the arithmetic -- the arithmetic is still perfectly satisfied.
    """
    from dataclasses import replace  # noqa: PLC0415

    restated = tuple(
        replace(attack, defence_in_depth=True)
        if attack.owner == "tests/test_domain_collapse_mutations.py"
        else attack
        for attack in CATALOGUE
    )
    defence = {a.attack_id for a in restated if a.defence_in_depth}
    kills = [a for a in restated if not a.defence_in_depth]

    # The arithmetic the old test relied on still holds under the attack.
    assert len(restated) == len(kills) + len(defence), (
        "the restatement must remain arithmetically consistent, or this case "
        "proves nothing about why counting was insufficient"
    )
    assert defence != DEFENCE_IN_DEPTH_ATTACKS, (
        "the restatement did not change the defence-in-depth set, so it is not "
        "the attack it claims to be"
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


def delegation_problems(attacks) -> list[str]:
    """Every attack whose owner is gone or no longer defines its killing test.

    A function rather than a loop inside one test, so the self-attacks below can
    RUN it against a deliberately broken attack. They previously asserted that
    an invented module path did not exist and that an invented function name was
    not defined -- both true of any string nobody had used, and neither reaching
    this logic at all.
    """
    problems: list[str] = []
    for attack in attacks:
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
            continue
        # A NAME IS NOT A PROOF. This checked only that a FunctionDef with the
        # right name existed, and Lens B exhibited it accepting private helpers
        # with zero assertions as the thing that kills an attack. Gutting the
        # five functions that carry all 41 kills left every count, the identity
        # set and GATE: PASS intact, because all five are parametrised so the
        # collected total does not move either.
        #
        # Static only, and deliberately so: this defends the catalogue against
        # shrinkage and substitution. Whether the RIGHT assertion runs on the
        # hostile path is the runner's question, answered by exact-node,
        # exact-phase, intended-property attribution.
        from test_killed_by_validation import _defensive_evidence  # noqa: PLC0415

        if _defensive_evidence(module.read_text(encoding="utf-8"), attack.killed_by) == 0:
            problems.append(
                f"{attack.attack_id}: {attack.owner} defines {attack.killed_by} "
                "but its body contains nothing that can fail"
            )
    return problems


def test_every_owner_module_exists_and_defines_its_killing_test():
    """"Covered elsewhere" is not evidence. The catalogue must say where."""
    problems = delegation_problems(CATALOGUE)
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
    """A named owner that no longer exists must fail, not be skipped over.

    This used to assert that an invented module path did not exist -- true of
    any string nobody had used, and it never reached the validation. The phantom
    now goes THROUGH `delegation_problems`, which is the code that would have to
    notice a real deletion.
    """
    phantom = Attack(
        root_property_id="AUTHORITY_DOMAIN_SEPARATION",
        attack_id="PHANTOM",
        owner="tests/test_module_that_does_not_exist.py",
        killed_by="test_nothing",
    )
    problems = delegation_problems([phantom])

    assert problems, "a missing owner module produced no problem at all"
    assert "PHANTOM" in problems[0] and "is gone" in problems[0], problems


def test_an_attack_without_a_killing_test_is_visible():
    """Every attack must name a test that really exists in its owner.

    This used to assert an invented function name was not defined in a module,
    which is true of any name nobody wrote and proves nothing about the
    catalogue. The phantom now names a REAL owner and a missing killing test,
    and the validation must report it.
    """
    phantom = Attack(
        root_property_id="AUTHORITY_DOMAIN_SEPARATION",
        attack_id="ORPHAN",
        owner="tests/test_domain_collapse_mutations.py",
        killed_by="test_a_function_that_does_not_exist",
    )
    problems = delegation_problems([phantom])

    assert problems, "an attack naming a nonexistent killing test was accepted"
    assert "no longer defines" in problems[0], problems

    # And the control: a real attack from the shipped catalogue passes.
    assert delegation_problems([CATALOGUE[0]]) == []


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


#: Every attack that must exist, BY NAME. A floor counts; this identifies.
#:
#: Lens B deleted six of the fourteen domain-collapse mutations and the campaign
#: landed exactly on MINIMUM_ATTACKS = 28 with every test green. A floor cannot
#: see which attacks are gone -- only how many remain -- so six specific
#: authority-domain collapses could stop being tested and the catalogue would
#: still certify itself.
#:
#: Written out rather than derived from the catalogue, because a list computed
#: from the thing it checks agrees with it by construction.
REQUIRED_ATTACK_IDS = frozenset(
    {
        # Authority-domain separation: all fourteen collapses.
        "M1", "M2", "M3", "M4", "M5", "M6", "M7",
        "M8", "M9", "M10", "M11", "M12", "M13", "M14",
        # Semantic-identity binding: all eight projection attacks.
        "9C-0", "9C-1", "9C-2", "9C-3", "9C-4", "9C-5", "9C-6", "9C-7",
        # Historical classes proved directly.
        "H01-DIRECT", "H02-DIRECT", "H05-DIRECT", "H06-DIRECT",
        "H07-DIRECT", "H08-DIRECT", "H09-DIRECT", "H10-DIRECT",
        # The governance-surface family: three defence-in-depth probes and the
        # compound attack that kills the property.
        "SURFACE-GUARD-A", "SURFACE-GUARD-B", "SURFACE-GUARD-C",
        "SURFACE-GUARD-D", "SURFACE-WHOLE-CHAIN",
        # H14/H16/H17/H19 gained direct attacks after the seven-class coverage
        # statement. The identity control refused to let them be protected only
        # by the floor, which is the discipline it was built for.
        "H14-DIRECT", "H15-DIRECT", "H16-DIRECT", "H17-DIRECT",
        "H18-DIRECT",
        # H19-DIRECT WAS REMOVED FROM THIS SET AND IS BACK, because removing it
        # was my error. I had measured its mutation raising FileNotFoundError
        # and read that as "the unsafe state is unreachable"; the crash came
        # from the member my probe deleted -- a contract, read eagerly -- not
        # from the attack. Against a required ROOT the same registered mutation
        # verifies a smaller subject and mints a digest, which is the recorded
        # defect exactly. An independent review found this; I reproduced it.
        "H19-DIRECT", 
    }
)


def test_every_named_attack_is_still_present():
    """The anti-shrink control that a floor cannot provide.

    Deleting attacks now fails by NAME, and the failure says which ones, so the
    diff that removes an authority-domain collapse has to argue for it.
    """
    present = {attack.attack_id for attack in CATALOGUE}
    missing = sorted(REQUIRED_ATTACK_IDS - present)
    assert missing == [], (
        f"these attacks have disappeared from the catalogue: {missing}. Each was "
        "a hostile representation of a real invariant; removing one is a "
        "reduction in what this repository proves, not a consolidation."
    )


def test_the_floor_alone_would_not_have_caught_the_deletion():
    """Why the identity set exists, stated as a measurement rather than a claim.

    Reproduces Lens B's deletion: drop the six domain attacks it dropped, and
    show the floor still passes while the identity check does not.
    """
    survivors = tuple(
        attack for attack in CATALOGUE
        if attack.attack_id not in {"M9", "M10", "M11", "M12", "M13", "M14"}
    )

    assert len(survivors) >= MINIMUM_ATTACKS, (
        f"{len(survivors)} left after the deletion, floor {MINIMUM_ATTACKS} -- "
        "this case only demonstrates the gap if the floor still passes"
    )
    missing = sorted(REQUIRED_ATTACK_IDS - {a.attack_id for a in survivors})
    assert missing == ["M10", "M11", "M12", "M13", "M14", "M9"], missing


def test_the_required_set_is_not_derived_from_the_catalogue():
    """A written expectation, checked by reading the source.

    If REQUIRED_ATTACK_IDS were built from CATALOGUE it would match it always,
    and the test above would be a tautology -- the exact defect recorded against
    EXPECTED_9C_IDS.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    declaration = source[source.index("REQUIRED_ATTACK_IDS = frozenset("):]
    declaration = declaration[: declaration.index("\n)\n")]

    assert "CATALOGUE" not in declaration, (
        "REQUIRED_ATTACK_IDS is computed from the catalogue it checks, so it "
        "agrees with it by construction and proves nothing"
    )
    assert "for " not in declaration, (
        "REQUIRED_ATTACK_IDS is built by a comprehension rather than written out"
    )


def test_no_attack_is_protected_only_by_the_floor():
    """The floor's own guard weakens exactly when the catalogue is eroded.

    `MINIMUM_ATTACKS > len(CATALOGUE) - largest` gets EASIER to satisfy as
    campaigns shrink: the smaller the catalogue, the smaller the shortfall the
    floor has to exceed. A control that relaxes in proportion to the damage is
    not an anti-shrink control.

    So the floor is no longer the anti-shrink control -- REQUIRED_ATTACK_IDS is,
    and this asserts its coverage is TOTAL. Every attack in the catalogue is
    named there, so losing any one fails by name whatever the floor says, and
    the floor is left as a secondary sanity bound rather than the thing standing
    between the campaign and quiet erosion.

    Adding an attack fails here until it is named. That is the same discipline
    REQUIRED_MODULES applies, and it is the point: the inventory is a decision
    someone records.
    """
    present = {attack.attack_id for attack in CATALOGUE}
    unprotected = sorted(present - REQUIRED_ATTACK_IDS)

    assert unprotected == [], (
        f"these attacks are in the catalogue but not named in "
        f"REQUIRED_ATTACK_IDS, so only the floor protects them: {unprotected}"
    )


def test_the_identity_control_survives_a_floor_that_is_far_too_low():
    """The floor could be set to 1 and deletion would still fail.

    Measured rather than asserted about: the same six-attack deletion Lens B
    performed is run against an absurd floor, and the identity check still
    reports every missing attack.
    """
    absurd_floor = 1
    survivors = tuple(
        attack for attack in CATALOGUE
        if attack.attack_id not in {"M9", "M10", "M11", "M12", "M13", "M14"}
    )

    assert len(survivors) >= absurd_floor, "the floor cannot catch this"
    missing = sorted(REQUIRED_ATTACK_IDS - {a.attack_id for a in survivors})
    assert missing == ["M10", "M11", "M12", "M13", "M14", "M9"], missing

def test_every_historical_class_has_exactly_one_terminal_disposition():
    """Task 11 closure is a statement about the SET, not about any one class.

    Every H-class must land in exactly one terminal bucket -- a direct kill, a
    compound kill, an obsolete historical attack, or delegation to a dedicated
    catalogue -- and none may be in two. A class that fell out of every bucket
    would silently stop being accounted for, which is how "NOT_YET_KILLED = 0"
    could be true while a property went unrepresented.
    """
    import test_historical_reproof as historical  # noqa: PLC0415

    every = {item.ident.split()[0] for item in historical.INVENTORY}
    buckets = {
        "direct": {i.ident.split()[0] for i in historical.DIRECT},
        "compound": set(historical.KILLED_VALIDLY_COMPOUND),
        "obsolete": set(historical.OBSOLETE_HISTORICAL_ATTACK),
        "delegated": {i.ident.split()[0] for i in historical.DELEGATED},
        "open": set(historical.NOT_YET_KILLED),
    }
    covered = set().union(*buckets.values())
    assert every == covered, (
        f"these classes have no terminal disposition: {sorted(every - covered)}"
    )

    overlaps = []
    for name, members in buckets.items():
        for other, rest in buckets.items():
            if name < other and (members & rest):
                overlaps.append(f"{name}/{other}: {sorted(members & rest)}")
    assert overlaps == [], f"classes in two terminal buckets at once: {overlaps}"

def test_every_attack_names_exactly_one_pytest_node():
    """Lens B P1-3, enforced globally rather than repaired specimen by specimen.

    H10 named a whole module -- 38 tests -- so any one of them failing credited
    its kill. Fixing H10 removed the instance; this removes the possibility.
    """
    import test_historical_reproof as historical  # noqa: PLC0415
    from mutation_workspace import AttackNotAdmissible, require_exact_node  # noqa: PLC0415

    problems = []
    for item in historical.INVENTORY:
        if not item.test:
            continue
        try:
            require_exact_node(item.test)
        except AttackNotAdmissible as refusal:
            problems.append(f"{item.ident.split()[0]}: {refusal}")
    assert problems == [], problems


def test_a_module_level_target_is_refused():
    """The negative case, against the real guard.

    Without this, the invariant above passes vacuously the day someone writes a
    module target -- it would simply report the new violation rather than
    proving the guard can reject one.
    """
    from mutation_workspace import (  # noqa: PLC0415
        AttackNotAdmissible,
        Outcome,
        require_exact_node,
    )

    for bad in ("tests/test_approval_ledger.py", "tests/test_x.py::", "tests/x.py::a::b",
                "not_a_module::test_x"):
        with pytest.raises(AttackNotAdmissible) as refusal:
            require_exact_node(bad)
        assert refusal.value.outcome is Outcome.INVALID_TEST_TARGET, bad

    require_exact_node("tests/test_approval_ledger.py::test_something")


def test_a_cumulative_attack_cannot_be_recorded_as_non_compound():
    """`compound` must mean what the catalogue says it means.

    H05 carried two edits, genuinely needed both, and was recorded
    `compound=False`. The kill was valid, so nothing unsafe followed -- but a
    label disagreeing with the semantics it describes is the exact shape of
    every defect this cycle found, and it is cheaper to refuse here than to
    rediscover it in a review.
    """
    import test_historical_reproof as historical  # noqa: PLC0415

    cumulative = {
        f"{item.ident.split()[0]}-DIRECT"
        for item in historical.DIRECT
        if item.extra_mutations
    }
    recorded = {attack.attack_id for attack in CATALOGUE if attack.compound}
    missing = sorted(cumulative - recorded)
    assert missing == [], (
        f"these attacks need more than one edit but are recorded as "
        f"non-compound: {missing}"
    )


def test_every_compound_attack_is_proven_minimal(tmp_path: Path):
    """FG25. MINIMALITY MEASURED, not inferred from the edit count.

    An extra edit could be scaffolding rather than a second enforcement route,
    so `len(extra_mutations) > 0` is a reason to CHECK minimality, never a
    proof of it. A compound whose components are not each necessary is a padded
    inventory: it looks like defence in depth and is really one route plus
    decoration.

    Measured for H05: removing the FileNotFoundError handler alone leaves the
    named proof PASSING, because FileNotFoundError IS an OSError and the second
    handler still catches it. Both are required before the verifier crashes
    instead of refusing.
    """
    import test_historical_reproof as historical  # noqa: PLC0415
    from mutation_validity import check_mutation  # noqa: PLC0415
    from mutation_workspace import (  # noqa: PLC0415
        AttackNotAdmissible,
        faithful_copy,
        require_caused_failure,
        run_node,
    )

    for item in historical.DIRECT:
        if not item.extra_mutations:
            continue
        # Drop the LAST edit. If the attack still kills, that edit was not
        # necessary and the compound is padded.
        edits = [item.mutation, *item.extra_mutations][:-1]
        tree = faithful_copy(tmp_path / item.ident.split()[0])
        for relative, anchor, replacement, count in edits:
            target = tree / relative
            before = target.read_text(encoding="utf-8")
            after = before.replace(anchor, replacement)
            check_mutation(relative, before, after, anchor, count)
            target.write_text(after, encoding="utf-8", newline="")

        report = tmp_path / f"{item.ident.split()[0]}.xml"
        completed = run_node(tree, item.test, report=report)
        try:
            require_caused_failure(report, item.test, completed.stdout + completed.stderr)
        except AttackNotAdmissible:
            continue  # did not kill without the final edit: the edit is required
        raise AssertionError(
            f"{item.ident}: the attack still kills without its last edit, so "
            "that edit is not an independently required route and this compound "
            "is padded rather than minimal"
        )


def test_every_killing_test_is_actually_collected_by_pytest():
    """TASK 11: the totals rest on tests that RUN, not on tests that exist.
    FG38: a proven attack whose proof was only DEFINED.

    `test_every_owner_module_exists_and_defines_its_killing_test` checks that
    the module contains `def <node>(`. That is presence. A node can be present
    and never run -- deselected by a marker, shadowed by a same-named
    definition later in the file, or excluded by configuration -- and every
    count in this catalogue would still be reported.

    So collection is MEASURED, by asking pytest what it would run. `addopts` is
    cleared because this repository sets `-q`, which makes a second `-q`
    summarise per module and hide the node ids entirely -- the output would then
    contain none of the names and this test would fail for a reason that has
    nothing to do with the catalogue.

    Parametrised nodes appear as `node[case]`, so a prefix match is the right
    comparison and the COUNT is reported: an attack whose node collects zero
    cases is an attack nothing proves.
    """
    import subprocess  # noqa: PLC0415
    import sys  # noqa: PLC0415

    collected = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:randomly", "-o", "addopts="],
        cwd=ROOT, capture_output=True, text=True, timeout=1800, check=False,
    ).stdout.replace(chr(92), "/")

    assert collected.count("::") > 500, (
        "pytest collection produced almost no node ids, so this test cannot "
        "establish anything about which killing tests run: "
        + collected[-300:]
    )

    uncollected = []
    for owner, node in sorted({(a.owner, a.killed_by) for a in CATALOGUE}):
        if collected.count(f"{owner}::{node}") == 0:
            uncollected.append(f"{owner}::{node}")

    assert uncollected == [], (
        "these attacks name a killing test that pytest does not collect, so "
        "the attack is counted in the totals and proven by nothing that runs: "
        f"{uncollected}"
    )
