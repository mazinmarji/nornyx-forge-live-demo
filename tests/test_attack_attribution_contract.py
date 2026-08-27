"""An attack with no violation criterion may not be credited with a kill.

R2. The runner establishes, in order, that the registered node exists, passes
pristine, targets production source, reaches the mutated clause, that the
mutation applied and loaded, and that the SAME node then failed in the call
phase. All of that is about a TEST FAILING. None of it asks WHICH PROPERTY
BROKE -- and a failure about a diagnostic NAME satisfies every one of those
steps while the security property stands untouched.

`AuthoritativeProperty` exists to close that, and it does, for the attacks that
carry one. The gap is the guard itself:

    if item.authoritative_property is not None:
        if not item.authoritative_property.violated_in(tree):
            fail(INVALID_PROPERTY_ATTRIBUTION)

An attack with NO criterion skips attribution entirely and is credited on the
victim test failing alone. Measured across the catalogue at the head this was
written against: 19 registered attacks, 14 carrying a criterion, 5 without
(H03, H04, H13 pending; H11, H12 delegated). `DIRECT` happens to contain only
the 14 today, so the omission is latent rather than live -- but nothing
structural keeps it that way, and "it happens to be fine right now" is not a
property.

THE CONTRACT THIS MODULE ENFORCES:

    1. a stable property ID
    2. a machine-verifiable violation criterion
    3. explanatory prose

Only 1 and 2 may affect a verdict. `prop`, `control` and `expect` are prose:
they describe the attack for a reader and must never decide it. In particular a
criterion is NEVER derived by promoting `prop` -- a sentence is not a
measurement, and mechanically turning one into the other would manufacture
authority from wording, which is the substitution this whole programme exists
to refuse.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
import test_historical_reproof as reproof
from attack_property import AuthoritativeProperty


def test_every_attack_the_runner_can_credit_carries_a_criterion() -> None:
    """The structural half: nothing creditable may lack attribution.

    `DIRECT` is what the runner is parametrised over, so an entry here without
    a criterion is an entry that can reach KILLED_VALIDLY on a test failure
    alone. This is the guard that keeps the behavioural gap below from becoming
    reachable by adding a row.
    """
    missing = [
        item.ident for item in reproof.DIRECT
        if getattr(item, "authoritative_property", None) is None
    ]
    assert missing == [], (
        "these attacks can be credited with a kill without any measurement of "
        "the property they claim to be about, because the runner only checks "
        f"attribution when a criterion is present: {missing}"
    )


def test_the_criterion_set_is_not_empty_and_is_typed() -> None:
    """Guard the guard. A `DIRECT` that emptied out, or criteria that were
    replaced by prose, would satisfy the test above while measuring nothing."""
    assert len(reproof.DIRECT) >= 14, (
        f"only {len(reproof.DIRECT)} attacks are registered as directly "
        "re-provable; the catalogue has shrunk and the sweep above now covers "
        "less than it did"
    )
    for item in reproof.DIRECT:
        criterion = item.authoritative_property
        assert isinstance(criterion, AuthoritativeProperty), (
            f"{item.ident}: the authoritative property is "
            f"{type(criterion).__name__}, not an AuthoritativeProperty. A "
            "string here would be PROSE deciding a verdict."
        )
        assert callable(criterion.violated_in), (
            f"{criterion.ident}: the violation criterion is not executable"
        )


def test_prose_fields_are_never_the_criterion() -> None:
    """`prop`, `control` and `expect` are descriptive only.

    The tempting repair for a missing criterion is to promote the sentence that
    is already there -- `authoritative_property = prop`. That manufactures
    authority out of wording: the sentence is unchanged, nothing new is
    measured, and the verdict becomes decidable by an author's phrasing. This
    asserts the promotion has not happened, in either direction.
    """
    for item in reproof.DIRECT:
        criterion = item.authoritative_property
        for field in ("prop", "control", "expect"):
            text = getattr(item, field, "")
            assert criterion.ident != text, (
                f"{item.ident}: the authoritative property's ID is the {field!r} "
                "prose verbatim, so the identity of the property is a sentence"
            )
            assert criterion.violated_in is not text, (
                f"{item.ident}: the violation criterion IS the {field!r} string"
            )


@pytest.mark.false_green("FG34")
def test_an_attack_without_a_criterion_is_refused_by_the_runner(
    tmp_path: Path,
) -> None:
    """The behavioural half, driven through the REAL runner.
    FG34: a KILL credited when only a named test failed.

    Same attack, same mutation, same victim test -- only the criterion removed.
    If the runner credits this, then omitting semantic attribution changes the
    verdict, which is the defect. The structural guard above prevents a
    criterion-less entry from being added to `DIRECT`; this one proves the
    runner itself would not honour such an entry even if it appeared by another
    route.
    """
    subject = next(
        item for item in reproof.DIRECT
        if item.ident.startswith("H10")
    )
    stripped = dataclasses.replace(subject, authoritative_property=None)

    with pytest.raises(BaseException) as raised:  # noqa: PT011 - pytest.fail
        reproof.test_removing_the_control_revives_the_defect(stripped, tmp_path)

    assert "AUTHORITATIVE" in str(raised.value).upper() or "CRITERION" in str(
        raised.value
    ).upper(), (
        "the runner refused, but not because attribution was missing, so this "
        f"proves nothing about the contract: {str(raised.value)[:200]}"
    )


def test_the_same_attack_with_its_criterion_is_still_credited(
    tmp_path: Path,
) -> None:
    """The control, and it is the load-bearing half.

    Without it, the test above is satisfied by a runner that refuses
    EVERYTHING -- which would close the gap by making the catalogue prove
    nothing at all. The same attack, unmodified, must still reach a verdict.
    """
    subject = next(
        item for item in reproof.DIRECT
        if item.ident.startswith("H10")
    )
    reproof.test_removing_the_control_revives_the_defect(subject, tmp_path)


# --------------------------------------------------------------------------
# TERMINAL CLASSIFICATION
#
# R2 requires every registered attack to reach ONE terminal classification
# before any total is calculated. The three below are exhaustive and mutually
# exclusive, and each one carries a different obligation:
#
#   CRITERION  the runner re-proves it directly, and refuses to credit it
#              unless an executable `violated_in` is violated in the mutant.
#              Enforced in `test_removing_the_control_revives_the_defect`.
#
#   DELEGATED  a dedicated catalogue module re-proves it. The obligation is
#              that the delegate performs its OWN attribution -- otherwise
#              delegation is simply a route around the criterion. Both
#              delegates were read and both do, in their own vocabulary; the
#              negative control below is what MEASURES that rather than
#              trusting the reading.
#
#   PENDING    not proven. The obligation is that it can never be COUNTED as
#              proven: it must not be creditable by the runner, and it must not
#              appear in a kill total.
#
# The map is written out rather than derived from the buckets it is checked
# against. Deriving it would make the test agree with the code by construction:
# any reclassification would move both sides together and assert nothing.
# --------------------------------------------------------------------------

TERMINAL_CLASSIFICATION = {
    "H01": "CRITERION", "H02": "CRITERION", "H05": "CRITERION",
    "H06": "CRITERION", "H07": "CRITERION", "H08": "CRITERION",
    "H09": "CRITERION", "H10": "CRITERION", "H14": "CRITERION",
    "H15": "CRITERION", "H16": "CRITERION", "H17": "CRITERION",
    "H18": "CRITERION", "H19": "CRITERION",
    "H11": "DELEGATED", "H12": "DELEGATED",
    "H03": "PENDING", "H04": "PENDING", "H13": "PENDING",
}


def _tag(item) -> str:
    return item.ident.split()[0]


def test_every_registered_attack_has_exactly_one_terminal_classification() -> None:
    """No attack may be unclassified, and none may be classified twice."""
    registered = {_tag(item) for item in reproof.INVENTORY}
    classified = set(TERMINAL_CLASSIFICATION)
    assert registered == classified, (
        "the registered attacks and the terminally classified attacks differ. "
        f"Registered but unclassified: {sorted(registered - classified)}. "
        f"Classified but not registered: {sorted(classified - registered)}. "
        "An unclassified attack is one whose evidential status nobody has "
        "decided, and R2 forbids calculating a total over such a set."
    )
    assert set(TERMINAL_CLASSIFICATION.values()) <= {
        "CRITERION", "DELEGATED", "PENDING"
    }


def test_the_classification_matches_where_each_attack_actually_sits() -> None:
    """The written map must agree with the buckets the runner really uses.

    This is the half that makes the map worth writing: if an attack moves
    between buckets, the map and the code disagree and this goes red, rather
    than the map silently following the code.
    """
    actual = {}
    for item in reproof.DIRECT:
        actual[_tag(item)] = "CRITERION"
    for item in reproof.DELEGATED:
        actual[_tag(item)] = "DELEGATED"
    for item in reproof.PENDING:
        actual[_tag(item)] = "PENDING"
    assert actual == TERMINAL_CLASSIFICATION, (
        "an attack has moved between buckets without its terminal "
        "classification being reconsidered: " + "; ".join(
            f"{tag}: recorded {TERMINAL_CLASSIFICATION.get(tag)!r}, "
            f"actually {actual.get(tag)!r}"
            for tag in sorted(set(actual) | set(TERMINAL_CLASSIFICATION))
            if actual.get(tag) != TERMINAL_CLASSIFICATION.get(tag)
        )
    )


def test_a_pending_attack_can_never_be_credited_by_the_runner() -> None:
    """PENDING means NOT PROVEN, and must cost a claim rather than earn one.

    `DIRECT` is what the runner is parametrised over. A pending attack that
    appeared there would be re-proved and counted like any other, which is the
    difference between "we have not shown this" and "we have shown this".
    """
    direct = {_tag(item) for item in reproof.DIRECT}
    leaked = sorted(
        tag for tag, kind in TERMINAL_CLASSIFICATION.items()
        if kind == "PENDING" and tag in direct
    )
    assert leaked == [], (
        f"these attacks are classified PENDING and are creditable: {leaked}"
    )


def test_a_delegated_attack_names_a_delegate_that_performs_attribution(
    tmp_path: Path,
) -> None:
    """Delegation must not be a route around the criterion.

    MEASURED, not read. The delegate's own negative control is INVOKED here: it
    asserts that a mutant which broke the run is not credited with a kill. If
    the delegate credited a crash, that control fails and this test fails with
    it -- which is what stops "H11 is proved elsewhere" from being a claim about
    a filename.

    BOUND, stated: this measures H11's delegate. H12's attribution is INLINE in
    `test_the_projection_attack_is_killed` (it requires the HONEST projection to
    distinguish the pair before crediting the attack that collapses it), and it
    is exercised by that module's own parametrisation rather than by a separate
    negative control this test could invoke. H12's classification therefore
    rests on that module running, which the census enforces, not on a control
    driven from here.
    """
    import test_domain_collapse_mutations as collapse  # noqa: PLC0415

    collapse.test_fg23_a_mutant_that_broke_the_run_is_not_a_kill(tmp_path)


def test_every_delegate_module_and_node_exists() -> None:
    """The cheap half, kept because a renamed module makes the above unrunnable."""
    missing = []
    for item in reproof.DELEGATED:
        module, _, node = item.test.partition("::")
        path = Path(reproof.ROOT) / module
        if not path.exists():
            missing.append(f"{item.ident}: {module} is gone")
        elif node and f"def {node.split('[')[0]}(" not in path.read_text(
            encoding="utf-8"
        ):
            missing.append(f"{item.ident}: {module} no longer defines {node}")
    assert missing == [], missing
