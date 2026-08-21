"""No criterion may turn an unmeasurable probe into a verdict.

R7-b. Two reviews, on two different probes, found the same shape: the probe
could not reach the symbol it observes, caught the resulting exception, and
reported a VALUE. The value scored a kill. So renaming a private helper, or
renaming a field on `RuntimeSubject`, credited an attack with breaking a
security property that nobody measured -- through this repository's own kill
protocol, with the owning module green.

The guard that closed the first instance matched a SYNTAX SHAPE: it walked the
probe sources with `ast` and asserted that none contained a bare
`except Exception`. A review pointed out what that is worth -- a probe can
swallow an exception without spelling it that way, and can spell it that way
for a legitimate reason -- and prescribed the alternative this module
implements: EXECUTE THE PROPERTY.

So this drives every criterion the module defines against a tree in which the
production symbols are gone, and requires each one to WITHDRAW. Nothing here
reads a probe's source. A criterion passes by behaving correctly, not by
avoiding a construct.

WHY A HOLLOW TREE AND NOT AN EMPTY ONE. In an empty directory every probe fails
at `import`, the child exits non-zero, and `run_probe`'s returncode check
refuses -- a path that was already correct and that no criterion can override.
That would prove nothing about the criteria. In a HOLLOW tree the modules all
exist and import cleanly, and only the SYMBOLS are absent, so the probe runs
far enough to have something to swallow. That is the state a rename actually
produces, and it is the state both recorded defects were reached from.

WHAT THIS DOES NOT REACH, stated rather than implied: a probe whose target
symbol exists and whose OBSERVED OBJECT lacks the field being read. Hollowing
the modules cannot produce that -- the module is empty, so the call never
returns an object at all. The second recorded defect (`getattr(subject,
"subject_verified", True)`, where an absent field defaulted to the value that
scores a kill) is repaired at the probe and is covered by
`test_a_probe_reports_absence_rather_than_inventing_a_value` below, which is a
narrower control over a smaller domain and is labelled as one.
"""

from __future__ import annotations

import ast
from pathlib import Path

import attack_property
import pytest
from attack_property import AuthoritativeProperty, PropertyNotViolated
from mutation_workspace import faithful_copy

#: The floor exists so this cannot quietly become a sweep over nothing. It is
#: the count at the commit that introduced the module; a criterion added later
#: is picked up automatically, and one DELETED makes this red.
MINIMUM_CRITERIA = 14


def _criteria() -> list[AuthoritativeProperty]:
    """Every criterion the module defines, DISCOVERED, not listed.

    A table of probe names here would reproduce the defect this module exists
    to refuse, one level up: the fifteenth probe would be judged by whoever
    remembered to add it. Anything that is an `AuthoritativeProperty` is in
    scope by construction.
    """
    found = sorted(
        (value for value in vars(attack_property).values()
         if isinstance(value, AuthoritativeProperty)),
        key=lambda criterion: criterion.ident,
    )
    assert len(found) >= MINIMUM_CRITERIA, (
        f"only {len(found)} criteria were discovered against a floor of "
        f"{MINIMUM_CRITERIA}. Either criteria were deleted, or the discovery "
        "above stopped seeing them -- and a sweep that finds nothing passes "
        "every assertion in this module."
    )
    return found


@pytest.fixture(scope="module")
def hollow_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A real checkout whose production modules import and define nothing."""
    tree = faithful_copy(tmp_path_factory.mktemp("hollow"))
    emptied = 0
    for area in ("src", "scripts"):
        for path in sorted((tree / area).rglob("*.py")):
            path.write_bytes(b"")
            emptied += 1
    assert emptied > 20, (
        f"only {emptied} modules were hollowed; the tree does not look like "
        "this repository and the sweep would measure nothing"
    )
    return tree


@pytest.mark.parametrize("criterion", _criteria(), ids=lambda c: c.ident)
def test_a_criterion_withdraws_when_its_symbols_are_gone(
    criterion: AuthoritativeProperty, hollow_tree: Path
) -> None:
    """Withdrawal is the only honest answer, and False is not withdrawal.

    `PropertyNotViolated` says the measurement did not answer. Returning False
    would say the control HELD, which is a positive claim about security state
    that a probe reaching an absent symbol has no basis for.
    """
    try:
        verdict = criterion.violated_in(hollow_tree)
    except PropertyNotViolated:
        return
    pytest.fail(
        f"{criterion.ident} returned {verdict!r} in a tree where the symbols it "
        "observes do not exist. It cannot have measured the property, so this "
        "is a verdict manufactured from an exception: "
        + ("True scores a KILL for an attack that broke nothing"
           if verdict else "False claims the control HELD when it never ran")
    )


def test_a_probe_reports_absence_rather_than_inventing_a_value() -> None:
    """The narrower control, over the domain the hollow sweep cannot reach.

    Labelled for what it is: this reads probe SOURCE, which is the weaker shape
    the module docstring criticises. It is here because the defect it guards --
    a three-argument `getattr` whose default decides the verdict -- happens on
    an object the hollow tree can never produce, and a weak guard over a real
    gap is worth more than no guard plus a claim of completeness.

    The convention it enforces is the repaired one: a probe that cannot observe
    what it needs prints an `unmeasurable` report, and `run_probe` withdraws
    centrally.
    """
    source = Path(attack_property.__file__).read_text(encoding="utf-8")
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            name = getattr(target, "id", "")
            if not (name.startswith("_H") and name.endswith("_PROBE")):
                continue
            if not isinstance(node.value, ast.Constant):
                continue
            for inner in ast.walk(ast.parse(str(node.value.value))):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Name)
                    and inner.func.id == "getattr"
                    and len(inner.args) == 3
                ):
                    offenders.append(name + ":" + str(inner.lineno))

    assert offenders == [], (
        "these probes read a field with a fallback value, so an ABSENT field "
        "produces a verdict instead of a withdrawal. A review measured exactly "
        "this: an absent `subject_verified` defaulted to True and was reported "
        "as a VERIFIED subject, which this repository's protocol scores as a "
        "kill. Report an `unmeasurable` result instead: " + repr(offenders)
    )
