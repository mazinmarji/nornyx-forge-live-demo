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
scores a kill) is repaired AT THE PROBE, in `tests/attack_property.py`: the
three fields are read with `hasattr` first and any absence is reported as
`unmeasurable`, so no default can decide. There is NO separate test of that
repair, and this docstring used to say there was -- it cited
test_a_probe_reports_absence_rather_than_inventing_a_value "below", and this
module defines three tests, none of them that one. Saying "covered by" and
naming nothing is worse than saying "not covered here", because the reader
stops looking.
"""

from __future__ import annotations

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


def test_renaming_a_reported_key_makes_h17_and_h18_withdraw_not_kill(
    hollow_tree: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """The attack itself, executed. This replaces two weaker guards in turn.

    FIRST there was a scan for three-argument `getattr`, written to close a
    defect where an absent field defaulted to the value that scores a kill. A
    review walked a second spelling through it: `state.get("integrity_state")`,
    whose implicit `None` feeds `None != "compromised"` -- the branch that
    returns VIOLATED.

    THEN I replaced that scan with a control that handed each criterion an
    EMPTY report and required a withdrawal. Measured before shipping it: with a
    plain dict, ZERO of the fourteen criteria returned a verdict -- they all
    raise `KeyError` on an empty report. The control passed identically with
    and without the repair, so it discriminated nothing. A test measured to be
    vacuous is worse than no test, because it is counted.

    So this drives the mutation the review actually used. Renaming the reported
    key in the production script leaves the forgery caught, named, and adding
    problems over the inert control -- the property is INTACT -- so both
    criteria must WITHDRAW. If either returns True it has credited a kill for a
    rename.
    """
    from mutation_workspace import faithful_copy  # noqa: PLC0415

    tree = faithful_copy(tmp_path_factory.mktemp("keyrename"))
    target = tree / "scripts" / "refresh_governance_evidence.py"
    source = target.read_text(encoding="utf-8")
    renamed = source.replace('state["integrity_state"]', 'state["integrity_verdict"]')
    assert renamed != source, (
        "the production script no longer spells the reported key this way, so "
        "this control is aimed at nothing and must be re-derived"
    )
    target.write_text(renamed, encoding="utf-8")

    for criterion in _criteria():
        if criterion.ident.split("_")[0] not in {"H17", "H18"}:
            continue
        try:
            verdict = criterion.violated_in(tree)
        except PropertyNotViolated:
            continue
        pytest.fail(
            f"{criterion.ident} returned {verdict!r} for a mutant that only "
            "RENAMED a reported key. The forgery is still caught and still "
            "named; nothing about the property changed. A kill credited here "
            "is a kill credited for a rename."
        )


def test_an_unmet_precondition_withdraws_instead_of_deciding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A probe whose own setup did not happen must not be believed.

    THE CLASS, after three rounds produced three instances of it: a criterion
    returning a verdict when the state it was measuring was never reached. An
    absent FIELD defaulted to the kill value; an absent KEY defaulted to None
    and `None != x` was the violated branch; and an injected FAULT never fired
    while the probe reported the value it would have reported anyway.

    `ProbeReport` closes the second and is structurally blind to the third,
    because there the probe SENDS the key carrying a value it invented. Only
    the probe knows whether its setup landed, so it says so and `run_probe`
    refuses on its behalf.

    THIS CONTROL DISCRIMINATES, and that is checked rather than assumed --
    round 6 shipped a control here that behaved identically with and without
    the repair, and it was deleted after being measured. Both arms are driven
    below: the same measurements with the precondition present and absent.
    """
    import json  # noqa: PLC0415

    measurements = {"refused": False, "returned": "x"}

    class _Child:
        returncode = 0
        stderr = ""
        stdout = ""

    def _fake_run(*_args, **_kwargs):
        return _Child

    monkeypatch.setattr(attack_property.subprocess, "run", _fake_run)

    # With the precondition reported UNMET, the criterion must never see it.
    _Child.stdout = json.dumps(
        dict(measurements, preconditions={"fault_delivered": False})
    )
    with pytest.raises(PropertyNotViolated):
        attack_property.run_probe(Path("."), "unused")

    # The control: the SAME measurements with no precondition are returned, and
    # `refused: False` is exactly what a criterion reads as VIOLATED. If this
    # arm also withdrew, the arm above would prove nothing.
    _Child.stdout = json.dumps(measurements)
    report = attack_property.run_probe(Path("."), "unused")
    assert report["refused"] is False, (
        "the control arm did not return the measurements, so the withdrawal "
        "above is not evidence that the precondition caused it"
    )

    # And a MET precondition must not withdraw either.
    _Child.stdout = json.dumps(
        dict(measurements, preconditions={"fault_delivered": True})
    )
    assert attack_property.run_probe(Path("."), "unused")["refused"] is False
