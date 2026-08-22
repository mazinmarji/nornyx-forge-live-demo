"""FG26 -- a measurement script that mutates the governed tree it measures.

The session fixture `conftest.py::_governed_tree_is_left_as_found` compares
`git status --porcelain` before and after the suite. It is the right guard and
it works, but it cannot be FG26's evidence, because FG26's mechanism is a probe
run OUTSIDE pytest: that is exactly how the incident happened, and a
session-scoped fixture is structurally blind to it.

The incident, recorded in TASK11_REPLAY.md: a criterion probe called `_apply()`
outside the module's restoring fixture, left
`.nornyx/contracts/runtime_network.nyx` modified in the real tree, and thereby
broke the anchors of every later attack -- producing a "2/8" measurement that
meant nothing. The result LOOKED like a finding.

So the class needs its own specimen: the comparison itself, exercised on
synthetic before/after states, plus the rule that an unanswerable git is not an
answer of "unchanged".
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import attack_property  # noqa: E402
from attack_property import PropertyNotViolated  # noqa: E402
from conftest import introduced_paths  # noqa: E402

CONTAMINATION_SPECIMENS = [
    ("a probe modified a governed contract",
     "", " M .nornyx/contracts/runtime_network.nyx", True),
    ("a probe left an untracked artifact",
     "", "?? evidence/probe-scratch.json", True),
    ("a probe modified one file among pre-existing edits",
     " M docs/ARCHITECTURE.md",
     " M docs/ARCHITECTURE.md" + chr(10) + " M src/nornyx_forge/approval_trust.py",
     True),
    ("nothing changed",
     " M docs/ARCHITECTURE.md", " M docs/ARCHITECTURE.md", False),
    ("a pre-existing edit was REVERTED, not introduced",
     " M docs/ARCHITECTURE.md", "", False),
]


@pytest.mark.false_green("FG26")
@pytest.mark.parametrize(
    ("label", "before", "after", "contaminated"),
    CONTAMINATION_SPECIMENS,
    ids=[case[0] for case in CONTAMINATION_SPECIMENS],
)
def test_fg26_contamination_is_detected_and_clean_runs_are_not(
    label: str, before: str, after: str, contaminated: bool
):
    """Both directions. A detector that fires on a clean run gets disabled.

    The reverted case matters: a probe that RESTORES something it found dirty
    has not contaminated anything, and flagging it would teach people to ignore
    the guard.
    """
    assert bool(introduced_paths(before, after)) is contaminated, (
        f"{label}: introduced={introduced_paths(before, after)}"
    )


def _drive_the_session_guard(before, after):
    """Run the real session fixture's body against controlled git answers.

    THE FIXTURE, NOT A COPY OF ITS ARITHMETIC. Every earlier version of this
    coverage called `introduced_paths` directly, so deleting the fixture's
    assertions -- both of them -- left this module green. A guard is what the
    fixture DOES; the helper it happens to call is an implementation detail.

    Returns None when the guard accepted the run, and lets the `AssertionError`
    out when it refused, because that refusal is the behaviour under test.
    """
    import conftest  # noqa: PLC0415

    definition = conftest._governed_tree_is_left_as_found
    body = getattr(definition, "__wrapped__", None)
    assert body is not None, (
        "the session fixture no longer exposes its underlying function, so "
        "this module can no longer drive the guard it claims to cover -- which "
        "is the failure this helper exists to make loud rather than silent"
    )

    answers = iter((before, after))
    original = conftest._worktree_state
    conftest._worktree_state = lambda: next(answers)
    try:
        generator = body()
        next(generator)
        try:
            next(generator)
        except StopIteration:
            return None
        raise AssertionError("the fixture yielded twice")
    finally:
        conftest._worktree_state = original


def test_fg26_the_session_guard_refuses_when_git_cannot_answer():
    """An unanswered question is not a clean result.

    Both states were once `""`, so an unusable git and a clean tree were the
    same value and the guard was silent in precisely the environment where a
    dirtied tree would go unnoticed. `UNANSWERED` separates them -- and this
    drives the fixture, so DELETING that check makes this red.
    """
    from conftest import UNANSWERED  # noqa: PLC0415

    with pytest.raises(AssertionError) as raised:
        _drive_the_session_guard(UNANSWERED, "M  BRD.md" + chr(10))
    assert "unanswered question" in str(raised.value), str(raised.value)

    with pytest.raises(AssertionError) as raised:
        _drive_the_session_guard("", UNANSWERED)
    assert "unanswered question" in str(raised.value), str(raised.value)


def test_fg26_the_session_guard_refuses_a_tree_the_suite_modified():
    """The positive case, through the fixture.

    A review replaced the fixture's comparison with `introduced = []` and this
    module stayed green at 17 passed, because nothing here ran the fixture.
    """
    with pytest.raises(AssertionError) as raised:
        _drive_the_session_guard(
            "", " M .nornyx/contracts/evidence/review_binding.json" + chr(10)
        )
    assert "left the governed tree modified" in str(raised.value)
    assert "review_binding.json" in str(raised.value), (
        "the refusal does not name the path that changed, so an operator "
        "cannot tell what to restore"
    )


def test_fg26_the_session_guard_accepts_a_run_that_changed_nothing():
    """The control, without which every assertion above is satisfiable by a
    fixture that refuses unconditionally."""
    unchanged = " M some-file-a-test-legitimately-left-dirty" + chr(10)
    assert _drive_the_session_guard(unchanged, unchanged) is None, (
        "the guard refused a run that introduced no new modification, so it "
        "would fail every session regardless of what the suite did"
    )


# --------------------------------------------------------------------------
# FG29 -- a mutant that CRASHED credited as one that violated the property.
#
# H19's criterion asked "is the refusal diagnostic present?" and a crash reason
# contains no diagnostic either, so `did not refuse properly` and `did not run`
# produced the same answer. Measured, H19's mutation raises FileNotFoundError
# rather than shrinking the subject -- so the recorded unsafe state was never
# reached and the kill was credited on an exception.
# --------------------------------------------------------------------------

CRASH_SPECIMENS = [
    ("the control decided, refusing", {"verified": False, "digest": "",
     "reason": "SUBJECT_SCOPE_INCOMPLETE: scope requires x"}, "decided"),
    ("the control decided, allowing", {"verified": True, "digest": "sha256:aa",
     "reason": ""}, "decided"),
    ("the mutant could not run at all", {"verified": False, "digest": "",
     "reason": "RAISED FileNotFoundError"}, "unmeasurable"),
    ("the mutant died importing", {"verified": False, "digest": "",
     "reason": "RAISED ModuleNotFoundError"}, "unmeasurable"),
]


@pytest.mark.false_green("FG29")
@pytest.mark.parametrize(
    ("label", "measured", "kind"),
    CRASH_SPECIMENS,
    ids=[case[0] for case in CRASH_SPECIMENS],
)
def test_fg29_a_crash_is_distinguishable_from_a_decision(
    label: str, measured: dict, kind: str, monkeypatch
):
    """The distinction the criterion has to draw, drawn BY THE CRITERION.

    This used to compute `str(measured["reason"]).startswith("RAISED ")` in the
    test body and assert it matched a hand-written label in the table beside
    it. That is a re-implementation checking itself: a review deleted the guard
    from `attack_property._h19_violated` and this owner stayed green at 14/14,
    with the FG29 defect -- a crash credited as a property violation -- fully
    restored. Nothing anywhere exercised the real guard.

    So the specimen is fed to the real criterion instead. An outcome reporting
    RAISED must terminate the measurement; anything else must be answered.
    """
    monkeypatch.setattr(attack_property, "run_probe", lambda tree, source: measured)

    if kind == "unmeasurable":
        with pytest.raises(PropertyNotViolated):
            attack_property._h19_violated(Path("."))
        return

    # The positive control, in the same test: a decided outcome must produce a
    # verdict rather than withdrawing, or the guard refuses everything and FG29
    # would be "closed" by measuring nothing at all.
    verdict = attack_property._h19_violated(Path("."))
    assert isinstance(verdict, bool), (
        f"{label}: a decided outcome did not yield a verdict"
    )


def test_fg29_a_crash_yields_no_verdict_by_any_route(monkeypatch):
    """A crash must produce NO ANSWER -- not a wrong one, and not a quiet one.

    Measured, by deleting guards from a copy of the criterion rather than by
    reasoning about them:

        both guards present   -> PropertyNotViolated   (withdraws, visibly)
        RAISED guard removed  -> PropertyNotViolated   (attribution catches it)
        both guards removed   -> False                 (no credit, silently)

    So this criterion no longer has a path on which a crash reports VIOLATED.
    That is worth stating precisely, because the historical FG29 shape was the
    last line reading `return "SUBJECT_SCOPE_INCOMPLETE" not in reason`, which
    made a crash message -- carrying no diagnostic, because it carries no
    decision -- report True and earn a kill. Restructuring the criterion to
    decide on state removed that path; the guards make the outcome an explicit
    withdrawal instead of a silent False.

    The distinction matters: a silent False says "the control held", which a
    crash did not establish either. Only a withdrawal says nothing was
    measured, and only a withdrawal is visible in the runner.
    """
    crashed = {"verified": False, "digest": "", "reason": "RAISED FileNotFoundError"}
    monkeypatch.setattr(attack_property, "run_probe", lambda tree, source: crashed)
    with pytest.raises(PropertyNotViolated):
        attack_property._h19_violated(Path("."))

    assert "SUBJECT_SCOPE_INCOMPLETE" not in crashed["reason"], (
        "the specimen no longer reproduces FG29: a crash whose text happens to "
        "carry the expected diagnostic would be answered correctly by accident"
    )


# --------------------------------------------------------------------------
# FG33 -- an unfinished measurement read as a measurement.
#
# A census bite test was run in a copy and TIMED OUT after 3000 seconds. The
# process exited non-zero, and a non-zero exit is exactly what "the gate
# refused the deletion" looks like. Reporting that as proof would have credited
# a resource limit as a security result.
#
# The owner that used to sit here asserted `(not timed_out) is usable` over a
# table in which every row set `usable = not timed_out`. That is an identity
# between two hand-written columns -- unfalsifiable over its own data -- and
# the guard it named existed NOWHERE: `timed_out` appeared in no other file in
# tests/ or scripts/, and no harness carried a completion flag.
#
# What actually protects the campaign is that both harness call sites pass
# `timeout=` to `subprocess.run`, which RAISES `TimeoutExpired` rather than
# returning a CompletedProcess with a non-zero code. That is a real guard and
# it is worth pinning; it was simply not the one the test described.
# --------------------------------------------------------------------------


@pytest.mark.false_green("FG33")
def test_fg33_a_run_that_exceeds_its_timeout_raises_instead_of_returning(tmp_path: Path):
    """The real property: an unfinished run yields no result to misread.

    If `subprocess.run` ever returned on timeout -- or a call site swallowed
    `TimeoutExpired` and handed back the CompletedProcess -- an exhausted
    resource limit would be indistinguishable from a refusal, which is the
    whole class.
    """
    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run(  # noqa: S603
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path, capture_output=True, text=True, timeout=1,
        )


def test_fg33_a_run_that_finishes_returns_its_code(tmp_path: Path):
    """The control. Without it the test above passes on a harness that raises always."""
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "raise SystemExit(2)"],
        cwd=tmp_path, capture_output=True, text=True, timeout=60,
    )
    assert done.returncode == 2, (
        "a run that finished did not report its own exit code, so a refusal "
        "could not be told from anything else either"
    )


def test_fg33_both_harness_entry_points_bound_their_runs():
    """Structural, over the real call sites rather than over a table.

    A timeout that is not passed cannot raise, so the property above would hold
    while the campaign ran unbounded. AST, not text: the word `timeout` in a
    comment is what let the previous owner look correct.
    """
    # THE SCOPE IS DERIVED. This listed four module paths while calling itself
    # "structural, over the real call sites rather than over a table" -- it had
    # replaced a two-entry table with a four-entry one. Two reviews measured the
    # same omission independently: `tests/inspection.py`, a harness that spawns
    # children for four proofs and meets this guard's own stated criterion, plus
    # four `scripts/` gates including `refresh_governance_evidence.py`, which
    # every `--verify` probe shells out to.
    #
    # SCOPE: modules that spawn children ON BEHALF OF a proof or a gate. That
    # is every non-`test_` module under `tests/` (the harnesses) and every
    # module under `scripts/` (the gates). Both are computed, so a new harness
    # is judged the day it lands.
    #
    # `Popen` IS NOT IN SCOPE, and not by oversight: it accepts no `timeout=`
    # keyword: the bound belongs on the later `wait`/`communicate`. Requiring
    # one would be requiring a TypeError, and `scripts/smoke_http.py` starts a
    # server it deliberately keeps running.
    #
    # THE RESIDUAL, corrected. This used to say ad-hoc calls inside individual
    # tests "hang a single test that pytest reports, which is a different and
    # much louder failure". That is FALSE here and was never measured:
    # `pytest_timeout` is not installed and no ini timeout is set, so a hung
    # child hangs the whole session and pytest reports nothing at all. Quieter,
    # not louder. Those call sites remain out of scope -- bounding every one is
    # a larger change than this guard -- but the exclusion is now recorded as a
    # known gap rather than excused by a property this repository does not have.
    harness = [
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "tests").glob("*.py"))
        if not path.name.startswith("test_")
    ] + [
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "scripts").glob("*.py"))
    ]
    assert len(harness) >= 8, (
        f"only {len(harness)} harness modules were discovered; the derivation "
        "above has stopped matching and this guard would sweep almost nothing"
    )
    unbounded = []
    for relative in harness:
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"run", "check_output"}
                    and getattr(node.func.value, "id", "") == "subprocess"):
                continue
            if not any(keyword.arg == "timeout" for keyword in node.keywords):
                unbounded.append(f"{relative}:{node.lineno}")
    assert unbounded == [], (
        "these harness call sites run a child process with no timeout, so a "
        f"hung run never terminates and never yields a result either: {unbounded}"
    )


def test_fg29_a_probe_whose_inner_measurement_fails_withdraws(tmp_path: Path):
    """B4-P1-1: the FG29 hole reopened one level down, inside the probes.

    `run_probe` refuses a child that exits non-zero or prints no JSON. The H17
    and H18 probes defeated that by swallowing their GRANDCHILD's failure
    themselves -- `state = json.loads(raw)["verification"] if raw else {}` --
    and then printing perfectly valid JSON of their own. `integrity_state`
    became None, `None != "compromised"` returned VIOLATED, and a review drove
    both attacks to KILLED_VALIDLY by moving a report from stdout to stderr,
    while the control still ran and still caught the forgery.

    The outer guard was never wrong; it was never reached. So the probes raise
    now, and this exercises that shape end to end rather than trusting it.
    """
    swallowed = (
        "import json, subprocess, sys" + chr(10)
        + "done = subprocess.run("
        "[sys.executable, '-c', \"import sys; print('x', file=sys.stderr)\"],"
        " capture_output=True, text=True)" + chr(10)
        + "start = done.stdout.find('{')" + chr(10)
        + "if start < 0:" + chr(10)
        + "    raise SystemExit('no JSON on stdout')" + chr(10)
        + "print(json.dumps({'attack_state': None}))" + chr(10)
    )
    with pytest.raises(PropertyNotViolated):
        attack_property.run_probe(tmp_path, swallowed)


def test_fg29_a_probe_that_measures_cleanly_still_answers(tmp_path: Path):
    """The positive control. Without it the test above passes on a `run_probe`
    that refuses every probe ever written."""
    measured = (
        "import json" + chr(10)
        + "print(json.dumps({'attack_state': 'compromised', 'attack_problems': 2}))"
        + chr(10)
    )
    assert attack_property.run_probe(tmp_path, measured)["attack_state"] == "compromised"


def test_fg29_neither_h17_nor_h18_defaults_a_missing_verification():
    """Structural, over the probe sources themselves.

    The defect was one expression, and it is the kind that comes back when
    someone tidies a probe. `if raw else {}` -- or any other default for an
    absent verification block -- turns an unmeasurable run into an answer.
    """
    # AST, NOT TEXT. My first version forbade the string `else {}` and went red
    # on its own explanatory comment, which QUOTES the defective expression.
    # That is the use/mention confusion this repository has three modules
    # dedicated to refusing, committed inside the test written to close it.
    for name in ("_H17_PROBE", "_H18_PROBE"):
        source = getattr(attack_property, name)
        tree = ast.parse(source)
        defaults = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.IfExp)
            and isinstance(node.orelse, ast.Dict)
            and not node.orelse.keys
        ]
        assert defaults == [], (
            f"{name} defaults its verification block to an empty dict when the "
            "child produced none, so a crashed or silenced --verify reads as a "
            f"measurement (line {defaults[0].lineno if defaults else '-'})"
        )
        raises = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id == "SystemExit"
        ]
        assert raises, (
            f"{name} does not fail closed when --verify yields no JSON"
        )
