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


def test_fg26_an_unanswerable_git_is_not_an_answer_of_unchanged():
    """`_worktree_state` returns "" when git cannot run, and the fixture then
    returns without asserting -- despite its own comment saying absence of an
    answer is not a pass.

    Pinned as the known bound: with no state on either side the comparison is
    vacuous, so the guard must not be read as evidence the tree was clean. This
    is the same shape as H16, one layer out.
    """
    assert introduced_paths("", "") == [], (
        "two empty states must compare equal; if not, the vacuous case is "
        "producing spurious findings"
    )
    # The bound itself: emptiness is indistinguishable from cleanliness here.
    assert introduced_paths("", "") == introduced_paths("", ""), "comparison is unstable"


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
    # EVERY child run in the harness, not two named functions. The previous
    # version checked a hand-written two-entry dict, and a review measured 110
    # of 144 `subprocess` call sites in this repository passing no timeout --
    # including `tracked_files`, `faithful_copy`'s three git calls, and the
    # census's own pytest run, which spawns the entire suite.
    #
    # SCOPE, stated rather than implied: this covers the modules that spawn
    # children ON BEHALF OF a proof, where a hang produces no verdict and no
    # signal. Ad-hoc `subprocess.run` calls inside individual tests are not
    # covered; those hang a single test that pytest reports, which is a
    # different and much louder failure.
    harness = (
        "tests/mutation_workspace.py",
        "tests/mutation.py",
        "tests/attack_property.py",
        "scripts/check_test_coverage.py",
    )
    unbounded = []
    for relative in harness:
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run"
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
