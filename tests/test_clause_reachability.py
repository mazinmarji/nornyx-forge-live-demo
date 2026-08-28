"""The reachability probe must see a marker raised inside a subprocess.

WHY THIS EXISTS. `require_baseline_clause_reached` decides whether a pristine
test executes the clause an attack removes. It decides that by planting a raise
and reading the failure text -- so anything that truncates the failure text
turns "reached" into "not reached", silently.

That happened. The probe first ran with `--tb=line`, and a test asserting on a
SUBPROCESS's output carries the whole traceback as its assertion message, which
`--tb=line` reduces to one line. The clause had run; the marker was invisible;
the probe reported the attack inadmissible for a reason that was not true.

The shape matters more than the flag. This repository's governance tests
routinely shell out and assert against captured output, so the marker is
usually two layers down: raised in a child, embedded in that child's traceback,
embedded again in the parent's assertion message. A probe that only saw markers
raised directly in the test process would be wrong about most of this suite.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from mutation_workspace import (  # noqa: E402
    CLAUSE_MARKER,
    AttackNotAdmissible,
    Outcome,
    require_baseline_clause_reached,
)

NL = chr(10)

#: The clause the probe will target, inside the child.
ANCHOR = "        raise RuntimeError('the tool refused')"

_TOOL = (
    "import sys\n\n\n"
    "def run(flag):\n"
    "    if flag:\n"
    + ANCHOR + "\n"
    "    return 'ok'\n\n\n"
    "if __name__ == '__main__':\n"
    "    print(run(sys.argv[1] == 'refuse'))\n"
)


def _outer_test(argument: str, expected_rc: str, claim: str) -> str:
    """A test shaped like the governance suites: run a child, assert its output."""
    return (
        "import subprocess, sys\n"
        "from pathlib import Path\n\n"
        "ROOT = Path(__file__).resolve().parents[1]\n\n\n"
        "def test_the_tool_behaves():\n"
        "    completed = subprocess.run(\n"
        "        [sys.executable, str(ROOT / 'tool.py'), '" + argument + "'],\n"
        "        capture_output=True, text=True,\n"
        "    )\n"
        "    assert completed.returncode == " + expected_rc + ", completed.stderr\n"
        "    assert " + claim + ", completed.stderr\n"
    )


def _workspace(tmp_path: Path, *, reached: bool) -> tuple[Path, str]:
    tree = tmp_path / "tree"
    (tree / "tests").mkdir(parents=True)
    (tree / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n', encoding="utf-8"
    )
    (tree / "tool.py").write_text(_TOOL, encoding="utf-8")
    if reached:
        source = _outer_test("refuse", "1", "'the tool refused' in completed.stderr")
    else:
        source = _outer_test("allow", "0", "'ok' in completed.stdout")
    (tree / "tests" / "test_outer.py").write_text(source, encoding="utf-8")
    return tree, "tests/test_outer.py::test_the_tool_behaves"


def test_a_marker_raised_in_a_subprocess_is_detected(tmp_path: Path):
    """The regression. The clause runs in a CHILD; the probe must still see it."""
    tree, node = _workspace(tmp_path, reached=True)

    # No exception raised means the clause was reached and the attack would be
    # admissible -- which is the whole claim being regressed.
    require_baseline_clause_reached(tree, node, "tool.py", ANCHOR, timeout=600)


def test_an_unreached_clause_is_reported_as_a_bad_aim(tmp_path: Path):
    """The other direction, and the reason the outcome has its own name.

    The node exists and the baseline passes; it simply never runs the clause.
    That is INVALID_TEST_AIM -- not INVALID_TEST_TARGET, which is a node that
    does not collect at all.
    """
    tree, node = _workspace(tmp_path, reached=False)

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_baseline_clause_reached(tree, node, "tool.py", ANCHOR, timeout=600)
    assert refusal.value.outcome is Outcome.INVALID_TEST_AIM, refusal.value.outcome
    assert "never executes the control" in str(refusal.value)


def test_the_probe_reverts_the_file_byte_exactly(tmp_path: Path):
    """The baseline the attack then measures must be pristine.

    A probe that left its raise behind would make every later step measure an
    instrumented tree.
    """
    tree, node = _workspace(tmp_path, reached=True)
    before = (tree / "tool.py").read_bytes()

    require_baseline_clause_reached(tree, node, "tool.py", ANCHOR, timeout=600)

    assert (tree / "tool.py").read_bytes() == before
    assert CLAUSE_MARKER not in (tree / "tool.py").read_text(encoding="utf-8")


def test_reachability_survives_output_that_shows_the_marker_nowhere(
    tmp_path: Path,
):
    """The sentinel decides, so no formatting choice can hide a reached clause.

    WHAT THIS REPLACES, and why the replacement is not a retreat. The
    predecessor asserted that `--tb=line` HIDES the marker, by running the
    probe under both flags and comparing. That is a claim about pytest's
    output formatter, and it held only where the workspace path was long
    enough to push the marker past the truncation point: green on a Windows
    workstation, RED on all four CI interpreters, where `/tmp/...` is short
    and the marker survived at the tail of the truncated line. Its own
    failure message said it should be re-derived rather than kept as
    decoration, and this is that re-derivation.

    The hazard it was built for is real and is now closed at the root:
    `require_baseline_clause_reached` writes a SENTINEL FILE carrying this
    run's nonce, and treats it as authoritative, precisely so reachability
    does not depend on which stream anything lands on or how a traceback is
    rendered. Pinning the formatter pinned the symptom; this pins the
    property.

    THE HARDEST CASE THE OUTPUT CAN OFFER: the named test swallows the
    probe's exception entirely and fails for an unrelated reason, so the
    marker appears NOWHERE in stdout or stderr. Corroboration is impossible
    and the sentinel is the only thing that can answer. This is not
    contrived: a test that wraps the call it exercises is ordinary, and the
    production comment names a swallowed exception as exactly what the
    sentinel exists to survive.
    """
    tree, node = _probe_project(
        tmp_path,
        "import tool" + NL + NL + NL
        + "def test_case():" + NL
        + "    try:" + NL
        + "        tool.run()" + NL
        + "    except RuntimeError:" + NL
        + "        pass" + NL
        + "    assert False, 'unrelated failure carrying no marker'" + NL,
        tool="def run():" + NL + "    value = 'ok'" + NL + "    return value" + NL,
    )

    # No exception here means the probe established reachability. The only
    # evidence available to it was the sentinel.
    require_baseline_clause_reached(tree, node, "tool.py", "    value = 'ok'",
                                    timeout=600)

    # AND THE PREMISE IS CHECKED WITH THE PROBE PLANTED, which is the only
    # moment it can be false. This block used to run pytest AFTER
    # `require_baseline_clause_reached` returned -- and that helper restores
    # the file byte-exactly in its `finally`, so the tree it measured had no
    # probe in it at all and `marker not in output` could not fail. A review
    # demonstrated it by running the identical assertion against the
    # NON-swallowing project, where the marker IS visible under the probe,
    # and watching it pass. An inert self-check on a specimen whose whole
    # subject is inert self-checks.
    target = tree / "tool.py"
    pristine = target.read_bytes()
    anchor = "    value = 'ok'"
    planted = target.read_text(encoding="utf-8").replace(
        anchor, '    raise RuntimeError("' + CLAUSE_MARKER + '")' + NL + anchor, 1
    )
    target.write_text(planted, encoding="utf-8", newline="")
    try:
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", node, "-p", "no:cacheprovider",
             "-q", "-p", "no:warnings", "--tb=long"],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=600,
        )
    finally:
        target.write_bytes(pristine)
    assert completed.returncode != 0, (
        "the planted raise did not even fail the test, so this project does "
        "not exercise the clause and proves nothing about the sentinel"
    )
    assert CLAUSE_MARKER not in completed.stdout + completed.stderr, (
        "the swallowing project shows the marker after all, so the call "
        "above could have succeeded on output corroboration rather than on "
        "the sentinel:" + NL + completed.stdout[-600:]
    )


# --------------------------------------------------------------------------
# FG16. A marker in the OUTPUT is not a clause that RAN.
# --------------------------------------------------------------------------


def _probe_project(tmp_path: Path, body: str, *, tool: str | None = None):
    """A miniature project whose test body is supplied verbatim."""
    tree = tmp_path / "tree"
    (tree / "tests").mkdir(parents=True)
    (tree / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n', encoding="utf-8"
    )
    if tool is not None:
        (tree / "tool.py").write_text(tool, encoding="utf-8")
    (tree / "tests" / "test_probe.py").write_text(body, encoding="utf-8")
    return tree, "tests/test_probe.py::test_case"


#: FG16_PARAMETRIC_CASES_WITHDRAWN was defined here and referenced
#: nowhere. A table nobody reads is documentation wearing the shape of
#: data, and this module's whole subject is the difference between the
#: two. Removed rather than wired up: the cases it named are covered by
#: the live parametrisation above.


def test_fg16_a_genuinely_raised_probe_is_reachability(tmp_path: Path):
    """Case 6. The control -- without it, refusing everything would pass above."""
    tree, node = _probe_project(
        tmp_path,
        "import tool\n\n\ndef test_case():\n    assert tool.run() == 'ok'\n",
        tool="def run():\n    value = 'ok'\n    return value\n",
    )
    require_baseline_clause_reached(tree, node, "tool.py", "    value = 'ok'",
                                    timeout=600)


def test_fg16_an_unreached_probe_is_a_bad_aim(tmp_path: Path):
    """Case 7. Reached and unreached must stay distinguishable."""
    tree, node = _probe_project(
        tmp_path,
        "import tool\n\n\ndef test_case():\n    assert tool.run(False) == 'ok'\n",
        tool="def run(flag):\n"
             "    if flag:\n"
             "        unreachable = 'never'\n"
             "        return unreachable\n"
             "    return 'ok'\n",
    )
    with pytest.raises(AttackNotAdmissible) as refusal:
        require_baseline_clause_reached(
            tree, node, "tool.py", "        unreachable = 'never'", timeout=600
        )
    assert refusal.value.outcome is Outcome.INVALID_TEST_AIM, refusal.value.outcome


def test_fg16_a_stale_marker_from_an_earlier_run_cannot_be_reused(tmp_path: Path):
    """The nonce, which is what stops a fixed marker matching old output.

    A constant marker can be satisfied by a cached report, a log from a previous
    probe, or a test that happens to print the word. Each invocation now plants
    a fresh token, so only THIS run's evidence counts.
    """
    tree, node = _probe_project(
        tmp_path,
        "import tool\n\n\ndef test_case():\n    assert tool.run() == 'ok'\n",
        tool="def run():\n    value = 'ok'\n    return value\n",
    )
    for _ in range(2):
        source = (tree / "tool.py").read_text(encoding="utf-8")
        require_baseline_clause_reached(tree, node, "tool.py", "    value = 'ok'",
                                        timeout=600)
        assert (tree / "tool.py").read_text(encoding="utf-8") == source
    # THE NONCE, CHECKED AS CODE. This declared `seen: set[str]`, never
    # populated it, and ended `assert seen == set()` -- an empty set asserted
    # empty, which is the tautology shape this repository catalogues as FG33.
    # The real claim was carried by `"uuid.uuid4()" in helper`, a text search
    # over the helper's source: FG13.
    #
    # AST instead, so a comment mentioning the call cannot satisfy it and a
    # rename to `uuid4()` cannot defeat it.
    helper = ast.parse((ROOT / "tests" / "mutation_workspace.py").read_text(
        encoding="utf-8"))
    nonce_calls = [
        node for node in ast.walk(helper)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Attribute) and node.func.attr == "uuid4")
            or (isinstance(node.func, ast.Name) and node.func.id == "uuid4")
        )
    ]
    assert nonce_calls, (
        "the probe no longer generates a per-run nonce, so a fixed marker could "
        "be matched against stale output"
    )
