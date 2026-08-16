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


def test_a_truncating_traceback_flag_would_hide_the_marker(tmp_path: Path):
    """The exact defect, reproduced, so restoring `--tb=line` fails here.

    Not a claim about pytest's behaviour -- both flags are run and compared.
    """
    tree, node = _workspace(tmp_path, reached=True)
    target = tree / "tool.py"
    original = target.read_text(encoding="utf-8")
    target.write_text(
        original.replace(
            ANCHOR, '        raise RuntimeError("' + CLAUSE_MARKER + '")\n' + ANCHOR, 1
        ),
        encoding="utf-8",
        newline="",
    )

    def _run(tb: str) -> str:
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", node, "-q", "-p", "no:cacheprovider",
             "-p", "no:warnings", "--tb=" + tb],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=600,
        )
        return completed.stdout + completed.stderr

    assert CLAUSE_MARKER in _run("long"), (
        "the marker is invisible even with a full traceback, so the probe "
        "cannot work at all"
    )
    assert CLAUSE_MARKER not in _run("line"), (
        "`--tb=line` no longer truncates the marker away, so this regression no "
        "longer describes a real hazard and should be re-derived rather than "
        "kept as decoration"
    )
