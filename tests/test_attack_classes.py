"""The class probes: a new member is caught by the class, not the next reviewer.

`docs/governance/CLOSURE_PROTOCOL.md` sets the rule these enforce. The registry
in `attack_classes.py` names root mechanisms; this module makes each one
mechanical, so that classifying a finding into a class is a decision with
consequences rather than a label.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

from attack_classes import (  # noqa: E402
    ATTACK_CLASSES,
    _contradiction_says,
    _detector_says,
    _screen_says,
)

NL = chr(10)


def test_every_attack_class_names_specimens_that_exist():
    """A class whose specimens do not resolve is a label, not a control.

    The registry is prose plus a list of node ids. The prose cannot be checked;
    the node ids can, and a class naming a test that was renamed or deleted
    would otherwise sit in the registry looking like coverage.

    Definition AND collection: a function that exists but is not collected --
    deselected, shadowed by a later definition, excluded by configuration --
    holds nothing down either, which is FG38's own class.
    """
    collected = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider", "-p", "no:randomly"],
        cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    ).stdout
    counted = {
        line.rpartition(":")[0]: int(line.rpartition(":")[2])
        for line in collected.splitlines()
        if line.startswith("tests/") and line.rpartition(":")[2].strip().isdigit()
    }
    missing = []
    for item in ATTACK_CLASSES:
        assert item.specimens, item.ident + " names no specimen at all"
        for node in item.specimens:
            relative, _, name = node.partition("::")
            source = ROOT / relative
            if not source.is_file():
                missing.append(item.ident + " -> " + relative + " does not exist")
                continue
            defined = any(
                isinstance(found, (ast.FunctionDef, ast.AsyncFunctionDef))
                and found.name == name
                for found in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
            )
            if not defined:
                missing.append(item.ident + " -> " + node + " is not defined")
            elif counted.get(relative, 0) <= 0:
                missing.append(item.ident + " -> " + relative + " collects nothing")
    assert missing == [], (
        "these attack classes name specimens the suite does not collect, so "
        "the class is held down by nothing: " + repr(missing)
    )


def test_every_attack_class_states_a_mechanism_and_an_instance():
    """A class with no instance is a theory; a class with no mechanism is a name."""
    for item in ATTACK_CLASSES:
        assert len(item.mechanism) > 80, item.ident + " states no mechanism"
        assert len(item.decided_by) > 40, (
            item.ident + " does not say how the question is decided instead"
        )
        assert item.instances, (
            item.ident + " names no instance, so nothing shows the class is "
            "real rather than imagined"
        )


def test_the_class_identifiers_are_unique_and_dense():
    """AC01..ACnn with no gaps, so a removed class is a visible diff."""
    idents = [item.ident for item in ATTACK_CLASSES]
    assert len(set(idents)) == len(idents), "duplicate attack-class identifier"
    expected = ["AC" + str(index).zfill(2) for index in range(1, len(idents) + 1)]
    assert idents == expected, (
        "the attack classes are not AC01..AC" + str(len(idents)).zfill(2)
        + " in order: " + repr(idents)
    )


# --------------------------------------------------------------------------
# AC01 — the class probe: synonyms must be answered identically
# --------------------------------------------------------------------------

#: (label, module source, body A, body B) -- A and B state the same thing.
SCREEN_SYNONYMS = [
    ("a swallowing handler, named and aliased",
     "_Err = AssertionError",
     "try:" + NL + "    assert real" + NL + "except AssertionError:" + NL + "    pass",
     "try:" + NL + "    assert real" + NL + "except _Err:" + NL + "    pass"),
    ("a swallowing handler, named and imported under another name",
     "from builtins import AssertionError as _E",
     "try:" + NL + "    assert real" + NL + "except AssertionError:" + NL + "    pass",
     "try:" + NL + "    assert real" + NL + "except _E:" + NL + "    pass"),
    ("suppression, qualified and aliased",
     "_Q = contextlib.suppress",
     "with contextlib.suppress(AssertionError):" + NL + "    assert real",
     "with _Q(AssertionError):" + NL + "    assert real"),
    ("a dead constant at column zero and one indent deep",
     "if True:" + NL + "    _OFF = False",
     "if _OFF:" + NL + "    assert real",
     "if _OFF:" + NL + "    assert real"),
    ("a loop that ends the block, two ways of writing the exit",
     "",
     "while True:" + NL + "    return" + NL + "assert real",
     "for _ in [1]:" + NL + "    return" + NL + "assert real"),
]


@pytest.mark.parametrize(
    ("label", "module_source", "first", "second"), SCREEN_SYNONYMS,
    ids=[case[0] for case in SCREEN_SYNONYMS],
)
def test_the_screen_answers_synonyms_identically(
    label: str, module_source: str, first: str, second: str,
):
    """AC01 over the guard screen.

    Two ways of writing one thing must get one answer. Every AC01 instance
    began as a pair like these where the answers differed, and each was
    repaired locally until the class was named.
    """
    left = _screen_says(module_source, first)
    right = _screen_says(module_source, second)
    assert left == right, (
        label + ": the screen answers " + str(left) + " and " + str(right)
        + " for two spellings of the same thing"
    )


#: (label, source A, source B) -- both ask a text question of a rendered tree.
DETECTOR_SYNONYMS = [
    ("membership and find",
     'x = "d" in ast.dump(n)', "x = ast.dump(n).find(chr(100)) >= 0"),
    ("dump and unparse",
     'x = "d" in ast.dump(n)', 'x = "d" in ast.unparse(n)'),
    ("inline and through a local",
     'x = "d" in ast.dump(n)', "r = ast.dump(n)" + NL + 'x = "d" in r'),
    ("receiver and argument",
     'x = "d" in ast.dump(n)', 'x = "d" in "{}".format(ast.dump(n))'),
    ("module-level re and a compiled pattern",
     'x = re.search("d", ast.dump(n))', 'x = re.compile("d").search(ast.dump(n))'),
]


@pytest.mark.parametrize(
    ("label", "first", "second"), DETECTOR_SYNONYMS,
    ids=[case[0] for case in DETECTOR_SYNONYMS],
)
def test_the_detector_answers_synonyms_identically(
    label: str, first: str, second: str,
):
    """AC01 over the reimplementation detector."""
    left, right = _detector_says(first), _detector_says(second)
    assert left == right, (
        label + ": the detector answers " + str(left) + " and " + str(right)
        + " for two spellings of the same question"
    )


#: (label, payload A, payload B) -- both state that nothing was inspected or
#: nothing was approved.
CONTRADICTION_SYNONYMS = [
    ("no inspections, as a dict and as a list",
     {"authenticated_inspections": {}}, {"authenticated_inspections": []}),
    ("no inspections, as a list and as null",
     {"authenticated_inspections": []}, {"authenticated_inspections": None}),
    ("not approved, as a string and as a record",
     {"approval": "not_granted"}, {"approval": {"granted": False}}),
    ("not approved, as a record and as a nested status",
     {"approval": {"granted": False}}, {"approval": {"status": "not_granted"}}),
]


@pytest.mark.parametrize(
    ("label", "first", "second"), CONTRADICTION_SYNONYMS,
    ids=[case[0] for case in CONTRADICTION_SYNONYMS],
)
def test_the_observer_answers_synonyms_identically(
    label: str, first: dict, second: dict, tmp_path: Path,
):
    """AC01 over the governance-integrity observer."""
    location = tmp_path / "artifact.json"
    left = _contradiction_says(first, location)
    right = _contradiction_says(second, location)
    assert left == right, (
        label + ": the observer answers " + str(left) + " and " + str(right)
        + " for two ways of stating the same absence"
    )


# --------------------------------------------------------------------------
# AC02 — the class probe: a fix nothing fails without
# --------------------------------------------------------------------------

#: (label, file, the fix as written, the fix removed, the specimen node).
#:
#: THE CLASS PROBE FOR AC02. Each row reverts ONE fix on a copy of the tree and
#: requires its named specimen to go RED. A fix added without a row here is a
#: fix nobody has shown to be load-bearing, which is the class.
REVERTIBLE_FIXES = [
    ("the module check reduced to an arity check",
     "tests/test_false_green_audit.py",
     "    return not isinstance(argument, CANNOT_BE_A_MODULE)",
     "    return True",
     "test_a_star_is_not_proof_that_a_module_was_supplied"),
    ("the screen filter reduced to two literal spellings",
     "tests/test_false_green_audit.py",
     "    known = SCREEN_ENTRY_POINTS if local_names is None else local_names",
     "    known = SCREEN_ENTRY_POINTS",
     "test_the_screen_is_recognised_however_it_is_named"),
    ("the pair helper reduced to counting elements",
     "tests/test_false_green_audit.py",
     "                assert pair and _could_be_a_module(node.value.elts[1]), (",
     "                assert pair, (",
     "test_a_pair_helper_must_return_something_that_could_be_a_module"),
]


@pytest.mark.parametrize(
    ("label", "relative", "before", "after", "node"), REVERTIBLE_FIXES,
    ids=[case[0] for case in REVERTIBLE_FIXES],
)
def test_reverting_one_fix_reddens_its_own_specimen(
    label: str, relative: str, before: str, after: str, node: str,
    tmp_path: Path,
):
    """AC02: a fix nothing fails without is not a fix that has been tested.

    One revert at a time, on a copy, so the specimen that goes red is decided
    by THIS fix and not by something that moved with it. Measured on the
    round-14 findings: three fixes reverted, every wiring control green, and
    the defect each was written for back in place.
    """
    import shutil  # noqa: PLC0415

    workspace = tmp_path / "tree"
    for name in ("tests", "src", "scripts"):
        shutil.copytree(
            ROOT / name, workspace / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    shutil.copy2(ROOT / "pyproject.toml", workspace / "pyproject.toml")

    target = workspace / relative
    text = target.read_text(encoding="utf-8")
    assert text.count(before) == 1, (
        label + ": the fix is not where this row says it is, so the revert "
        "would measure nothing"
    )
    target.write_text(text.replace(before, after), encoding="utf-8", newline="")

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-p", "no:randomly", "-q",
         "-o", "addopts=", "--no-header", "-p", "no:cacheprovider",
         str(workspace / relative) + "::" + node],
        cwd=workspace, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    assert completed.returncode != 0, (
        label + ": reverting this fix left its own specimen GREEN, so nothing "
        "measures whether the fix is there:" + NL + completed.stdout[-600:]
    )


def test_every_revertible_fix_passes_before_it_is_reverted():
    """The control for the controls: green at HEAD, red only under the revert.

    Without this, a row whose specimen is red for an unrelated reason would
    look like a working revert control.
    """
    nodes = sorted({row[4] for row in REVERTIBLE_FIXES})
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-p", "no:randomly", "-q",
         "-o", "addopts=", "--no-header", "-p", "no:cacheprovider",
         *["tests/test_false_green_audit.py::" + node for node in nodes]],
        cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    assert completed.returncode == 0, (
        "a revert control's specimen is failing at HEAD, so its RED under the "
        "revert would prove nothing:" + NL + completed.stdout[-600:]
    )
