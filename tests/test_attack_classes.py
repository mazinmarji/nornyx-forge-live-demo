"""The class probes: a new member is caught by the class, not the next reviewer.

`docs/governance/CLOSURE_PROTOCOL.md` sets the rule these enforce. The registry
in `attack_classes.py` names root mechanisms; this module makes each one
mechanical, so that classifying a finding into a class is a decision with
consequences rather than a label.
"""

from __future__ import annotations

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


def collected_node_ids() -> set:
    """Every node id pytest would collect, read from pytest.

    `-o addopts=` because this repository's configured addopts summarise
    collection as `path: COUNT`, and the counts are what the previous version
    of this check parsed -- discarding the node ids that were the answer.
    """
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-o", "addopts=", "--no-header",
         "-p", "no:cacheprovider", "-p", "no:randomly"],
        cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    ids = {
        line.strip().replace(chr(92), "/")
        for line in completed.stdout.splitlines()
        if line.strip().startswith("tests/") and "::" in line
    }
    assert len(ids) > 1000, (
        "collection produced " + str(len(ids)) + " node ids, so this check "
        "would pass vacuously:" + NL + completed.stdout[-500:]
    )
    return ids


def test_every_attack_class_names_specimens_that_exist():
    """A class whose specimens do not resolve is a label, not a control.

    NODE COLLECTION, not file collection. This asked `ast.walk` for ANY
    function of that name -- a nested helper, a shadowing redefinition, a plain
    utility all satisfied it -- and then whether the FILE collected anything.
    Its own docstring claimed otherwise in as many words: "a function that
    exists but is not collected -- deselected, shadowed by a later definition,
    excluded by configuration -- holds nothing down either, which is FG38's own
    class." All three named cases passed, and a hostile class naming a function
    nested inside another test's body passed every registry check.

    That is AC01 in the module that defines AC01: a rule matching a name
    occurring somewhere in a file, standing in for the question of whether THIS
    NODE is collected. The node ids were in the output the check already read.
    """
    collected = collected_node_ids()
    missing = []
    for item in ATTACK_CLASSES:
        assert item.specimens, item.ident + " names no specimen at all"
        for node in item.specimens:
            relative, _, name = node.partition("::")
            if not (ROOT / relative).is_file():
                missing.append(item.ident + " -> " + relative + " does not exist")
                continue
            if not name.startswith("test_"):
                missing.append(
                    item.ident + " -> " + node + " is not a test node id"
                )
                continue
            # Parametrised nodes collect as `node[id]`, so a prefix match on
            # the bare id is the right question -- but anchored, so a
            # shorter name cannot be satisfied by a longer one that starts
            # with it. (Spelled out rather than shown: in this repository
            # backticks around a test_ name mean it resolves, so a
            # backticked placeholder is a citation of a guard that does not
            # exist -- which the citation check duly refused.)
            if not any(
                found == node or found.startswith(node + "[")
                for found in collected
            ):
                missing.append(item.ident + " -> " + node + " is not collected")
    assert missing == [], (
        "these attack classes name specimens the suite does not collect, so "
        "the class is held down by nothing: " + repr(missing)
    )


def test_a_specimen_that_is_defined_but_not_collected_is_refused():
    """The control for the control: the check must be able to say no.

    A nested function bearing a collected test's name passed every registry
    check before this. The three ways a name can exist without being a node --
    nested, not `test_`-prefixed, absent from collection -- are each refused,
    and the refusal is measured rather than assumed.
    """
    real = ATTACK_CLASSES[0].specimens[0]
    relative = real.partition("::")[0]
    for bogus in (relative + "::worker",
                  relative + "::_screen_says",
                  relative + "::test_this_node_does_not_exist_anywhere"):
        collected = collected_node_ids()
        name = bogus.partition("::")[2]
        refused = (
            not name.startswith("test_")
            or not any(found == bogus or found.startswith(bogus + "[")
                       for found in collected)
        )
        assert refused, bogus + " would satisfy the registry check"


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

#: (label, module A, body A, module B, body B, the answer both must give).
#:
#: TWO MODULE SOURCES, because one row could not construct the contrast its own
#: id named: "column zero and one indent deep" passed the SAME body twice under
#: the SAME module source, so it asserted `f(x) == f(x)` and could not fail for
#: any implementation, including a deleted one.
#:
#: AND THE ANSWER IS STATED, not just the agreement. Every row of all three
#: tables shared the same answer -- 0 for the screen, True for the other two --
#: so an `exercised_assertions` that always returned 0, or a detector that
#: always returned True, passed the whole class probe. Agreement is half the
#: property; the rows now say which answer, and rows whose shared answer is the
#: OTHER one are here so a constant implementation fails.
SCREEN_SYNONYMS = [
    ("a swallowing handler, named and aliased",
     "_Err = AssertionError",
     "try:" + NL + "    assert real" + NL + "except AssertionError:" + NL + "    pass",
     "_Err = AssertionError",
     "try:" + NL + "    assert real" + NL + "except _Err:" + NL + "    pass", 0),
    ("a swallowing handler, named and imported under another name",
     "from builtins import AssertionError as _E",
     "try:" + NL + "    assert real" + NL + "except AssertionError:" + NL + "    pass",
     "from builtins import AssertionError as _E",
     "try:" + NL + "    assert real" + NL + "except _E:" + NL + "    pass", 0),
    ("suppression, qualified and aliased",
     "_Q = contextlib.suppress",
     "with contextlib.suppress(AssertionError):" + NL + "    assert real",
     "_Q = contextlib.suppress",
     "with _Q(AssertionError):" + NL + "    assert real", 0),
    ("a dead constant at column zero and one indent deep",
     "_OFF = False", "if _OFF:" + NL + "    assert real",
     "if True:" + NL + "    _OFF = False", "if _OFF:" + NL + "    assert real", 0),
    ("a loop that ends the block, two ways of writing the exit",
     "", "while True:" + NL + "    return" + NL + "assert real",
     "", "for _ in [1]:" + NL + "    return" + NL + "assert real", 0),

    # ---- rows whose shared answer is the OTHER one ----------------------
    ("a live constant at column zero and one indent deep",
     "_ON = True", "if _ON:" + NL + "    assert real",
     "if True:" + NL + "    _ON = True", "if _ON:" + NL + "    assert real", 1),
    ("a narrow handler, named and aliased, which does NOT swallow",
     "_N = ValueError",
     "try:" + NL + "    assert real" + NL + "except ValueError:" + NL + "    pass",
     "_N = ValueError",
     "try:" + NL + "    assert real" + NL + "except _N:" + NL + "    pass", 1),
    ("a break that leaves the loop, two ways of writing the loop",
     "", "while True:" + NL + "    break" + NL + "assert real",
     "", "for _ in [1]:" + NL + "    break" + NL + "assert real", 1),
]


@pytest.mark.parametrize(
    ("label", "module_a", "first", "module_b", "second", "answer"), SCREEN_SYNONYMS,
    ids=[case[0] for case in SCREEN_SYNONYMS],
)
def test_the_screen_answers_synonyms_identically(
    label: str, module_a: str, first: str, module_b: str, second: str, answer: int,
):
    """AC01 over the guard screen.

    Two ways of writing one thing must get one answer, AND it must be the right
    answer. Every AC01 instance began as a pair like these where the answers
    differed, and each was repaired locally until the class was named.
    """
    left = _screen_says(module_a, first)
    right = _screen_says(module_b, second)
    assert left == right, (
        label + ": the screen answers " + str(left) + " and " + str(right)
        + " for two spellings of the same thing"
    )
    assert left == answer, (
        label + ": both spellings answer " + str(left) + " and the guard "
        "executes " + str(answer) + " failing thing(s) -- agreeing on the "
        "wrong answer is not the property"
    )


#: (label, source A, source B, whether both ask a text question).
DETECTOR_SYNONYMS = [
    ("membership and find",
     'x = "d" in ast.dump(n)', "x = ast.dump(n).find(chr(100)) >= 0", True),
    ("dump and unparse",
     'x = "d" in ast.dump(n)', 'x = "d" in ast.unparse(n)', True),
    ("inline and through a local",
     'x = "d" in ast.dump(n)', "r = ast.dump(n)" + NL + 'x = "d" in r', True),
    ("receiver and argument",
     'x = "d" in ast.dump(n)', 'x = "d" in "{}".format(ast.dump(n))', True),
    ("module-level re and a compiled pattern",
     'x = re.search("d", ast.dump(n))', 'x = re.compile("d").search(ast.dump(n))',
     True),

    # ---- rows whose shared answer is the OTHER one ----------------------
    ("tree comparison, two renderings, both legitimate",
     "x = ast.dump(a) == ast.dump(b)", "x = ast.unparse(a) == ast.unparse(b)", False),
    ("a question about ordinary text, two spellings",
     'x = "d" in source', 'x = source.find("d") >= 0', False),
]


@pytest.mark.parametrize(
    ("label", "first", "second", "asks"), DETECTOR_SYNONYMS,
    ids=[case[0] for case in DETECTOR_SYNONYMS],
)
def test_the_detector_answers_synonyms_identically(
    label: str, first: str, second: str, asks: bool,
):
    """AC01 over the reimplementation detector."""
    left, right = _detector_says(first), _detector_says(second)
    assert left == right, (
        label + ": the detector answers " + str(left) + " and " + str(right)
        + " for two spellings of the same question"
    )
    assert left is asks, (
        label + ": both spellings answer " + str(left) + " and the right "
        "answer is " + str(asks)
    )


#: (label, payload A, payload B, whether both contradict a `pass` verdict).
CONTRADICTION_SYNONYMS = [
    ("no inspections, as a dict and as a list",
     {"authenticated_inspections": {}}, {"authenticated_inspections": []}, True),
    ("no inspections, as a list and as null",
     {"authenticated_inspections": []}, {"authenticated_inspections": None}, True),
    ("no inspections, as null and as ABSENT",
     {"authenticated_inspections": None}, {}, True),
    ("no inspections, as a zero and as a false",
     {"authenticated_inspections": 0}, {"authenticated_inspections": False}, True),
    ("not approved, as a string and as a record",
     {"approval": "not_granted"}, {"approval": {"granted": False}}, True),
    ("not approved, as a false and as a zero",
     {"approval": {"granted": False}}, {"approval": {"granted": 0}}, True),
    ("not approved, as a record and as a nested status",
     {"approval": {"granted": False}}, {"approval": {"status": "not_granted"}}, True),

    # ---- rows whose shared answer is the OTHER one ----------------------
    ("a real inspection, as a list and as a dict",
     {"authenticated_inspections": [{"by": "r"}]},
     {"authenticated_inspections": {"r": {"at": "t"}}}, False),
    ("a granted approval, as a record and as a nested status",
     {"approval": {"granted": True}}, {"approval": {"status": "granted"}}, False),
]


@pytest.mark.parametrize(
    ("label", "first", "second", "contradicts"), CONTRADICTION_SYNONYMS,
    ids=[case[0] for case in CONTRADICTION_SYNONYMS],
)
def test_the_observer_answers_synonyms_identically(
    label: str, first: dict, second: dict, contradicts: bool, tmp_path: Path,
):
    """AC01 over the governance-integrity observer.

    The artifact is named as an independent review or an approval record,
    because the question "does this artifact report an inspection" is only
    answerable for an artifact whose subject IS one. Keying on the presence of
    a field instead meant deleting the field left the check with nothing to
    look at, which is how absence became the simplest escape.
    """
    location = tmp_path / "artifact.json"
    schema = ("nornyx.forge.approval_record.v1"
              if "approval" in {*first, *second}
              else "nornyx.forge.independent_review_record.v1")
    left = _contradiction_says(first, location, schema)
    right = _contradiction_says(second, location, schema)
    assert left == right, (
        label + ": the observer answers " + str(left) + " and " + str(right)
        + " for two ways of stating the same thing"
    )
    assert left is contradicts, (
        label + ": both spellings answer " + str(left) + " and the right "
        "answer is " + str(contradicts)
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

    THIS PROBE COULD NOT FAIL, and that is AC06. It asserted
    `completed.returncode != 0` on a copied tree that was not a git repository,
    where `tests/conftest.py`'s session-scoped working-tree guard raises at
    teardown on EVERY run -- pristine included. Measured: a semantics-preserving
    reformat supplied as the "revert" and the probe passed. `0 failed` and
    `9 failed` were the same verdict to it.

    Four questions now, not one, using the machinery this repository already
    owns for exactly this and did not reach for:

        the workspace is a git repository   so the tree guard can answer
        the specimen PASSES there first     `require_pristine_baseline`
        the revert really changed code      `check_python_mutation`
        the NAMED node failed, in the call  `require_caused_failure`
                                            phase, reading the JUnit report

    The pristine step is the one that was missing, and it has to run in the
    SAME workspace: the old companion control measured green at ROOT, a git
    repository, so it structurally could not see this.
    """
    import shutil  # noqa: PLC0415
    import subprocess as sub  # noqa: PLC0415

    from mutation_validity import check_python_mutation  # noqa: PLC0415
    from mutation_workspace import (  # noqa: PLC0415
        require_caused_failure,
        require_pristine_baseline,
        run_node,
    )

    workspace = tmp_path / "tree"
    workspace.mkdir()
    for name in ("tests", "src", "scripts"):
        shutil.copytree(
            ROOT / name, workspace / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for name in ("pyproject.toml", ".gitignore"):
        shutil.copy2(ROOT / name, workspace / name)
    # A GIT REPOSITORY, so the tree guard reports a state instead of refusing
    # to answer -- which is what turned every exit code in here into a 1.
    for command in (
        ["init", "-q"],
        ["config", "user.email", "fixture@example.invalid"],
        ["config", "user.name", "fixture"],
        ["add", "-A"],
        ["commit", "-qm", "pristine"],
    ):
        sub.run(["git", *command], cwd=workspace, check=True, capture_output=True)  # noqa: S603, S607

    target = workspace / relative
    pristine = target.read_text(encoding="utf-8")
    assert pristine.count(before) == 1, (
        label + ": the fix is not where this row says it is, so the revert "
        "would measure nothing"
    )

    # GREEN HERE FIRST. Not at ROOT -- in this workspace, under this
    # interpreter, with this conftest.
    node_id = relative + "::" + node
    require_pristine_baseline(workspace, node_id)

    reverted = pristine.replace(before, after)
    check_python_mutation(relative, pristine, reverted, before, 1)
    target.write_text(reverted, encoding="utf-8", newline="")
    sub.run(["git", "add", "-A"], cwd=workspace, check=True, capture_output=True)  # noqa: S603, S607
    sub.run(  # noqa: S603, S607
        ["git", "commit", "-qm", "reverted"], cwd=workspace,
        check=True, capture_output=True,
    )

    report = tmp_path / "report.xml"
    completed = run_node(workspace, node_id, report=report)
    assert completed.returncode != 0, (
        label + ": reverting this fix left its own specimen GREEN, so nothing "
        "measures whether the fix is there:" + NL + completed.stdout[-600:]
    )
    # AND THE NAMED NODE FAILED, IN THE CALL PHASE. A non-zero exit is not a
    # kill: it is also a collection error, a fixture failure, or a teardown
    # guard. That distinction is the whole finding.
    require_caused_failure(report, node_id, completed.stdout + completed.stderr)


def test_the_revert_probe_refuses_a_revert_that_changes_nothing(tmp_path: Path):
    """The control for the control, and the demonstration that it now binds.

    A semantics-preserving reformat is supplied as the revert. The old probe
    PASSED on exactly this. It must now fail, and fail because the specimen
    stayed green rather than because anything else went wrong.
    """
    row = REVERTIBLE_FIXES[0]
    label, relative, before, _after, node = row
    inert = "    return (not isinstance(argument, CANNOT_BE_A_MODULE))"
    assert inert != before

    with pytest.raises(Exception) as raised:  # noqa: PT011 - several types qualify
        test_reverting_one_fix_reddens_its_own_specimen(
            label, relative, before, inert, node, tmp_path,
        )
    message = str(raised.value)
    # THREE WAYS A NO-OP CAN BE CAUGHT, and all three are the probe
    # doing its job. `check_python_mutation` reaches it first: the parse
    # tree is identical, so nothing executable was modified. If a future
    # no-op slipped past that, the specimen would stay green and the
    # first clause would catch it instead.
    assert (
        "TARGET UNCHANGED" in message
        or "left its own specimen GREEN" in message
        or "did not fail" in message
    ), (
        "the probe rejected a no-op revert for some other reason, so it is "
        "not the no-op it detected: " + message[:400]
    )
