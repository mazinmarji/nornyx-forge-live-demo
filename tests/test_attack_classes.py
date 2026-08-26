"""The class probes: a new member is caught by the class, not the next reviewer.

`docs/governance/CLOSURE_PROTOCOL.md` sets the rule these enforce. The registry
in `attack_classes.py` names root mechanisms; this module makes each one
mechanical, so that classifying a finding into a class is a decision with
consequences rather than a label.
"""

from __future__ import annotations

import ast
import importlib
import re
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

#: (label, file, fix as written, fix removed, specimen file, specimen node).
#:
#: THE CLASS PROBE FOR AC02. Each row reverts ONE fix on a copy of the tree and
#: requires its named specimen to go RED. A fix added without a row here is a
#: fix nobody has shown to be load-bearing, which is the class.
#:
#: THE SPECIMEN FILE IS ITS OWN COLUMN because it is not always the mutated
#: one. A class probe lives with its class, so the AC07 rows revert a fix in
#: one module and are answered by a specimen in this one. Deriving the node id
#: from the mutated file, which is what this table did, cannot express that --
#: and the shape it could not express is exactly the shape a class probe has.
REVERTIBLE_FIXES = [
    ("the module check reduced to an arity check",
     "tests/test_false_green_audit.py",
     "    return not isinstance(argument, CANNOT_BE_A_MODULE)",
     "    return True",
     "tests/test_false_green_audit.py", "test_a_star_is_not_proof_that_a_module_was_supplied"),
    ("the screen filter reduced to two literal spellings",
     "tests/test_false_green_audit.py",
     "    known = SCREEN_ENTRY_POINTS if local_names is None else local_names",
     "    known = SCREEN_ENTRY_POINTS",
     "tests/test_false_green_audit.py", "test_the_screen_is_recognised_however_it_is_named"),
    ("the pair helper reduced to counting elements",
     "tests/test_false_green_audit.py",
     "                assert pair and _could_be_a_module(node.value.elts[1]), (",
     "                assert pair, (",
     "tests/test_false_green_audit.py", "test_a_pair_helper_must_return_something_that_could_be_a_module"),
    # ---- AC07: reverting a version fix must redden the floor probe -------
    ("the module-level tomllib fallback removed",
     "tests/test_xfail_strictness.py",
     "try:"
     + NL + "    import tomllib"
     + NL + "except ModuleNotFoundError:  # pragma: no cover - only on Python 3.10"
     + NL + "    import tomli as tomllib",
     "import tomllib",
     "tests/test_attack_classes.py",
     "test_no_module_imports_stdlib_newer_than_the_floor"),
    ("the in-test tomllib fallback removed",
     "tests/test_false_green_audit.py",
     "    try:"
     + NL + "        import tomllib  # noqa: PLC0415"
     + NL + "    except ModuleNotFoundError:  # pragma: no cover - only on Python 3.10"
     + NL + "        import tomli as tomllib  # noqa: PLC0415",
     "    import tomllib  # noqa: PLC0415",
     "tests/test_attack_classes.py",
     "test_no_module_imports_stdlib_newer_than_the_floor"),
    # SKIPPED ON THE FLOOR ITSELF. `except*` source does not parse on 3.10
    # at all, so the specimen filters it out before it can be an offender
    # and removing the mark cannot redden anything. The row proves the mark
    # is load-bearing on every interpreter that can see past the floor.
    pytest.param(
    "the skipif guarding except* source removed",
     "tests/test_false_green_audit.py",
     "    pytest.param(\"try:\" + NL + \"    assert real\" + NL"
     + NL + "                 + \"except* AssertionError:\" + NL + \"    pass\", 0,"
     + NL + "                 marks=_NEEDS_EXCEPT_STAR),",
     "    (\"try:\" + NL + \"    assert real\" + NL + \"except* AssertionError:\" + NL"
     + NL + "     + \"    pass\", 0),",
     "tests/test_attack_classes.py",
     "test_every_specimen_source_parses_at_the_declared_floor",
     marks=pytest.mark.skipif(
         sys.version_info < (3, 11),
         reason="except* does not parse on the floor interpreter, so the "
                "specimen cannot see it with or without the mark",
     )),
    # ---- AC02: a signed field that no consumer evaluates ----------------
    ("the findings binding weakened to a condition that never holds",
     "src/nornyx_forge/reviewer_trust.py",
     "    if carried != signed_digest:",
     "    if carried is None and signed_digest is None:",
     "tests/test_reviewer_authentication.py",
     "test_findings_cannot_be_edited_after_review"),
    # ---- AC04: a widening applied to one analysis and not its sibling ---
    ("the sys.modules recogniser disabled",
     "scripts/check_architecture.py",
     "    if not is_map:",
     "    if True:",
     "tests/test_architecture_vocabulary.py",
     "test_an_undeclared_edge_is_refused_however_it_is_spelled"),
    # ---- AC01: a decision taken from an incidental failure mode ---------
    #
    # THE SHARED PARSE, not the branch that consults it. Reverting only the
    # `_looks_like_a_plaintext_mark` call in `_assert_witness_structure`
    # leaves the DatabaseError route answering correctly on whichever
    # platform takes it -- which is exactly why the repair shipped green on
    # Windows with no specimen at all, and a review had to find that. The
    # single parse is what both routes depend on.
    ("the plain-text witness parse reduced to None",
     "src/nornyx_forge/nornyx_runtime.py",
     "        return value if value >= 0 else None",
     "        return None",
     "tests/test_ledger_continuity.py",
     "test_a_plaintext_witness_is_classified_for_migration_on_every_route"),
    ("the migration that converts a plain-text witness removed",
     "src/nornyx_forge/cli.py",
     "        if legacy_mark is not None:",
     "        if False:",
     "tests/test_ledger_continuity.py",
     "test_the_named_remedy_converts_the_artifact_it_names"),
    # ---- the construct refusal that replaced two enumerations ----------
    ("the unresolvable-access refusal reduced to nothing",
     "scripts/check_architecture.py",
     "    sites: list[tuple[int, str]] = []",
     "    return []",
     "tests/test_architecture_vocabulary.py",
     "test_an_undeclared_edge_is_refused_however_it_is_spelled"),
    # NOT A ROW: the distinctness clause in
    # `scripts/refresh_governance_evidence.py`. Its specimen,
    # `test_one_reviewer_cannot_cover_every_role`, builds its own workspace
    # and settles contracts inside it, which cannot run nested in this
    # harness's workspace -- `require_pristine_baseline` refused it as
    # INVALID_BASELINE rather than letting a workspace defect read as a kill.
    #
    # The revert was measured IN PLACE instead, and the result is recorded
    # here because a measurement that lives only in a commit message is what
    # CLOSURE_PROTOCOL forbids. Reverting
    #     review_status = "pass" if not absent and not shared else "observed"
    # to `"pass" if not absent else "observed"` fails that specimen with:
    #     the evidence index claims a passing independent review over an
    #     inspection derive_assurance_state refuses:
    #     {"status": "pass", "verdict_basis": "authenticated inspection is
    #      not independent: 3 inspector roles are covered by 1 reviewer(s)"}
]


def _row_label(case) -> str:
    """The label of a revert row, whether or not it carries marks.

    A `pytest.param` is a NamedTuple whose first element is the VALUES
    tuple, so `case[0]` returns the whole row once a row acquires a mark,
    and pytest refuses a tuple as an id -- a collection error for every
    case in the table, not just the marked one.
    """
    values = getattr(case, "values", case)
    return values[0]


@pytest.mark.parametrize(
    ("label", "relative", "before", "after", "specimen", "node"),
    REVERTIBLE_FIXES,
    ids=[_row_label(case) for case in REVERTIBLE_FIXES],
)
def test_reverting_one_fix_reddens_its_own_specimen(
    label: str, relative: str, before: str, after: str, specimen: str,
    node: str, tmp_path: Path,
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
    # `.nornyx` TOO. A specimen that imports the test modules -- which the
    # AC07 floor probe does, because the tables it reads are module
    # attributes -- reaches modules that read the contracts at import time,
    # and a workspace without them fails BEFORE any mutation. That is not a
    # kill, and `require_pristine_baseline` correctly refused to call it one.
    # THE UNION OF WHAT THE SPECIMEN FIXTURES COPY, read off them rather
    # than guessed one failure at a time: `tests/test_independent_inspection.py`
    # builds its workspace from scripts, src, docs, .nornyx, tests and
    # .github. A revert row naming a specimen there fails at the pristine
    # baseline without them -- INVALID_BASELINE, which is the machinery
    # correctly refusing to call a missing fixture a kill.
    # governance documents, and a workspace without them fails at the
    # pristine baseline -- INVALID_BASELINE, the machinery correctly
    # refusing to call a missing fixture a kill.
    for name in ("tests", "src", "scripts", ".nornyx", "docs", ".github"):
        if not (ROOT / name).is_dir():  # pragma: no cover - all present
            continue
        shutil.copytree(
            ROOT / name, workspace / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    # THE FILES A SPECIMEN'S OWN FIXTURE COPIES. `tests/test_architecture_vocabulary.py`
    # builds its gate workspace from README.md, BRD.md and Dockerfile as well,
    # and a revert row naming a specimen in that module fails at the pristine
    # baseline without them -- INVALID_BASELINE, which is the machinery
    # correctly refusing to call an environment defect a kill.
    for name in ("pyproject.toml", ".gitignore", "README.md", "BRD.md",
                 "Dockerfile"):
        if not (ROOT / name).is_file():  # pragma: no cover - all present
            continue
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
    node_id = specimen + "::" + node
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
    label, relative, before, _after, specimen, node = row
    inert = "    return (not isinstance(argument, CANNOT_BE_A_MODULE))"
    assert inert != before

    with pytest.raises(Exception) as raised:  # noqa: PT011 - several types qualify
        test_reverting_one_fix_reddens_its_own_specimen(
            label, relative, before, inert, specimen, node, tmp_path,
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


def _specimen_sources(value, depth: int = 0):
    """Yield (source, guarded) for every string reachable in a specimen table.

    `guarded` is True when the string arrived inside a `pytest.param` carrying a
    `skipif` mark, because such a row does not run on the interpreter the mark
    excludes and so cannot error there.
    """
    if depth > 6:
        return
    if isinstance(value, str):
        if len(value) > 6 and NL in value:
            yield value, False
        return
    if hasattr(value, "values") and hasattr(value, "marks"):
        guarded = any(mark.name == "skipif" for mark in value.marks)
        for item in value.values:
            for text, _ in _specimen_sources(item, depth + 1):
                yield text, guarded
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _specimen_sources(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _specimen_sources(key, depth + 1)
            yield from _specimen_sources(item, depth + 1)


def _handler_catches_import(handler: ast.ExceptHandler) -> bool:
    kind = handler.type
    if kind is None:
        return True
    names = []
    for element in (kind.elts if isinstance(kind, ast.Tuple) else [kind]):
        if isinstance(element, ast.Name):
            names.append(element.id)
    return any(
        name in ("ImportError", "ModuleNotFoundError", "Exception")
        for name in names
    )


def _unguarded_imports(tree: ast.AST):
    """Every import statement NOT inside a try that catches an import failure."""
    guarded: set = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        if not any(_handler_catches_import(h) for h in node.handlers):
            continue
        # THE HANDLER BODY COUNTS TOO. The fallback lives there --
        # `except ModuleNotFoundError: import tomli as tomllib` -- so
        # collecting only `node.body` reported the remediation for this
        # class AS an instance of it. The over-reach control caught that.
        branches = [*node.body, *node.orelse]
        for handler in node.handlers:
            branches.extend(handler.body)
        for statement in branches:
            for inner in ast.walk(statement):
                if isinstance(inner, (ast.Import, ast.ImportFrom)):
                    guarded.add(id(inner))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)) and id(node) not in guarded:
            yield node


def _imported_roots(node) -> list:
    if isinstance(node, ast.Import):
        return [alias.name.split(".")[0] for alias in node.names]
    if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
        return [node.module.split(".")[0]]
    return []


# ---------------------------------------------------------------------------
# AC07 -- a support range declared, and measured at one point in it
# ---------------------------------------------------------------------------

#: Stdlib modules that do not exist at every version `requires-python` allows.
#:
#: A HAND-MAINTAINED VOCABULARY, and the only one in this section. The two parse
#: axes below are decided by CPython own parser; this one cannot be, because the
#: stdlib exposes no "introduced in" metadata to derive it from. The limit is
#: therefore stated rather than implied: a module absent on an old interpreter
#: and missing from this table is NOT caught here, and the 3.10 CI job is what
#: catches it. That is a backstop after a push, which is the cost this class
#: exists to REDUCE, not to eliminate.
STDLIB_INTRODUCED = {
    "tomllib": (3, 11),
    "graphlib": (3, 9),
    "zoneinfo": (3, 9),
}


def declared_floor() -> tuple:
    """The oldest interpreter `requires-python` admits, read from it.

    DERIVED, not typed again here. A floor restated in this file would go stale
    against the declaration the moment the declaration moved, and the probe
    would keep passing -- measuring a version nobody supports while reading as
    though it measured the range.
    """
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    line = next(
        (row for row in text.splitlines()
         if row.strip().startswith("requires-python")),
        None,
    )
    assert line, "pyproject.toml declares no requires-python"
    lower = re.search(r">=\s*(\d+)\.(\d+)", line)
    assert lower, "requires-python declares no lower bound: " + line
    return (int(lower.group(1)), int(lower.group(2)))


def repository_modules() -> list:
    return sorted(
        [*(ROOT / "tests").rglob("*.py"), *(ROOT / "src").rglob("*.py"),
         *(ROOT / "scripts").rglob("*.py")]
    )


def test_the_floor_is_read_from_the_declaration():
    """The probes below are only as honest as where they get the floor.

    If `declared_floor` returned a constant, every assertion in this section
    would still pass while measuring an interpreter the project no longer
    supports. So it is read from the same file pip reads, and the value is
    checked to be a real lower bound rather than whatever a regex happened to
    find.
    """
    floor = declared_floor()
    assert floor[0] == 3 and 6 <= floor[1] <= 20, floor
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert ">=" + str(floor[0]) + "." + str(floor[1]) in text, (
        "the floor " + repr(floor) + " is not the one pyproject declares"
    )
    assert floor <= sys.version_info[:2], (
        "the floor is newer than the interpreter running this suite, so the "
        "suite is not running on a version the project claims to support"
    )


def test_every_module_parses_at_the_declared_floor():
    """Every module must be PARSEABLE on the oldest supported interpreter.

    A module that is not is a collection error there -- the whole module lost,
    not one test. `feature_version` is CPython own parser answering the
    question, so this is not a vocabulary of banned syntax maintained here.

    WHAT `feature_version` DOES NOT MODEL, stated because the sentence above
    reads as though it covered the whole grammar and a review measured that
    it does not. It gates the features CPython guards explicitly -- `except*`
    and pattern matching among them -- but NOT PEP 701, so an f-string using
    3.12-only nesting or quote reuse parses here and breaks the 3.10 and 3.11
    jobs. There are none at this head. CI is the backstop for that shape, as
    it is for the import table.
    """
    floor = declared_floor()
    broken = []
    for path in repository_modules():
        source = path.read_text(encoding="utf-8")
        try:
            ast.parse(source, feature_version=floor)
        except SyntaxError as exc:
            broken.append(
                path.relative_to(ROOT).as_posix() + ":" + str(exc.lineno)
                + " " + str(exc.msg)
            )
    assert not broken, (
        "these modules do not parse on Python " + ".".join(map(str, floor))
        + ", which pyproject declares supported: " + repr(broken)
    )


def test_every_specimen_source_parses_at_the_declared_floor():
    """And so must every specimen the suite hands to `ast.parse`.

    THE ASSEMBLED STRING, not the literals it is built from. The three
    `except*` rows that provoked this class are written as fragments joined by
    `+ NL +`, so no single literal in the file is a parseable statement and a
    scan of `ast.Constant` nodes -- which is what I wrote first -- returned a
    confident zero. The tables are read from the imported modules instead, so
    the value examined is the one the parametrisation actually receives.

    A row already marked `skipif` is not a finding: it is the remediation. That
    is read off the mark rather than named here, so removing the mark makes this
    test fail rather than silently exempting the row.
    """
    floor = declared_floor()
    offenders = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        module = importlib.import_module(path.stem)
        for attr in dir(module):
            if attr.startswith("__"):
                continue
            for text, guarded in _specimen_sources(getattr(module, attr, None)):
                if guarded:
                    continue
                try:
                    ast.parse(text)
                except SyntaxError:
                    continue
                try:
                    ast.parse(text, feature_version=floor)
                except SyntaxError as exc:
                    offenders.append(path.name + "::" + attr + " " + str(exc.msg))
    assert not offenders, (
        "these specimen sources are fed to `ast.parse` and are rejected on "
        "Python " + ".".join(map(str, floor)) + ", so the test carrying them "
        "errors there rather than proving anything: "
        + repr(sorted(set(offenders)))
    )


def test_no_module_imports_stdlib_newer_than_the_floor():
    """An unguarded import of a module that does not exist yet.

    Guarded means wrapped in a `try` whose handler catches `ImportError` or
    `ModuleNotFoundError` -- the shape `scripts/check_architecture.py` already
    used and the test suite did not.
    """
    floor = declared_floor()
    offenders = []
    for path in repository_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in _unguarded_imports(tree):
            for name in _imported_roots(node):
                introduced = STDLIB_INTRODUCED.get(name)
                if introduced and introduced > floor:
                    offenders.append(
                        path.relative_to(ROOT).as_posix() + ":" + str(node.lineno)
                        + " imports " + name + " ("
                        + ".".join(map(str, introduced)) + "+)"
                    )
    assert not offenders, (
        "these imports are of stdlib newer than the declared floor and are not "
        "guarded by a fallback: " + repr(offenders)
    )


@pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="on the floor interpreter itself there is no post-floor syntax "
           "that parses here, so this control has nothing to demonstrate",
)
def test_the_floor_probe_sees_a_violation_that_is_really_there():
    """The over-reach control, both directions, on real inputs.

    Every assertion above is a "no offenders" shape, which a broken derivation
    satisfies by finding nothing. So: a specimen that genuinely cannot parse at
    the floor must be seen, a guarded import must NOT be reported, and an
    unguarded one must be.
    """
    floor = declared_floor()
    star = "try:" + NL + "    pass" + NL + "except* ValueError:" + NL + "    pass"
    ast.parse(star)
    assert floor <= (3, 10), (
        "the floor moved to " + repr(floor) + "; this control asserts that 3.10 "
        "rejects except*, which is the right control only while 3.10 is supported"
    )
    with pytest.raises(SyntaxError):
        ast.parse(star, feature_version=(3, 10))

    guarded = ast.parse(
        "try:" + NL + "    import tomllib" + NL
        + "except ModuleNotFoundError:" + NL + "    import tomli as tomllib"
    )
    assert not list(_unguarded_imports(guarded)), (
        "a fallback-guarded import was reported as unguarded, so the fix for "
        "this class would be reported as the defect"
    )
    bare = ast.parse("import tomllib")
    assert [_imported_roots(n) for n in _unguarded_imports(bare)] == [["tomllib"]], (
        "a bare import of a 3.11-only module was not seen"
    )


# ---------------------------------------------------------------------------
# The freeze -- Forge Hardening v1
# ---------------------------------------------------------------------------

#: The attack corpus, frozen for v1. See `docs/governance/RELEASE_CONTRACT_V1.md`.
#:
#: A SET, compared in both directions, because "frozen" stated in a document is
#: AC03 and the document says so itself. The false-green inventory has had this
#: check since it was written; the attack classes did not, so for seven classes
#: the word "frozen" rested on nobody editing the tuple.
FROZEN_ATTACK_CLASSES = frozenset(
    {"AC01", "AC02", "AC03", "AC04", "AC05", "AC06", "AC07"}
)


def test_the_attack_corpus_is_exactly_the_frozen_set():
    """Both directions, so neither adding nor dropping a class is silent.

    Adding a class to `ATTACK_CLASSES` without amending the contract makes the
    release contract describe a corpus that is not the one in force. Dropping
    one makes the contract claim coverage that no longer exists. Under the
    bounded protocol the second is the dangerous direction: the whole point of
    freezing is that a later reviewer meets a probe rather than the defect, and
    a class deleted to make a suite green would remove exactly that.

    Changing the set is a deliberate act between versions, and it fails here
    until the contract is amended with it.
    """
    live = {item.ident for item in ATTACK_CLASSES}
    assert live == FROZEN_ATTACK_CLASSES, (
        "the live attack corpus and the frozen set disagree; added "
        + repr(sorted(live - FROZEN_ATTACK_CLASSES)) + ", missing "
        + repr(sorted(FROZEN_ATTACK_CLASSES - live))
    )
    assert len(ATTACK_CLASSES) == len(FROZEN_ATTACK_CLASSES), (
        "a class identifier appears twice, so the corpus is smaller than it counts"
    )


def test_the_release_contract_names_exactly_the_frozen_classes():
    """The contract document is parsed, not trusted.

    `RELEASE_CONTRACT_V1.md` restates the seven identifiers for a reader, and
    says in its own text that the restatement is not authoritative. That
    sentence is worth nothing on its own -- it is the same shape as every stale
    comment this repository has found beside a live constant -- so the
    restatement is compared against the live corpus here, in both directions.
    """
    contract = ROOT / "docs" / "governance" / "RELEASE_CONTRACT_V1.md"
    assert contract.is_file(), str(contract) + " does not exist"
    text = contract.read_text(encoding="utf-8")
    named = set(re.findall(r"\bAC\d{2}\b", text))
    live = {item.ident for item in ATTACK_CLASSES}
    assert named == live, (
        "the release contract names " + repr(sorted(named)) + " and the live "
        "corpus is " + repr(sorted(live)) + "; the contract must be amended "
        "with the corpus, not after it"
    )
    # THE COUNTS TOO. The freeze table writes `(7)` and `(42)` beside the
    # corpora, under a sentence claiming each freeze is mechanical rather
    # than declared. The `(7)` was pinned by the comparison above; the
    # `(42)` was parsed by nothing -- a count typed beside a corpus, which
    # is AC03 and which CLOSURE_PROTOCOL.md refuses to do for exactly this
    # reason. A review found it in the document that names the class.
    from test_false_green_audit import INVENTORY  # noqa: PLC0415

    counts = {
        "attack classes": (r"Attack classes \((\d+)\)", len(ATTACK_CLASSES)),
        "false-green corpus": (r"False-green corpus \((\d+)\)", len(INVENTORY)),
    }
    for label, (pattern, live_count) in counts.items():
        stated = re.search(pattern, text)
        assert stated, (
            "the freeze table no longer states a count for " + label
            + ", so the row cannot be checked against the corpus"
        )
        assert int(stated.group(1)) == live_count, (
            "the contract says " + stated.group(1) + " " + label + " and there "
            "are " + str(live_count)
        )

    for item in ATTACK_CLASSES:
        assert item.title in text, (
            item.ident + " is named in the contract but its title is not the "
            "live one, so the reader is told a different class was frozen: "
            + repr(item.title)
        )
