"""Required evidence being absent is not a successful empty verification.

Four defects in this repository have shared one root cause:

    missing contracts directory  -> empty result   -> intact
    empty contracts directory    -> empty result   -> intact
    missing review_binding.json  -> loop skipped   -> intact
    git binary unreachable       -> empty path set -> clean tree

Each was fixed where it was found. Four instances of one class is not four
bugs, so this is the class written down as a control:

    PRESENT + VERIFIED        -> intact / authenticated / available
    PRESENT + INVALID         -> compromised / unauthenticated
    REQUIRED BUT ABSENT       -> unavailable / incomplete
    OPTIONAL AND ABSENT       -> explicitly not-applicable

never

    absent -> empty collection -> no problems -> success

The behavioural half asserts each known instance still fails closed. The
structural half is the part that generalises: a scan for the constructs that
produced them, so a FIFTH one has to be classified deliberately instead of
appearing by accident.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from nornyx_forge.governed_subject import INTEGRITY_UNAVAILABLE  # noqa: E402
from nornyx_forge.subject_observer import observe_governance_integrity  # noqa: E402

#: Modules where absence can change an authority answer.
NL = chr(10)

SURFACES = (
    "src/nornyx_forge/approval_trust.py",
    "src/nornyx_forge/reviewer_trust.py",
    "src/nornyx_forge/governed_subject.py",
    "src/nornyx_forge/subject_observer.py",
    "src/nornyx_forge/subject_bootstrap.py",
    "src/nornyx_forge/nornyx_runtime.py",
    "scripts/refresh_governance_evidence.py",
    "scripts/governed_content.py",
)

#: Handlers that may return an empty collection, each with the reason absence
#: cannot increase authority there. Classifying one is a decision someone makes
#: in writing; the scan below fails on anything not listed.
#:
#: Keyed by "<relative>:<function>" so moving a construct into a new function is
#: a new decision rather than an inherited exemption.
CLASSIFIED_EMPTY_RETURNS: dict[str, str] = {
    # Empty, and that is the current truth rather than an oversight: after the
    # dirty-tree fix there is no handler in these modules that turns a failure
    # into an empty collection. Two entries were written here from memory and
    # named functions that do not exist, which
    # `test_every_classification_still_names_a_real_site` caught -- an
    # exemption for a site that is not there is cover for whatever later takes
    # the name.
    #
    # An entry belongs here only with a reason beginning OPTIONAL. or
    # CONDITIONAL. that says why absence at that site cannot increase authority.
}


#: Zero-argument builtin constructors that produce an empty value.
#:
#: `frozenset` and `bytearray` were absent from the four this used to list, and
#: `str`/`bytes` were never considered. They are here for completeness rather
#: than because anything returns them: the point is that the rule no longer
#: depends on which of them a handler happens to spell.
EMPTY_CONSTRUCTORS = frozenset({
    "bytearray", "bytes", "dict", "frozenset", "list", "set", "str", "tuple",
})


def _is_empty_value(value: ast.expr, empty_names: set) -> bool:
    """Is this expression an empty collection or string?

    STRUCTURE, NOT SPELLING. The rule this replaced tested for `ast.List` with
    no elements, `ast.Dict` with no keys, and a call to one of four names.
    Measured against it, every one of these was invisible:

        return ()                a tuple displays as neither List nor Dict
        return frozenset()       a fifth constructor
        return ''                emptiness is not only about containers
        return b''
        except ...:              the scan read only the handler's top level
            if partial:
                return []
        except ...:              and only the returned expression itself
            rows = []
            return rows

    In a module whose whole subject is that a rule naming four spellings is a
    rule about the spellings. `literal_eval` decides the class and executes
    nothing.

    `return None` IS NOT COVERED, deliberately and after measuring it: adding it
    finds 13 further sites across these eight surfaces, and it is a different
    construct. An empty collection reads to a caller as "I looked and there was
    nothing"; `None` reads as "no answer", and callers branch on it. Widening
    this rule to cover it would put 13 sites in front of a classification table
    whose entries must each state why absence cannot increase authority --
    which is worth doing on its own evidence, not as a side effect of a fix to
    the spelling problem. Recorded in the ledger as its own exposure.
    """
    if isinstance(value, ast.Name):
        return value.id in empty_names
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        return (
            value.func.id in EMPTY_CONSTRUCTORS
            and not value.args
            and not value.keywords
        )
    try:
        literal = ast.literal_eval(value)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        # Anything computed is not an empty literal, and `literal_eval` says so
        # by refusing rather than by returning a value.
        return False
    return literal is not None and hasattr(literal, "__len__") and len(literal) == 0


def _empty_return_sites(relative: str) -> list[tuple[str, int]]:
    """Every `except ...: return <empty>` in a module, with its function."""
    source = (ROOT / relative).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=relative)
    found: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.ExceptHandler):
                continue
            # Names the handler itself binds to something empty, so
            # `rows = []` followed by `return rows` is the same site as
            # `return []` -- one rename apart, and the rename hid it.
            empty_names: set = set()
            for statement in ast.walk(inner):
                if isinstance(statement, ast.Assign) and _is_empty_value(
                    statement.value, empty_names
                ):
                    empty_names |= {
                        target.id for target in statement.targets
                        if isinstance(target, ast.Name)
                    }
            # ANYWHERE IN THE HANDLER, not only its top level: a return under
            # an `if` inside the handler is the same swallowed failure.
            for statement in ast.walk(inner):
                if (
                    isinstance(statement, ast.Return)
                    and statement.value is not None
                    and _is_empty_value(statement.value, empty_names)
                ):
                    found.append((node.name, statement.lineno))
    return found


#: (label, handler body, is it a swallowed failure).
#:
#: The five that expect True were all invisible to the rule that named four
#: spellings, in the module whose subject is that naming spellings is not a
#: rule. The four that expect False are the over-reach control: a handler that
#: returns something, or re-raises, is not a swallowed failure, and a screen
#: that flagged those would put real code in front of a classification table
#: for no reason.
EMPTY_RETURN_SPECIMENS = [
    ("an empty tuple display", "    return ()", True),
    ("a fifth constructor", "    return frozenset()", True),
    ("an empty string", "    return ''", True),
    ("empty bytes", "    return b''", True),
    ("returned from inside the handler",
     "    if partial:" + NL + "        return []", True),
    ("bound to a name first",
     "    rows = []" + NL + "    return rows", True),
    ("the spelling the old rule did catch", "    return []", True),

    # --- and the other direction, which must stay unflagged -------------
    ("a non-empty literal", "    return [1]", False),
    ("a computed value", "    return _recover()", False),
    ("a constructor with an argument", "    return list(rows)", False),
    ("a name bound to something real",
     "    rows = _recover()" + NL + "    return rows", False),
    ("a re-raise", "    raise", False),
]


@pytest.mark.parametrize(
    ("label", "handler", "swallowed"), EMPTY_RETURN_SPECIMENS,
    ids=[case[0] for case in EMPTY_RETURN_SPECIMENS],
)
def test_the_scan_answers_emptiness_and_not_a_list_of_spellings(
    label: str, handler: str, swallowed: bool, tmp_path: Path, monkeypatch,
):
    """Every synonym of "I looked and there was nothing" is the same site.

    Driven through `_empty_return_sites` itself rather than a copy of its rule,
    so this cannot pass against a second implementation that agrees with the
    specimens and not with the scan the gate runs.
    """
    module = tmp_path / "surface.py"
    module.write_text(
        "def probe():" + NL
        + "    try:" + NL
        + "        return _work()" + NL
        + "    except Exception:" + NL
        + NL.join("    " + line for line in handler.split(NL)) + NL,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "test_absence_is_not_success.ROOT", tmp_path, raising=True,
    )
    found = _empty_return_sites("surface.py")
    assert bool(found) is swallowed, (
        label + ": the scan " + ("missed" if swallowed else "flagged")
        + " this handler:" + NL + handler
    )
    if swallowed:
        assert found[0][0] == "probe", found


def test_every_empty_return_from_a_handler_is_classified():
    """A swallowed failure must be a decision, not a default.

    `except Exception: return []` is how the dirty-tree gate came to report a
    clean tree when git could not be run at all. The construct is not banned --
    some absences genuinely are optional -- but each one has to say which, and
    an unclassified one fails here rather than being read as harmless.
    """
    unclassified: list[str] = []
    for relative in SURFACES:
        for function, lineno in _empty_return_sites(relative):
            key = f"{relative}:{function}"
            if key not in CLASSIFIED_EMPTY_RETURNS:
                unclassified.append(f"{key} (line {lineno})")

    assert unclassified == [], (
        "these handlers turn a failure into an empty result with no stated "
        "reason why absence cannot increase authority. Classify each in "
        "CLASSIFIED_EMPTY_RETURNS or make it fail closed: " + str(unclassified)
    )


def test_every_classification_still_names_a_real_site():
    """A stale exemption is a hole nobody is watching.

    Moving or deleting one of these would otherwise leave its entry standing as
    cover for whatever later takes the name.
    """
    live = {
        f"{relative}:{function}"
        for relative in SURFACES
        for function, _ in _empty_return_sites(relative)
    }
    stale = sorted(set(CLASSIFIED_EMPTY_RETURNS) - live)
    assert stale == [], f"these classifications name sites that no longer exist: {stale}"


def test_each_classification_states_a_reason():
    """An allowlist without reasons becomes a place to hide things."""
    for key, reason in CLASSIFIED_EMPTY_RETURNS.items():
        assert reason.startswith(("OPTIONAL.", "CONDITIONAL.")), key
        assert len(reason) > 80, f"{key} is exempted without a real explanation"


# --------------------------------------------------------------------------
# The four known instances, each still failing closed
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "location"),
    [
        ("a missing contracts directory", "no/such/directory"),
        ("a contracts directory holding none", "tests"),
    ],
)
def test_an_unobservable_governance_surface_is_unavailable(label: str, location: str):
    state = observe_governance_integrity(ROOT / location)
    assert state.status == INTEGRITY_UNAVAILABLE, label
    assert state.authorizes_consequential_action is False, label


def test_an_unrunnable_git_is_not_a_clean_tree(monkeypatch: pytest.MonkeyPatch):
    """The fourth instance, reproduced exactly.

    `_git_lines` raises SystemExit on a non-zero exit and SystemExit is not an
    Exception, so that path was already fail-closed. What the handler caught was
    git being unreachable -- and it answered "no unstaged paths", which reads as
    a clean governed tree and lets an approval be honoured over content nobody
    could prove was unchanged.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    real = subprocess.run

    def unreachable(args, **kwargs):
        if args and args[0] == "git":
            raise FileNotFoundError(2, "not found", "git")
        return real(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", unreachable)
    with pytest.raises(SystemExit) as refusal:
        refresh._unstaged_governed_paths()
    assert "clean governed tree cannot be proven" in str(refusal.value)


def test_a_missing_review_binding_is_not_a_passing_verification(tmp_path: Path):
    """The third instance, at the tool's own boundary.

    Deleting the artifact that carries the claims verification recomputes must
    not be the way to pass verification.
    """
    work = tmp_path / "repo"
    work.mkdir()
    archive = tmp_path / "tree.tar"
    subprocess.run(["git", "-C", str(ROOT), "archive", "-o", str(archive), "HEAD"], check=True)
    shutil.unpack_archive(str(archive), str(work), format="tar")
    for command in (["init", "-q"], ["config", "user.email", "a@b.invalid"],
                    ["config", "user.name", "a"], ["add", "-A"],
                    ["commit", "-qm", "fixture"]):
        subprocess.run(["git", "-C", str(work), *command], capture_output=True, check=True)

    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    for step in (["--as-of", "2026-08-11T00:00:00Z"], ["--sync-contracts"],
                 ["--review-binding"]):
        assert subprocess.run(
            [sys.executable, "scripts/refresh_governance_evidence.py", *step],
            cwd=work, capture_output=True, env=env,
        ).returncode == 0

    (work / ".nornyx/contracts/evidence/review_binding.json").unlink()
    completed = subprocess.run(
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        cwd=work, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env,
    )
    report = json.loads(completed.stdout[completed.stdout.find("{"):])["verification"]
    assert report["integrity_state"] != "intact"
    assert any("review binding is absent" in problem for problem in report["problems"])


# --------------------------------------------------------------------------
# A governed MODULE the tool imports, removed. Distinct from a governed file or
# contract, which is a different absence handled on a different path.
# --------------------------------------------------------------------------


def _settled_copy(tmp_path: Path) -> Path:
    """A faithful workspace with its evidence set generated in causal order."""
    from mutation_workspace import faithful_copy, isolated_env  # noqa: PLC0415

    tree = faithful_copy(tmp_path)
    env = isolated_env(tree)
    for step in (["--as-of", "2026-08-11T00:00:00Z"], ["--sync-contracts"],
                 ["--review-binding"]):
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "scripts/refresh_governance_evidence.py", *step],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=env, timeout=900,
        )
        assert completed.returncode == 0, completed.stderr[-400:]
    return tree


def _verify(tree: Path):
    from mutation_workspace import isolated_env  # noqa: PLC0415

    return subprocess.run(  # noqa: S603
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=isolated_env(tree), timeout=900,
    )


def test_a_deleted_governed_module_is_refused_not_crashed(tmp_path: Path):
    """THE CONTROL THAT HAD NO PROOF.

    `_refuse_missing_governed_module` translates a ModuleNotFoundError for
    governed source into a governance finding. Nothing exercised it: the test
    named for this class deletes a governed FILE or CONTRACT, and neither raises
    ModuleNotFoundError, so the helper never ran in any test in this suite.

    Traced backward from the observable rather than assumed. Deleting
    `src/nornyx_forge/reviewer_trust.py` and running `--verify` produces exit 2
    and a structured refusal naming the absent module -- and that message is
    built in exactly one place, which is the helper.

    The distinction under test is SEMANTIC, not the exit code. A traceback also
    exits non-zero. What separates a refusal from a crash is that the refusal is
    machine-readable, names the missing content, and reports integrity as
    UNAVAILABLE rather than claiming anything about soundness.
    """
    tree = _settled_copy(tmp_path)
    (tree / "src/nornyx_forge/reviewer_trust.py").unlink()

    completed = _verify(tree)
    combined = completed.stdout + completed.stderr

    # A CRASH would put a traceback on stderr and no JSON on stdout.
    assert "Traceback (most recent call last)" not in combined, (
        f"a missing governed module produced an uncontrolled traceback:\n"
        f"{combined[-600:]}"
    )
    assert completed.stdout.strip().startswith("{"), (
        f"the refusal is not machine-readable:\n{combined[-400:]}"
    )

    report = json.loads(completed.stdout[completed.stdout.find("{"):])
    assert report["status"] == "fail"
    verification = report["verification"]
    assert verification["integrity_state"] == "unavailable", verification
    assert verification["governed_input_match"] is False
    assert any(
        "nornyx_forge.reviewer_trust" in problem
        for problem in verification["problems"]
    ), verification["problems"]


def test_the_refusal_names_the_module_rather_than_the_python_error(tmp_path: Path):
    """An operator must learn that governed content is absent.

    Not that Python could not import something -- which is what a traceback
    says, and it sends the reader to reinstall the tool instead of restoring the
    file.
    """
    tree = _settled_copy(tmp_path)
    (tree / "src/nornyx_forge/reviewer_trust.py").unlink()

    report = json.loads(_verify(tree).stdout[_verify(tree).stdout.find("{"):])
    problem = report["verification"]["problems"][0]

    assert "governed content is missing" in problem, problem
    assert "not present in the tree" in problem, problem
    assert "ModuleNotFoundError" not in problem, (
        "the refusal leaks the Python exception name, which describes the "
        "interpreter's difficulty rather than the governed state"
    )


@pytest.mark.false_green("FG37")
def test_a_non_governed_import_failure_keeps_its_traceback(tmp_path: Path):
    """The control, and the reason the translation is narrow.
    FG37: a structural control that a COMMENT satisfied.

    Only modules under the governed source packages are translated. Anything
    else is a real environment fault, and dressing it up as a governance finding
    would hide a broken installation behind a sentence about governed content.
    """
    # AST, NOT SUBSTRING. R5: a scan must structurally distinguish USE from
    # MENTION. Measured on the previous version of this guard: the real
    # `raise exc` was deleted and replaced with the comment
    #
    #     # a non-governed failure would raise exc here
    #
    # and this control PASSED. `"raise exc" in source` cannot tell a statement
    # from a sentence about one, and a guard that a comment satisfies is not a
    # check on the code.
    #
    # (Three behavioural tests in this module did catch that deletion, which is
    # why it was not a live false green. But relying on a sibling test to cover
    # what this one claims is a helper standing in for a measured semantic --
    # the substitution the invariant names.)
    import ast  # noqa: PLC0415

    tree = ast.parse(
        (ROOT / "scripts/refresh_governance_evidence.py").read_text(encoding="utf-8")
    )
    handler = next(
        (node for node in ast.walk(tree)
         if isinstance(node, ast.FunctionDef)
         and node.name == "_refuse_missing_governed_module"),
        None,
    )
    assert handler is not None, (
        "the refusal function is gone or renamed, so this control is aimed "
        "at nothing"
    )

    guarded = [
        node for node in ast.walk(handler)
        if isinstance(node, ast.Set)
        and {getattr(e, "value", None) for e in node.elts}
        == {"governed_content", "nornyx_forge"}
    ]
    assert guarded, (
        "the translation is no longer restricted to the governed packages by a "
        "literal set of their names, so an unrelated ImportError could be "
        "reported as missing governed content"
    )

    reraises = [node for node in ast.walk(handler) if isinstance(node, ast.Raise)]
    assert reraises, (
        "the function contains no `raise` STATEMENT, so a non-governed "
        "ModuleNotFoundError is no longer re-raised -- whatever the comments say"
    )
