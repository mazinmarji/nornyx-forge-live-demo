"""A mutation workspace faithful enough that a pristine proof still passes.

WHY THIS EXISTS. The previous harness copied an allowlist -- `src`, `tests`,
`scripts`, `.nornyx` and four root files -- and credited a kill for any non-zero
pytest exit. Three historical classes "passed" because their named tests ALREADY
FAILED in that workspace: `.github` was absent, `README.md` and `BRD.md` were
absent, and there was no `.git` for `git ls-files`. A docstring-only edit earned
the same certificate. The classification was measuring the workspace, not the
control.

So the surface is no longer guessed. Every file git tracks is copied, and git
metadata is real, because the tests' own fixtures depend on both. Anything the
repository deliberately does not track -- `.venv`, `evidence/runtime`, caches --
is absent for the same reason it is absent from a clean checkout.

THE ADMISSION PROTOCOL, in order. A step that fails ends the attempt with the
outcome named beside it; none of them may be reported as a kill:

    1  the named test node EXISTS                    INVALID_TEST_TARGET
    2  the named test PASSES pristine                INVALID_BASELINE
    3  the target is PRODUCTION source               INVALID_MUTATION
    4  the named test REACHES the mutated clause     INVALID_TEST_AIM
    5  the mutation applies to an executable node    INVALID_MUTATION
    6  the mutant is what loads                      INVALID_MUTATION_ENVIRONMENT
    7  the intended semantic effect is present       INVALID_MUTATION
    8  the EXACT node fails, in the call phase,      KILLED_VALIDLY
       for the INTENDED property

Step 2 is the one that was missing, and it is the one that matters: an attack
cannot be classified until its proof is shown to work when nothing is broken.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from enum import Enum
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]

#: Tracked paths that must NOT be copied, with the reason. Deliberately tiny --
#: an exclusion list is a place for a required surface to go missing, which is
#: the defect this module exists to remove.
NEVER_COPY: dict[str, str] = {}


class Outcome(str, Enum):
    """Every way an attack attempt can end. There is no other."""

    KILLED_VALIDLY = "KILLED_VALIDLY"
    DEFENCE_IN_DEPTH = "DEFENCE_IN_DEPTH"
    SURVIVED = "SURVIVED"
    INVALID_MUTATION = "INVALID_MUTATION"
    INVALID_MUTATION_ENVIRONMENT = "INVALID_MUTATION_ENVIRONMENT"
    INVALID_BASELINE = "INVALID_BASELINE"
    INVALID_TEST_TARGET = "INVALID_TEST_TARGET"
    #: The node EXISTS and PASSES pristine, and instrumentation proves it never
    #: executes the clause the attack removes. Distinct from
    #: INVALID_TEST_TARGET, which is a node that does not collect at all: here
    #: the test is real, runs, and is simply aimed somewhere else. Nothing about
    #: removing the control can be concluded from it.
    INVALID_TEST_AIM = "INVALID_TEST_AIM"


class AttackNotAdmissible(AssertionError):
    """The attempt never reached the property, so it is not a result.

    Carries the outcome so a catalogue can count it in the right column instead
    of folding every failure into "not killed".
    """

    def __init__(self, outcome: Outcome, message: str) -> None:
        super().__init__(f"{outcome.value} -- {message}")
        self.outcome = outcome


class NotAGitCheckout(RuntimeError):
    """The suite is running somewhere `git ls-files` cannot answer.

    A `git archive` tarball is a faithful copy of the CONTENT and carries no
    `.git`, so every proof that asks git what is tracked fails -- 62 failures
    and 10 errors across 16 modules when a review measured it, including all
    nineteen `test_removing_the_control_revives_the_defect` cases, the mutation
    catalogue, and three false-green guards.

    Those are the repository's central "every historical defect stays dead"
    evidence, and they pass in any git CHECKOUT. But a reviewer handed the
    artifact form -- an archive -- cannot run them, and 62 unexplained failures
    is the worst possible way to learn why.
    """


def tracked_files() -> list[str]:
    """Everything git tracks, which is what a clean checkout would contain."""
    completed = subprocess.run(  # noqa: S603
        ["git", "ls-files", "-z"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=False,
        timeout=600,
    )
    if completed.returncode != 0:
        raise NotAGitCheckout(
            "`git ls-files` failed in " + str(ROOT) + ": "
            + (completed.stderr or "").strip()[:200]
            + ". These proofs need a git CHECKOUT, not a `git archive` "
            "extraction -- an archive carries the content and no `.git`, so "
            "every proof that asks git what is tracked fails for a reason "
            "unrelated to the control under test. Clone the repository instead."
        )
    return [name for name in completed.stdout.split(chr(0)) if name]


def faithful_copy(destination: Path) -> Path:
    """A workspace a pristine proof can pass in.

    The whole tracked worktree plus real git metadata. `git init` and a single
    commit, because several proofs shell out to `git ls-files` and a directory
    with no repository makes them fail for a reason that has nothing to do with
    the control under test.
    """
    tree = destination / "tree"
    tree.mkdir(parents=True, exist_ok=True)

    names = tracked_files()
    if len(names) < 100:
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION_ENVIRONMENT,
            f"git tracks only {len(names)} files; this is not the repository",
        )
    for name in names:
        if name in NEVER_COPY:
            continue
        source = ROOT / name
        if not source.is_file():
            continue
        target = tree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    # BOUNDED. A review measured 110 of 144 `subprocess` call sites in this
    # repository passing no timeout, these among them, while FG33's recorded
    # guard is "bound every child run". An unbounded child cannot time out; it
    # hangs, and a hung run yields no verdict in either direction.
    subprocess.run(["git", "init", "-q"], cwd=tree, check=True,  # noqa: S603
                   capture_output=True, timeout=600)
    subprocess.run(["git", "add", "-A"], cwd=tree, check=True,  # noqa: S603
                   capture_output=True, timeout=600)
    subprocess.run(  # noqa: S603
        ["git", "-c", "user.email=harness@example.invalid", "-c", "user.name=harness",
         "commit", "-q", "-m", "mutation workspace"],
        cwd=tree, check=True, capture_output=True, timeout=600,
    )
    return tree


def isolated_env(tree: Path) -> dict:
    """PYTHONPATH ahead of the editable .pth, so the mutant is what loads."""
    import os  # noqa: PLC0415

    return {**os.environ, "PYTHONPATH": str(tree / "src")}


def run_node(tree: Path, node: str, *, timeout: int = 1800, report: Path | None = None):
    command = [sys.executable, "-m", "pytest", node, "-p", "no:cacheprovider",
               "-q", "-p", "no:warnings", "--tb=line"]
    if report is not None:
        command += ["--junit-xml", str(report)]
    return subprocess.run(  # noqa: S603
        command,
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=isolated_env(tree), timeout=timeout,
    )


def require_caused_failure(
    report: Path, node: str, output: str, *, expected_property: str = ""
) -> None:
    """Step 5. The EXACT named node must have failed, in the call phase, for
    the intended property.

    Four distinct questions, and the old implementation answered only the
    weakest of them by summing `<failure>` across the whole report:

        did the named node run at all        -> INVALID_TEST_TARGET
        did it error rather than fail        -> INVALID_MUTATION
        is the evidence ambiguous            -> INVALID_MUTATION_ENVIRONMENT
        did it fail for the intended reason  -> INVALID_MUTATION

    "Same node failed" is still weaker than "same node failed BECAUSE the
    intended security assertion was violated", which is why
    `expected_property` exists. H05 is the worked example: the contradiction
    between "the mutation kills" and "the recorded control is not decisive" was
    resolved only by reading WHICH assertion failed.

    `returncode != 0` does not distinguish "the assertion this control is proven
    by did not hold" from "the mutant no longer imports". Lens B re-aimed H06 at
    an unrelated rename and collected a kill on an ImportError -- the control was
    never reached, never mind removed.

    Read from the JUnit report rather than the summary prose, because `<failure>`
    and `<error>` are different elements and "1 failed" and "1 error" are the
    same shape of sentence.
    """
    if not report.is_file():
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION_ENVIRONMENT,
            f"pytest produced no report for {node}, so the run cannot be "
            f"classified:\n{output[-400:]}",
        )
    root = ElementTree.parse(report).getroot()

    # THE EXACT NODE, not the report. Summing failures across every testcase
    # meant the named proof could PASS while an unrelated one broke, and the
    # campaign recorded the control as removed. `node` was accepted as an
    # argument and used only in messages.
    module, _, name = node.partition("::")
    stem = module.removesuffix(".py").replace("/", ".").replace("\\", ".")
    module_stem = stem.rsplit(".", 1)[-1]
    # A COLLECTION ERROR is written against the MODULE, not the node: pytest
    # emits classname='' and name='<module>' with an <error> child, because the
    # node never came into existence to be named. Measured, not assumed --
    # matching only on node name reported that as "no result for this node",
    # which is true but loses the more useful fact that the mutant did not
    # import.
    collection_errors = [
        case for case in root.iter("testcase")
        if (case.get("name") or "") == module_stem and list(case.iter("error"))
    ]
    matched = collection_errors + [
        case for case in root.iter("testcase")
        # pytest writes the parametrised id as `name[param]`, and the classname
        # carries the module path. Matching the stem keeps parametrised cases
        # attributable to the node that owns them.
        if (case.get("name") or "").split("[")[0] == name
        and (case.get("classname") or "").endswith(stem.rsplit(".", 1)[-1])
    ]
    if not matched:
        present = sorted({
            f"{c.get('classname')}::{c.get('name')}" for c in root.iter("testcase")
        })
        raise AttackNotAdmissible(
            Outcome.INVALID_TEST_TARGET,
            f"the report contains no result for {node}. Whatever else ran, this "
            f"proof did not, so nothing can be credited to it. Present: "
            f"{present[:6]}",
        )

    failures = [f for case in matched for f in case.iter("failure")]
    errors = [e for case in matched for e in case.iter("error")]

    # A PARAMETRISED NODE IS A FAMILY, and matching on the stem aggregates all
    # of it. A review measured H07 under its mutant as 25 cases, 8 failed and
    # 17 PASSED -- so the control was only partly removed, while the report
    # said flatly that the node failed. The verdict no longer rests on this
    # (the attack's executable property criterion decides), but the split must
    # be visible rather than collapsed, because 'the node failed' and 'a third
    # of its parameters failed' are different facts.
    family = [case for case in matched if case not in collection_errors]
    failed_cases = [c for c in family if list(c.iter("failure")) or list(c.iter("error"))]
    partial = len(family) > 1 and 0 < len(failed_cases) < len(family)
    breakdown = (
        f" [parametrised family: {len(failed_cases)} of {len(family)} cases"
        f" failed]" if partial else ""
    )

    if errors and failures:
        # AMBIGUOUS. "There exists a failure for this node" is the aggregate
        # shortcut one level down: with an error alongside it, the run cannot
        # show that the intended call-phase assertion is what decided the
        # outcome.
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION_ENVIRONMENT,
            f"{node}{breakdown} reported BOTH a failure and an error, so which one decided "
            "the result cannot be established. A kill needs the call-phase "
            "assertion to be the reason, not one of two candidate reasons.",
        )
    if errors:
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION,
            f"{node}{breakdown} ERRORED under the mutant rather than failing. Setup, "
            "teardown and collection failures mean the control was never "
            f"reached, so nothing was proven about it:\n{output[-400:]}",
        )
    if not failures:
        raise AttackNotAdmissible(
            Outcome.SURVIVED,
            f"{node}{breakdown} reported no failing assertion under the mutant.",
        )

    if expected_property:
        # THE INTENDED PROPERTY, not merely a failure. Correct node, wrong
        # reason is still a false kill: the node can fail in the call phase,
        # with a genuine assertion, about something the attack never touched.
        # This is what stops `<failure>` becoming the next label standing in for
        # semantics.
        evidence = " ".join(
            (f.get("message") or "") + " " + (f.text or "") for f in failures
        )
        # SUBSTRING, AND THAT IS A STATED BOUND RATHER THAN ATTRIBUTION.
        # Asking whether the failure text CONTAINS a phrase is the same shape
        # this repository refuses elsewhere: a renamed assertion message
        # changes the answer while the property is untouched. It is kept
        # because it is strictly better than nothing at the one place it runs,
        # and it is honest about what it is.
        #
        # It also runs NOWHERE IN THE CAMPAIGN. `grep` for callers passing
        # `expected_property` returns only `tests/test_failure_attribution.py`;
        # the historical re-proof runner does not pass it. So FG19's owner
        # exercises a path the campaign does not take -- already recorded at
        # `test_historical_reproof.py`'s note on FG19, and repeated here so a
        # reader of THIS function is not left believing the campaign attributes
        # failures this way.
        if expected_property.lower() not in evidence.lower():
            raise AttackNotAdmissible(
                Outcome.INVALID_MUTATION,
                f"{node}{breakdown} failed, but not attributable to the intended property. "
                f"Expected the failure to concern {expected_property!r}; the "
                f"assertion was: {evidence.strip()[:220]}",
            )


def require_node_exists(tree: Path, node: str) -> None:
    """Step 1. A deleted or renamed proof must not be mistaken for a failure.

    `pytest module::missing_node` exits 4 and prints `ERROR: not found:`, which
    contains neither "no tests ran" nor "INTERNALERROR" -- so the previous
    stdout-substring guard did not fire, and a class could report KILLED with
    its only proof deleted and the control fully intact.

    Collection is asked directly, and the exit code is read rather than the
    prose: pytest uses 4 for usage/collection errors and 5 for "no tests
    collected".
    """
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", node, "--collect-only", "-q",
         "-p", "no:cacheprovider", "-p", "no:warnings"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=isolated_env(tree), timeout=600,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode in (4, 5) or "not found" in output or "no tests ran" in output:
        raise AttackNotAdmissible(
            Outcome.INVALID_TEST_TARGET,
            f"{node} does not collect, so nothing can be killed by it:\n"
            f"{output[-400:]}",
        )
    if completed.returncode != 0:
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION_ENVIRONMENT,
            f"collection of {node} errored:\n{output[-400:]}",
        )


def require_pristine_baseline(tree: Path, node: str) -> None:
    """Step 2. The proof must work when nothing is broken.

    THE MISSING STEP. Without it, `returncode != 0` credits a kill for a
    workspace defect, a missing fixture file, or an unrelated import error --
    and it did, three times.
    """
    completed = run_node(tree, node)
    if completed.returncode != 0:
        raise AttackNotAdmissible(
            Outcome.INVALID_BASELINE,
            f"{node} FAILS before any mutation is applied, so its result says "
            "nothing about the control:\n"
            f"{(completed.stdout + completed.stderr)[-600:]}",
        )


def require_mutant_origin(tree: Path, modules: tuple[str, ...]) -> None:
    """Step 4. Origin is read from the loaded module, never grepped.

    A text search for `sys.path.insert(0` matches an unrelated line; only asking
    the interpreter where a module actually came from proves anything.
    """
    probe = ";".join(
        [f"import {name} as _m{i}" for i, name in enumerate(modules)]
        + [f"print(_m{i}.__file__)" for i in range(len(modules))]
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=isolated_env(tree), timeout=600,
    )
    if completed.returncode != 0:
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION_ENVIRONMENT,
            f"the origin probe could not import: {completed.stderr[-400:]}",
        )
    resolved = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    # Compared as PATHS, not as strings. Windows hands back the same directory
    # as both `C:\Users\MAZIN~1.LAP\...` and `C:\Users\mazin.LAPTOP-...\...`, so
    # a substring test reports a correctly isolated workspace as an escape --
    # measured while investigating B-P2-5, where it did exactly that. Getting
    # this wrong is not conservative: it turns admissible attacks into
    # environment errors and would push someone to relax the check.
    root = tree.resolve()
    escaped = [
        path for path in resolved if root not in Path(path).resolve().parents
    ]
    if not resolved or escaped:
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION_ENVIRONMENT,
            f"production modules resolved outside the mutant workspace: {escaped}",
        )


#: Raised by the probe below, and searched for in the run's output.
CLAUSE_MARKER = "NORNYX_CLAUSE_REACHED"


def require_baseline_clause_reached(
    tree: Path, node: str, relative: str, anchor: str, *, timeout: int = 1800
) -> None:
    """Step 3. The pristine test must EXECUTE the clause the attack targets.

    THE STEP H14 SHOWED WAS MISSING. `require_pristine_baseline` proves the
    named test passes; it says nothing about whether the test ever reaches the
    control being removed. H14 removed the discard of unauthenticated
    attestations and its named test kept passing -- because that test runs with
    no reviewer trust store, so the function returns at an earlier guard and the
    discard is never executed. A passing baseline and an unreachable clause look
    identical, and the difference is the whole result.

    Machine-verified rather than argued. A probe raise is inserted at the clause
    and the named test is re-run: if the clause executes, the test fails carrying
    the marker; if it passes, the clause was never reached and no conclusion
    about removing it is admissible.

    The probe is applied to a THROWAWAY copy of the file and reverted, so the
    baseline the attack then measures is byte-identical to pristine.
    """
    target = tree / relative
    original = target.read_bytes()
    before = original.decode("utf-8")
    if before.count(anchor) != 1:
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION,
            f"the clause probe needs exactly one occurrence of the anchor in "
            f"{relative}; found {before.count(anchor)}",
        )

    # A NONCE PER INVOCATION. A fixed marker can be matched against stale
    # output, a cached report, or -- as actually happened -- a source line
    # echoed by a traceback. Only this run's token counts.
    import uuid  # noqa: PLC0415

    token = f"{CLAUSE_MARKER}-{uuid.uuid4().hex[:12]}"
    stripped = anchor.lstrip("\n")
    indent = stripped[: len(stripped) - len(stripped.lstrip())]
    # A SIDE-CHANNEL SENTINEL, not only a raise.
    #
    # Reading the marker out of pytest's output makes reachability depend on the
    # named test's own diagnostic formatting. H07 proved that concretely: its
    # branch body DOES execute -- sentinel written, `RuntimeError: <nonce>` on
    # the child's stderr -- but that test asserts `returncode == 2` first and
    # prints `completed.stdout`, so the marker was never shown and the probe
    # reported the attack inadmissible for a reason that was not true.
    #
    # The sentinel is independent of which stream anything lands on, of which
    # assertion fires first, and of any `except` between the clause and the top:
    # a swallowed exception still leaves the file behind. Written only inside
    # the disposable workspace, never by production code.
    sentinel = tree / ".clause-probe-reached"
    sentinel.unlink(missing_ok=True)
    probe = (
        f'{indent}__import__("pathlib").Path(r"{sentinel}").write_text("{token}")\n'
        f'{indent}raise RuntimeError("{token}")\n{anchor}'
    )
    try:
        target.write_text(before.replace(anchor, probe, 1), encoding="utf-8", newline="")
        # THE PROBE MUST PRODUCE RUNNABLE CODE. Planted inside an import's
        # parentheses it does not, and the SyntaxError then fails the test for a
        # reason unrelated to the clause -- while `--tb=long` echoes the
        # offending SOURCE LINE, marker and all, into the output. Measured: this
        # reported CLAUSE REACHED for a file that would not compile. A probe
        # that cannot run cannot report reachability.
        try:
            compile(target.read_text(encoding="utf-8"), str(target), "exec")
        except SyntaxError as exc:
            raise AttackNotAdmissible(
                Outcome.INVALID_MUTATION_ENVIRONMENT,
                f"the clause probe made {relative} unparseable ({exc}), so this "
                "anchor is not a statement boundary and reachability cannot be "
                "measured from it",
            ) from exc
        # `--tb=long`, not the usual `--tb=line`. The marker travels inside the
        # failure message, and a test that asserts on a SUBPROCESS's output
        # carries the whole traceback as its assertion text -- which `--tb=line`
        # truncates to one line, hiding exactly the evidence this step needs.
        # Measured: the clause ran, the test failed, and the marker was invisible.
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", node, "-p", "no:cacheprovider",
             "-q", "-p", "no:warnings", "--tb=long"],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=isolated_env(tree), timeout=timeout,
        )
    finally:
        target.write_bytes(original)
    assert target.read_bytes() == original, "the clause probe was not reverted"
    # Read and remove before judging, so the workspace is left as found whatever
    # the verdict is.
    sentinel_present = sentinel.is_file()
    sentinel_token = sentinel.read_text(encoding="utf-8") if sentinel_present else ""
    sentinel.unlink(missing_ok=True)

    output = completed.stdout + completed.stderr
    if completed.returncode == 0:
        raise AttackNotAdmissible(
            Outcome.INVALID_TEST_AIM,
            f"{node} PASSES with a raise planted at {relative}'s clause, so it "
            "never executes the control this attack removes. A conclusion drawn "
            "from removing it would be about a clause the test does not reach.",
        )
    # The marker must appear as a RAISED EXCEPTION, not as echoed source. With
    # `--tb=long` pytest prints the offending source line, so searching for the
    # bare marker finds it whether or not that line ever executed -- which is
    # how this reported a reached clause inside a file that did not compile.
    # PROVENANCE, not a substring. Three independent things must agree: the
    # exception was RAISED (`RuntimeError: <token>`), it carries THIS run's
    # nonce, and the traceback names the file the probe was planted in. Matching
    # the bare marker found it in echoed source for a file that never ran, and
    # a fixed marker would also match stale output from an earlier probe.
    # The sentinel is AUTHORITATIVE; the raised marker is corroboration. Either
    # suffices, and requiring both would reinstate the dependency on the
    # harness's formatting that the sentinel exists to remove.
    reached = sentinel_present and sentinel_token == token
    raised = f"RuntimeError: {token}"
    named_file = Path(relative).name
    corroborated = raised in output and named_file in output
    if not reached and not corroborated:
        # The clause may well have run; what failed is the harness's ability to
        # SEE that it did. Reporting this as a test-aim problem would blame the
        # attack for an instrumentation gap.
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION_ENVIRONMENT,
            f"{node} failed under the clause probe but not because the clause "
            f"ran -- the marker is absent:\n{output[-400:]}",
        )


#: Directories whose contents may be the SEMANTIC TARGET of a security mutation.
#: Production and governed source only. A campaign that mutates its own proofs
#: proves nothing about the system it claims to defend.
PRODUCTION_MUTATION_ROOTS = ("src", "scripts", ".nornyx")


def require_production_mutation_scope(relative: str) -> None:
    """Step 3. The mutation must target production or governed source.

    NOTHING CONSTRAINED THIS. `SecurityClass.mutation[0]` was an arbitrary
    relative path and `check_mutation` dispatched on file extension alone, so an
    attack could be "proved" by mutating the test that judges it: insert
    `@pytest.mark.xfail(strict=True)` above the named node, and with
    `xfail_strict` on the run reports `<failure>` and the protocol credits
    KILLED_VALIDLY -- while the control it claims to have removed is
    byte-identical to pristine.

    Decided on a CANONICAL RESOLVED path, not a string prefix. `./tests/x.py`,
    `tests/../tests/x.py` and `src/../tests/x.py` all name the same file and
    none of them starts with `tests/`, so a prefix test answers a question about
    spelling rather than about which file is being changed.
    """
    candidate = PurePosixPath(Path(relative).as_posix())
    if candidate.is_absolute() or ".." in candidate.parts:
        # Normalise before judging, so the decision is about the file.
        candidate = PurePosixPath(os.path.normpath(str(candidate)).replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION,
            f"the mutation target {relative!r} escapes the repository, so which "
            "file it names cannot be decided",
        )
    root = candidate.parts[0] if candidate.parts else ""
    if root not in PRODUCTION_MUTATION_ROOTS:
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION,
            f"the mutation targets {candidate}, which is not production or "
            f"governed source ({', '.join(PRODUCTION_MUTATION_ROOTS)}). A "
            "campaign that mutates its own proofs proves nothing about the "
            "system: a kill would be credited with the control untouched.",
        )


def require_exact_node(node: str) -> None:
    """The attack must name ONE pytest node, never a module.

    H10 named `tests/test_approval_ledger.py` -- 38 collected tests -- so any
    one of them failing credited its kill, and nothing in the accounting could
    say which. `require_caused_failure` sums failures across the whole report,
    so a module target means "something in here broke" is recorded as "this
    control was removed".

    Shape only. That the node EXISTS is `require_node_exists`, and that the
    failure belongs to it is `require_caused_failure`; this refuses a target
    that could never be attributed in the first place.
    """
    module, separator, name = node.partition("::")
    if not separator or not name.strip():
        raise AttackNotAdmissible(
            Outcome.INVALID_TEST_TARGET,
            f"the attack names {node!r}, which is a module rather than one "
            "pytest node. A kill credited against a whole module says only that "
            "something in it failed, and nothing can say which control that was.",
        )
    if "::" in name:
        raise AttackNotAdmissible(
            Outcome.INVALID_TEST_TARGET,
            f"the attack names {node!r}, which addresses more than one level. "
            "Exactly one node, so the failure has exactly one owner.",
        )
    if not module.endswith(".py"):
        raise AttackNotAdmissible(
            Outcome.INVALID_TEST_TARGET,
            f"the attack names {node!r}, whose module part is not a Python file",
        )
