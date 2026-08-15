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
    3  the mutation applies to an executable node    INVALID_MUTATION
    4  the mutant is what loads                      INVALID_MUTATION_ENVIRONMENT
    5  the intended semantic effect is present       INVALID_MUTATION
    6  the SAME node runs, and fails                 KILLED_VALIDLY

Step 2 is the one that was missing, and it is the one that matters: an attack
cannot be classified until its proof is shown to work when nothing is broken.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from enum import Enum
from pathlib import Path

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


class AttackNotAdmissible(AssertionError):
    """The attempt never reached the property, so it is not a result.

    Carries the outcome so a catalogue can count it in the right column instead
    of folding every failure into "not killed".
    """

    def __init__(self, outcome: Outcome, message: str) -> None:
        super().__init__(f"{outcome.value} -- {message}")
        self.outcome = outcome


def tracked_files() -> list[str]:
    """Everything git tracks, which is what a clean checkout would contain."""
    completed = subprocess.run(  # noqa: S603
        ["git", "ls-files", "-z"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
    )
    return [name for name in completed.stdout.split("\0") if name]


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

    subprocess.run(["git", "init", "-q"], cwd=tree, check=True, capture_output=True)  # noqa: S603
    subprocess.run(["git", "add", "-A"], cwd=tree, check=True, capture_output=True)  # noqa: S603
    subprocess.run(  # noqa: S603
        ["git", "-c", "user.email=harness@example.invalid", "-c", "user.name=harness",
         "commit", "-q", "-m", "mutation workspace"],
        cwd=tree, check=True, capture_output=True,
    )
    return tree


def isolated_env(tree: Path) -> dict:
    """PYTHONPATH ahead of the editable .pth, so the mutant is what loads."""
    import os  # noqa: PLC0415

    return {**os.environ, "PYTHONPATH": str(tree / "src")}


def run_node(tree: Path, node: str, *, timeout: int = 1800):
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", node, "-p", "no:cacheprovider",
         "-q", "-p", "no:warnings", "--tb=line"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=isolated_env(tree), timeout=timeout,
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
    escaped = [path for path in resolved if str(tree) not in path]
    if not resolved or escaped:
        raise AttackNotAdmissible(
            Outcome.INVALID_MUTATION_ENVIRONMENT,
            f"production modules resolved outside the mutant workspace: {escaped}",
        )
