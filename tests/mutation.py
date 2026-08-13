"""Run the real authorities against a MUTATED copy of the source tree.

A control is load-bearing only if changing it changes what the system does.
Nothing else establishes that: a test can assert a refusal that some unrelated
clause was producing all along, and this repository has shipped exactly that --
a matrix where every case refused for a mis-signed fixture while appearing to
measure authority.

The copy is mutated on disk and driven in a SUBPROCESS. Monkeypatching cannot
answer the question being asked, which is what a change to the source would do,
not what a replaced function returns.

STRICT KILL CRITERIA, enforced here rather than left to the reader:

    the mutation must actually apply     -- exact occurrence count, or refuse
    the mutant must RUN TO COMPLETION    -- exit 0 and valid JSON
    the observable must change           -- and in the direction named

No credit is available for a syntax error, an import failure, or a refusal that
some other clause produced. Those are the ways a mutation catalogue reports
green while proving nothing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Copied wholesale so imports inside the mutant resolve to the mutant. A
#: partial copy leaves `sys.path` entries pointing back at the pristine tree,
#: which is how a mutation harness silently measures the original.
#: `scripts` is here because tests/signing.py imports the ISSUER from it --
#: the signing utility deliberately kept outside the runtime package.
_TREES = ("src", "tests", "scripts")


@dataclass(frozen=True)
class Mutation:
    """One named change to the source, and what it must do to be killed."""

    name: str
    #: (relative path, exact text to replace, replacement, expected occurrences)
    edits: tuple[tuple[str, str, str, int], ...]
    scenario: str
    #: The probe field that must change, and its value under the mutant.
    observable: str
    expected: object
    why: str
    flags: tuple[str, ...] = ()
    #: Additional fields that must hold under the mutant, e.g. the effect ran.
    also: dict = field(default_factory=dict)


def _materialize(destination: Path) -> Path:
    tree = destination / "tree"
    tree.mkdir(parents=True, exist_ok=True)
    for name in _TREES:
        shutil.copytree(
            ROOT / name,
            tree / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    return tree


def apply_edits(tree: Path, edits) -> None:
    """Apply every edit, refusing when one did not match what it expected.

    A mutation that silently fails to apply produces a mutant identical to the
    original, which then "survives" -- and a survivor is read as a missing test.
    The count is asserted so a renamed line cannot quietly turn this catalogue
    into a list of no-ops.
    """
    for relative, old, new, occurrences in edits:
        target = tree / relative
        source = target.read_text(encoding="utf-8")
        found = source.count(old)
        if found != occurrences:
            raise AssertionError(
                f"mutation anchor did not match in {relative}: expected "
                f"{occurrences} occurrence(s) of {old.strip()[:70]!r}, found {found}. "
                "The mutation did not apply, so any result would be the "
                "unmutated behaviour wearing a mutant's name."
            )
        target.write_text(source.replace(old, new), encoding="utf-8", newline="")


def probe(destination: Path, scenario: str, *, edits=(), flags=()) -> dict:
    """Measure one build -- pristine when `edits` is empty -- and return its report."""
    tree = _materialize(destination)
    apply_edits(tree, edits)
    work = destination / "work"
    work.mkdir(parents=True, exist_ok=True)

    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(tree / "tests" / "authority_probe.py"),
            str(work),
            scenario,
            *flags,
        ],
        capture_output=True,
        text=True,
        cwd=str(tree),
        timeout=300,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "the build did not run to completion, so nothing was measured. A "
            "syntax or import failure is not a killed mutation:\n"
            + (completed.stderr or "")[-1500:]
        )
    for line in reversed(completed.stdout.strip().splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    raise AssertionError(f"the probe emitted no report:\n{completed.stdout[-1500:]}")
