"""Run the suite and refuse to pass over tests that silently did not run.

A green CI run reported success while executing 139 of 202 tests. `nornyx` lived
only in the `demo` extra and the test job installed `[dev]`, so every
`@needs_nornyx` test skipped — the approval wiring, injection, materialization,
expiry and pre-approval-baseline controls were asserted by nothing, and the job
that was supposed to be guarding them said `success`.

Installing the extra fixes today's instance. This script fixes the class: a skip
is only acceptable if it was declared in advance, and anything else fails the
run. A test that does not execute proves nothing, and the failure mode is silent
by construction — pytest reports skips as a number nobody reads.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Skips that are a deliberate part of the design, keyed by the test allowed to
#: skip and carrying the reason it is allowed.
#:
#: Keyed by identity, not by message. This matched a substring of the skip text,
#: so any new test whose reason happened to contain one of these phrases was
#: exempted without anyone deciding it should be. That is not hypothetical: two
#: tests in this repository were written borrowing `set FORGE_DOCKER_TESTS=1` —
#: one for a POSIX-only fixture, one for a Docker-daemon fixture — and the census
#: counted both as expected and said nothing. Under identity keying, borrowing a
#: reason string buys nothing, because the exemption names the test.
EXPECTED_SKIPS = {
    # Symlink and FIFO fixtures cannot be built on a Windows workstation without
    # elevation. The property is not weakened: every CI test job runs Linux and
    # executes these, and test_the_refusals_are_reachable_on_every_platform
    # asserts the refusals still exist in the observer, so a deletion cannot hide
    # behind this exemption.
    "tests/test_special_files.py::test_a_symlink_under_a_governed_root_is_refused":
        "Symlink, FIFO and device-node fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these, and test_the_refusals_are_reachable_on_every_platform asserts the refusals still exist in the observer, so deleting one cannot hide here.",
    "tests/test_special_files.py::test_a_symlink_pointing_outside_the_tree_is_refused":
        "Symlink, FIFO and device-node fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these, and test_the_refusals_are_reachable_on_every_platform asserts the refusals still exist in the observer, so deleting one cannot hide here.",
    "tests/test_special_files.py::test_a_fifo_under_a_governed_root_is_refused":
        "Symlink, FIFO and device-node fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these, and test_the_refusals_are_reachable_on_every_platform asserts the refusals still exist in the observer, so deleting one cannot hide here.",
    "tests/test_special_files.py::test_a_device_node_is_refused_if_one_can_be_referenced":
        "Symlink, FIFO and device-node fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these, and test_the_refusals_are_reachable_on_every_platform asserts the refusals still exist in the observer, so deleting one cannot hide here.",
    # The in-image subject proof needs a live Docker daemon, which a workstation
    # may not have. Not optional: the container-launch job runs these with its
    # own skip census, so a skip there fails that job rather than passing
    # quietly.
    "tests/test_runtime_image_subject.py::test_the_built_image_establishes_its_own_subject":
        "The in-image subject proof needs a live Docker daemon, which a workstation may not have. Not optional: the container-launch job runs these with its own skip census, so a skip there fails that job rather than passing quietly.",
    "tests/test_runtime_image_subject.py::test_the_image_needs_no_git_to_know_what_it_is":
        "The in-image subject proof needs a live Docker daemon, which a workstation may not have. Not optional: the container-launch job runs these with its own skip census, so a skip there fails that job rather than passing quietly.",
    "tests/test_runtime_image_subject.py::test_the_packaged_subject_is_not_assumed_equal_to_the_repository_subject":
        "The in-image subject proof needs a live Docker daemon, which a workstation may not have. Not optional: the container-launch job runs these with its own skip census, so a skip there fails that job rather than passing quietly.",
    "tests/test_runtime_image_subject.py::test_a_missing_required_contract_in_the_image_refuses":
        "The in-image subject proof needs a live Docker daemon, which a workstation may not have. Not optional: the container-launch job runs these with its own skip census, so a skip there fails that job rather than passing quietly.",
    # The live container build downloads packages, which BRD-004 forbids for the
    # default offline run. CI exercises it in the container-launch job.
    "tests/test_container_launch.py::test_compose_up_build_starts_the_application":
        "The live container build downloads packages, which BRD-004 forbids for the default offline run. CI exercises it in the container-launch job instead, so it is covered — just not here.",
}


#: The suite must not quietly get smaller. A collection error, a renamed
#: directory or a deleted file all reduce the count without failing anything —
#: which is how 63 tests once sat behind a green run. Raise this as the suite
#: grows; lowering it is a decision someone has to make on purpose, in a diff.
NEWLINE = chr(10)

MINIMUM_COLLECTED = 440

#: Modules whose absence is a governance regression, not a smaller suite. Each
#: holds the proof of an invariant that was reached through a reproduced exploit,
#: so a report that does not mention one means the proof is gone. A floor alone
#: would not catch this: deleting one file and adding tests elsewhere keeps the
#: total up while the invariant goes unproven.
REQUIRED_MODULES = (
    "tests/test_approval_authentication.py",
    "tests/test_approval_ledger.py",
    "tests/test_reviewer_authentication.py",
    "tests/test_independent_inspection.py",
    "tests/test_trust_directionality.py",
    "tests/test_content_binding.py",
    "tests/test_subject_scope.py",
    "tests/test_security_context.py",
    "tests/test_evaluation_time.py",
    "tests/test_execution_semantics.py",
    "tests/test_skip_gate.py",
    "tests/test_documented_claims.py",
    "tests/test_process_execution_spellings.py",
    "tests/test_approval_artifact_authentication.py",
    "tests/test_governance_approval_verifier.py",
    "tests/test_process_capability.py",
    "tests/test_dockerfile_surface.py",
)


def node_id(case) -> str:
    """The junit testcase as a pytest nodeid, parametrisation stripped.

    `classname` is dotted and `name` may carry a `[param]` suffix. An exemption
    covers a test, not one of its parameter sets: a parametrised case that skips
    for a declared environmental reason skips for every parameter, and listing
    each one would mean adding a new parameter silently loses its exemption.
    """
    classname = (case.get("classname") or "").replace(".", "/")
    name = (case.get("name") or "").split("[", 1)[0]
    return f"{classname}.py::{name}" if classname else name


def classify(report: Path) -> tuple[int, int, list[str], set[str]]:
    """Split a junit report into (total, expected skips, unexpected skips).

    Separated from the run so the gate itself is testable: a guard whose failure
    path has never executed is a guess about what it would do.
    """

    root = ET.parse(report).getroot()
    unexpected: list[str] = []
    seen_modules: set[str] = set()
    allowed = 0
    total = 0
    for case in root.iter("testcase"):
        total += 1
        seen_modules.add(node_id(case).split("::", 1)[0])
        skipped = case.find("skipped")
        if skipped is None:
            continue
        message = (skipped.get("message") or "") + (skipped.text or "")
        if node_id(case) in EXPECTED_SKIPS:
            allowed += 1
            continue
        unexpected.append(f"{node_id(case)} — {message.strip()}")
    return total, allowed, unexpected, seen_modules


def evaluate(report: Path, pytest_returncode: int) -> int:
    """Decide the verdict from a report. Separated so the refusals are testable.

    `main()` used to hold this inline, so the three paths that make this gate a
    gate -- missing required module, collection below floor, GATE: FAIL -- had
    never once executed under test. The module docstring already said a guard
    whose failure path has never run is a guess about what it would do; only
    `classify` had been separated far enough to act on that.
    """
    total, allowed, unexpected, seen_modules = classify(report)

    print(f"collected {total}, expected skips {allowed}, unexpected skips {len(unexpected)}")

    if unexpected:
        print(NEWLINE + "These tests did not run, and were not declared as expected skips:" + NEWLINE)
        for entry in unexpected:
            print(f"  {entry}")
        print(
            NEWLINE + "A skipped test asserts nothing. Either install what it "
            "needs, or add the test to EXPECTED_SKIPS with why it is acceptable. "
            "Naming a reason another test already uses no longer exempts "
            "anything."
        )
        print(NEWLINE + "GATE: FAIL - undeclared skips")
        return 2

    missing_modules = [name for name in REQUIRED_MODULES if name not in seen_modules]
    if missing_modules:
        print(NEWLINE + "These modules contributed no tests to the report:" + NEWLINE)
        for name in missing_modules:
            print(f"  {name}")
        print(
            NEWLINE + "Each proves an invariant reached through a reproduced "
            "exploit. A report that never mentions one means that proof is "
            "gone, however many tests ran elsewhere."
        )
        print(NEWLINE + "GATE: FAIL - a required test module is missing")
        return 2

    if total < MINIMUM_COLLECTED:
        print(
            NEWLINE + f"collected {total}, below the floor of "
            f"{MINIMUM_COLLECTED}. A suite that silently shrinks looks "
            "exactly like a suite that passes. If tests were removed on "
            "purpose, lower the floor in the same diff and say why."
        )
        print(NEWLINE + "GATE: FAIL - collection below floor")
        return 2

    # The last line must state the verdict. The skip census above reads like
    # success whatever pytest concluded, and a truncated or filtered view of
    # this output was taken for a passing suite while tests were failing.
    if pytest_returncode != 0:
        print(NEWLINE + f"GATE: FAIL - pytest exited {pytest_returncode}; see failures above")
    else:
        print(NEWLINE + "GATE: PASS")
    return pytest_returncode


def main() -> int:
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / "report.xml"
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", f"--junitxml={report}"],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if not report.exists():
            print("pytest produced no report; treating as failure")
            return completed.returncode or 1

        # One implementation of the verdict, exercised by tests. Keeping a copy
        # here would mean the tested path and the run path could disagree, which
        # is the defect this whole gate exists to notice.
        return evaluate(report, completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
