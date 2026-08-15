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
from collections import Counter
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


#: Tests allowed to be expected failures, keyed by identity. INTENTIONALLY
#: EMPTY: a security proof that is expected to fail is a proof that is off,
#: and the honest response is to fix it or delete it rather than to record
#: that it does not work. An entry here needs a reason a reviewer can check.
EXPECTED_XFAILS: dict[str, str] = {}


#: The suite must not quietly get smaller. A collection error, a renamed
#: directory or a deleted file all reduce the count without failing anything —
#: which is how 63 tests once sat behind a green run. Raise this as the suite
#: grows; lowering it is a decision someone has to make on purpose, in a diff.
NEWLINE = chr(10)

#: Raised from 440 against a suite of 645. That floor left 200 tests of slack:
#: ten whole modules -- including the untrusted-text vocabulary, the dirty-tree
#: gate, action binding and mission binding -- could be deleted with this gate
#: still printing PASS. A floor that permits a third of the suite to vanish is
#: not an anti-shrink control.
#:
#: Kept just below the real count rather than equal to it, so ordinary
#: consolidation does not fail the gate while a deletion of any consequence
#: does. It is meant to be raised when the suite grows.
#: The smallest number of tests each required module may contribute.
#:
#: REQUIRED_MODULES asks whether a module is PRESENT. Lens B deleted 43 tests
#: across six modules -- including the dirty-tree gate this floor was raised for
#: -- and the run landed exactly on the aggregate floor with every module still
#: technically present, because other modules had grown. Presence is not
#: coverage, and an aggregate cannot see which proofs went.
#:
#: Each entry is roughly 90% of what the module contributed when it was written:
#: a NO-SILENT-SHRINK bound, not a target. Ordinary consolidation passes;
#: removing a third of a security module does not, and lowering the number has
#: to happen in the diff where it can be argued with.
REQUIRED_MODULE_MINIMUMS: dict[str, int] = {
    "tests/test_approval_authentication.py": 34,
    "tests/test_approval_ledger.py": 38,
    "tests/test_reviewer_authentication.py": 23,
    "tests/test_independent_inspection.py": 14,
    "tests/test_trust_directionality.py": 8,
    "tests/test_content_binding.py": 19,
    "tests/test_subject_scope.py": 13,
    "tests/test_security_context.py": 10,
    "tests/test_evaluation_time.py": 12,
    "tests/test_execution_semantics.py": 10,
    "tests/test_skip_gate.py": 14,
    "tests/test_documented_claims.py": 6,
    "tests/test_process_execution_spellings.py": 22,
    "tests/test_approval_artifact_authentication.py": 8,
    "tests/test_governance_approval_verifier.py": 36,
    "tests/test_process_capability.py": 52,
    "tests/test_evidence_integrity_verifier.py": 8,
    "tests/test_dockerfile_surface.py": 16,
    "tests/test_authority_domains.py": 16,
    "tests/test_domain_immutability.py": 8,
    "tests/test_domain_collapse_mutations.py": 18,
    "tests/test_execution_mode_truth.py": 7,
    "tests/test_architecture_vocabulary.py": 9,
    "tests/test_inspection_subject_matrix.py": 4,
    "tests/test_subject_layer_matrix.py": 15,
    "tests/test_semantic_projection_exclusions.py": 15,
    "tests/test_task8_closure.py": 8,
    "tests/test_semantic_binding_theorem.py": 23,
    "tests/test_production_security_context.py": 13,
    "tests/test_canonical_text_writes.py": 7,
    "tests/test_approval_wiring.py": 7,
    "tests/test_approval_injection.py": 11,
    "tests/test_materialization_injection.py": 18,
    "tests/test_expiry_semantics.py": 7,
    "tests/test_pre_approval_baseline.py": 5,
    "tests/test_action_binding.py": 29,
    "tests/test_untrusted_text.py": 41,
    "tests/test_subject_completeness.py": 9,
    "tests/test_governance_integrity_authority.py": 11,
    "tests/test_artifact_authority.py": 16,
    "tests/test_collection_completeness.py": 9,
    "tests/test_absence_is_not_success.py": 6,
    "tests/test_trust_snapshot.py": 16,
    "tests/test_historical_reproof.py": 19,
    "tests/test_mutation_catalogue.py": 24,
    "tests/test_false_green_audit.py": 12,
    "tests/test_xfail_strictness.py": 9,
}

MINIMUM_COLLECTED = 945

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
    "tests/test_evidence_integrity_verifier.py",
    "tests/test_dockerfile_surface.py",
    # The two approval authorities are independently provisioned. Deleting
    # either of these leaves the split in place and the proof of it gone.
    "tests/test_authority_domains.py",
    "tests/test_domain_immutability.py",
    "tests/test_domain_collapse_mutations.py",
    # What each execution mode DOES, and every policy control name held to
    # a decision point. Both exist because a document outlived the thing it
    # described.
    "tests/test_execution_mode_truth.py",
    "tests/test_architecture_vocabulary.py",
    # Regeneration stability, and derived-evidence tamper followed all the
    # way to the effect boundary rather than to a diagnosis.
    "tests/test_inspection_subject_matrix.py",
    # The two subjects kept apart: scope and authority-config changes
    # move the RUNTIME subject, and neither moves what was inspected.
    "tests/test_subject_layer_matrix.py",
    # Nothing leaves the semantic projection without an authority
    # classification. Deleting this file re-opens the one-line diff that
    # removes an authored block from inspection binding.
    "tests/test_semantic_projection_exclusions.py",
    # Task 8 stated as its own theorem: what happens to an ALREADY VALID
    # inspection when the governed input changes underneath it.
    "tests/test_task8_closure.py",
    # The semantic-binding theorem: no VALID authored change may move a
    # Nornyx decision while the inspection identity holds still.
    "tests/test_semantic_binding_theorem.py",
    # The security context proven where it is USED, not only where it is built.
    # `test_security_context.py` passed in full while nothing under `src/` ever
    # called the bootstrap, so the mechanism suite cannot stand in for this one.
    "tests/test_production_security_context.py",
    # Canonical-LF enforced on WRITE. It was enforced on read only, so this
    # system's own tooling produced files its subject observer then refused.
    "tests/test_canonical_text_writes.py",
    # The five controls this module's own docstring names as the ones the
    # incident silenced. Naming them in the prose and omitting them from the
    # list meant the gate did not protect the thing it was written for.
    "tests/test_approval_wiring.py",
    "tests/test_approval_injection.py",
    "tests/test_materialization_injection.py",
    "tests/test_expiry_semantics.py",
    "tests/test_pre_approval_baseline.py",
    # A grant binds to one act, and the risk vocabulary is closed. Both are
    # reproduced-exploit proofs and both were absent from this list.
    "tests/test_action_binding.py",
    "tests/test_untrusted_text.py",
    # The metamorphic matrix behind the semantic inspection subject. Without it,
    # trading contract bytes for contract meaning rests on an argument rather
    # than a measurement.
    "tests/test_subject_completeness.py",
    # An integrity-compromised runtime must not reach a consequential
    # effect. Without this, excluding derived governance state from the
    # inspection subject is a hole rather than a channel.
    "tests/test_governance_integrity_authority.py",
    # Every artifact that can influence a decision declares what kind of
    # authority it carries, and each class proves its claim behaviourally.
    "tests/test_artifact_authority.py",
    # Deleting an expected member of an authority collection must become
    # visible. Six collections answered correctly and one did not.
    "tests/test_collection_completeness.py",
    # The class behind four separate defects, written down as a control:
    # required evidence being absent is not a successful empty
    # verification.
    "tests/test_absence_is_not_success.py",
    # Trust is parsed and frozen at bootstrap; a running context cannot be
    # re-aimed by editing the file it was built from.
    "tests/test_trust_snapshot.py",
    # Authentication proves who signed; authorization proves what they may
    # do. The directionality matrix keeps those separate.
    # The historical security inventory, and the meta-controls that keep it
    # from silently shrinking.
    "tests/test_historical_reproof.py",
    # The authoritative mutation inventory: two counts kept apart, every
    # owner mechanically verifiable, and its own shrinkage self-attacked.
    "tests/test_mutation_catalogue.py",
    # The nine false-green classes, each with a self-attack that must trip
    # its guard. Deleting this file removes the only proof the proof system
    # cannot succeed for the wrong reason.
    "tests/test_false_green_audit.py",
    # Strict xfail and a closed expected-failure inventory. Without this a
    # single decorator silences a security proof with the gate still green.
    "tests/test_xfail_strictness.py",
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


def classify(
    report: Path,
) -> tuple[
    int, int, list[str], "Counter[str]", set[str], list[str], list[str]
]:
    """Split a junit report into (total, expected skips, unexpected skips).

    Separated from the run so the gate itself is testable: a guard whose failure
    path has never executed is a guess about what it would do.
    """

    root = ET.parse(report).getroot()
    unexpected: list[str] = []
    unexpected_xfails: list[str] = []
    errors: list[str] = []
    # A COUNT per module, not a presence set: presence cannot see a module
    # that kept one test and lost forty.
    seen_modules: Counter[str] = Counter()
    skipped_identities: set[str] = set()
    allowed = 0
    total = 0
    for case in root.iter("testcase"):
        # A COLLECTION ERROR IS NOT A TEST. pytest emits a `<testcase>` carrying
        # `<error>` when a module fails to import, and counting it meant a module
        # that does not load still incremented the total, still satisfied
        # REQUIRED_MODULES, and now would still contribute to its per-module
        # floor. A broken module read as present and contributing -- the census
        # certifying coverage that could not have run.
        if case.find("error") is not None:
            errors.append(node_id(case))
            continue
        total += 1
        seen_modules[node_id(case).split("::", 1)[0]] += 1
        skipped = case.find("skipped")
        if skipped is None:
            continue
        # An EXPECTED FAILURE is not a skip. pytest reports both as `<skipped>`
        # in JUnit XML, distinguished only by `type`, and conflating them is a
        # vocabulary error with real consequences in both directions: a strict
        # xfail would have to be added to EXPECTED_SKIPS to pass this gate,
        # putting a test that runs and asserts into a list whose stated meaning
        # is "asserts nothing", and thereafter its exemption would also cover it
        # if it ever became a genuine skip.
        #
        # The distinction is the gate's own premise. A skipped test did not
        # execute; an xfail executed and failed exactly as predicted.
        #
        # But `continue` was WRONG, and the comment that justified it was false:
        # it claimed xfails are strict here, and `xfail_strict` was set nowhere.
        # One `@pytest.mark.xfail` could therefore silence a failing security
        # proof with the census reporting nothing. Strictness is now configured
        # AND xfails are counted against a closed allowlist, so an undeclared
        # expected-failure fails the run in its own vocabulary rather than
        # borrowing the skip exemption list.
        if (skipped.get("type") or "") == "pytest.xfail":
            identity = node_id(case)
            if identity not in EXPECTED_XFAILS:
                unexpected_xfails.append(identity)
            continue
        message = (skipped.get("message") or "") + (skipped.text or "")
        if node_id(case) in EXPECTED_SKIPS:
            allowed += 1
            skipped_identities.add(node_id(case))
            continue
        unexpected.append(f"{node_id(case)} — {message.strip()}")
    return (
        total, allowed, unexpected, seen_modules, skipped_identities,
        unexpected_xfails, errors,
    )


def evaluate(report: Path, pytest_returncode: int) -> int:
    """Decide the verdict from a report. Separated so the refusals are testable.

    `main()` used to hold this inline, so the three paths that make this gate a
    gate -- missing required module, collection below floor, GATE: FAIL -- had
    never once executed under test. The module docstring already said a guard
    whose failure path has never run is a guess about what it would do; only
    `classify` had been separated far enough to act on that.
    """
    (
        total, allowed, unexpected, seen_modules, skipped_identities,
        unexpected_xfails, errors,
    ) = classify(report)

    if errors:
        print(NEWLINE + "These test cases ERRORED rather than running:" + NEWLINE)
        for entry in errors:
            print(f"  {entry}")
        print(
            NEWLINE + "A collection error is not a test. A module that fails to "
            "import cannot have proved anything, so a census over this run "
            "would certify coverage that never executed."
        )
        print(NEWLINE + "GATE: FAIL - the run carries collection errors")
        return 2

    print(
        f"collected {total}, expected skips {allowed}, "
        f"unexpected skips {len(unexpected)}, "
        f"unexpected xfails {len(unexpected_xfails)}"
    )

    if unexpected_xfails:
        print(NEWLINE + "These tests are marked as expected failures and are not "
              "in EXPECTED_XFAILS:" + NEWLINE)
        for entry in unexpected_xfails:
            print(f"  {entry}")
        print(
            NEWLINE + "An xfail is a proof with an off switch. Fix the test, or "
            "add it to EXPECTED_XFAILS with why an expected failure is the "
            "honest state. The intended inventory is EMPTY."
        )
        print(NEWLINE + "GATE: FAIL - undeclared expected failures")
        return 2

    # An exemption whose test did not skip is a STANDING PERMISSION nobody
    # needs: if that test later starts skipping for an unrelated reason, the
    # census stays silent because the name is already on the list. Reported
    # rather than failed, because these are legitimately platform-dependent --
    # the POSIX exemptions are unused on Linux and the Docker ones on a machine
    # with a daemon. A reviewer needs to see which permissions were live.
    unused = sorted(set(EXPECTED_SKIPS) - skipped_identities)
    if unused:
        print(
            NEWLINE + f"{len(unused)} skip exemption(s) were not used in this run "
            "(platform-dependent, or stale):"
        )
        for name in unused:
            print(f"  {name}")

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

    shrunk = [
        f"{name}: {seen_modules.get(name, 0)} collected, floor {floor}"
        for name, floor in sorted(REQUIRED_MODULE_MINIMUMS.items())
        if seen_modules.get(name, 0) < floor
    ]
    if shrunk:
        print(NEWLINE + "These required modules contribute fewer tests than "
              "their declared floor:" + NEWLINE)
        for entry in shrunk:
            print(f"  {entry}")
        print(
            NEWLINE + "An aggregate floor cannot see this: other modules grow and "
            "absorb the loss, which is how 43 tests across six modules were "
            "deleted while the run landed exactly on the total. Restore the "
            "proofs, or lower the floor in the diff where it can be argued with."
        )
        print(NEWLINE + "GATE: FAIL - a required module shrank")
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
