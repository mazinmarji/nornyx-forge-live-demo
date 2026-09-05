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
    # The two AC07 controls that cannot speak on the floor interpreter.
    "tests/test_attack_classes.py::test_the_floor_probe_sees_a_violation_that_is_really_there":
        "On Python 3.10 -- the floor `requires-python` declares -- there is no post-floor syntax that also parses on the running interpreter, so these two AC07 controls have nothing to demonstrate there. `except*` does not parse on 3.10 at all. Both execute on 3.11, 3.12 and 3.13, which is where the property they pin is observable.",
    "tests/test_attack_classes.py::test_reverting_one_fix_reddens_its_own_specimen":
        "On Python 3.10 -- the floor `requires-python` declares -- there is no post-floor syntax that also parses on the running interpreter, so these two AC07 controls have nothing to demonstrate there. `except*` does not parse on 3.10 at all. Both execute on 3.11, 3.12 and 3.13, which is where the property they pin is observable.",
    # Three rows of ROUND_FOUR_SPECIMENS are `except*` source text.
    "tests/test_false_green_audit.py::test_the_screen_answers_the_shapes_a_fourth_round_demonstrated":
        "except* is 3.11+ syntax and ast.parse REJECTS it on 3.10, which requires-python allows and the CI matrix runs. The property is not weakened: TRY_NODES already degrades via getattr(ast, 'TryStar', None), so on 3.10 there is no such node to miscount, and the 3.11, 3.12 and 3.13 jobs all execute these three rows.",
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
    # BRD-F-005's measured disclosure. Declared here because a review measured
    # the census returning 2 on every clean checkout on account of these nine,
    # while this repository's own commit message said 'All gates rc=0'. The
    # module and its skip were introduced together and EXPECTED_SKIPS was edited
    # twice without an entry.
    #
    # FOUR HUMAN-BLOCKED EXEMPTIONS WERE REMOVED HERE, and the reason is worth
    # keeping. They read, verbatim and four times over:
    #
    #   "This measurement runs the shipped demonstration, which needs
    #    `.nornyx/runtime/nornyx.agentic_network.lock`. That lock is gitignored
    #    and `prepare_runtime.py` exits 2 without a human approval, so NO
    #    reader and NO CI job can produce one ... HUMAN-BLOCKED, not
    #    platform-blocked"
    #
    # The shipped demonstration does not need the lock. Measured on a copy of
    # the 216 tracked files -- exactly a clean clone, no `.nornyx/runtime/`:
    #
    #     demo --offline   EXIT 0, status pass
    #     nornyx_evidence  {"status": "fallback",
    #                       "load_error": "RUNTIME_LOCK_MISSING"}
    #
    # The absence lands in the deterministic fallback, as CLAUDE.md documents,
    # and the run completes. With the lock present the only change is the
    # `load_error` string; both paths fall back, because without an approval
    # the authorizer does not load either way.
    #
    # Removing the precondition took `test_brd_evidence_shape.py` from 9 skips
    # and 1 test to 10 tests, all passing. Nine cases had been declared
    # permanently unobtainable by a human dependency that was not there.
    #
    # `HUMAN_BLOCKED` is the ONE category this repository says no autonomous
    # run may close. Inflating it is the mirror image of the substitution the
    # rest of this file polices: claiming a blocker that does not exist rather
    # than a control that does not exist. A reviewer auditing the skip census
    # was told the strongest check of BRD-F-005 was unavailable, and accepted
    # nine permanent skips instead of spending a minute disproving it.
    "tests/test_container_launch.py::test_compose_up_build_starts_the_application":
        "The live container build downloads packages, which BRD-004 forbids for the default offline run. CI exercises it in the container-launch job instead, so it is covered — just not here.",
    # RLIMIT_NPROC is a POSIX per-user-id limit. These two proofs hold a busy
    # real uid against the trusted verifier and probe the budget the kernel
    # then holds, neither of which exists on a Windows workstation, where a Job
    # Object confines the verifier instead. The property is not weakened: every
    # CI test job runs Linux and executes both, and the provenance proof
    # requires enforced limits on every platform.
    "tests/test_trusted_greenfield_acceptance.py::test_posix_process_budget_survives_a_busy_real_uid":
        "RLIMIT_NPROC is a POSIX per-user-id limit; a Windows workstation confines the verifier with a Job Object instead. The property is not weakened: every CI test job runs Linux and executes this proof, and the provenance proof requires enforced limits on every platform.",
    "tests/test_trusted_greenfield_acceptance.py::test_posix_process_budget_is_applied_above_the_ambient_task_count":
        "RLIMIT_NPROC is a POSIX per-user-id limit; a Windows workstation confines the verifier with a Job Object instead. The property is not weakened: every CI test job runs Linux and executes this proof, and the provenance proof requires enforced limits on every platform.",
    "tests/test_trusted_greenfield_acceptance.py::test_posix_process_budget_refuses_more_than_its_incremental_allowance":
        "RLIMIT_NPROC is a POSIX per-user-id limit; a Windows workstation confines the verifier with a Job Object instead. The property is not weakened: every CI test job runs Linux and executes this proof, and the provenance proof requires enforced limits on every platform.",
    "tests/test_trusted_greenfield_acceptance.py::test_posix_ambient_measurement_ignores_project_controlled_state":
        "The ambient baseline is read from /proc, which a Windows workstation does not have; there the verifier is confined by a Job Object whose limit needs no baseline. The property is not weakened: every CI test job runs Linux and executes this proof.",
    "tests/test_trusted_greenfield_acceptance.py::test_posix_limits_fail_closed_when_the_ambient_count_cannot_be_measured":
        "The POSIX baseline and its fail-closed path do not exist on a Windows workstation, where a Job Object confines the verifier instead. The property is not weakened: every CI test job runs Linux and executes this proof, and the parent's resource-limits refusal is proved on every platform.",
    # PR-18's Windows-hosted runtime evidence: a real child process started
    # from a real bundle folder on a Windows host. The Linux census cannot
    # express these; the windows-runtime CI job runs the module on
    # windows-latest under a skip census of its own, so a skip THERE fails
    # that job rather than passing quietly, and the cross-platform half of
    # the same properties runs here in tests/test_windows_runtime.py.
    "tests/test_windows_host_runtime.py::test_w1_w2_w11_w12_the_bundles_own_code_serves_from_an_unrelated_directory":
        "Windows-hosted runtime evidence: a real child process from a real bundle folder on a Windows host. The property is not weakened: the windows-runtime CI job runs this module on windows-latest with a skip census of its own, so a skip there fails that job rather than passing quietly.",
    "tests/test_windows_host_runtime.py::test_w3_the_windows_runtime_binds_loopback_only":
        "Windows-hosted runtime evidence: a real child process from a real bundle folder on a Windows host. The property is not weakened: the windows-runtime CI job runs this module on windows-latest with a skip census of its own, so a skip there fails that job rather than passing quietly.",
    "tests/test_windows_host_runtime.py::test_w6_a_second_process_joins_the_running_instance_and_starts_nothing":
        "Windows-hosted runtime evidence: a real child process from a real bundle folder on a Windows host. The property is not weakened: the windows-runtime CI job runs this module on windows-latest with a skip census of its own, so a skip there fails that job rather than passing quietly.",
    "tests/test_windows_host_runtime.py::test_w7_w8_stale_metadata_and_an_impostor_are_not_this_runtime":
        "Windows-hosted runtime evidence: a real child process from a real bundle folder on a Windows host. The property is not weakened: the windows-runtime CI job runs this module on windows-latest with a skip census of its own, so a skip there fails that job rather than passing quietly.",
    "tests/test_windows_host_runtime.py::test_w9_w20_a_stopped_runtime_restarts_over_the_same_persisted_project":
        "Windows-hosted runtime evidence: a real child process from a real bundle folder on a Windows host. The property is not weakened: the windows-runtime CI job runs this module on windows-latest with a skip census of its own, so a skip there fails that job rather than passing quietly.",
    "tests/test_windows_host_runtime.py::test_w16_w17_the_journey_reaches_the_governed_boundary_and_the_build_is_refused":
        "Windows-hosted runtime evidence: a real child process from a real bundle folder on a Windows host, once per declared provider. The property is not weakened: the windows-runtime CI job runs this module on windows-latest with a skip census of its own, so a skip there fails that job rather than passing quietly.",
    "tests/test_windows_host_runtime.py::test_w13_w14_the_self_contained_launcher_refuses_visibly_without_its_interpreter":
        "Windows-hosted runtime evidence: the literal self-contained launcher run through cmd.exe on a Windows host. The property is not weakened: the windows-runtime CI job runs this module on windows-latest with a skip census of its own, so a skip there fails that job rather than passing quietly.",
    "tests/test_windows_host_runtime.py::test_the_entry_guard_speaks_when_the_folder_cannot_load":
        "Windows-hosted runtime evidence: the entry guard exercised on a real child process under a redirected profile on a Windows host. The property is not weakened: the windows-runtime CI job runs this module on windows-latest with a skip census of its own, so a skip there fails that job rather than passing quietly.",
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
    # The class probes. A class whose specimens stop being collected is a
    # class held down by nothing, so this module has a floor like any
    # other -- the registry is only as real as the tests it names.
    # The capsule's authority split: 26 collected at introduction, floor at
    # band(26) = 24 exactly, because the slack guard requires every declared
    # floor to BE the band of what its module collects. The line a model
    # cannot cross alone is only as real as the specimens that hold it.
    "tests/test_project_capsule.py": 24,
    # The Experience Contract: 20 collected at introduction, floor at
    # band(20) = 18 exactly. The stages a model cannot move and the READY a
    # JSON edit cannot spell are held by these.
    "tests/test_experience_contract.py": 18,
    # The provider seam: 16 collected at introduction, floor at band(16) = 15.
    # The conformance suite and the invariance proof that wrapping the Claude
    # path changed nothing observable.
    "tests/test_provider_contract.py": 15,
    # The Codex adapter's conformance: 10 collected at introduction, floor at
    # band(10) = 9. Same harness technique as the Claude conformance,
    # separate proof -- and the two mapping limits pinned, not hidden.
    "tests/test_codex_provider.py": 12,
    # The pre-registered equivalence proof: 18 collected at introduction,
    # floor at band(18) = 17. The criteria were frozen in
    # docs/governance/PROVIDER_EQUIVALENCE_PREREG.md one commit before this
    # module existed, so losing its specimens means losing the only
    # executable form of that registration.
    "tests/test_provider_equivalence.py": 17,
    # The C1 rendering guards: 19 collected at introduction, floor at
    # band(19) = 18. Round-trip closure on the three shipped contracts,
    # plus the hostile specimens for every quiet death of the rule --
    # dropped clause, paraphrase, reorder, injected prose, softened
    # authority statement.
    "tests/test_governance_rendering.py": 18,
    # The onboarding surface: 14 collected at introduction, floor at
    # band(14) = 13. The capsule's authority rules exercised through the
    # real routes over a real store -- model actors refused where the
    # capsule refuses them, tamper named TAMPERED, absence reported as
    # absence, the governance route serving only the guarded rendering.
    "tests/test_onboarding_app.py": 13,
    # The launch path: 9 collected at introduction, 13 after the post-PR-18
    # hardening (the common Host rule, N3), floor at band(13) = 12. The
    # FORGE_ROOT doctrine held at every layer -- relative directories
    # refused in assemble, main and the launcher alike, the loopback
    # binding pinned -- and the loopback Host rule held on the common
    # composition, on the console path, and by a census of `src/` for any
    # composition that omits it.
    "tests/test_onboarding_launch.py": 12,
    # Provider-routed engineering execution: 9 collected at introduction,
    # floor at band(9) = 9. The default path preserved structurally, the
    # no-silent-fallback rule, and a real flow call site recording the
    # provider that actually ran.
    "tests/test_provider_execution.py": 9,
    # The confirmed capsule provider drives the build; proposals never do:
    # 7 collected at introduction, floor at band(7) = 7. The authority
    # split extended to execution, over the real CLI and a real store.
    "tests/test_capsule_selection.py": 7,
    # The sharing preview under C5: 10 collected at introduction, floor at
    # band(10) = 9. Shape-closed minimization (its first sweep-based guard
    # let a fragment leak through -- the specimen caught the guard), the
    # never-sent state as data, and no network path in the module.
    "tests/test_experience_sharing.py": 9,
    # The Windows bundle builder: 10 collected at introduction, 18 after
    # PR-18 and its inspections, 45 after the post-PR-18 hardening (the
    # smoke verdict, N1) and its three in-session inspections, floor at
    # band(45) = 41. The Dockerfile-parsed
    # anti-drift pin, the resolver's markers, the src-before-pylib
    # shadowing order with no site line, the probed installer, the refusal
    # of an unverified or incomplete interpreter archive, the mode marker,
    # the two launchers -- the self-contained one naming no fallback
    # interpreter -- the launch-directory command lookup turned off before
    # any command, and the smoke's `pass` bound to the conjunction of its
    # recorded observations (S1-S9, over scripted observations and through
    # the smoke over a scripted launcher, its exception paths and bounds
    # included, and against a hostile listener on its scratch port).
    "tests/test_windows_bundle.py": 41,
    # PR-18's Windows runtime, cross-platform deterministic: 36 collected
    # after the three in-session inspections, 37 after the post-PR-18
    # hardening (the served composition's Host rule, N3), floor at
    # band(37) = 34. The
    # launched folder as the running code, the carried interpreter or none,
    # explicit project authority, one owner per project under a file lock
    # (retried while a launch waits; a finished run's record provisional),
    # loopback-only binding and a loopback-only Host, the browser only
    # after the server answered its own probe, stale metadata and impostors
    # refused without terminating anything, bounded notices, operational
    # state kept out of the governance answer, the project and the seals,
    # and capsule authority persisting across a runtime restart.
    "tests/test_windows_runtime.py": 34,
    # PR-18's Windows-hosted evidence: 10 collected after the inspections
    # (the journey once per declared provider, and the one test that runs
    # everywhere and pins the windows-runtime job), floor at band(10) = 9.
    # Real child processes from a real bundle folder at a path with spaces
    # and non-ASCII characters, from an unrelated working directory;
    # declared skips off Windows, run by the windows-runtime CI job under
    # its own skip census.
    "tests/test_windows_host_runtime.py": 9,
    # The BRD derivation: 9 collected at introduction, floor at band(9) = 9.
    # Round-tripped against the real parse_brd; a proposal-only capsule
    # refuses; open proposals author nothing; heading collisions refused.
    "tests/test_brd_authoring.py": 9,
    # The build trigger: 9 collected at introduction, floor at band(9) = 9.
    # The no-terminal path runs only confirmed state; model actors, missing
    # prerequisites and interleaved builds refused by name; the flow's
    # result reported verbatim.
    "tests/test_build_trigger.py": 9,
    # PR-17's journey orchestration: 49 collected at introduction, floor at
    # band(49) = 45. The lifecycle moved only through the contract -- creation
    # at DISCOVER, the explicit human CONFIRM and READY, BUILD -> TEST ->
    # GOVERN from the translated flow result and nothing a worker wrote,
    # failure and retry through the contract's own, tamper fail-closed,
    # duplicates and stale requests judged against the persisted state, the
    # no-terminal journey through the routes alone, and the pre-PR-17 gap
    # (lifecycle absent at every step) pinned closed.
    "tests/test_basic_user_journey.py": 45,
    # P17-B1's authority boundary: 35 collected at introduction, floor at
    # band(35) = 32. The provider's writable path into the store -- forged
    # READY dirty and committed, forged capsule authority, the mid-build
    # poll and actions, the restart with and without a detected breach,
    # the real DevelopmentFlow worker seam, the seal's own detections and
    # rebuild, and the thread-start lock release.
    "tests/test_provider_authority_boundary.py": 32,
    # Declared is not eligible (R1-R3 of the independent review): 16
    # collected at introduction, floor at band(16) = 15. The governed build
    # refusing both declared providers before anything executes, no
    # fallback, the Forge-owned decision pinned in the served composition,
    # the seam's own eligibility, the protected-store-without-seal refusal
    # and the legacy distinction.
    "tests/test_governed_provider_eligibility.py": 15,
    "tests/test_codex_confinement_admission.py": 18,
    # PR-16's trust boundary: 107 collected after CI, security-review, POSIX
    # process-budget and F-002 remediation, floor at band(107) = 97. Real
    # DevelopmentFlow repair/review paths, all seven hostile specimens, exact
    # isolated invocation, strict result-protocol refusals, process-capability
    # equivalence, provenance, and the controlled old-profile false green live
    # together. The two Linux loader, five executor-control, five POSIX
    # process-budget regressions, and eight F-002 subject-failure and
    # process-replacement proofs are included; critical acceptance identities
    # are pinned separately.
    "tests/test_trusted_greenfield_acceptance.py": 97,
    "tests/test_attack_classes.py": 44,
    "tests/test_approval_authentication.py": 44,
    "tests/test_killed_by_validation.py": 8,
    "tests/test_failure_attribution.py": 9,
    "tests/test_baseline_discrimination.py": 6,
    #: LOWERED, and the reason is recorded because anti-shrink exists to
    #: catch exactly this shape. Three documents left the current-claim
    #: surface by declaration when the hardened baseline was integrated with
    #: main -- two SHA-bound G2 assessments and one methodology -- so this
    #: module sweeps fewer documents. No test was deleted and no proof was
    #: weakened; the corpus it quantifies over is smaller by a declared
    #: scope decision. See `classify_document` in tests/test_documented_claims.py.
    # Raised 155 -> 160 for the provider-equivalence round: the frozen
    # pre-registration is a governance document, so the document sweep
    # gained five parametrized cases (177 collected, band(177) = 160) --
    # caught by `test_no_module_floor_drifts_far_below_its_module`.
    # Raised 160 -> 162 for the anchored-measurement isolation round: the
    # re-execution gained its enclosing-repository and reader-hook proofs
    # (179 collected, band(179) = 162).
    # Raised 162 -> 166 for the Windows-runtime round: A-023, the Windows
    # section of docs/VALIDATION.md and the README bundle section entered
    # the document sweep (184 collected, band(184) = 166) -- the sweep
    # growing when governed prose lands is the sweep working.
    "tests/test_recorded_measurements.py": 171,
    "tests/test_approval_reachability.py": 17,
    "tests/test_approval_ledger.py": 65,
    # Protected because Lens B measured 103 tests of slack in the aggregate
    # floor, and named these two: the evidence-binding proofs and the sole
    # regression for the reachability probe were both deletable.
    "tests/test_evidence_binding.py": 19,
    "tests/test_clause_reachability.py": 7,
    "tests/test_reviewer_authentication.py": 25,
    "tests/test_independent_inspection.py": 16,
    "tests/test_trust_directionality.py": 9,
    "tests/test_content_binding.py": 19,
    "tests/test_subject_scope.py": 13,
    "tests/test_security_context.py": 10,
    "tests/test_evaluation_time.py": 15,
    "tests/test_execution_semantics.py": 10,
    # 43 collected after the PR-16 executor-control identities were added,
    # floor at band(43) = 39.
    "tests/test_skip_gate.py": 39,
    "tests/test_documented_claims.py": 144,
    "tests/test_claim_surface_boundary.py": 8,
    "tests/test_process_execution_spellings.py": 22,
    "tests/test_approval_artifact_authentication.py": 9,
    "tests/test_governance_approval_verifier.py": 45,
    "tests/test_process_capability.py": 52,
    "tests/test_evidence_integrity_verifier.py": 9,
    "tests/test_dockerfile_surface.py": 16,
    "tests/test_authority_domains.py": 18,
    "tests/test_domain_immutability.py": 9,
    "tests/test_domain_collapse_mutations.py": 24,
    "tests/test_execution_mode_truth.py": 21,
    "tests/test_architecture_vocabulary.py": 29,
    "tests/test_inspection_subject_matrix.py": 5,
    "tests/test_subject_layer_matrix.py": 15,
    "tests/test_semantic_projection_exclusions.py": 15,
    "tests/test_task8_closure.py": 10,
    "tests/test_semantic_binding_theorem.py": 34,
    "tests/test_production_security_context.py": 19,
    "tests/test_canonical_text_writes.py": 8,
    "tests/test_approval_wiring.py": 8,
    "tests/test_approval_injection.py": 11,
    "tests/test_materialization_injection.py": 18,
    "tests/test_expiry_semantics.py": 8,
    "tests/test_pre_approval_baseline.py": 6,
    "tests/test_action_binding.py": 35,
    "tests/test_untrusted_text.py": 65,
    "tests/test_subject_completeness.py": 9,
    "tests/test_governance_integrity_authority.py": 36,
    "tests/test_artifact_authority.py": 16,
    "tests/test_collection_completeness.py": 9,
    # Raised 21 -> 27 for the fifth instance of the class -- a repository that
    # is not this tree's -- six nodes (29 collected, band(29) = 27).
    # Raised 27 -> 44 for the reader-configuration round: ten configuration
    # routes, two attributes routes, the attributes-source variable, the
    # path beyond MAX_PATH, the neutral-environment checkout, the
    # genuine-change, git-failure and git-refusal guards and the one-runner
    # structural check, nineteen nodes (48 collected, band(48) = 44).
    "tests/test_absence_is_not_success.py": 44,
    "tests/test_trust_snapshot.py": 19,
    "tests/test_historical_reproof.py": 56,
    "tests/test_mutation_catalogue.py": 38,
    "tests/test_false_green_audit.py": 296,
    "tests/test_xfail_strictness.py": 18,
    "tests/test_approval_lifecycle.py": 5,
    "tests/test_architecture_coverage.py": 18,
    "tests/test_architecture_security.py": 7,
    "tests/test_authority_config.py": 12,
    "tests/test_brd_evidence_shape.py": 9,
    "tests/test_capability_binding.py": 9,
    "tests/test_console_encoding.py": 3,
    "tests/test_container_launch.py": 6,
    "tests/test_contract_generator.py": 1,
    "tests/test_demo_flow.py": 1,
    "tests/test_dirty_tree_gate.py": 31,
    "tests/test_evidence.py": 26,
    "tests/test_governance_failure.py": 18,
    "tests/test_in_session_reviews.py": 3,
    "tests/test_mission_binding.py": 11,
    "tests/test_probe_containment.py": 18,
    # Drives all 14 attack criteria against a HOLLOW tree (a real
    # checkout with src/ and scripts/ emptied) and requires each to
    # WITHDRAW. It found two probes -- H07 and H15 -- that three review
    # rounds and an AST sweep had all missed.
    "tests/test_probe_withdrawal.py": 15,
    # The sidecar state space driven through `consume`, plus the
    # controls. A review found the previous repair to this area
    # shipped with ZERO executing tests -- the handler, both raise
    # sites and the whole migration path unreached under a green
    # suite -- which is why the P1 it was meant to close survived it.
    "tests/test_ledger_continuity.py": 52,
    #: The v1 boundary of architecture-check, pinned from both sides:
    #: five disclosed routes and three controls that must stay decided.
    "tests/test_module_acquisition_limits.py": 11,
    # A7-P1-2: the crash sweep, both restore directions, and the
    # concurrency controls. The sweep spawns 60 children per node, so
    # this module is slow by construction -- the price of MEASURING a
    # crash boundary rather than reasoning about it.
    "tests/test_ledger_atomicity.py": 25,
    # R2: the authoritative-property contract and the terminal
    # classification of every registered attack.
    "tests/test_attack_attribution_contract.py": 9,
    # R3: every structural refusal in verify_action_approval, and WHICH
    # control catches each -- so a shadowing change is visible.
    "tests/test_approval_structure_refusals.py": 10,
    # R6: the four consequential-authority properties composed on the
    # real boundary, with the EFFECT counted rather than the decision read.
    "tests/test_consequential_authority_path.py": 29,
    # Discovers every trust store structurally and requires the registry
    # to cover all of them, so the reviewer store cannot again sit
    # outside checks the approver store beside it has had for rounds.
    "tests/test_trust_store_parity.py": 5,
    "tests/test_policy.py": 1,
    "tests/test_repository_structure.py": 2,
    "tests/test_requirements.py": 1,
    "tests/test_runtime_authority.py": 15,
    "tests/test_runtime_image_subject.py": 8,
    "tests/test_scratch_containment.py": 3,
    "tests/test_special_files.py": 5,
    "tests/test_subject_metamorphic.py": 8,
    "tests/test_subject_provenance.py": 8,
    "tests/test_validation_script.py": 1,
}

# Raised again, from 1120, when round-3 remediation took the suite to 1255 and
# `test_the_floor_sits_below_the_current_suite_and_above_nothing` went red at
# 135 of slack -- the band guard doing exactly its job. 1190 leaves 65.
# Raised from 945, then from 1000. Lens B measured 118 tests of slack against
# 1063 collected -- enough to delete whole modules with this gate still green,
# and it named the dirty-tree gate and the reachability regressions as
# deletable. 1000 fixed that, and then the Lens C work added ~30 tests and
# reopened the gap: 1000 against 1115 collected is 115 of slack, and
# `tests/test_skip_gate.py` failed exactly as designed.
#
# THIS NUMBER IS MEANT TO NEED UPDATING. A floor computed from the current
# count could never detect shrinkage -- it would move down with the deletion it
# is supposed to catch. So it stays a constant, and the guard requiring it to
# sit within 10% of the real suite is the thing that forces a deliberate raise
# whenever the suite grows. Twice now that guard has been the one to notice.
# Raised again, from 1225, by round-5 remediation: 1370 collected. The growth
# is mostly ADVERSARIAL CORPUS -- 33 nodes in `test_documented_claims.py` and 5
# in `test_recorded_measurements.py` pinning every forgery three reviews walked
# past this repository's guards, plus 15 in the new `test_probe_withdrawal.py`
# driving every attack criterion against a tree with no symbols in it. 1290
# leaves 80 of slack, the same deliberate margin as the last two raises.
# Raised again, from 1290, by round-6 remediation: 1423 collected. The growth
# is the executing proof two reviews said was missing -- 25 nodes driving the
# high-water sidecar's whole state space through `consume`, and the round-6
# additions to the two claim corpora. 1340 leaves 83 of slack, the same
# deliberate margin as the last three raises.
#: How many CASES each declared skip identity may contribute. Anything not
#: named here may contribute ONE -- an unparametrised test.
#:
#: `EXPECTED_SKIPS` is keyed on the identity with `[param]` stripped, so
#: without this a single entry exempted an unbounded number of cases. A review
#: drove forty skipping parameter sets of one declared identity through the
#: real `classify` and measured `unexpected=[]` with both floors padded by
#: forty.
EXPECTED_SKIP_CASES: dict[str, int] = {
    # The four identities this once held caps for no longer skip: their
    # premise was that the shipped demonstration needs a runtime lock, and
    # it does not. See the note in EXPECTED_SKIPS above.
    #
    # THREE, not the default one: three rows of ROUND_FOUR_SPECIMENS are
    # `except*` source. A cap of one would let a fourth parameter start
    # skipping on 3.10 behind a permission granted for these three.
    "tests/test_false_green_audit.py::test_the_screen_answers_the_shapes_a_fourth_round_demonstrated": 3,
    # ONE revert row skips on 3.10, not the whole identity. No count of the
    # rows is written here: it said seven while the table held ten, in the
    # block whose subject is stale prose beside a live constant.
    "tests/test_attack_classes.py::test_reverting_one_fix_reddens_its_own_specimen": 1,
    # ONE CASE PER DECLARED PROVIDER, off Windows. The journey-to-the-boundary
    # proof runs a real runtime once for each provider PROVIDERS declares; a
    # third provider would be a diff here as well as in the contract.
    "tests/test_windows_host_runtime.py::test_w16_w17_the_journey_reaches_the_governed_boundary_and_the_build_is_refused": 2,
}

# Raised again, from 1340, by round-7 remediation: 1531 collected. Most of the
# growth is not new tests but newly VISIBLE ones -- selection now uses the
# container-independent recogniser, so documents whose transcripts sit in
# blockquotes, bullets and tables enter the parametrised sweep that was only
# ever handed fenced ones. 1450 leaves 81 of slack.
# RAISED ABOVE THE SUM OF THE PER-MODULE FLOORS, which is the only way this is
# a floor at all. At 1450 against a module-floor sum of 1458 the aggregate could
# never fire on its own: any report satisfying every module also satisfied it, so
# it was a declared check that could not reach a verdict.
# `test_the_floor_refusal_actually_runs` caught it.
#
# THIS COMMENT HAS NOW GONE STALE TWICE, in the file whose whole purpose is to
# notice counts changing, and both times a review found it rather than a test.
# The first stale line claimed "1490 sits above the sum and 77 below the 1567
# actually collected" and was wrong by 27 the day it was written. The second
# claimed 1687 collected against a 1562 sum and "14 above the sum" -- three
# numbers, none of them true at the head that carried them, and the arithmetic
# did not hold between them either.
#
# So the numbers below are dated and measured, and nothing here is derived by
# hand. Re-measured for the codex-adapter round (10 new collected in
# tests/test_codex_provider.py; 93 -> 94 modules) by a full
# `--collect-only` over tests/. Re-measured for the AC07 probe, which added
# ten collected cases to tests/test_attack_classes.py and pushed its
# declared floor below the band -- caught by
# `test_no_module_floor_drifts_far_below_its_module`, not by a reader.
# Re-measured for the provider-equivalence round: 18 new collected in
# tests/test_provider_equivalence.py (94 -> 95 modules), and 5 more in
# tests/test_recorded_measurements.py because the frozen pre-registration
# is itself a document the document sweep parametrizes over -- a test
# census growing when a governance document lands is the sweep working.
# Re-measured for the governance-rendering round: 19 new collected in
# tests/test_governance_rendering.py (95 -> 96 modules). Re-measured for
# the onboarding round: 14 new collected in tests/test_onboarding_app.py
# (96 -> 97 modules). Re-measured for the launch-wiring round: 9 new
# collected in tests/test_onboarding_launch.py (97 -> 98 modules).
# Re-measured for the provider-execution round: 9 new collected in
# tests/test_provider_execution.py (98 -> 99 modules). Re-measured for
# the capsule-selection round: 7 new collected in
# tests/test_capsule_selection.py (99 -> 100 modules). Re-measured for
# the sharing-preview round: 10 new collected in
# tests/test_experience_sharing.py (100 -> 101 modules). Re-measured for
# the windows-bundle round: 10 new collected in
# tests/test_windows_bundle.py (101 -> 102 modules). Re-measured for the
# brd-authoring round: 9 new collected in tests/test_brd_authoring.py
# (102 -> 103 modules). Re-measured for the build-trigger round: 9 new
# collected in tests/test_build_trigger.py (103 -> 104 modules). Re-measured
# for the PR-16 trusted-greenfield round and its inspector/CI/security
# remediation: 94 collected in tests/test_trusted_greenfield_acceptance.py and
# ten census identity proofs in tests/test_skip_gate.py (104 -> 105
# modules). Re-measured for the POSIX process-budget repair that turned the
# PR-16 matrix green, and again for the three proofs that the budget is an
# increment rather than a licence, and again for the eight F-002 subject-
# failure and process-replacement proofs: 107 collected in
# tests/test_trusted_greenfield_acceptance.py (105 modules). Re-measured for
# the anchored-measurement isolation round: 6 new collected in
# tests/test_absence_is_not_success.py and 2 in
# tests/test_recorded_measurements.py (105 modules). Both module floors were
# raised to their bands, which lifted the module-floor sum past the aggregate,
# so the aggregate moves up by the same eight and keeps its margin --
# Re-measured for the Windows-runtime round (PR-18), after its three
# in-session inspections: 36 collected in tests/test_windows_runtime.py, 10
# in tests/test_windows_host_runtime.py, 8 more in
# tests/test_windows_bundle.py and 5 more in
# tests/test_recorded_measurements.py (108 -> 110 modules); the module-floor
# sum rose by 54 and the aggregate by 55.
# `test_the_aggregate_floor_sits_above_the_sum_of_the_module_floors` caught
# it, not a reader. Re-measured for the reader-configuration round: 19 new
# collected in tests/test_absence_is_not_success.py (105 modules); that
# module's floor rose 27 -> 44 to its band, the module-floor sum rose by the
# same seventeen, and the aggregate follows it to keep the margin.
# Re-measured for the basic-user journey round (PR-17): 49 new collected in
# tests/test_basic_user_journey.py and 1 in tests/test_build_trigger.py
# (105 -> 106 modules); the new module's floor is its band, 45, so the
# module-floor sum rises by 45 and the aggregate follows it. Re-measured
# for the P17-B1 repair: 35 new collected in
# tests/test_provider_authority_boundary.py (106 -> 107 modules), floor at
# its band, 32, and one more in tests/test_basic_user_journey.py (50, floor
# unchanged at its band); the module-floor sum rises by 32 and the aggregate
# follows. Re-measured for the governed-eligibility remediation: 16 new
# collected in tests/test_governed_provider_eligibility.py (107 -> 108
# modules), floor at its band, 15; the module-floor sum rises by 15 and the
# aggregate follows. Re-measured for the post-PR-18 hardening round (N1, the
# smoke verdict; N3, the common Host rule) and its three in-session
# inspections: 27 new collected in tests/test_windows_bundle.py, 4 in
# tests/test_onboarding_launch.py and 1 in tests/test_windows_runtime.py
# (110 modules); those three floors rose to their bands (17 -> 41,
# 9 -> 12, 33 -> 34), so the module-floor sum rises by 28 and the
# aggregate follows. Re-measured for PA-01, the Codex confinement
# measurement: 19 new collected in tests/test_codex_confinement_admission.py
# (110 -> 111 modules) at its band, 18. Two existing floors moved for
# reasons worth separating, because only one of them is "a module grew".
# tests/test_codex_provider.py gained the three UTF-8 output cases (13
# collected, 9 -> 12). tests/test_recorded_measurements.py gained nothing
# of its own: it PARAMETRISES over the governance documents, so adding
# docs/governance/CODEX_CONFINEMENT_MEASUREMENT.md raised what it collects
# to 189 and its floor with it (166 -> 171). A doc is a test here, and a
# tranche that adds one owes the census the same update a new module does.
# The module-floor sum rises by 26 and the aggregate follows:
#
# (rows below):
#
#     collected across tests/     2826   (111 modules)
#     sum of the module floors    2599
#     band(2826) = ceil(0.9*n)    2544
#     MINIMUM_COLLECTED           2607
#     above the module sum         8
#     below what collects         219
#
# The two margins are ROWS now, not prose. A review moved the constant and its
# row together to 1650 and left the sentences saying "15 above the sum" and
# "116 below what actually collects" -- both then wrong by 38 -- and every
# guard stayed green, because the guard checked the rows and nothing
# read the three hand-derived numbers beside them. Two of those three are
# rows now. The third stayed in prose and has gone stale TWICE since: it
# said 152 when the bands granted 163, was corrected to 163 in the same
# commit that raised two floors and made the answer 166, and two
# independent reviews found it again at 166. Five rots in the comment
# whose whole subject is that prose beside a constant is not a measurement
# of it. It is prose because it is a DERIVED quantity -- the sum of the
# per-module slacks -- and every derived quantity here that was promoted
# to a row stopped rotting. This one is the last, and it is now checked:
# `test_the_slack_the_bands_grant_is_the_measured_sum`.
#
# Being above the module sum is the only thing that makes the aggregate a
# gate at all: at or below it, any report satisfying every module floor also
# satisfies the aggregate, and it is a declared check that cannot reach a
# verdict of its own. Being below what collects is the working room; the
# per-module bands already grant 227 in total, and the aggregate refuses
# shrinkage spread thinly enough to stay inside every individual band.
#
# The two bounds are held by
# `test_the_aggregate_floor_sits_above_the_sum_of_the_module_floors` and
# `test_the_floor_sits_below_the_current_suite_and_above_nothing`. Neither of
# them used to read this comment, which is why it could rot twice while both
# stayed green: prose beside a constant is not a measurement of it.
#
# THAT IS NOW CLOSED. The guard named next parses the SIX rows above and
# compares each against the live value, and the collection test compares the
# first row against what it actually collected. A third rot is a red test,
# not a review finding. The guard is
# `test_the_aggregate_floor_comment_states_the_measured_numbers`.
#
# Two test names in the paragraph this replaces DID NOT EXIST -- prose citing
# guards nobody ever wrote, which is the same failure one level up, and a
# third draft of this very comment broke a real name across a line so that it
# cited nothing either. Every backticked `test_...` in this block is now
# checked against the suite by that same guard, so a cited name that does not
# resolve is red rather than reassuring.
MINIMUM_COLLECTED = 2607

# PR-16's threat model is identity-sensitive: a raw module count can stay green
# while H1, H7, or the standing real-flow proof is replaced by an unrelated
# case. These exact proofs must therefore be present and executed, not merely
# absorbed by the module's ordinary anti-shrink floor.
PR16_REQUIRED_EXECUTED = {
    "tests/test_trusted_greenfield_acceptance.py::test_real_flow_accepts_a_fresh_project_without_forge_repository_scripts",
    "tests/test_trusted_greenfield_acceptance.py::test_real_flow_refuses_the_stub_verifier_attack",
    "tests/test_trusted_greenfield_acceptance.py::test_exact_invocation_ignores_project_local_nornyx_forge",
    "tests/test_trusted_greenfield_acceptance.py::test_exact_invocation_ignores_path_cwd_and_python_environment",
    "tests/test_trusted_greenfield_acceptance.py::test_acceptance_provenance_binds_profile_origin_version_revision_and_digests",
    "tests/test_trusted_greenfield_acceptance.py::test_real_flow_allows_genuine_subject_repair_with_the_same_verifier",
    "tests/test_trusted_greenfield_acceptance.py::test_real_flow_verifier_failure_dominates_provider_claims",
    "tests/test_trusted_greenfield_acceptance.py::test_standing_real_development_flow_uses_the_trusted_profile",
    "tests/test_trusted_greenfield_acceptance.py::test_security_static_rejects_reflected_executor_control",
    "tests/test_trusted_greenfield_acceptance.py::test_executor_rejects_a_hard_link_to_its_completion_record",
}


def band(collected: int) -> int:
    """The smallest floor that still counts as tracking a suite of this size.

    ONE DEFINITION, because there were three and two of them disagreed.
    `collected * 9 // 10` TRUNCATES; the rule is a CEILING, and a truncating
    copy accepts a floor one test lower than the ceiling copy demands. At
    today's numbers they agree, which is exactly how the drift survived: two
    copies of a rule agree until they do not, and then the weaker one silently
    accepts.

    Defined here rather than in a test module because both `tests/test_skip_gate.py`
    and `tests/attack_property.py` already import this file, and neither imports
    the other.
    """
    return -(-collected * 9 // 10)

#: Modules whose absence is a governance regression, not a smaller suite. Each
#: holds the proof of an invariant that was reached through a reproduced exploit,
#: so a report that does not mention one means the proof is gone. A floor alone
#: would not catch this: deleting one file and adding tests elsewhere keeps the
#: total up while the invariant goes unproven.
#: EVERY test module is named here. A review deleted four whole modules -- 81
#: tests including the dirty-tree gate and the runtime-authority proofs -- and
#: the census still reported GATE: PASS, because 24 of 78 modules were named
#: nowhere. `test_dirty_tree_gate.py` carried comments saying a floor raise had
#: been made to protect it while the census could not see it at all.
#: `test_every_test_module_is_named_in_the_census` keeps this exhaustive.
REQUIRED_MODULES = (
    # The class probes. A registry of root mechanisms is only as real
    # as the tests it names, so the module holding them is required
    # like any other control: losing it loses every class at once.
    "tests/test_attack_classes.py",
    "tests/test_module_acquisition_limits.py",
    "tests/test_brd_evidence_shape.py",
    "tests/test_approval_authentication.py",
    "tests/test_killed_by_validation.py",
    "tests/test_failure_attribution.py",
    "tests/test_baseline_discrimination.py",
    "tests/test_recorded_measurements.py",
    "tests/test_approval_reachability.py",
    "tests/test_approval_ledger.py",
    "tests/test_evidence_binding.py",
    "tests/test_clause_reachability.py",
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
    # The bounded claim surface: prose is not an authoritative input, and
    # the structured surface is. Deleting this module would delete the
    # only proof of the property that replaced C9-P1-7's overbroad one.
    "tests/test_claim_surface_boundary.py",
    "tests/test_process_execution_spellings.py",
    "tests/test_codex_provider.py",
    "tests/test_provider_contract.py",
    "tests/test_provider_equivalence.py",
    "tests/test_governance_rendering.py",
    "tests/test_onboarding_app.py",
    "tests/test_onboarding_launch.py",
    "tests/test_provider_execution.py",
    "tests/test_capsule_selection.py",
    "tests/test_experience_sharing.py",
    "tests/test_windows_bundle.py",
    "tests/test_windows_runtime.py",
    "tests/test_windows_host_runtime.py",
    "tests/test_brd_authoring.py",
    "tests/test_build_trigger.py",
    "tests/test_basic_user_journey.py",
    "tests/test_provider_authority_boundary.py",
    "tests/test_governed_provider_eligibility.py",
    # PA-01. The eligibility module above proves the DECISION fails closed;
    # this one proves the criterion behind it cannot be satisfied by an edit.
    # Losing it would leave `PROVIDER_CONFINEMENT` promotable to `established`
    # with no measurement objecting.
    "tests/test_codex_confinement_admission.py",
    "tests/test_trusted_greenfield_acceptance.py",
    "tests/test_project_capsule.py",
    "tests/test_experience_contract.py",
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
    "tests/test_approval_lifecycle.py",
    "tests/test_architecture_coverage.py",
    "tests/test_architecture_security.py",
    "tests/test_authority_config.py",
    "tests/test_capability_binding.py",
    "tests/test_console_encoding.py",
    "tests/test_container_launch.py",
    "tests/test_contract_generator.py",
    "tests/test_demo_flow.py",
    "tests/test_dirty_tree_gate.py",
    "tests/test_evidence.py",
    "tests/test_governance_failure.py",
    "tests/test_in_session_reviews.py",
    "tests/test_mission_binding.py",
    "tests/test_probe_containment.py",
    "tests/test_probe_withdrawal.py",
    "tests/test_ledger_continuity.py",
    "tests/test_ledger_atomicity.py",
    "tests/test_attack_attribution_contract.py",
    "tests/test_approval_structure_refusals.py",
    "tests/test_consequential_authority_path.py",
    "tests/test_trust_store_parity.py",
    "tests/test_policy.py",
    "tests/test_repository_structure.py",
    "tests/test_requirements.py",
    "tests/test_runtime_authority.py",
    "tests/test_runtime_image_subject.py",
    "tests/test_scratch_containment.py",
    "tests/test_special_files.py",
    "tests/test_subject_metamorphic.py",
    "tests/test_subject_provenance.py",
    "tests/test_validation_script.py",
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
    int, int, list[str], "Counter[str]", "Counter[str]", set[str],
    list[str], list[str]
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
    executing_modules: Counter[str] = Counter()
    skipped_identities: set[str] = set()
    skipped_cases: Counter[str] = Counter()
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
        # DECLARED SKIPS COUNT HERE, and that is a bound worth naming rather
        # than a property. This module's premise is that a skipped test proves
        # nothing, yet a skip increments both the aggregate total and its
        # module's floor.
        #
        # "COULD IN PRINCIPLE" WAS AN UNDERSTATEMENT, and understating a hole
        # is the failure this census exists to refuse. Measured on a clean
        # checkout: `tests/test_brd_evidence_shape.py` has a floor of 9 and
        # reports `sssssssss.` -- NINE OF TEN SKIP. Driving the production
        # `evaluate()` with its ONE executing test deleted gave collected 1593,
        # expected skips 9, unexpected skips 0, GATE: PASS, return code 0. The
        # named mitigation was that one deletable test.
        #
        # So a required module now has to contribute at least one EXECUTED
        # case, checked at the gate below. That is deliberately NOT a change to
        # the floors: excluding skips from them would drop the collected total
        # by the whole declared-skip count and require every floor to move at
        # once, which is a change to argue for in its own diff. This closes the
        # measured hole without moving a single number.
        #
        # Not silently corrected, because excluding them would drop the
        # collected total by the whole declared-skip count and require every
        # floor to move at once, which is a change that should be argued for in
        # its own diff rather than smuggled into a P3 sweep.
        #
        # THE MITIGATION THAT USED TO BE CLAIMED HERE WAS FALSE. It read: "What
        # closes the hole meanwhile is that EVERY skip must be DECLARED in
        # EXPECTED_SKIPS and the declaration list is pinned: converting a test
        # into a skip requires an entry, and an entry is a diff." A review
        # measured that `node_id` strips `[param]`, so ONE declared identity
        # exempts EVERY parameter set of it -- forty skipping parameters of an
        # already-declared test needed zero new entries, padded both floors, and
        # touched no declaration.
        #
        # So the COUNT is pinned too, per identity, below. Growing a
        # parametrisation into more skips is now a diff, which is what the
        # sentence above claimed and did not deliver.
        total += 1
        module_name = node_id(case).split("::", 1)[0]
        seen_modules[module_name] += 1
        skipped = case.find("skipped")
        if skipped is None:
            # EXECUTED, as distinct from COLLECTED. See
            # `executing_modules` at the gate below.
            executing_modules[module_name] += 1
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
            identity = node_id(case)
            skipped_cases[identity] += 1
            permitted = EXPECTED_SKIP_CASES.get(identity, 1)
            if skipped_cases[identity] > permitted:
                # THE DECLARATION COVERS A COUNT, NOT AN IDENTITY. Growing a
                # parametrisation into more skipped cases than were declared is
                # a diff now, which is what the comment above claimed and did
                # not deliver.
                unexpected.append(
                    f"{identity} — skipped {skipped_cases[identity]} cases "
                    f"against a declared {permitted}; raise the entry in "
                    "EXPECTED_SKIP_CASES or stop skipping the new parameters"
                )
                continue
            allowed += 1
            skipped_identities.add(identity)
            continue
        unexpected.append(f"{node_id(case)} — {message.strip()}")
    return (
        total, allowed, unexpected, seen_modules, executing_modules,
        skipped_identities,
        unexpected_xfails, errors,
    )


def executed_node_ids(report: Path) -> set[str]:
    """Exact identities that completed without skip, xfail, or collection error."""
    root = ET.parse(report).getroot()
    return {
        node_id(case)
        for case in root.iter("testcase")
        if case.find("error") is None and case.find("skipped") is None
    }


def evaluate(report: Path, pytest_returncode: int) -> int:
    """Decide the verdict from a report. Separated so the refusals are testable.

    `main()` used to hold this inline, so the three paths that make this gate a
    gate -- missing required module, collection below floor, GATE: FAIL -- had
    never once executed under test. The module docstring already said a guard
    whose failure path has never run is a guess about what it would do; only
    `classify` had been separated far enough to act on that.
    """
    (
        total, allowed, unexpected, seen_modules, executing_modules,
        skipped_identities,
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

    missing_pr16 = sorted(PR16_REQUIRED_EXECUTED - executed_node_ids(report))
    if missing_pr16:
        print(NEWLINE + "These PR-16 hostile or real-flow proofs did not execute:" + NEWLINE)
        for name in missing_pr16:
            print(f"  {name}")
        print(
            NEWLINE + "A module floor can be met by unrelated growth. H1-H7 and "
            "the standing real-DevelopmentFlow proof are identity-bound so one "
            "cannot disappear behind another test."
        )
        print(NEWLINE + "GATE: FAIL - a required PR-16 specimen did not execute")
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

    inert = [
        f"{name}: {seen_modules.get(name, 0)} collected, "
        f"{executing_modules.get(name, 0)} executed"
        for name in REQUIRED_MODULES
        if executing_modules.get(name, 0) == 0
    ]
    if inert:
        print(NEWLINE + "These required modules contributed no EXECUTED test:"
              + NEWLINE)
        for entry in inert:
            print(f"  {entry}")
        print(
            NEWLINE + "A skipped test asserts nothing, and a module whose whole "
            "floor is met by declared skips is present, counted, and proving "
            "nothing. Measured on a clean checkout, one required module was "
            "already one deletion away from exactly that."
        )
        print(NEWLINE + "GATE: FAIL - a required module executed nothing")
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
            # BOUNDED. The census spawns the whole suite; an unbounded child
            # here means the gate itself can hang, and a gate that never
            # returns is indistinguishable from one nobody ran.
            timeout=14400,
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
