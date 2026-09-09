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
    # The standing-obligation checker's symlink refusals, the same fixture
    # limit as the four above.
    "tests/test_standing_development_obligations.py::test_an_overlay_symlink_that_resolves_into_the_repository_is_refused":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_an_overlay_symlink_inside_the_repository_pointing_outside_is_refused":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_a_symlink_loop_overlay_is_refused_without_a_traceback":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_a_disposition_symlink_under_the_runtime_root_pointing_outside_is_refused":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_a_symlink_chain_that_passes_through_the_repository_is_refused":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_a_link_reached_through_a_directory_symlink_into_the_repository_is_refused":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_a_fifo_overlay_is_refused_without_blocking":
        "A FIFO fixture needs os.mkfifo, which a Windows workstation does not have. The property is not weakened: every CI test job runs Linux and executes it, and the single-descriptor read it exercises is the same code path every other overlay test runs.",
    "tests/test_standing_development_obligations.py::test_a_directory_symlink_chain_through_the_repository_is_refused":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_a_double_slash_spelling_of_a_symlink_target_is_judged":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_a_link_retargeted_between_the_walk_and_the_open_is_refused":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_a_file_replaced_by_an_in_repository_link_after_the_walk_is_refused":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_the_identity_traversal_follows_no_link_and_is_bounded":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    "tests/test_standing_development_obligations.py::test_nothing_beyond_an_unfollowed_link_is_consulted":
        "Symlink fixtures cannot be built on a Windows workstation without elevation. The property is not weakened: every CI test job runs Linux and executes these twelve, and the in-repository refusal they exercise is also held by test_an_overlay_inside_the_repository_is_refused, which runs on every platform.",
    # The standing-obligation checker's junction refusals: real junctions,
    # Windows only, run where they exist.
    "tests/test_standing_obligations_windows.py::test_a_real_junction_is_an_unsupported_link_and_a_plain_directory_is_not":
        "Directory junctions exist only on Windows, so these six build nothing here. The property is not weakened: the windows-runtime CI job runs tests/test_standing_obligations_windows.py and refuses a skip, so every one of them executes on the platform it concerns; the classifier they exercise is also held on every platform by test_every_reparse_point_that_is_not_a_symlink_is_an_unsupported_link over fake lstat results.",
    "tests/test_standing_obligations_windows.py::test_a_junction_chain_through_the_repository_is_refused":
        "Directory junctions exist only on Windows, so these six build nothing here. The property is not weakened: the windows-runtime CI job runs tests/test_standing_obligations_windows.py and refuses a skip, so every one of them executes on the platform it concerns; the classifier they exercise is also held on every platform by test_every_reparse_point_that_is_not_a_symlink_is_an_unsupported_link over fake lstat results.",
    "tests/test_standing_obligations_windows.py::test_a_junction_inside_the_repository_pointing_outside_is_refused":
        "Directory junctions exist only on Windows, so these six build nothing here. The property is not weakened: the windows-runtime CI job runs tests/test_standing_obligations_windows.py and refuses a skip, so every one of them executes on the platform it concerns; the classifier they exercise is also held on every platform by test_every_reparse_point_that_is_not_a_symlink_is_an_unsupported_link over fake lstat results.",
    "tests/test_standing_obligations_windows.py::test_a_junction_that_never_touches_the_repository_is_still_refused":
        "Directory junctions exist only on Windows, so these six build nothing here. The property is not weakened: the windows-runtime CI job runs tests/test_standing_obligations_windows.py and refuses a skip, so every one of them executes on the platform it concerns; the classifier they exercise is also held on every platform by test_every_reparse_point_that_is_not_a_symlink_is_an_unsupported_link over fake lstat results.",
    "tests/test_standing_obligations_windows.py::test_a_namespace_spelling_of_an_in_repository_path_is_refused":
        "Directory junctions exist only on Windows, so these six build nothing here. The property is not weakened: the windows-runtime CI job runs tests/test_standing_obligations_windows.py and refuses a skip, so every one of them executes on the platform it concerns; the classifier they exercise is also held on every platform by test_every_reparse_point_that_is_not_a_symlink_is_an_unsupported_link over fake lstat results.",
    "tests/test_standing_obligations_windows.py::test_a_plain_external_overlay_is_admitted_through_the_whole_cycle":
        "Directory junctions exist only on Windows, so these six build nothing here. The property is not weakened: the windows-runtime CI job runs tests/test_standing_obligations_windows.py and refuses a skip, so every one of them executes on the platform it concerns; the classifier they exercise is also held on every platform by test_every_reparse_point_that_is_not_a_symlink_is_an_unsupported_link over fake lstat results.",
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
    # The Windows 8.3 short name is produced by a Windows API on a volume that
    # generates short names; off Windows there is nothing to compare, and the
    # two sibling tests (None for a missing path on every host; None off
    # Windows via the platform-name seam) run everywhere. Declared here so
    # the Linux census can name the skip by identity; on a Windows workstation
    # with 8.3 generation enabled the test executes and this exemption is
    # reported unused, which is the platform-dependent shape the census
    # already tolerates for the POSIX-only proofs. The skip's precondition is
    # asked of the API directly, not of the function under test, so a
    # `_short_path_name` that answers None on a volume that generates short
    # names FAILS the test there rather than turning it into this skip.
    "tests/test_independent_inspection.py::test_short_path_name_is_the_real_8_3_form_on_windows":
        "GetShortPathNameW is a Windows API, and a volume may have 8.3 generation disabled; the test asks the API directly whether a short form exists and skips only when the API is absent or yields none. The property is not weakened: the missing-path and off-Windows None branches run on every host, and the real 8.3 form is exercised on any Windows workstation whose volume generates one.",
    # Parity repair round six (security F-1 and F-2). `CreateProcess` is the
    # only spawn API that answers error 206 for an over-long EXECUTABLE PATH,
    # and its 32767-character command-line bound is the only bound the
    # adapters' WINDOWS_COMMAND_LINE_LIMIT can be held against by a real
    # spawn. Off Windows there is nothing to spawn against, so these three
    # skip there and the Linux census names them by identity; on a Windows
    # workstation they execute and the exemptions are reported unused, the
    # platform-dependent shape the census already tolerates for the 8.3 test
    # above. The property is not weakened: the classifier's rule -- a 206 is
    # the length refusal only when the computed line exceeds the bound --
    # runs on every host over synthesised 206s on either side of the bound in
    # both adapter suites' classifier tests.
    "tests/test_provider_contract.py::test_an_over_long_executable_path_is_unavailable_not_a_length_refusal":
        "Only CreateProcess answers error 206 for an over-long executable path, so the real-spawn half of this proof exists on Windows alone; it also skips on a Windows volume without long-path support, which cannot hold the 300-character path. The property is not weakened: the classifier's rule runs on every host over synthesised 206s in both adapter suites' classifier tests.",
    "tests/test_codex_provider.py::test_an_over_long_executable_path_is_unavailable_not_a_length_refusal":
        "Only CreateProcess answers error 206 for an over-long executable path, so the real-spawn half of this proof exists on Windows alone; it also skips on a Windows volume without long-path support, which cannot hold the 300-character path. The property is not weakened: the classifier's rule runs on every host over synthesised 206s in both adapter suites' classifier tests.",
    "tests/test_provider_contract.py::test_the_windows_command_line_limit_is_the_operating_systems_not_a_copy_of_the_rule":
        "The 32767-character bound is CreateProcess's, and the two real spawns that hold WINDOWS_COMMAND_LINE_LIMIT against it (a 32766-character line accepted, 32767 refused with 206) exist on Windows alone. The property is not weakened: the classifier's boundary semantics are held on every host by synthesised specimens on either side of the constant, and the routed tool-list specimen exceeds the bound on both CI platforms.",
    "tests/test_windows_host_runtime.py::test_an_unbearered_stop_against_the_real_child_is_refused_and_leaves_it_serving":
        "Windows-hosted runtime evidence: an un-bearered stop sent to a real child process from a real bundle folder on a Windows host, refused with the record still ready. The property is not weakened: the windows-runtime CI job runs this module on windows-latest with a skip census of its own, so a skip there fails that job rather than passing quietly.",
    # The one unscripted smoke test. It drives `smoke_bundle` against a real
    # `cmd.exe` running a real `start ""` whose grandchild outlives the call --
    # the shape that hung the first operator embedded-interpreter run, and the
    # shape every other test in that module replaces away.
    "tests/test_windows_bundle.py::test_the_smoke_terminates_against_a_launcher_that_detaches":
        "Inherited-handle duplication at CreateProcess is a Windows property: `start \"\"` hands the grandchild duplicates of the parent's handles, and there is nothing to demonstrate on a platform that has no such call. The property is not weakened: the windows-latest CI job runs this module with a skip census of its own, so a skip THERE fails that job rather than passing quietly, and the scripted tests beside it fail everywhere if the driver goes back to holding pipes -- the double reads the `stdout` handle it is passed, which `capture_output=True` does not provide.",
    # A junction is an NTFS directory-shaped reparse point that `is_symlink()`
    # reports False for. POSIX has no such shape -- a symlink to a directory
    # answers True and takes a different branch of `_write_fresh` entirely --
    # so the plant these two rows need cannot be built on the Linux test jobs.
    # This is the ONE exemption Tranche D declares, and it buys nothing that
    # matters: the two DIRECTORY rows of the same parametrisation take the
    # identical branch and execute on every platform, so deleting the repair
    # cannot hide here. Both junction rows execute on a Windows workstation,
    # where the exemptions are then reported unused.
    "tests/test_provider_authority_boundary.py::test_a_crash_inside_the_marker_write_leaves_a_junction_marker_standing":
        "A junction is an NTFS directory-shaped reparse point that is_symlink() reports False for, and POSIX has no equivalent, so this row's plant cannot be built on a Linux job. The property is not weakened: the directory rows of the same parametrisation take the identical branch of _write_fresh and execute on every platform, and both junction rows execute on a Windows workstation.",
    "tests/test_provider_authority_boundary.py::test_an_oserror_inside_the_marker_write_leaves_a_junction_marker_standing":
        "A junction is an NTFS directory-shaped reparse point that is_symlink() reports False for, and POSIX has no equivalent, so this row's plant cannot be built on a Linux job. The property is not weakened: the directory rows of the same parametrisation take the identical branch of _write_fresh and execute on every platform, and both junction rows execute on a Windows workstation.",
    # Round 5 crossed the shape axis with the failure axis. The three whole-function
    # junction rows below need declaring for the same reason as the two above; the
    # two PARAMETRISED identities need declaring too, and round 4 recorded that the
    # census could not do that. It can: `classify` strips `[param]` before matching
    # here, and EXPECTED_SKIP_CASES bounds how many cases one identity may skip.
    "tests/test_provider_authority_boundary.py::test_the_rebuild_leaves_no_readable_instant_at_a_live_junction":
        "A junction is an NTFS directory-shaped reparse point that is_symlink() reports False for, and POSIX has no equivalent, so this row's plant cannot be built on a Linux job. The property is not weakened: _is_directory_entry sends the DIRECTORY rows down the identical branch and those execute on every platform, and all seven junction rows execute on a Windows workstation.",
    "tests/test_provider_authority_boundary.py::test_the_rebuild_leaves_no_readable_instant_at_a_dangling_junction":
        "A junction is an NTFS directory-shaped reparse point that is_symlink() reports False for, and POSIX has no equivalent, so this row's plant cannot be built on a Linux job. The property is not weakened: _is_directory_entry sends the DIRECTORY rows down the identical branch and those execute on every platform, and all seven junction rows execute on a Windows workstation.",
    "tests/test_provider_authority_boundary.py::test_the_wipe_removes_a_dangling_junction_the_worker_left_behind":
        "A junction is an NTFS directory-shaped reparse point that is_symlink() reports False for, and POSIX has no equivalent, so this row's plant cannot be built on a Linux job. The property is not weakened: _is_directory_entry sends the DIRECTORY rows down the identical branch and those execute on every platform, and all seven junction rows execute on a Windows workstation.",
    "tests/test_provider_authority_boundary.py::test_the_marker_write_is_shape_correct_at_every_interior_instant":
        "The shape matrix skips the cells this HOST cannot build, with the operating system's own refusal as the reason. On Windows os.symlink raises [WinError 1314] A required privilege is not held by the client without SeCreateSymbolicLinkPrivilege, so the three symlink shapes skip; on Linux they build and the two junction shapes skip instead. EXPECTED_SKIP_CASES caps this identity at three, which is the larger of the two platform counts, so a fourth skipping parameter is a diff. The predicate these cells would exercise is measured against synthesised attributes in test_the_directory_entry_predicate_answers_the_shapes_this_host_cannot_build.",
    # ROUND 6 followed the removal to the site round 5 created. The authority
    # shape matrix skips the same three symlink cells for the same reason, and
    # its two junction shapes are whole functions for the same reason as the
    # rebuild matrix above: a declaration cannot single out one parameter.
    "tests/test_provider_authority_boundary.py::test_the_neutralisation_fails_closed_at_a_live_junction_authority":
        "A junction is an NTFS directory-shaped reparse point that is_symlink() reports False for, and POSIX has no equivalent, so this row's plant cannot be built on a Linux job. The property is not weakened: _is_directory_entry sends the DIRECTORY rows down the identical branch and those execute on every platform, and all seven junction rows execute on a Windows workstation.",
    "tests/test_provider_authority_boundary.py::test_the_neutralisation_fails_closed_at_a_dangling_junction_authority":
        "A junction is an NTFS directory-shaped reparse point that is_symlink() reports False for, and POSIX has no equivalent, so this row's plant cannot be built on a Linux job. The property is not weakened: _is_directory_entry sends the DIRECTORY rows down the identical branch and those execute on every platform, and all seven junction rows execute on a Windows workstation.",
    "tests/test_provider_authority_boundary.py::test_the_neutralisation_fails_closed_at_every_authority_shape":
        "The shape matrix skips the cells this HOST cannot build, with the operating system's own refusal as the reason. On Windows os.symlink raises [WinError 1314] A required privilege is not held by the client without SeCreateSymbolicLinkPrivilege, so the three symlink shapes skip; on Linux they build and the two junction shapes skip instead. EXPECTED_SKIP_CASES caps this identity at three, which is the larger of the two platform counts, so a fourth skipping parameter is a diff. The predicate these cells would exercise is measured against synthesised attributes in test_the_directory_entry_predicate_answers_the_shapes_this_host_cannot_build.",
    "tests/test_provider_authority_boundary.py::test_the_rebuild_leaves_no_readable_instant_at_any_destination_shape":
        "The shape matrix skips the cells this HOST cannot build, with the operating system's own refusal as the reason. On Windows os.symlink raises [WinError 1314] A required privilege is not held by the client without SeCreateSymbolicLinkPrivilege, so the three symlink shapes skip; on Linux they build and the two junction shapes skip instead. EXPECTED_SKIP_CASES caps this identity at three, which is the larger of the two platform counts, so a fourth skipping parameter is a diff. The predicate these cells would exercise is measured against synthesised attributes in test_the_directory_entry_predicate_answers_the_shapes_this_host_cannot_build.",
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
    # The provider seam: 16 collected at introduction, floor at band(16) = 15,
    # raised to 26 for the Claude UTF-8 decode repair (PA-01 sibling), to 37
    # for the provider-adapter parity round (13 new, 41 total), and to 48 for
    # the parity REPAIR round -- 12 new collected (53 total): deeply nested
    # JSON specimens proving `run()` survives a `RecursionError` out of
    # `json.loads` (array and object shapes, two exit codes each), a
    # directory and a zero-byte executable proving the added `OSError` catch
    # around `subprocess.run`, a lingering mixed-stream specimen closing the
    # timeout branch's unpinned `+ out + err`, three new session_id character-
    # class specimens (NUL, embedded newline, bidi override) plus their
    # direct helper assertions, and a both-streams-malformed specimen pinning
    # no trailing newline. Floor at band(53) = 48. Raised 48 -> 57 for the
    # parity repair ROUND THREE -- 10 new collected (63 total): a NUL in the
    # goal reported not raised, a NUL in the executable name unavailable not
    # raised, three workspace shapes (missing, a file, a NUL) reported as the
    # error class naming the workspace, the two adapters' shared malformed-
    # invocation code and delimiter held equal, a timed-out run with nothing
    # readable carrying no delimiter, the strong-RTL session_id specimen, the
    # ASCII-identifier helper test, and the direct digest-raises test that
    # replaced an inert assertion. Floor at band(63) = 57. Raised 57 -> 60
    # for the parity repair ROUND FOUR -- 3 new collected (66 total): an
    # over-long argument list reported as the error class naming its length
    # (a 1 MB goal through the direct worker), the argument-length classifier
    # exercised on both platforms' refusals (E2BIG, and Windows error 206
    # arriving as errno 2), and the cross-module identity test holding both
    # adapters' session rules and bound equal over the shared specimen table.
    # Floor at band(66) = 60. Raised 60 -> 61 for the parity repair ROUND
    # FIVE -- 1 new collected (67 total): the reported command-line length
    # held to the line the platform counts (the quoted `CreateProcess` line
    # plus its terminator on Windows, the per-argument sum elsewhere),
    # against the function and against a real refusal's sentence. Floor at
    # band(67) = 61. Raised 61 -> 63 for the parity repair ROUND SIX -- 2
    # new collected (69 total): an existing executable at an over-long path
    # (CreateProcess answers the same error 206 as the length refusal) held
    # to the unavailable class under the executable's sentence, and the
    # 32767-character bound held against two real spawns of the operating
    # system rather than against a copy of the rule; the classifier test
    # was rewritten in place to take the command. Both new tests skip off
    # Windows by declared exemption. Floor at band(69) = 63.
    "tests/test_provider_contract.py": 63,
    # The Codex adapter's conformance: 10 collected at introduction, floor at
    # band(10) = 9. Same harness technique as the Claude conformance,
    # separate proof -- and the two mapping limits pinned, not hidden.
    # Raised 9 -> 12 for the PA-01 UTF-8 specimens, 12 -> 15 for the
    # verifier-repair round, 15 -> 32 for the provider-adapter parity round
    # (19 new, 35 total), and 32 -> 43 for the parity REPAIR round -- 12 new
    # collected (47 total), mirroring the Claude additions exactly: deeply
    # nested JSON (parsed per JSONL line via `_session_from_jsonl`), the
    # directory/zero-byte-executable `OSError` specimens, the lingering
    # mixed-stream timeout specimen, the three new session_id character-class
    # specimens plus their direct helper assertions, and the both-streams-
    # malformed no-trailing-newline specimen. Floor at band(47) = 43. Raised
    # 43 -> 51 for the parity repair ROUND THREE -- 9 new collected (56
    # total), mirroring the Claude additions minus the cross-adapter constant
    # pin (which lives in the contract module): NUL in the goal, NUL in the
    # executable name, the three workspace shapes, the delimiter-free timeout,
    # the strong-RTL specimen, the ASCII-identifier helper test, and the
    # direct digest-raises test. Floor at band(56) = 51. Raised 51 -> 53 for
    # the parity repair ROUND FOUR -- 2 new collected (58 total): the
    # over-long argument list reported as the error class naming its length,
    # mirroring the Claude specimen, and THIS adapter's argument-length
    # classifier exercised on both platforms' refusals in this suite -- added
    # because the round-4 mutation matrix found the Codex E2BIG arm unpinned
    # here (the 1 MB specimen takes the Windows error-206 arm on the Windows
    # host, and the contract module's classifier test is not run against a
    # Codex mutant). The identity test stays in the contract module. Floor at
    # band(58) = 53. Raised 53 -> 54 for the parity repair ROUND FIVE -- 1
    # new collected (59 total): the same command-line-length rule held for
    # THIS adapter's own function and refusal sentence. Floor at
    # band(59) = 54. Parity repair ROUND SIX -- 1 new collected (60 total):
    # the over-long executable path specimen mirrored for THIS adapter
    # (Windows only, by declared exemption); the classifier test rewritten
    # in place to take the command. band(60) = 54, so the floor stands.
    "tests/test_codex_provider.py": 54,
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
    # hardening (the common Host rule, N3), 14 after Tranche B round 4 (the
    # console start link read from stdout: a nonce, not the bearer, redeemed
    # once), 15 after Tranche B round 6 (a LEXICAL pin that the comment beside
    # that print no longer claims the nonce "stays off disk" -- a redirected
    # stdout was measured carrying it to a file and redeeming for the bearer),
    # floor at band(15) = 14. The
    # FORGE_ROOT doctrine held at every layer -- relative directories
    # refused in assemble, main and the launcher alike, the loopback
    # binding pinned -- and the loopback Host rule held on the common
    # composition, on the console path, and by a census of `src/` for any
    # composition that omits it.
    "tests/test_onboarding_launch.py": 14,
    # Provider-routed engineering execution: 9 collected at introduction,
    # floor at band(9) = 9. The default path preserved structurally, the
    # no-silent-fallback rule, and a real flow call site recording the
    # provider that actually ran. Raised 9 -> 12 for the parity repair ROUND
    # THREE -- 4 new collected (13 total): the repair-goal composition driven
    # from a real provider emitting a NUL, through the direct Claude worker
    # and the routed Codex worker
    # (`test_a_nul_in_provider_output_is_escaped_when_composed_into_the_repair_goal`),
    # the exact C0 character set the composition escapes, and a static pin
    # that the flow composes only through `compose_repair_goal`. Floor at
    # band(13) = 12. Raised 12 -> 17 for the parity repair ROUND FOUR -- 5
    # new collected (18 total): one control-heavy gate cannot push the
    # composed goal past the contract (both provider shapes, from a real
    # provider flooding 2500 NULs), four ordinary failing gates compose
    # within the bound while the record does not, each gate's escaped tail
    # bounded on its own, and the bound's relation to the contract's own
    # ceiling; the static composition pin became the behavioural one that
    # drives `acceptance()` with a spy in `compose_repair_goal`'s place.
    # Floor at band(18) = 17. Raised 17 -> 18 for the parity repair ROUND
    # FIVE -- 2 new collected (20 total): a routed task with a short goal
    # and a long tool list reaches the adapters' argument-length branch on
    # both adapters, which `ProviderTask.validate` does not prevent (it
    # bounds the goal, not the tool list or the workspace). Floor at
    # band(20) = 18. Raised 18 -> 20 for Tranche B ROUND SIX -- 2 new
    # collected (22 total): the routed provider process, on BOTH routes, is
    # handed an environment carrying no FORGE_* and no bare FORGE, read back
    # from what the child actually received. `_provider_env()` was pinned only
    # in tests/test_control_plane_session.py, which the windows-runtime CI job
    # does not run, so on that job the stripping was asserted by nothing.
    # ROUND SEVEN completed that move: the job did not run THIS module either
    # when round six wrote the sentence above, so the pin was still Linux-only
    # (round-6 test T-P3-2); `.github/workflows/ci.yml` now names it in the
    # windows-runtime module list -- and 1 new collected (23 total) reads that
    # list. ROUND EIGHT corrects what that reader read: it asked whether the
    # module's path appeared anywhere in the job BLOCK, which the YAML comment
    # round seven added to that block satisfied on its own, so removing the
    # module from the pytest command left it green (round-7 finding F-1). It
    # now reads the `python -m pytest` invocation line, with the comment-only
    # job built in the test as the specimen it must refuse. Floor at
    # band(23) = 21.
    "tests/test_provider_execution.py": 21,
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
    # included, and against a hostile listener on its scratch port). Tranche B
    # added the smoke's bearer (three tests) and its repair round the fence
    # position of the smoke's session file (49 collected); round 4 added the
    # two-segment request witness and the 200-exchange no-reset witness for
    # the listener helper behind the CI failure: 51 collected, floor at
    # band(51) = 46. Round 5 replaced the "no bearer sent" specimen with the
    # pair that pins the smoke's session-file WAIT -- a runtime writing the
    # file 300 ms after readiness, and one that never writes it -- and the
    # `session_file` observation is required, so a missing bearer is named
    # once: 52 collected, floor at band(52) = 47. Round 6 made that wait's
    # ordering an EVENT rather than a reading of `time.monotonic()` (15.6 ms
    # on Windows <= 3.12, which put 46 of 300 reads of a 0.3 s wait under
    # 0.3 and failed the module 2 of 9 unmutated runs), gave the "never
    # arrives" case the budget witness its docstring had been claiming
    # without one, and added the guard that the smoke contract counts the
    # observations it lists: 53 collected, floor at band(53) = 48. Raised
    # 48 -> 49 for the launcher-pipe repair: ONE new test, and the only one in
    # this module that replaces nothing -- it drives `smoke_bundle` against a
    # real detaching launcher, which is the path the scripted 53 had never
    # executed and where the hang lived. 54 collected, band(54) = 49.
    "tests/test_windows_bundle.py": 49,
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
    # and capsule authority persisting across a runtime restart. Tranche B and
    # its repair round added the control-plane session over the REAL runtime
    # (57 collected): the nonce bootstrap and the
    # secrets absent from record, log, trail, page, identity and every
    # response header, on the browser-failure branch too; the two-slot reopen,
    # its 409 under --no-browser and the joiner's notices; the session-file
    # fence and its after-readiness ordering; the access log off; and a
    # flood of non-ASCII credentials leaving no traceback. Round 3 added the
    # owner-failure 503 across four exception shapes and the joiner told of
    # it, a handler's own exception class on the browser-failure branch, the
    # pre-existing session file left as found, and the fence resolving the
    # runtime directory itself (64 collected). Round 4 added the `\\?\`,
    # `\\.\`, `//?/` and UNC spellings of every fenced root over real
    # launches that create nothing, the `[seal]` case on a seal directory of
    # its own, the namespace-prefix specimens on the fence function, the 8.3
    # and junction aliases, the trailing dot and space, and an adapter whose
    # `__str__` raises on both failure branches: 76 collected, floor at
    # band(76) = 69. Round 5 added the two POST-RESOLUTION fence witnesses
    # through the candidate-resolution seam (a plain spelling that RESOLVES
    # prefixed, on the session file and on the runtime directory: both blocks
    # had been deletable with the module green), the embedded-NUL notice on
    # both caller-supplied operands, and the join path's own `_said`
    # specimen: 80 collected, floor at band(80) = 72. Round 6 rebuilt that NUL
    # case as the four combinations its CI failure demanded -- both
    # resolutions (`Path.resolve`, which raises on <= 3.12, and the 3.13 shape,
    # which answers) crossed with the candidate under the relocated profile and
    # outside it -- over all THREE fenced operands, with a control that the two
    # resolutions really differ here; and added the witness that the fenced
    # ROOTS are resolved for real and never through the candidate seam, plus
    # specimens for the assembly-failure and session-file `_said` sites, which
    # no test referenced: 87 collected, floor at band(87) = 79. Round 7 added
    # ONE: `launch`'s own fenced roots -- the seal directory and the candidate
    # project -- get the aliasing-resolver witness the session-file fence got
    # in round 6, because routing them through the candidate seam had survived
    # all 87 of the above (round-6 test T-P3-3). The NUL case gained a FOURTH
    # operand, `--bundle-root`, inside the cases it already had. 88 collected,
    # floor at band(88) = 80. The session-file visibility repair added FOUR:
    # the final path never observable with partial content under a slow write,
    # the move refusing a target already there while a taken STAGING name is a
    # different fact, no staging file outliving a placement that succeeded or
    # failed, and the scripted wait holding until the bearer PARSES rather than
    # until the file exists. 92 collected, floor at band(92) = 83. That
    # repair's second round added FOUR more on the same function: a target
    # already there refused before any bearer reaches disk (`os.open` never
    # called) while the MOVE still refuses one that appears after the check,
    # the move's 20 x 50 ms sharing-violation retry, a staging name taken
    # after a successful move left alone rather than deleted, and every
    # placement failure naming the file it could not use. 96 collected, floor
    # at band(96) = 87. The record-read transient repair added ONE: a read that
    # lands inside the record's whole-file-replace window, widened by an
    # adversarial writer, must leave both two-channel waits taking another turn
    # rather than raising `TypeError: 'NoneType' object is not subscriptable`
    # -- which is what the windows-runtime job did on `main` at dabaade.
    # 97 collected, floor at band(97) = 88.
    "tests/test_windows_runtime.py": 88,
    # Tranche B's control-plane session: 43 collected at introduction, 77 after
    # the repair round, 80 after round 3 (the allowlisted routes ignoring
    # cookies, the owner-failure 503 on the composed surface, the page's CSP
    # pinned lexically), 97 after round 4 (the AST pin over verify AND redeem,
    # the reopen queue -- A/B/C at the session and on the wire under an
    # injected clock, bound, expiry, the derivation joining the two
    # constants -- the default TTL through create_app's own session, the
    # near-miss census, the read-only refusal bodies, the redeem cache
    # headers, the bare FORGE drop, the raising __str__ adapter, and the
    # architecture gate's forbidden entry proved by injection), 98 after
    # round 5 (the comparison detector's own positive and negative controls,
    # once it was taught to read a comparison written as a CALL), floor at
    # band(98) = 89. The gate over the bare and the
    # COMPOSED surface (every method on every route against a hardcoded
    # allowlist, state bytes and lifecycle unchanged, stop never requested),
    # the token and two-slot nonce unit (TTL, constant-time over bytes, the
    # credential alphabet), strict bearer parsing and every partial bearer
    # refused, the redeem and reopen browser-provenance checks with Origin
    # serialization specimens, websocket and unknown scopes refused, a gate
    # that cannot raise, the docs routes off, the echo-free refusals, every
    # response's headers against a declared set, and the provider exclusion
    # over the real build route with the REAL flow and a fake provider process.
    # Raised 89 -> 90 for ROUND SEVEN -- 1 new collected (99 total): the
    # comparison detector reads the IMPORT, and a per-method AST pin cannot
    # see a module-scope alias at all, so the binding is forbidden at every
    # scope of the module (round-6 test T-P3-1, where
    # `from operator import eq as _same` survived all 98). ROUND EIGHT --
    # 1 new collected (100 total): a comparison helper DEFINED at module scope
    # is neither an operator inside the method nor an import, and
    # `def _same(a, b): return a == b` called from `verify` survived all 99
    # (round-7 finding F-2(b)); the new test enumerates exactly which
    # module-scope callables `verify` and `redeem` reach and exactly what the
    # one they do reach compares. Floor UNCHANGED at band(100) = 90, which
    # band(99) already was.
    "tests/test_control_plane_session.py": 90,
    # Tranche C, slice C2: the real-surface control-plane probe harness. 48
    # collected after the second review round (19 at introduction), floor at
    # band(48) = 44. The route table held equal to the served composition in
    # process (a Mount or a WebSocketRoute reddens it) and the wire census
    # over a real port; the in-process self-probe classifying itself
    # admitted_nuisance with principal_separated not_separated and explaining
    # why that is not confinement, its memory handle not_applicable on its
    # own pid, and a cross-process CLI witness against the same surface; the
    # classifier deriving allowlist membership from the constant, refusing a
    # partial log a confined state, and letting a gated 2xx dominate; the
    # record validator refusing a non-socket transport (M6), a socket fact
    # mislabelled as an inference (M6), a state, reason or coverage that
    # disagrees with its own log (M8), a surface-absent record claiming a
    # state (M8), `unreachable` by name, `separated` from C2, an incomplete
    # subject, a declared instance match, a fabricated positive control, a
    # host identity in the clear, a bearer, and an artefact reporting a pass
    # -- and the one bound it cannot refuse (a self-declared transport label)
    # measured and stated; redaction, the artefact producers, the absolute
    # system executables, the loopback host rule, the deadline, the exit
    # codes and the no-provider/no-synchronous-launch property each pinned.
    # The Windows-only artefact facilities degrade to not_applicable off
    # Windows, so the module runs on every CI platform with no declared skip.
    # 68 after the THIRD review round, floor at band(68) = 62. Twenty more:
    # nine hostile `/api/runtime` bodies through a real loopback listener (a
    # `pid` of the wrong type used to reach `int(pid)` and end the run in a
    # traceback), every refusal `main()` can reach held to exit 4 on one
    # stderr line naming no path, an `--out` inside the working tree refused,
    # the redaction backstop matching a JSON-ESCAPED home path (the only shape
    # it ever sees), a lexical sweep of the module source for this host's
    # login and machine name and their 8.3 forms, `Deadline.budget` as
    # arithmetic and the subject-binding subprocesses held to it, a deadline
    # expiring AFTER the matrix recorded and counted and inconclusive, the
    # `refused` artefact outcome on both branches that used to say `observed`
    # for a denial, the drive-absolute PATH rule, `localhost` normalised to
    # the address it names, the surface-absent rule's own shape, and the
    # `echoed` field asserted for the first time.
    "tests/test_control_plane_authority.py": 66,
    # PR-18's Windows-hosted evidence: 10 collected after the inspections
    # (the journey once per declared provider, and the one test that runs
    # everywhere and pins the windows-runtime job), 11 after Tranche B
    # round 3 added the un-bearered stop against the real child (refused,
    # record still ready, log clean), 12 after round 5 added the harness's
    # own dead-child pin -- the second test here that runs on every platform,
    # because it is a property of the harness and starts no runtime -- and 13
    # after the session-file visibility repair added the THIRD such pin: the
    # wait holds until the bearer PARSES, not merely until the file exists,
    # which is the window the job's one `401` at PR #46's head came through.
    # Floor at band(13) = 12. 14 after that repair's second round added the
    # FOURTH platform-independent pin here: the windows job's collected-count
    # floor, derived from a live collection of the modules the job's own
    # command names, after the floor and the sentence beside it drifted apart
    # and the whole of THIS module could have vanished from the job unnoticed.
    # Floor at band(14) = 13.
    # Real child processes from a real bundle folder at a path with spaces
    # and non-ASCII characters, from an unrelated working directory;
    # declared skips off Windows, run by the windows-runtime CI job under
    # its own skip census.
    "tests/test_windows_host_runtime.py": 13,
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
    # rebuild, and the thread-start lock release. Raised 32 -> 37 for
    # Tranche D, the seal re-proof -- 6 new collected (41 total): the three
    # marker states of a crash inside `_rebuild`, which used to leave the
    # store permanently readable as legacy; the write-order gap, which had
    # no coverage at all; the refusal and the persisted history reporting
    # what they measured rather than naming an actor; and the marker trust
    # basis as an implication over the eligibility decision. Round 2 of that
    # review made the last of those a BICONDITIONAL -- the implication could be
    # spent in advance -- and added the fourth crash instant that demands the
    # marker hoist plus four rows pinning that the recovery path writes no
    # bytes through a planted link: 41 -> 46, band(41) = 37 -> band(46) = 42.
    # Round 3 added the instant those five rows could not reach -- INSIDE the
    # seal marker's own write, where round 2's remove-then-write reopened the
    # fall-open its own hoist had just closed -- in both forms, a crash and a
    # durable OSError: 46 -> 48, band(46) = 42 -> band(48) = 44.
    # Round 4 added the SHAPES those two rows could not reach. Both plant an
    # ordinary FILE at the marker, where `os.replace` does the whole job; a
    # DIRECTORY or a JUNCTION has to be removed first, and round 3 removed it
    # where the old code did -- before the temp existed -- so for those two
    # shapes its own repair left standing the fall-open it had just closed.
    # Four rows, two shapes by two forms, plus two pinning the cleanliness
    # exemption that stops Forge's own crash residue reading as tamper and the
    # matcher that recognises it: 48 -> 54, band(48) = 44 -> band(54) = 49.
    # Round 5 crossed the two axes rounds 3 and 4 had enumerated apart: ten
    # destination shapes by four interior instants of `_write_fresh` by two
    # failure forms, and the same ten shapes by five interior instants of
    # `_rebuild`. Plus the wipe's own copy of the predicate, the call-order
    # trace, the ordinary-reader row and the stray that a save makes tracked:
    # 54 -> 79, band(54) = 49 -> band(79) = 72.
    #
    # Round 6 took the cross product to the removal site round 5 created, at
    # the AUTHORITY paths: twelve shapes (the ten above plus a read-only
    # hardlink and a held handle) crossed with both authority names and with
    # {clean, handled OSError, process death}, as ten parametrised rows and
    # two junction functions. Plus the read-only recoverability row, the
    # second-removal-raises row, and two rows on the best-effort marker write
    # -- that it never masks the real error, and that it never spends the
    # protection it defends. 79 -> 95, band(79) = 72 -> band(95) = 86.
    #
    # Round 7 adds ONE row and no shapes:
    # `test_the_exclusive_create_fallback_writes_the_markers_exact_bytes`,
    # which asserts the bytes of the exclusive-create fallback -- the one write
    # in that module outside the byte-exact idiom, and the one no row was
    # watching. It never skips, on any platform. 95 -> 96, band(95) = 86 ->
    # band(96) = 87, so the module's own slack is 9 either way and the total
    # the bands grant does not move.
    #
    # Tranche E adds SIX rows and no shapes, in the module that already holds
    # the seal boundary because the process witness is that boundary's freshness
    # question: the adapter-level rollback of store and seal together, the same
    # attack through the shipped surface with its human restoration, the
    # no-false-positive sweep over every writing route, the cross-restart limit
    # pinned in the affirmative against the disclosure it names, the closed
    # currency/continuity vocabulary, and the page's own words. None of them
    # skips on any platform -- a byte-for-byte copy of two directories needs no
    # junction and no symlink. 96 -> 102, band(96) = 87 -> band(102) = 92: the
    # module-floor SUM rises by five, while the slack this module contributes
    # rises by one (9 at 96, 10 at 102), because `ceil(0.9n)` moved by five
    # where the module moved by six. The two are different quantities and the
    # comment beside `MINIMUM_COLLECTED` states each of them separately.
    #
    # ONE MAINTENANCE ROW after Tranche E, for a race this module's own rollback
    # helper hit in CI on 3.11: `_remove_tree` died with `FileNotFoundError` on
    # `.git/objects/7f`, a fanout directory that was there when `rmtree` listed
    # the store and gone when it visited it. The handler chmod'd the vanished
    # path and raised out of `rmtree`. It never skips -- the vanishing is
    # injected at the listing, not raced, so it needs no threads and no
    # platform. 102 -> 103, band(102) = 92 -> band(103) = 93: the module-floor
    # sum rises by one and so does the module, so the slack it contributes is 10
    # either way and the total the bands grant does not move.
    "tests/test_provider_authority_boundary.py": 93,
    # Declared is not eligible (R1-R3 of the independent review): 16
    # collected at introduction, floor at band(16) = 15. The governed build
    # refusing both declared providers before anything executes, no
    # fallback, the Forge-owned decision pinned in the served composition,
    # the seam's own eligibility, the protected-store-without-seal refusal
    # and the legacy distinction.
    "tests/test_governed_provider_eligibility.py": 15,
    # PA-01's admission criterion: 38 collected before Tranche C, 66 after
    # slice C1 replaced one criterion, floor at band(66) = 60. The 28 new hold
    # the replacement itself: that `control_plane_authority` is required
    # `denied` and `control_plane_reachability` is gone from the criterion but
    # kept as data (historical evidence still spells its probes with it and
    # must stay loadable); that only a record of Forge's own gated surface is
    # competent for it, a controlled test listener included; the whole
    # state-to-outcome mapping including the separation conditional; that both
    # providers stay ineligible with the refusal naming the missing property
    # rather than an approval; and the strictly-stronger obligation measured
    # over the repository's own recorded probes in both directions -- the
    # retired criterion's required outcome entails the successor's, the
    # entailment never runs backwards, and it still does not ADMIT anything.
    # Round 2 added 5 for the criterion review's finding: the mapping table is
    # parametrised from the contract's state list in both directions, only
    # `unreachable` may answer the required outcome without a measured
    # separation, the conditional is asserted over BOTH states it covers, the
    # documents claiming the widening is guarded are pinned to the guarded set
    # the mapping is measured to have, and the witness selection is read
    # structurally for any retired name.
    # C3 round 2 added 9 more, all closing the same defect class -- a label
    # standing where a measurement belonged: the derived cross-product cells
    # over the producer's own state tuple, the unanswered-log case that makes
    # `attempt_observed` derived rather than declared, the C3 document's three
    # tables held row by row to the record under them, the measured counts held
    # across four documents and the contract's docstring, the two shipped
    # platform spellings refusing to combine, and five type refusals (a status
    # that is not an integer, a route that is not a pair of strings) that used
    # to fail open or raise `TypeError`. Floor at band(106) = 96.
    "tests/test_codex_confinement_admission.py": 96,
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
    # Raised 175 -> 180 for TRANCHE I, the real embedded-interpreter run:
    # docs/governance/EMBEDDED_INTERPRETER_RUN.md entered the document sweep
    # (199 collected, band(199) = 180). This module PARAMETRISES over the
    # governance documents, so it gained nothing of its own -- a doc is a test
    # here, and a tranche that adds one owes the census the same update a new
    # module does.
    # Raised 180 -> 184 for the STANDING-OBLIGATION ADMISSION mechanism:
    # docs/governance/STANDING_DEVELOPMENT_OBLIGATIONS.md entered the document
    # sweep (204 collected, band(204) = 184). Same shape as Tranche I: a
    # governance document is a test here.
    "tests/test_recorded_measurements.py": 184,
    # The standing-obligation checker: 82 collected at introduction, 103 after
    # the in-session adversarial review round, 106 after the Codex review of
    # the merged head (the directory-link chain, the count-free output, the
    # uninspected reason stated), floor at band(106) = 96.
    # Registry validity and duplicate refusal; the closed disposition
    # vocabulary and field sets; digest binding and staleness; exact
    # coverage; `defer` only for a deferred item; no discovery under planted
    # decoys, with the structural lint stated as a lint; the in-repository
    # overlay refusal as given, at every component and link and after
    # resolution; and the sentinel sweep over every output, file, refusal and
    # refusal context on the failure paths -- a symlink loop, a chain through
    # the tree, a directory-link chain, a FIFO, invalid UTF-8, a repeated JSON
    # key, a trailing line break in an identifier, an unhashable value, a
    # deeply nested document, a repeated option, a stray argument,
    # twenty-three malformed shapes.
    "tests/test_standing_development_obligations.py": 133,
    "tests/test_standing_obligations_windows.py": 7,
    "tests/test_approval_reachability.py": 17,
    "tests/test_approval_ledger.py": 65,
    # Protected because Lens B measured 103 tests of slack in the aggregate
    # floor, and named these two: the evidence-binding proofs and the sole
    # regression for the reachability probe were both deletable.
    "tests/test_evidence_binding.py": 19,
    "tests/test_clause_reachability.py": 7,
    "tests/test_reviewer_authentication.py": 25,
    # Raised 16 -> 17 for the provider-adapter parity round: the
    # home-relative reviewer-trust-store-path specimen (18 collected),
    # floor at band(18) = 17. Raised 17 -> 22 for the parity REPAIR round --
    # 6 new collected (24 total): five direct store-path rendering specimens
    # (lowercase drive/user, an 8.3 short name, a different user, a
    # different drive, the POSIX shape) and one static regression grepping
    # the COMMITTED evidence tree for the reader's login name, machine name,
    # and host-path patterns. Floor at band(24) = 22. Raised 22 -> 37 for the
    # parity repair ROUND THREE -- 17 new collected (41 total): the case seam
    # pinned to `os.path.normcase` and BOTH of its behaviours exercised on
    # every host (Windows folds case, POSIX does not), the after-home boundary,
    # five whole-token redaction specimens (a space, parentheses, UNC in two
    # spellings, a POSIX space) plus the under-home space, the home-forms
    # assembly, three `_short_path_name` tests (one of which skips off
    # Windows -- declared below), and the leak detector's known-positive and
    # known-negative controls with the committed-evidence sweep run under the
    # CI runner's identity too
    # (`test_committed_evidence_is_clean_for_the_ci_runners_identity_too`).
    # Floor at band(41) = 37.
    "tests/test_independent_inspection.py": 37,
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
    # TWO, on a Windows workstation: the two link shapes -- a directory link
    # and a file link retargeted between the walk and the open -- are one
    # parametrised identity, and both need a symlink. On Linux neither skips.
    "tests/test_standing_development_obligations.py::test_a_link_retargeted_between_the_walk_and_the_open_is_refused": 2,
    # THREE, and three is the LARGER of the two platform counts rather than a
    # sum: on Windows the three symlink shapes skip, on Linux the two junction
    # shapes do. A cap of two would fail the Windows workstation and a cap of
    # five would let three new parameters start skipping unnoticed.
    "tests/test_provider_authority_boundary.py::test_the_marker_write_is_shape_correct_at_every_interior_instant": 3,
    # The rebuild matrix excludes the junction shapes -- they are whole
    # functions, because a declaration cannot single out one parameter -- so
    # this identity skips three on Windows and none on Linux.
    "tests/test_provider_authority_boundary.py::test_the_rebuild_leaves_no_readable_instant_at_any_destination_shape": 3,
    # The authority-path matrix carries twelve shapes rather than ten -- a
    # read-only hardlink and a held handle, which are the two the read-only
    # retry must REFUSE and the two the best-effort marker write exists for --
    # but it skips the same three symlink cells and no more, because the two
    # extra shapes build on every platform.
    "tests/test_provider_authority_boundary.py::test_the_neutralisation_fails_closed_at_every_authority_shape": 3,
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
# The module-floor sum rises by 26 and the aggregate follows. Re-measured
# again for the PA-01 VERIFIER REPAIR, which is where the discrimination
# suite actually grew: closing the three founder-review findings took
# tests/test_codex_confinement_admission.py from 19 to 38 collected (floor
# 18 -> 35) and the malformed-UTF-8 specimens took
# tests/test_codex_provider.py from 13 to 16 (floor 12 -> 15). No module
# was added, so the count stays at 111; the module-floor sum rises by 20
# and the aggregate follows. Re-measured for the Claude adapter's UTF-8
# decode repair, the PA-01 sibling: 12 new collected in
# tests/test_provider_contract.py (16 -> 28; three valid typographic
# specimens, six malformed ones -- three payloads on each of the two
# streams, because review found the stderr half of the decode branch
# had no specimen -- the failure-vocabulary check, the carriage-return
# specimen, and the timed-out malformed stream that must still be
# fingerprinted), floor 15 -> 26 at its band. No module added, so
# 111 stands; the module-floor sum rises by 11 and the aggregate follows.
# Re-measured for the provider-adapter parity round: 19 new collected in
# tests/test_codex_provider.py (16 -> 35; the timeout branch now
# fingerprints a failed stream, closing A-025's open item; both-stream
# malformed parametrization and the carriage-return specimen mirrored from
# Claude via the new shared tests/provider_specimens.py; the stderr
# valid-UTF-8 fallback; readable-sibling-kept specimens on the
# completed-process branch, both adapters; session_id validation specimens
# and their direct unit test; the recomputed-offset and real-exit-code
# pins; and the direct `_decode`/`_fingerprint` type-refusal tests), floor
# 15 -> 32 at its band; 13 more in tests/test_provider_contract.py
# (28 -> 41; the Claude-side half of the same additions), floor 26 -> 37 at
# its band; and 1 more in tests/test_independent_inspection.py (17 -> 18;
# the home-relative reviewer-trust-store-path specimen, closing a
# host-specific absolute path that had reached committed governance
# evidence), floor 16 -> 17 at its band. No module added, so 111 stands;
# the module-floor sum rises by 29 and the aggregate follows. Re-measured for
# the provider-adapter parity REPAIR round, closing three independent
# reviewers' findings against b52abd7: 12 new collected in
# tests/test_provider_contract.py (41 -> 53; deeply nested JSON specimens
# proving `run()` survives a `RecursionError`, a directory and a zero-byte
# executable proving the added `OSError` catch, a lingering mixed-stream
# timeout specimen, three session_id character-class specimens plus their
# direct helper assertions, and a both-streams-malformed no-trailing-newline
# specimen), floor 37 -> 48 at its band; 12 more in
# tests/test_codex_provider.py (35 -> 47; the same additions mirrored),
# floor 32 -> 43 at its band; and 6 more in
# tests/test_independent_inspection.py (18 -> 24; five direct store-path
# rendering specimens, against the helper then called `_home_relative` and
# since replaced by `_store_display` -- lowercase drive/user, an 8.3 short
# name, a different user, a different drive, the POSIX shape -- and one static
# regression grepping the COMMITTED evidence tree for the reader's login
# name, machine name, and host-path patterns), floor 17 -> 22 at its band.
# No module added, so 111 stands; the module-floor sum rises by 27 and the
# aggregate follows. Re-measured for the parity repair ROUND THREE, closing
# the second model-only bounded review against dce970a (two of whose findings
# would have turned the Linux CI matrix red): 10 new collected in
# tests/test_provider_contract.py (53 -> 63; NUL in the goal and in the
# executable name, three workspace shapes, the shared malformed-invocation
# code and delimiter, the delimiter-free timeout, the strong-RTL and
# ASCII-identifier session_id specimens, the direct digest-raises test),
# floor 48 -> 57 at its band; 9 more in tests/test_codex_provider.py
# (47 -> 56; the same minus the cross-adapter pin), floor 43 -> 51; 17 more
# in tests/test_independent_inspection.py (24 -> 41; the case seam exercised
# under both platforms' rules, the boundary, whole-token redaction specimens,
# the home-forms assembly, the short-name tests, and the leak detector's
# positive and negative controls -- the CI-red login-as-substring defect is
# pinned by the NEGATIVE control,
# `test_the_leak_detector_stays_silent_on_a_login_that_is_inside_a_word`
# (a bare-substring detector fires on `runner` inside `gate_runner` there,
# and on the committed tree under the CI runner's identity), while its
# positive sibling
# `test_the_leak_detector_fires_on_the_json_escaped_windows_shape` pins the
# doubled-backslash shape), floor 22 -> 37; and 4 more in
# tests/test_provider_execution.py (9 -> 13; the repair-goal composition
# driven from a real provider emitting a NUL), floor 9 -> 12. No module
# added, so 111 stands; the module-floor sum rises by 35 and the aggregate
# follows. Re-measured for the parity repair ROUND FOUR, closing the third
# model-only bounded review against 60c4374 (the composed repair goal
# bounded under the contract, the over-long argument list classified, the
# 8.3 test's precondition asked of the API, the composition pin made
# behavioural): 3 new collected in tests/test_provider_contract.py
# (63 -> 66), floor 57 -> 60; 2 more in tests/test_codex_provider.py
# (56 -> 58; the second added when the round-4 mutation matrix found the
# Codex E2BIG arm unpinned in that suite), floor 51 -> 53; 5 more in
# tests/test_provider_execution.py (13 -> 18), floor 12 -> 17;
# tests/test_independent_inspection.py stays at 41 (the 8.3 test was
# rewritten in place). No module added, so 111 stands; the module-floor sum
# rises by 10 and the aggregate follows. Re-measured for the parity repair
# ROUND FIVE, closing the fourth model-only bounded review (the routed
# path's reachability of the argument-length branch pinned, the reported
# length made the line the platform counts): 1 new collected in
# tests/test_provider_contract.py (66 -> 67), floor 60 -> 61; 1 more in
# tests/test_codex_provider.py (58 -> 59), floor 53 -> 54; 2 more in
# tests/test_provider_execution.py (18 -> 20), floor 17 -> 18. No module
# added, so 111 stands; the module-floor sum rises by 3 and the aggregate
# follows. Re-measured for the parity repair ROUND SIX, closing the fifth
# model-only bounded review against 6ea2a09 (Windows error 206 shared
# between the length refusal and an over-long executable path, the arm
# gated on the computed line exceeding the bound, the bound held against
# the operating system): 2 new collected in tests/test_provider_contract.py
# (67 -> 69), floor 61 -> 63; 1 more in tests/test_codex_provider.py
# (59 -> 60), floor unchanged at band(60) = 54;
# tests/test_provider_execution.py stays at 20. No module added, so 111
# stands; the module-floor sum rises by 2 and the aggregate follows.
# Re-measured for the Tranche B control-plane session and its
# repair round together: a new module tests/test_control_plane_session.py
# collects 77 (floor at band(77) = 70), tests/test_windows_runtime.py gained
# twenty session tests over the real runtime (37 -> 57, floor 34 -> 52) and
# tests/test_windows_bundle.py four (45 -> 49, floor 41 -> 45); 111 -> 112
# modules, the module-floor sum rises by 92 and the aggregate follows.
# Re-measured for Tranche B round 3: tests/test_windows_runtime.py 57 -> 64
# (floor 52 -> 58), tests/test_control_plane_session.py 77 -> 80 (floor
# 70 -> 72), tests/test_windows_host_runtime.py 10 -> 11 (floor 9 -> 10);
# 112 modules stand; the module-floor sum rises by 9 to 2731, which would
# have left the aggregate floor of 2730 BELOW the sum -- no gate at all --
# so the aggregate rises to 2739 and keeps the same 8 of headroom above it.
# Re-measured for Tranche B round 4: tests/test_control_plane_session.py
# 80 -> 97 (floor 72 -> 88), tests/test_windows_runtime.py 64 -> 76 (floor
# 58 -> 69), tests/test_windows_bundle.py 49 -> 51 (floor 45 -> 46),
# tests/test_onboarding_launch.py 13 -> 14 (floor 12 -> 13); 112 modules
# stand; the module-floor sum rises by 29 to 2760 and the aggregate follows
# to 2768, keeping the same 8 above it. RE-MEASURED FROM SCRATCH for round 5,
# where Tranche B was rebased onto the provider-adapter parity slice: the two
# branches raised floors on disjoint modules, so the merged table is the union
# of both and every number below is a fresh measurement of the merged tree
# rather than either branch's arithmetic carried across. Round 5's own changes
# move four modules: tests/test_control_plane_session.py 97 -> 98 (floor
# 88 -> 89), tests/test_windows_bundle.py 51 -> 52 (46 -> 47),
# tests/test_windows_host_runtime.py 11 -> 12 (10 -> 11) and
# tests/test_windows_runtime.py 76 -> 80 (69 -> 72). 112 modules stand; the
# module-floor sum is 2872 and the aggregate follows to 2880, keeping the same
# 8 above it. Re-measured for Tranche B round 6, which repairs round 5's CI
# failure and its two reviewers' findings: tests/test_windows_runtime.py
# 80 -> 87 (floor 72 -> 79), tests/test_windows_bundle.py 52 -> 53 (47 -> 48),
# tests/test_provider_execution.py 20 -> 22 (18 -> 20) and
# tests/test_onboarding_launch.py 14 -> 15 (13 -> 14).
# tests/test_control_plane_session.py stays at 98: its detector was widened
# and its positive control given more specimens, inside the tests it already
# had. 112 modules stand; the module-floor sum rises by 11 to 2883 and the
# aggregate follows to 2891, keeping the same 8 above it.
# Re-measured for Tranche B round 7, which closes the sixth review's findings:
# tests/test_windows_runtime.py 87 -> 88 (floor 79 -> 80),
# tests/test_control_plane_session.py 98 -> 99 (89 -> 90) and
# tests/test_provider_execution.py 22 -> 23 (20 -> 21). One test each: the
# witness for `launch`'s own fenced roots, the module-scope comparison-binding
# check, and the read of the windows-runtime job's module list. 112 modules
# stand; the module-floor sum rises by 3 to 2886 and the aggregate follows to
# 2894, keeping the same 8 above it. Both margins below are unchanged, which
# is arithmetic and not luck: each of the three modules gained one collected
# test and one floor, and `ceil(0.9n)` moved by exactly one at each of 88, 99
# and 23, so every per-module slack is what it was.
# Re-measured for Tranche B round 8, which closes the seventh review's
# findings: tests/test_control_plane_session.py 99 -> 100, and this time the
# floor does NOT move -- `ceil(0.9*99)` and `ceil(0.9*100)` are both 90. So
# the module-floor sum stays 2886, MINIMUM_COLLECTED stays 2894, "above the
# module sum" stays 8, and the two rows that DO move are the ones that read
# the suite: collected 3145 -> 3146, `band(n)` 2831 -> 2832, and the working
# room below the floor 251 -> 252. The slack the bands grant rises by the
# same one, 259 -> 260, because that module now collects one more test above
# a floor that did not follow it.
# Re-measured for the session-file visibility repair:
# tests/test_windows_runtime.py 88 -> 92 (floor 80 -> 83) and
# tests/test_windows_host_runtime.py 12 -> 13 (11 -> 12). Five tests: four on
# the writer that now stages the bearer and moves it into place complete, one
# on the host harness that waits for a bearer it can PARSE. 112 modules stand;
# the module-floor sum rises by 4 to 2890 and the aggregate follows to 2898,
# keeping the same 8 above it. collected 3146 -> 3151, `band(n)` 2832 -> 2836,
# and the working room below the floor 252 -> 253. The slack the bands grant
# rises by one, 260 -> 261: the runtime module gained four collected against
# three of floor, and the host module one against one.
# Re-measured for that repair's second round, which closes the review's own
# findings on it: tests/test_windows_runtime.py 92 -> 96 (floor 83 -> 87) and
# tests/test_windows_host_runtime.py 13 -> 14 (12 -> 13). Five tests: four on
# the placement -- a target already there refused before any bearer reaches
# disk, the move's sharing-violation retry, a staging name taken after a
# successful move left alone, and every failure naming the file it could not
# use -- and one on the windows job's collected-count floor, which is now
# DERIVED from a live collection rather than restated in prose that had gone
# false. 112 modules stand; the module-floor sum rises by 5 to 2895 and the
# aggregate follows to 2903, keeping the same 8 above it. collected
# 3151 -> 3156, `band(n)` 2836 -> 2841, and the working room below the floor
# stays 253. The slack the bands grant stays 261, which is arithmetic and not
# luck: `ceil(0.9n)` moved by four at 96 and by one at 14, exactly the
# collected gain at each:
# Re-measured for Tranche C, slice C2, the real-surface control-plane probe
# harness: a new module tests/test_control_plane_authority.py collects 68
# after its third review round (floor at band(68) = 62); 112 -> 113 modules,
# the module-floor sum rises by 62 to 2957 and the aggregate follows to 2965,
# keeping the same 8 above it. The suite it collects rises 3156 -> 3224,
# band(n) 2841 -> 2902, the working room below the floor 253 -> 259, and the
# slack the bands grant 261 -> 267 (the module collects six tests above its
# floor). No criterion changed and no skip was declared: the module runs on
# every CI platform, its Windows-only artefact facilities degrading to
# not_applicable off Windows
# (`test_the_documented_paths_equal_the_served_compositions_route_table` and
# `test_the_self_probe_is_admitted_nuisance_and_not_separated`).
# Re-measured for Tranche C, slice C1, which replaced ONE admission criterion:
# tests/test_codex_confinement_admission.py 38 -> 66 collected (floor
# band(38) = 35 -> band(66) = 60), 61 of them at the slice's first head and 5
# more in round 2, where criterion review found the separation guard covering
# only half the widening. 113 modules stand -- the rows live in the module that
# already held the criterion, so the windows-runtime job's six modules and its
# arithmetic floor are untouched -- the module-floor sum rises by 25 to 2982 and
# the aggregate follows to 2990, keeping the same 8 above it. The suite collects
# 3224 -> 3252, band(n) 2902 -> 2927, the working room below the floor stays 262
# (the aggregate moved with the collection), and the slack the bands grant stays
# 270: this module collects six above its floor at 66 exactly as it did at 61,
# because the band moved with it. No provider row moved and no skip was declared
# (`test_both_providers_are_ineligible_and_the_reason_names_the_missing_property`):
# Re-measured for the record-read transient repair, which makes the two
# two-channel waits in tests/test_windows_runtime.py treat an unreadable
# publish window as "not settled yet": that module collects 96 -> 97 (floor
# band(96) = 87 -> band(97) = 88) for the pin that widens the window with an
# adversarial writer. 113 modules stand; the module-floor sum rises by one to
# 2983 and the aggregate follows to 2991, keeping the same 8 above it. The
# suite collects 3252 -> 3253, band(n) 2927 -> 2928, the working room below the
# floor stays 262 (the aggregate moved with the collection), and the slack the
# bands grant stays 270: this module collects nine above its floor at 97
# exactly as it did at 96, because `ceil(0.9n)` moved by one with it. The
# windows-runtime job's own arithmetic floor DOES move, 256 -> 257, because its
# six modules now carry 270; that number is derived from a live collection by
# `test_the_windows_job_floor_is_the_arithmetic_it_states`, which holds the
# job's sentence to it. No provider row moved and no skip was declared.
# Re-measured for Tranche C slice C3 -- the record-to-probe translation, the
# first control-plane record taken from a CONFINED principal, and the
# presence-check repair that measurement forced. THREE rows move, and one of
# them is not a module anybody edited:
# tests/test_codex_confinement_admission.py 66 -> 97 collected (floor
# band(66) = 60 -> band(97) = 88) for the translation's refusals, its derivation
# over the whole state x separation cross-product, and the shipped record
# translated and assessed rather than transcribed;
# tests/test_control_plane_authority.py 68 -> 73 (floor 62 -> 66) for the
# presence-check pins; and tests/test_recorded_measurements.py 189 -> 194
# (floor 171 -> 175), because docs/governance/CONTROL_PLANE_AUTHORITY_MEASUREMENT.md
# joins its parametrised document sweep -- the sweep growing when governed prose
# lands is the sweep working, and this row is stated because a census counting
# only the modules the author typed in would have been wrong by five.
# 113 modules stand; the module-floor sum rises by 36 to 3019 and the aggregate
# follows to 3027, keeping the same 8 above it. The suite collects 3253 -> 3294,
# band(n) 2928 -> 2965, the working room below the floor 262 -> 267, and the
# slack the bands grant 270 -> 275: each of the three modules now collects one
# more above its own band than it did. The windows-runtime job's own arithmetic
# floor moves 257 -> 262, because its six modules now carry 275. NO PROVIDER ROW
# MOVED and no skip was declared: the confined measurement reached
# `admitted_nuisance` with `principal_separated: unknown`, which the mapping
# answers `inconclusive`, so `control_plane_authority` stays unmet and Codex
# stays `declared`
# (`test_the_recorded_c3_measurement_translates_to_the_verdict_it_states`):
#
# Re-measured for TRANCHE C, SLICE C3 ROUND 2, which closed eight blocking
# findings from three independent read-only lanes. ONE module moves:
# tests/test_codex_confinement_admission.py 97 -> 106 collected (floor
# band(97) = 88 -> band(106) = 96). Nine new nodes, every one of them a
# measurement replacing a label -- see the module-floor comment above for the
# list. NO OTHER MODULE MOVES and 113 modules stand, so the windows-runtime
# job's own arithmetic floor is untouched at 262 (its six modules still collect
# 14/15/23/53/73/97, sum 275, floor 275 - 14 + 1). The module-floor sum rises by
# 8 to 3027 and the aggregate follows to 3035, keeping the same 8 above it. The
# suite collects 3294 -> 3303, band(n) 2965 -> 2973, the working room below the
# floor 267 -> 268, and the slack the bands grant 275 -> 276, because the one
# module that moved now collects one more above its own band. NO PROVIDER ROW
# MOVED: the round-2 repairs are guards over the same record, and the record
# still reaches `admitted_nuisance` with `principal_separated: unknown`.
#
# One wording note, because it was measured rather than assumed: a first draft
# of the CHANGELOG entry for this round tripped `_transcript_runs` in
# tests/test_recorded_measurements.py -- two wrapped prose lines read as a
# `key value` pair -- which put CHANGELOG.md into that module's document sweep
# and added five nodes there. The prose was rewrapped rather than the detector
# widened; the sweep is right to be broad.
#
# TWO SLICES ARE RECORDED BELOW AND ONLY THE SECOND DESCRIBES THIS TREE.
# Tranche I's paragraph states the totals of the BASE this slice is rebased
# onto; it is kept because the floor it raised is still live and this is the
# derivation of why tests/test_recorded_measurements.py sits at 180. The rows
# at the end of the block are the measured totals of THIS tree, and the
# Tranche D paragraph is the one that reaches them.
#
# Re-measured for TRANCHE I, the real embedded-interpreter run. NO MODULE WAS
# ADDED and no module gained a test of its own; 113 modules stand. What moved is
# the DOCUMENT SWEEP: docs/governance/EMBEDDED_INTERPRETER_RUN.md records the
# operator act A-023 had carried as NOT PERFORMED, and
# tests/test_recorded_measurements.py parametrises five checks over the
# governance documents, so it collects 194 -> 199 and its floor follows
# band(194) = 175 -> band(199) = 180. The module-floor sum rose by 5 to 3032
# and the aggregate followed to 3040, keeping the same 8 above it. The suite
# collected 3303 -> 3308, band(n) 2973 -> 2978, and the working room below the
# floor stayed 268. THE SLACK THE BANDS GRANT WAS UNCHANGED at 276: the one
# module that moved gained five collected and five of floor, so it still sits
# exactly 19 above its own band. NO PROVIDER ROW MOVED -- the run is operator
# evidence about a bundle folder and decides nothing about admission -- and the
# recorded smoke result is `fail`, which is the finding rather than a
# regression in this suite.
#
# Re-measured for Tranche D, the seal re-proof, which closes a fall-open in
# the store's own recovery path, hoists the seal marker above the rebuild's
# authority writes, makes the marker-basis interlock a biconditional that an
# empty confinement table cannot satisfy by vacuity, stops the recovery path
# writing bytes through a planted link, and stops two refusals naming an actor
# they never measured. Round 3 closes the fall-open that round 2's own
# link-hardening reopened inside the marker's write; round 4 closes the two
# SHAPES round 3's own repair left it open for; and round 5 stops patching the
# guard, because a remove-then-create window is irreducible for a
# directory-shaped entry and each round had closed the cells it enumerated and
# left one out. The fall-open is a CONJUNCTION -- the marker absent AND forged
# authority readable -- and `_rebuild` now neutralises the untrusted authority
# before it touches the marker, so the shape space stops being load-bearing.
# ONE row moves: tests/test_provider_authority_boundary.py collects 35 -> 79
# (floor band(35) = 32 -> band(79) = 72). 113 modules stand -- every new node
# is in the module that already held the seal boundary -- the module-floor sum
# rises by forty to 3072 and the aggregate follows to 3080, keeping the same 8
# above it. The suite collects 3308 -> 3352, band(n) 2978 -> 3017, the working
# room below the floor 269 -> 272 (the collection rose by twenty-five in round
# 5 and the aggregate by twenty-three), and the slack the bands grant 277 ->
# 280: this module collects seven above its floor at 79 where it collected
# four at 48, because `ceil(0.9n)` moved by twenty-three while the module moved
# by twenty-five. The windows-runtime job's floor is untouched at 262: none of
# its six modules is tests/test_provider_authority_boundary.py, and the six
# collect 14/15/23/53/73/97 as that job's own sentence states -- measured here
# from the same collection, not inherited from it. No provider row moved.
#
# SEVEN SKIP IDENTITIES ARE DECLARED, and which of them fire depends on the
# platform, which is the point of declaring them by identity with a case cap
# rather than by parameter. Round 5's rows are a CROSS PRODUCT of ten
# destination shapes with the interior instants of `_write_fresh` and of
# `_rebuild`, and no host can build all ten. On a Windows workstation
# `os.symlink` raises `[WinError 1314] A required privilege is not held by the
# client`, so three cases of each parametrised identity skip -- six on this
# workstation, and the five junction rows all execute. On the Linux test jobs
# the symlink shapes build and the junction shapes cannot, so the five
# whole-function junction rows skip along with two cases of the shape matrix,
# and the rebuild matrix's exemption is reported unused. Neither platform
# leaves a property unproven: `_is_directory_entry` sends the DIRECTORY rows
# down the identical branch on both, and the predicate's answer for the four
# symlink cases is measured against synthesised attributes by
# `test_the_directory_entry_predicate_answers_the_shapes_this_host_cannot_build`,
# which never skips anywhere.
#
# ROUND 4 RECORDED THAT A PARAMETRISED ROW COULD NOT BE DECLARED AT ALL, and
# that is false: `classify` strips `[param]` before matching against
# EXPECTED_SKIPS, `test_every_declared_exemption_names_a_test_that_exists`
# resolves the bare function name, and EXPECTED_SKIP_CASES bounds the count --
# which is exactly how tests/test_windows_host_runtime.py's parametrised
# journey row has been declared since PR-18. What cannot be declared is ONE
# PARAMETER of a parametrised identity, so a row skipping for a reason its
# siblings do not still has to be its own function. That is why the junction
# rows are functions and the shape matrix is not.
#
# THE FOUR FIGURES ABOVE ARE ROUND 5'S AND THIS TREE IS NOT ROUND 5.
# The paragraph arrived at the Tranche I rebase already saying them --
# rounds 6 and 7 moved the module again and did not follow it here --
# and the rebase shifted them by the five Tranche I added, which keeps
# them describing round 5 against this base rather than making them
# true of this commit. What IS true of this commit is the rows at the
# end of this block: module-floor sum 3087, aggregate 3095, suite 3369
# collected, band(n) 3033. Those are measured, and they are what every
# guard reads. Nothing compares this paragraph to them, which is how a
# round-5 sentence survived two rounds and a rebase intact.
#
# Those figures are stated against main AFTER TRANCHE I landed -- the
# real embedded-interpreter run, which raised
# tests/test_recorded_measurements.py from 175 to 180 and the suite
# from 3303 to 3308 -- and were re-measured from a fresh collection
# when this slice was rebased onto it. It was measured against Tranche
# C slice C3 before that, and those totals are gone from here for the
# same reason the older ones are. The slice's first two review rounds were first measured against the older
# base (3253 -> 3259 -> 3264, aggregate 2991 -> 2996 -> 3001), and every one of
# those totals is false for this tree. They are not kept beside the constant,
# because a superseded measurement left standing next to the thing it no
# longer measures is precisely the rot this block exists to stop -- and a
# rebase is the one moment that manufactures it wholesale. What survives the
# rebase is the module delta itself, 35 -> 54: six nodes in round 1, five in
# round 2, two in round 3 and six in round 4, a fact about the slice rather
# than about the base under it:
#
# Re-measured for the STANDING-OBLIGATION ADMISSION mechanism (PR #51), after
# its reconciliation with main as it stood AFTER TRANCHE E, the monotonic
# freshness slice, one in-session adversarial review round and one Codex
# review round. ONE MODULE WAS ADDED:
# tests/test_standing_development_obligations.py collects 106 with a floor at
# band(106) = 96, so 114 modules stand. The DOCUMENT SWEEP moved as well:
# docs/governance/STANDING_DEVELOPMENT_OBLIGATIONS.md is a governance
# document, so tests/test_recorded_measurements.py collects 199 -> 204 and its
# floor follows band(199) = 180 -> band(204) = 184. The module-floor sum rises
# by 100 to 3192 and the aggregate follows to 3200, keeping the same 8 above
# it. The suite collects 3375 -> 3486, band(n) 3038 -> 3138, and the working
# room below the floor moves 275 -> 286. THE SLACK THE BANDS GRANT moves
# 283 -> 294: the new module sits 10 above its band and the sweep module now
# sits 20 above its own, one more than before. Earlier reconciliations of this
# same slice, against main before Tranche D and before Tranche E, measured
# 3416 and 3480 across 114 modules; those totals are gone from here for the
# reason the paragraph above gives. NO PROVIDER ROW MOVED -- admission is
# procedure and decides nothing about eligibility, approval or release.
#
# THE SECOND CODEX ROUND ADDS ONE MODULE AND FORTY-THREE TESTS.
# tests/test_standing_development_obligations.py collects 106 -> 142 (floor
# band(106) = 96 -> band(142) = 128): the reparse-point classifier, the
# Windows link-target rule, the identity backstop, the double-slash chain,
# five swap-between-walk-and-open shapes, the one-sentence private refusals
# and the measured-claim sweep. tests/test_standing_obligations_windows.py is
# new and collects 7 (floor band(7) = 7; the band is no smaller for a module
# this size): six real directory junctions, buildable only on Windows, so
# each is a declared skip here and executes in the windows-runtime job, which
# refuses a skip -- plus the one test that runs everywhere and holds that the
# job names the module, without which the module would be present and
# executing nothing. 115 modules stand. The module-floor sum rises by 39 to
# 3231 and the aggregate follows to 3239, keeping the same 8 above it; the
# suite collects 3486 -> 3529, band(n) 3138 -> 3177, and the working room
# below the floor 286 -> 290. THE SLACK THE BANDS GRANT moves 294 -> 298: the
# standing module now sits 14 above its band rather than 10, and the Windows
# module sits on its own. Ten declared symlink skips in the standing module
# now rather than seven, beside the FIFO: the three new link shapes, one of
# them two cases. NO PROVIDER ROW MOVED.
#
# (rows below):
#
#     collected across tests/     3536   (115 modules)
#     sum of the module floors    3238
#     band(3536) = ceil(0.9*n)    3183
#     MINIMUM_COLLECTED           3246
#     above the module sum         8
#     below what collects         290
#
# THE THIRD CODEX ROUND ADDS THREE TESTS AND NO MODULE.
# tests/test_standing_development_obligations.py collects 142 -> 145 (floor
# band(142) = 128 -> band(145) = 131): the alias rooted below the repository
# root, the identity traversal that follows no link and refuses past its
# bound, and the unfollowed link that nothing looks beyond. The module-floor
# sum rises by three to 3236 and the aggregate follows to 3244, keeping the
# same 8 above it; the suite collects 3531 -> 3534, band(n) 3178 -> 3181, and
# the working room below the floor stays 290. THE SLACK THE BANDS GRANT stays
# 298: the module and its floor each moved by three. Twelve declared symlink
# skips in the standing module now rather than ten: the two new link shapes.
# NO PROVIDER ROW MOVED.
#
# THE FOURTH CODEX ROUND ADDS TWO TESTS AND NO MODULE.
# tests/test_standing_development_obligations.py collects 145 -> 147 (floor
# band(145) = 131 -> band(147) = 133): the stat failure that refuses the
# identity traversal whole rather than leaving a directory out, and the
# traversal that scans each directory once whatever its aliases. Both run
# everywhere -- the entries are supplied to the traversal, not built on disk
# -- so no skip is declared. The module-floor sum rises by two to 3238 and
# the aggregate follows to 3246, keeping the same 8 above it; the suite
# collects 3534 -> 3536, band(n) 3181 -> 3183, and the working room below
# the floor stays 290. THE SLACK THE BANDS GRANT stays 298: the module and
# its floor each moved by two. NO PROVIDER ROW MOVED.
#
# THE FIFTH RECONCILIATION OF PR #51, with main as it stood after the
# launcher-pipe repair below, moves that repair's one row into this tree and
# adds no module of its own: tests/test_windows_bundle.py collects 53 -> 54
# (floor band(53) = 48 -> band(54) = 49) here as it did on main. The rows
# above were RE-MEASURED from a fresh collection of this merged tree, not
# summed from either side's rows: 115 modules collect 3531, the module
# floors sum to 3233, band(n) is 3178. The aggregate follows main's own
# rule for this tree -- the module sum plus 8 -- and lands at 3241, which is
# main's 3102 raised by the standing-obligation floors this branch adds and
# this branch's 3239 raised by two, the same two units main added for the
# same reason; the room above the module sum is 8 again and the room below
# what collects is 290. THE SLACK THE BANDS GRANT is 298: band(54) = 49 leaves
# the bundle module the same 5 that band(53) = 48 did, so nothing moved. The
# windows-latest job's floor moves with the bundle module's one new test,
# 276 -> 277 over seven modules, from a collection of those modules rather
# than from either side's arithmetic. Every generated evidence artifact was
# regenerated over this merged tree rather than taken from either side.
#
# THE FOURTH RECONCILIATION OF PR #51, with main as it stood after the
# vanished-entry repair below, moves that repair's one row into this tree and
# adds no module of its own: tests/test_provider_authority_boundary.py
# collects 102 -> 103 (floor band(102) = 92 -> band(103) = 93) here as it did
# on main. The module-floor sum rises by one to 3232 and the suite collects
# 3529 -> 3530; band(n) stays 3177, because ceil(0.9 * 3530) is 3177 too.
# MINIMUM_COLLECTED does not move, exactly as main chose not to move it for
# the same one-test change, so the room above the module sum falls 8 -> 7
# while the room below what collects rises 290 -> 291. The slack the
# per-module bands grant stays 298: the module and its floor each moved by
# one. Every generated evidence artifact was regenerated over this merged
# tree rather than taken from either side.
#
# THE VANISHED-ENTRY REPAIR MOVED THE SAME ROW AND ADDED NO MODULE. One test in
# tests/test_provider_authority_boundary.py, 102 -> 103 (floor band(102) = 92 ->
# band(103) = 93), for the CI race described at that module's floor above;
# MINIMUM_COLLECTED did not move. The slack the per-module bands grant was
# unchanged: the module and its floor each moved by one. ITS SUITE-WIDE
# TOTALS ARE NOT KEPT HERE, for the reason the Tranche E paragraph below
# gives: they described main before this reconciliation and are false of
# this tree; the paragraph above carries the merged measurement.
#
# THE LAUNCHER-PIPE REPAIR MOVES ONE ROW AND ADDS NO MODULE. The unscripted
# smoke test lives in the module that already holds the smoke, so
# tests/test_windows_bundle.py collects 53 -> 54 (floor band(53) = 48 ->
# band(54) = 49) and 113 modules still stand. The rows above were re-measured
# from a fresh collection after this slice was rebased onto the vanished-entry
# repair below, and they are NOT this slice's old rows plus that repair's: the
# module-floor sum rises by one to 3094 and the suite collects
# 3376 -> 3377, so band(n) goes 3039 -> 3040,
# but the AGGREGATE RISES BY TWO, 3100 -> 3102. That second unit
# is not this slice's row moving twice. The repair below raised the module sum
# and left MINIMUM_COLLECTED standing, so the room above the sum had fallen to
# 7; putting this slice's floor at sum + 8 restores the margin this block has
# carried since it was written. The working room below what collects therefore
# FALLS 276 -> 275, because the collection rose by one and the
# aggregate by two -- the one row a merge of the two slices would have got
# wrong in both directions at once. The slack the bands grant is unchanged at
# 283: band(54) = 49 leaves this module the same 5 that band(53) = 48 did. ONE
# skip is added, declared by identity above -- the test is Windows-only because
# the defect is a Windows CreateProcess property -- and the windows-latest
# job's own floor moves with it, 262 -> 263, because that job runs this module.
#
# THE VANISHED-ENTRY REPAIR MOVED A DIFFERENT ROW AND ADDED NO MODULE. One test
# in tests/test_provider_authority_boundary.py, 102 -> 103 (floor
# band(102) = 92 -> band(103) = 93), for the CI race described at that module's
# floor above. It never skips -- the vanishing is injected at the listing, not
# raced, so it needs no threads and no platform -- and no provider row moved.
# ITS SUITE-WIDE TOTALS ARE NOT KEPT HERE. They described the tree before the
# slice above and are false of this one, and a superseded measurement left
# standing beside the thing it no longer measures is precisely the rot this
# block exists to stop -- and a rebase is the one moment that manufactures it
# wholesale. What survives a later slice is the module delta.
#
# TRANCHE E MOVED THAT SAME ROW AND ADDED NO MODULE. The process witness lives
# in the module that already holds the seal boundary, so
# tests/test_provider_authority_boundary.py collected 96 -> 102 (floor
# band(96) = 87 -> band(102) = 92) and 113 modules still stood. No provider row
# moved and no skip was added: the six new rows need neither a junction nor a
# symlink, only a byte-for-byte copy of two directories, so they execute on
# every platform. ITS SUITE-WIDE TOTALS ARE NOT KEPT HERE EITHER, for the
# reason given one paragraph up.
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
# per-module bands already grant 298 in total, and the aggregate refuses
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
#
# A SIXTH rot, and a new shape: a Tranche C rebase spliced the constant below
# into the MIDDLE of the "working room" sentence twenty-one lines up and left
# that sentence's second clause standing HERE, where the constant belongs.
# Every guard stayed green -- the slack figure was still correct and still
# findable, because the guard that reads it searches the whole file for the
# phrase and cannot see where the phrase sits. So the numbers did not drift
# this time; the PROSE AND THE CONSTANT drifted apart from each other, which
# no guard in this file measures and a reader meets first. Recorded rather
# than silently repaired, because the file whose subject is that prose beside
# a constant is not a measurement of it had its own prose cut in half by a
# merge for two review rounds.
MINIMUM_COLLECTED = 3246

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
    "tests/test_control_plane_session.py",
    "tests/test_control_plane_authority.py",
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
    "tests/test_standing_development_obligations.py",
    "tests/test_standing_obligations_windows.py",
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
