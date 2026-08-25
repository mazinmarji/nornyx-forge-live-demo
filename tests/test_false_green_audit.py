"""Task 12. The proof system must not be able to succeed for the wrong reason.

Thirty-three false-green classes have actually occurred in this repository. Each
one produced a green run that proved nothing, and each is now a named class with
an executable guard and a self-attack that must trip it.

FG01-FG09 are failures of individual proofs. FG10-FG15 are failures of the PROOF
SYSTEM -- the machinery that decides whether a proof counted -- and they were
found by an external review after this file already existed and reported 9/9
guarded. An audit cannot be trusted to notice that it is itself the thing
failing.

The self-attack matters more than the guard. A guard nobody has fired is a claim;
a guard that has been shown to reject the exact historical mistake is evidence.
So every FG below reproduces its original failure and requires the guard to
refuse BEFORE any security conclusion is drawn.

No credit is taken from a syntax error, an unrelated failure, or a collection
error, except where the guard under test is itself a collection guard.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from guard_evidence import (  # noqa: E402
    cannot_fail as _cannot_fail,
)
from guard_evidence import (  # noqa: E402
    exercised_assertions,
)
from mutation_validity import InvalidMutation, check_mutation  # noqa: E402

#: A newline, spelled so no tool can eat the escape.
NL = chr(10)


@dataclass(frozen=True)
class FalseGreen:
    ident: str
    false_claim: str
    root_cause: str
    guard: str
    owner: str
    #: (path, before, after, count, property) -- an EXECUTABLE reproduction of
    #: this class's defect, applied to the real tree and undone afterwards.
    #: When present, the marked guard MUST go red under it, FOR ITS OWN REASON.
    #:
    #: `property` is a phrase that has to appear in the failure evidence. The
    #: contract used to call `require_caused_failure` WITHOUT it, and that
    #: helper's own docstring says why that is not attribution: "same node
    #: failed" is weaker than "same node failed BECAUSE the intended assertion
    #: was violated". Measured: a report where the FG22 owner failed in the
    #: call phase for an unrelated reason RETURNED CLEAN without it, and
    #: INVALID_MUTATION with it. Both phrases below were taken from the actual
    #: failure text, by running the mutation and reading what came out.
    #:
    #: `root_cause` and `guard` above are PROSE and always were. A review
    #: found two markers sitting on nodes that could not fail for the control
    #: their class names -- FG33's exercised CPython's subprocess timeout and
    #: would have passed with every file here deleted -- and prose could not
    #: have caught either. Only ident + this triple affect a verdict.
    #:
    #: Optional ON PURPOSE. Defaulting to None leaves the classes that have no
    #: reproduction yet UNMIGRATED rather than guessed, which is the same
    #: discipline `authoritative_property` follows for the attack catalogue.
    #: `test_every_false_green_class_has_a_terminal_classification` is what
    #: stops that default from becoming a silent exemption.
    reproduces: tuple | None = None


INVENTORY = (
    FalseGreen(
        "FG01", "a role/domain refusal, when the signature was actually broken",
        "an unknown keyword landed in **overrides and was applied AFTER signing",
        "authenticate the grant before drawing any authority conclusion",
        "tests/test_false_green_audit.py::test_fg01_a_wrong_keyword_breaks_the_signature",
    ),
    FalseGreen(
        "FG02", "an authority refusal, when authentication had already failed",
        "a tampered signature refuses earlier than the clause under test",
        "assert every earlier clause succeeds first",
        "tests/test_false_green_audit.py::test_fg02_a_tampered_signature_is_caught_as_a_prerequisite",
    ),
    FalseGreen(
        "FG03", "a governance mutation, when only prose changed",
        "first-occurrence text replacement matched a comment or docstring",
        "mutation targets must be executable, proven by span",
        "tests/test_false_green_audit.py::test_fg03_a_comment_target_is_refused",
    ),
    FalseGreen(
        "FG04", "a restored workspace, when only step one of the chain ran",
        "regeneration is one step of a causal order, not a restoration",
        "byte-exact restoration, or the full documented chain",
        "tests/test_false_green_audit.py::test_fg04_partial_restoration_is_detected",
    ),
    FalseGreen(
        "FG05", "a trust/role refusal, when the grant was already spent",
        "paired halves shared one workspace and therefore one ledger",
        "each half asserts its own initial ledger state",
        "tests/test_false_green_audit.py::test_fg05_a_shared_ledger_contaminates_the_pair",
    ),
    FalseGreen(
        "FG06", "instability, when the system was converging to a fixed point",
        "the first sample was taken before the state had settled",
        "settle first, then require one value across N post-settlement samples",
        "tests/test_false_green_audit.py::test_fg06_convergence_is_told_apart_from_oscillation",
    ),
    FalseGreen(
        "FG07", "a survivor, when the mutation never applied",
        "str.replace with a stale anchor is a silent no-op",
        "exact occurrence count before writing",
        "tests/test_false_green_audit.py::test_fg07_a_stale_anchor_is_refused",
    ),
    FalseGreen(
        "FG08", "a security result, when the child imported the original source",
        "an editable .pth outranks a late sys.path insert",
        "prove module origin is inside the mutant workspace",
        "tests/test_false_green_audit.py::test_fg08_an_unisolated_child_is_refused",
    ),
    FalseGreen(
        "FG09", "consumption, when only possession was shown",
        "`context.field is X` says nothing about the decision consulting X",
        "a behavioural differential: X1 and X2 must decide differently",
        "tests/test_false_green_audit.py::test_fg09_possession_does_not_discriminate",
    ),
    FalseGreen(
        "FG10", "a kill, when the pristine workspace already failed",
        "the copy omitted files the named proof depends on",
        "run the named test unmutated and refuse the attempt if it fails",
        "tests/test_false_green_audit.py::test_fg10_a_workspace_whose_baseline_already_fails_is_refused",
    ),
    FalseGreen(
        "FG11", "a kill, when the named test node no longer exists",
        "`pytest module::gone` exits 4 and prints neither guarded phrase",
        "ask pytest to collect the node and read the exit code",
        "tests/test_false_green_audit.py::test_fg11_a_missing_test_node_is_not_a_kill",
    ),
    FalseGreen(
        "FG12", "a green census, when a proof was marked as expected to fail",
        "xfails were skipped past the gate on a false claim of strictness",
        "xfail_strict configured, and xfails counted against a closed allowlist",
        "tests/test_false_green_audit.py::test_fg12_an_undeclared_expected_failure_fails_the_census",
    ),
    FalseGreen(
        "FG13", "proven mutant origin, when a text search matched an unrelated line",
        "`sys.path.insert(0` appears at the top of nearly every test module",
        "read `module.__file__` from the interpreter, comparing paths as paths",
        "tests/test_false_green_audit.py::test_fg13_a_text_search_is_not_proof_of_mutant_origin",
    ),
    FalseGreen(
        "FG14", "an intact suite, when critical proofs were deleted",
        "an aggregate floor absorbs the loss when other modules grow",
        "per-module minimums, and attacks required BY NAME",
        "tests/test_false_green_audit.py::test_fg14_an_aggregate_floor_permits_deleting_critical_proofs",
    ),
    FalseGreen(
        "FG15", "SURVIVED or KILLED, when only one route of a chain was removed",
        "the attempt was valid in every respect; the enforcement inventory was not",
        "enumerate every route, record each as defence-in-depth, kill with a compound",
        "tests/test_false_green_audit.py::test_fg15_one_route_of_a_chain_is_not_the_property",
    ),
    FalseGreen(
        "FG16", "a control was attacked, when only a TEST fixture was mutated",
        "the mutation applied to executable code that was not production code",
        "resolve the target and require it under src/, scripts/ or .nornyx/",
        "tests/test_historical_reproof.py::test_fg16_a_mutation_outside_production_scope_is_refused",
    ),
    FalseGreen(
        "FG17", "an exact proof node, when a whole module stood in for one",
        "`tests/test_x.py` was accepted where `tests/test_x.py::test_node` was required",
        "reject any target without exactly one `::` and a real node name",
        "tests/test_historical_reproof.py::test_fg17_a_module_target_cannot_stand_in_for_an_exact_node",
    ),
    FalseGreen(
        "FG18", "a kill, when the named node passed and a different node failed",
        "`<failure>` elements were summed across the whole JUnit report",
        "match the exact node, handling parametrised ids, before crediting anything",
        "tests/test_failure_attribution.py::test_case1_an_unrelated_node_failing_is_not_a_kill",
    ),
    FalseGreen(
        "FG19", "a kill, when the right node failed for an unrelated reason",
        "exact-node attribution alone permits a genuine failure about something else",
        "require the failure text to carry the intended root property",
        "tests/test_failure_attribution.py::test_case6_the_named_node_failing_for_the_wrong_reason_is_not_a_kill",
    ),
    FalseGreen(
        "FG20", "a green gate, when the shell reported the last pipeline stage",
        "`pytest ... | tail` returns tail's exit status, not pytest's",
        "declare `shell: bash` so `-o pipefail` applies, and assert it",
        "tests/test_documented_claims.py::test_ci_shell_propagates_pipeline_failure",
    ),
    FalseGreen(
        "FG21", "a marker or claim is present, when only prose mentions it",
        "a substring scan cannot tell executable code from a docstring or quotation",
        "parse with AST, or treat quoted spans as mention rather than assertion",
        "tests/test_xfail_strictness.py::test_the_marker_detector_reads_code_and_not_prose",
    ),
    FalseGreen(
        "FG22", "a clean gate, when the violation was added to the baseline excusing it",
        "a grandfather list that the author may extend absolves the author's own commit",
        "record culpable entries separately, pin the count, and keep --no-baseline",
        # OWNER CORRECTED to the node that fails for this class; the one
        # previously named is a substring scan and passed under FG22's own
        # defect.
        "tests/test_evidence_binding.py"
        "::test_the_escape_hatch_is_exercised_not_merely_present",
        # Delete the escape hatch's BEHAVIOUR while leaving its NAME in the
        # file -- which is precisely how the class was missed.
        ("scripts/check_evidence_binding.py",
         "known_violations() if apply_baseline else set()",
         "known_violations()", 1, "escape hatch"),
    ),
    FalseGreen(
        "FG23", "a kill, when the observable collapsed because the mutant broke the run",
        "the direct-observable shape has no phase attribution to catch a crashed mutant",
        "require the mutant to RUN: observables intact, reasons not tracebacks",
        "tests/test_domain_collapse_mutations.py::test_fg23_a_mutant_that_broke_the_run_is_not_a_kill",
    ),
    FalseGreen(
        "FG24", "a targeted attack, when the projection degenerated into a constant",
        "hiding every difference satisfies the same equality as hiding the one attacked",
        "require the mutated projection to still distinguish some other pair",
        "tests/test_semantic_binding_theorem.py::test_fg24_a_constant_projection_is_refused_by_the_guard",
    ),
    FalseGreen(
        "FG25", "a minimal compound, when an edit could be dropped and it still killed",
        "compound membership was recorded from intent rather than re-measured",
        "re-run each compound without its last edit and require it to survive",
        "tests/test_mutation_catalogue.py::test_every_compound_attack_is_proven_minimal",
    ),
    FalseGreen(
        "FG26", "a measurement, when the probe itself mutated the real governed tree",
        "an ad-hoc script ran outside the session fixture that restores the tree",
        "snapshot and restore around every step, in a finally, inside the suite",
        "tests/test_probe_containment.py::test_fg26_contamination_is_detected_and_clean_runs_are_not",
    ),
    FalseGreen(
        "FG27", "a closed set, when the enumeration excluded members before checking",
        "the query filtered candidates out before the closure check could see them",
        "enumerate the complete candidate set first; never exclude on the way in",
        "tests/test_approval_ledger.py::test_r1_a_hostile_ledger_object_cannot_enable_replay",
    ),
    FalseGreen(
        "FG28", "a protocol step, when the authoritative path never invoked it",
        "the step existed, had passing unit tests, and was not called at the verdict",
        "prove the production caller invokes it and the verdict moves when it fails",
        "tests/test_historical_reproof.py::test_r2_a_green_helper_cannot_stand_in_for_the_runner",
    ),
    FalseGreen(
        "FG29", "a violated property, when the mutant crashed instead of deciding",
        "an absent diagnostic reads the same whether it refused wrongly or never ran",
        "an unmeasurable mutant terminates the measurement rather than answering it",
        "tests/test_probe_containment.py::test_fg29_a_crash_is_distinguishable_from_a_decision",
    ),
    FalseGreen(
        "FG30", "a verified transcript, when only one displayed field was checked",
        "a fence made every line look verified while one digest was recomputed",
        "verify every displayed field by re-execution, or move it outside the fence",
        "tests/test_recorded_measurements.py::test_r4_a_fabricated_field_inside_an_anchored_block_is_refused",
    ),
    FalseGreen(
        "FG31", "a repository-wide sweep, when it scanned README and docs only",
        "the docstring claimed totality while the loop named a subset",
        "one canonical discovery helper, used by every claim sweep, UI included",
        "tests/test_execution_mode_truth.py::test_the_ui_surface_sweep_finds_the_dashboard",
    ),
    FalseGreen(
        "FG32", "a control, when no production path can reach it",
        "the apparatus was complete and no shipped caller could supply its input",
        "trace the shipped path to the control and pin the call site structurally",
        "tests/test_approval_reachability.py::test_the_flow_passes_the_grant_to_the_boundary",
    ),
    FalseGreen(
        "FG33", "a result, when the run did not finish",
        "a timeout exits non-zero, which is what a refusal also looks like",
        # THE GUARD IS RESTATED, because the one recorded here did not exist.
        # It said "carry completion alongside the exit code", and nothing in
        # this repository ever did: `timed_out` appeared in no file outside the
        # owner's own parametrize table, and the owner asserted
        # `(not timed_out) is usable` over rows that DEFINED usable as
        # `not timed_out` -- an identity between two hand-written columns.
        #
        # What actually protects the campaign is that both harness entry points
        # pass `timeout=` to `subprocess.run`, which RAISES rather than
        # returning a CompletedProcess whose exit code could be misread. That
        # is a real guard; it was simply not the one written down.
        "bound every child run, so a timeout RAISES and yields no result to misread",
        # OWNER CORRECTED to the node this entry's own note describes.
        # Measured with the eight `timeout=` bindings stripped from the
        # harness: the node named here went RED and the one previously
        # named stayed GREEN, because it exercises CPython's subprocess
        # timeout rather than anything this repository does.
        "tests/test_probe_containment.py"
        "::test_fg33_both_harness_entry_points_bound_their_runs",
        # Strip the timeout bindings the campaign actually relies on.
        # The COUNT is part of the reproduction: a stale anchor that matches
        # nothing is FG07, and one that matches more than intended is a
        # different mutation than the one recorded.
        ("tests/mutation_workspace.py", "timeout=timeout", "timeout=None",
         2, "with no timeout"),
    ),
    FalseGreen(
        "FG34", "a KILL, when only a named test failed",
        "semantic attribution was OPTIONAL -- `if item.authoritative_property "
        "is not None` -- so an attack carrying no machine-verifiable criterion "
        "skipped attribution and was credited on the victim test failing alone",
        "attribution is mandatory: an attack with no executable criterion is "
        "refused as NO_AUTHORITATIVE_PROPERTY rather than counted",
        "tests/test_attack_attribution_contract.py"
        "::test_an_attack_without_a_criterion_is_refused_by_the_runner",
    ),
    FalseGreen(
        "FG35", "a floor, when the check could not reach its own verdict",
        "the aggregate collection floor sat BELOW the sum of the per-module "
        "floors, 1450 against 1458, so every report satisfying the modules "
        "satisfied it too and it could never refuse anything on its own",
        "the aggregate floor must exceed the sum of the parts it aggregates",
        "tests/test_skip_gate.py"
        "::test_the_aggregate_floor_sits_above_the_sum_of_the_module_floors",
    ),
    FalseGreen(
        "FG36", "a verified anchor, when only one rendering was ever read",
        "anchored transcripts were located with the container-DEPENDENT block "
        "grammar, so a claim rendered tab-indented, blockquoted or bulleted was "
        "never field-checked against the commit it named",
        "recognition is container-independent, and every rendering is pinned",
        "tests/test_recorded_measurements.py"
        "::test_r4_an_anchor_is_recognised_in_every_rendering",
    ),
    FalseGreen(
        "FG37", "a structural control, when a COMMENT satisfied it",
        "a declared control checked production structure by substring and "
        "passed after the statement was deleted and replaced by a comment "
        "mentioning it -- a substring cannot tell a statement from a sentence "
        "about one",
        "the control walks the AST and requires a real statement node, so a "
        "mention cannot satisfy what only a use should",
        "tests/test_absence_is_not_success.py"
        "::test_a_non_governed_import_failure_keeps_its_traceback",
    ),
    FalseGreen(
        "FG38", "a proven attack, when its proof was only DEFINED",
        "the catalogue verified the owner module contained `def <node>(`; a "
        "node can be present and never run -- deselected, shadowed by a later "
        "definition, or excluded by configuration -- and still be counted",
        "collection is measured by asking pytest what it would collect, and a declared guard may carry no skip or xfail marker",
        "tests/test_mutation_catalogue.py"
        "::test_every_killing_test_is_actually_collected_by_pytest",
    ),
    FalseGreen(
        "FG40", "a repaired rule, when a second copy of it was left standing",
        "the screen deciding whether a guard executes anything that can fail "
        "had four implementations. Repairing the one a reviewer was pointing "
        "at left the others intact, and the mutation catalogue consumed the "
        "weakest: measured accepting `assert 1 == 1`, `record.fail(reason)` "
        "and `io.StringIO('raises.txt')` as evidence for a node carrying 14 "
        "of the 41 attacks",
        "ONE implementation in `tests/guard_evidence.py`, every consumer "
        "importing it, and a guard refusing the retired spellings elsewhere",
        "tests/test_false_green_audit.py"
        "::test_no_module_reimplements_the_evidence_screen",
        # Put a retired spelling back where the guard can see it. The anchor is
        # a real repair from the round that installed the guard: two sites in
        # this module were substring-matching a dumped AST to identify a call.
        ("tests/test_execution_mode_truth.py",
         '_mentions(n, "demo_command")',
         '"demo_command" in ast.dump(n)', 1, "dumped AST"),
    ),
    FalseGreen(
        "FG41", "a screen, when it refused a GENUINE guard",
        "the screen deciding whether a guard executes anything that can fail "
        "is documented to resolve every undecided case toward 'this is a real "
        "assertion' -- it may miss a vacuous guard, it may never fail a live "
        "one. It failed live ones in two places: a module name whose literal "
        "binding was not its only binding stayed a constant and folded the "
        "branch under it, and `break`/`continue` inside a loop were read as "
        "ending the block AROUND the loop, so every assertion after "
        "`while True: break` was judged dead",
        "a second binding of any kind disqualifies a module constant, and "
        "`inside_loop` tells a loop exit from a block exit; both directions "
        "are pinned by specimens, including the cases a naive fix would break",
        "tests/test_false_green_audit.py"
        "::test_a_module_name_bound_twice_is_not_a_constant",
        # Put the old module pass back: skip a statement that is not a
        # literal assignment WITHOUT disqualifying the names it binds.
        ("tests/guard_evidence.py",
         "disqualified.update(bound_names(node))",
         "continue", 1, "executes nothing"),
    ),
    FalseGreen(
        "FG42", "a swallowing rule, when ONE alias line renamed the exception",
        "`SWALLOWING` lists three exception classes and the rule asked whether "
        "the handler was SPELLED one of them. Measured end to end on a real "
        "audited guard: adding `_Swallow = AssertionError` and wrapping the "
        "body in `try: ... except _Swallow: pass` took its subject from 5 "
        "FAILED to 8 passed, with the screen reporting `exercised` 1 both "
        "times -- and `constant_bindings`, in the same file, already resolved "
        "aliases to a fixed point for the folding axis",
        "the handler type and the `suppress` callee are resolved to the names "
        "they DENOTE, through module and local aliases to a fixed point, so a "
        "rename catches what the original caught",
        "tests/test_false_green_audit.py"
        "::test_a_swallowing_handler_is_found_however_the_class_is_named",
        # Stop resolving a bare name through its aliases, which is
        # exactly what the rule did before: ask for the spelling.
        ("tests/guard_evidence.py",
         "return aliases.get(expression.id, {expression.id})",
         "return {expression.id}", 1, "failing thing(s)"),
    ),
    FalseGreen(
        "FG39", "single use, when two durable stores were committed separately",
        "the consumption row and the continuity witness were written to two "
        "files in sequence, so a process death between them left the row "
        "durable and the witness stale -- 8 of 45 kill points -- after which a "
        "ledger-only restore released the already-spent grant",
        "both stores are written in ONE SQLite transaction over an attached "
        "database, in a journal mode where that commit covers the set",
        "tests/test_ledger_atomicity.py"
        "::test_no_kill_point_during_a_consumption_leaves_the_stores_disagreeing",
    ),
)



#: Pinned by IDENTITY, never by count. "16 classes" is satisfied by any sixteen
#: strings; this is satisfied only by these. FG14 is the class about exactly
#: that substitution, so expressing its own inventory as a count would be the
#: defect naming itself.
#: SPELLED OUT. This was a generator over `range(1, 34)` while the
#: docstring below said the inventory is compared "rather than a literal
#: range... and by SET, never by count". A range IS a count in disguise:
#: dropping the highest class is a one-character edit to the bound, which
#: is exactly the same-size diff the named set was supposed to make
#: larger. Verdict-neutral when a review found it, and that is the point
#: -- it would not have stayed neutral.
EXPECTED_FALSE_GREEN_CLASSES = frozenset({
    "FG01",
    "FG02",
    "FG03",
    "FG04",
    "FG05",
    "FG06",
    "FG07",
    "FG08",
    "FG09",
    "FG10",
    "FG11",
    "FG12",
    "FG13",
    "FG14",
    "FG15",
    "FG16",
    "FG17",
    "FG18",
    "FG19",
    "FG20",
    "FG21",
    "FG22",
    "FG23",
    "FG24",
    "FG25",
    "FG26",
    "FG27",
    "FG28",
    "FG29",
    "FG30",
    "FG31",
    "FG32",
    "FG33",
    # Task 12: the mechanisms R2-R6 and Task 11 measured during remediation.
    "FG34",
    "FG35",
    "FG36",
    "FG37",
    "FG38",
    "FG39",
    "FG40",
    # Round 7: the two directions a fresh lens found in the screen itself.
    "FG41",
    "FG42",
})

#: Mechanisms learned across the whole remediation, mapped to the class that
#: expresses them. Three map onto existing classes; eleven needed new ones. The
#: test is whether an existing specimen could actually CATCH the defect -- not
#: whether the words sound similar.
#: MECHANISM -> CLASS, for the mechanisms found while remediating this
#: repository. NOT an index of how every class arose: twelve of the classes
#: predate this table and have no entry, and I briefly asserted otherwise --
#: writing a test that demanded exhaustiveness the map never claimed, then
#: watching it name twelve classes as "unexplained" when the map had simply
#: never covered them. Inventing a requirement and calling its violation a
#: defect is the same error as inventing a claim.
#:
#: What IS checked: every class this table names must exist.
MECHANISM_TO_CLASS = {
    "subprocess_provenance_loss": "FG08",
    "exact_set_identity_vs_count": "FG14",
    "branch_body_reachability": "FG13",
    "production_scope_substitution": "FG16",
    "exact_node_substitution": "FG17",
    "wrong_node_failure_attribution": "FG18",
    "wrong_property_failure_attribution": "FG19",
    "pipe_exit_code_masking": "FG20",
    "use_versus_mention_scanning": "FG21",
    "exception_baseline_self_enlargement": "FG22",
    "unhealthy_mutant_credited": "FG23",
    "degenerate_projection_credited": "FG24",
    "compound_minimality_drift": "FG25",
    "adhoc_probe_governed_contamination": "FG26",
    "pre_closure_exclusion": "FG27",
    "declared_step_never_invoked": "FG28",
    "crash_credited_as_violation": "FG29",
    "displayed_exceeds_verified": "FG30",
    "partial_sweep_claiming_totality": "FG31",
    "control_unreachable_from_production": "FG32",
    "unfinished_run_read_as_result": "FG33",
    # Mapped, not minted: a separator class that misses the machine
    # spelling, and a detector recognising only one form of failure,
    # are both "the pattern does not match the thing" -- FG21.
    "separator_class_misses_machine_spelling": "FG21",
    "evidence_counter_misses_a_failure_form": "FG21",
    # And a third of the same family, found in the health check that decides
    # whether a mutant RAN: it recognised a crash only when the exception class
    # was named for one (`...Error`, `...Exception`), so ten of the eleven
    # classes this subject can actually raise -- `TrustStoreUnavailable` first
    # among them -- read as ordinary refusals. A blocklist of two suffixes is
    # still a blocklist.
    #
    # MAPPED, NOT MINTED, MEANS SOMETHING NARROWER THAN IT LOOKS. FG21's owner
    # is about an xfail-marker detector reading code rather than prose; it
    # could not catch THIS defect, and this entry does not claim it could. The
    # mapping records which FAMILY a mechanism belongs to, so the audit's
    # inventory stays a set of distinct hazards rather than growing an ID for
    # every instance. The specimen that actually catches this one lives with
    # the mechanism, in `test_domain_collapse_mutations.py`.
    "crash_detector_matches_only_named_suffixes": "FG21",
}


#: Assertions whose subject is fixed before the suite runs. Each is a REAL
#: edit an adversary can make to a marked guard: they keep the node, keep the
#: marker, keep collection identical, and assert nothing.
VACUOUS_ASSERTIONS = [
    "True", "1", "'text'", "1 == 1", "not False", "'a' in 'abc'",
    "[1]", "(1, 2)", "{'k': 'v'}", "1 < 2 < 3", "True and 1",
    "2 + 2 == 4", "10 % 3 == 1", "not (1 > 2)",
]

#: Assertions that read state. The screen must credit every one of these, or a
#: genuine guard gets called vacuous and the audit fails for a lie in the other
#: direction -- which is the worse failure, because it is loud and wrong.
REAL_ASSERTIONS = [
    "result == 4", "compute()", "obj.field", "values[0]",
    "'a' in haystack", "len(rows) == 2", "not missing",
    "report.returncode != 0", "{name: 1} == expected",
]

#: THE STATED COST OF A BOUNDED FOLDER. These ARE fixed at parse time and the
#: screen credits them anyway, because deciding them needs operators that turn
#: a folder into an interpreter with a memory budget. Pinned as a list to
#: argue with: shrinking it is progress, and growing it silently is not.
UNDECIDED_BY_DESIGN = [
    "2 ** 2 == 4",              # growth: no exponent is folded
    "1 << 4 == 16",             # growth: no shift is folded
    "'a' + 'b' == 'ab'",        # sequences are never grown by arithmetic
    "4294967297 * 2 > 0",       # an operand past 2**32 is refused
]


#: Binary operators the folder deliberately does not fold, and why.
#:
#: DERIVED-AGAINST, not merely listed. `UNDECIDED_BY_DESIGN` above is a set of
#: example expressions, and a review pointed out the obvious hole in that: it
#: asserts each listed shape is undecided and says nothing about whether the
#: list is COMPLETE. Two shapes inside the declared vocabulary were mis-decided
#: -- `True or compute()` and `1 if True else 0` are fixed at parse time and
#: were credited as real assertions -- while the comment beside the list said
#: the only unscreened shapes were exponent, shift, sequence arithmetic and
#: operands past 2**32.
#:
#: The BoolOp and IfExp cases are folded now. This table closes the other half:
#: every binary operator Python has is either folded or named here, so a new
#: operator cannot appear in the gap without someone writing down why.
DELIBERATELY_UNFOLDED_OPERATORS = {
    "Pow": "exponent: unbounded growth from small operands",
    "LShift": "shift: unbounded growth from small operands",
    "RShift": "shift: paired with LShift rather than reasoned about separately",
    "MatMult": "matrix multiply: no literal in this repository can produce one",
}


def _dispatched_statement_names() -> set:
    """Statement types `executed_nodes` names in an `isinstance` check."""
    import inspect  # noqa: PLC0415

    import guard_evidence  # noqa: PLC0415

    tree = ast.parse(inspect.getsource(guard_evidence.executed_nodes))
    named: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "ast":
                named.add(node.attr)
        if isinstance(node, ast.Name) and node.id in {"TRY_NODES", "MATCH_NODE"}:
            named.update(
                {"Try", "TryStar"} if node.id == "TRY_NODES" else {"Match"}
            )
    return named


def _folded_expression_names() -> set:
    """Expression types `_decide` names in an `isinstance` check."""
    import inspect  # noqa: PLC0415

    import guard_evidence  # noqa: PLC0415

    tree = ast.parse(inspect.getsource(guard_evidence._decide))
    return {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "ast"
    }


#: Every place that asks the screen how many failing things a REAL guard
#: executes, as (module path, function name).
#: The two consumers this check was written for, kept as the floor.
#:
#: A HAND-MAINTAINED LIST OF CONSUMERS IS THE THING IT GUARDS AGAINST.
#: A third module importing the screen and calling it without the module
#: argument was invisible here, and would have restored the escape this
#: check exists to close. `screen_consumers()` finds them by reading the
#: imports, so a new one is checked the moment it is written; these two
#: are still named so that DELETING a consumer is also a red test.
SCREEN_CONSUMERS = (
    ("tests/test_false_green_audit.py",
     "test_every_false_green_class_has_a_self_attack_that_trips_its_guard"),
    ("tests/test_killed_by_validation.py", "_defensive_evidence"),
)


def screen_consumers() -> list:
    """Every module under `tests/` that imports the shared screen."""
    found = []
    for module in sorted((ROOT / "tests").rglob("*.py")):
        if module.name == "guard_evidence.py":
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            imported = (
                isinstance(node, ast.ImportFrom)
                and node.module == "guard_evidence"
            ) or (
                isinstance(node, ast.Import)
                and any(a.name == "guard_evidence" for a in node.names)
            )
            if imported:
                # THE PATH IT WAS FOUND AT, not its basename. The widening
                # from `glob` to `rglob` discovered nested modules and then
                # threw the subdirectory away, so `tests/nested/test_x.py`
                # was reported as `tests/test_x.py` and
                # `screen_call_sites` opened a DIFFERENT FILE -- the flat
                # one -- while the nested module's unchecked calls went
                # uninspected. Set equality then hid it too, because the
                # duplicated flat name collapsed into an already-named
                # entry. Half of a widening is how the escape it closed
                # came back.
                found.append(module.relative_to(ROOT).as_posix())
                break
    return found


def test_the_named_consumers_are_all_the_consumers():
    """A list of callers typed by hand is the defect it guards against.

    `SCREEN_CONSUMERS` is two entries somebody wrote down. A third module
    importing the screen and calling it WITHOUT the module argument would
    have restored the escape the check below exists to close -- a
    module-level `_OFF = False` folding a guard to nothing -- and no test
    would have looked at it.

    Discovery is by import, so a new consumer is covered the moment it is
    written. The named pair is kept as a floor: a consumer DISAPPEARING is
    also a diff to argue with, and set equality catches both directions.
    """
    discovered = set(screen_consumers())
    named = {relative for relative, _ in SCREEN_CONSUMERS}
    assert named <= discovered, (
        "a module named as a consumer no longer imports the screen: "
        + repr(sorted(named - discovered))
    )
    unnamed = discovered - named
    assert unnamed == set(), (
        "these modules import the shared screen and are not named in "
        "SCREEN_CONSUMERS, so nothing checks that they pass the module: "
        + repr(sorted(unnamed))
    )


#: The screen's entry points, however the call is spelled.
SCREEN_ENTRY_POINTS = frozenset({"exercised_assertions", "executed_nodes"})


def screen_local_names(tree: ast.AST) -> set:
    """Every local name bound to a screen entry point in this module.

    `from guard_evidence import exercised_assertions as _screen` binds the
    screen to `_screen`, and a filter that knew two spellings walked past
    `_screen(fn)` entirely. Measured inside the real consumer
    `_defensive_evidence`: the alias added, the module argument dropped,
    all five wiring controls green, and the screen's answer on an
    `_OFF = False` guard moving from 0 to 2.

    The previous repair closed a spelling class by adding a spelling,
    which leaves the class open. This reads the imports instead: whatever
    the entry point is called HERE is what a call to it is called.
    """
    names = set(SCREEN_ENTRY_POINTS)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "guard_evidence":
            for alias in node.names:
                if alias.name in SCREEN_ENTRY_POINTS:
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Assign):
            # `_screen = exercised_assertions` is the same rename without
            # an import statement.
            denoted = node.value
            named = (denoted.attr if isinstance(denoted, ast.Attribute)
                     else getattr(denoted, "id", ""))
            if named in SCREEN_ENTRY_POINTS:
                names.update(
                    target.id for target in node.targets
                    if isinstance(target, ast.Name)
                )
    return names


def _asks_the_screen(call: ast.Call, local_names: set | None = None) -> bool:
    """Is this a call to the shared screen, however it is named here?

    The filter required `ast.Name`, so `import guard_evidence` followed by
    `guard_evidence.exercised_assertions(node)` was invisible -- two
    module-less calls in a DISCOVERED consumer, uninspected. Discovery had
    been widened to attribute-form imports and inspection had not, which is
    the same half-widening that let a nested consumer be read from the
    wrong file one round earlier.
    """
    known = SCREEN_ENTRY_POINTS if local_names is None else local_names
    callee = call.func
    if isinstance(callee, ast.Name):
        return callee.id in known
    if isinstance(callee, ast.Attribute):
        return callee.attr in known
    return False


def screen_call_sites(relative: str) -> list:
    """Every call to the screen in a module, with the function it sits in.

    NOT just the one function named in `SCREEN_CONSUMERS`. That list pairs a
    module with a single function, so a SECOND function in an already-named
    module could ask the screen without the module argument and be
    discovered, named, and never looked at -- restoring the escape by the
    one route the discovery check made look covered.
    """
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    local_names = screen_local_names(tree)
    sites = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and _asks_the_screen(
                call, local_names,
            ):
                sites.append((node.name, call))
    return sites


#: Helpers that return the `(guard, module)` pair the screen wants.
#:
#: Named rather than inferred from the `*`, because the star says only
#: that something is unpacked and not that it unpacks to two things.
#:
#: AND THE NAME IS NOT THE PROPERTY EITHER. This was `frozenset({"_guard"})`
#: under a comment claiming a starred call passes only when what is starred
#: is a call to something DECLARED TO RETURN THE PAIR -- and nothing
#: declared or checked that: `f(*_guard())` with zero arguments passed, and
#: any consumer defining its own one-tuple `_guard` would have too. A rule
#: about a name, in the module whose subject is that a rule about a
#: spelling is not a rule. `test_every_pair_helper_really_returns_a_pair`
#: reads each named helper's `return` and requires a two-element tuple.
PAIR_HELPERS = frozenset({"_guard"})


#: Expression shapes that syntactically CANNOT be a module.
#:
#: Listed rather than described, because the description drifted from the
#: code the moment it was written: it said "a literal of any other kind"
#: while an f-string walked through, and "an empty container" while
#: non-empty ones were refused too.
CANNOT_BE_A_MODULE = (
    ast.Constant,      # None, a number, a string, a bool
    ast.JoinedStr,     # an f-string is a literal too
    ast.List, ast.Tuple, ast.Set, ast.Dict,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
    ast.Lambda,
    ast.UnaryOp, ast.BoolOp, ast.Compare,
)


def _could_be_a_module(argument: ast.expr) -> bool:
    """Could this expression be a module, or is it plainly not one?

    Statically the value is unknowable, and this does not pretend
    otherwise: `f(guard, whatever())` is admitted, because a call could
    return a module. What it refuses is `CANNOT_BE_A_MODULE` -- the shapes
    that syntactically cannot be one. That is the whole distance between an
    arity check and a module check, and it is the distance a one-token edit
    travelled.

    THIS DOCSTRING SAID "a literal of any other kind" and admitted an
    f-string, a lambda and a comprehension -- none of which can be a module,
    and an f-string of which is a literal. It also said "an empty container"
    while refusing non-empty ones too. Both halves are now the table below.
    """
    return not isinstance(argument, CANNOT_BE_A_MODULE)


def _supplies_the_module(call: ast.Call) -> bool:
    """Does this call hand the screen a module?

    A starred argument counts: `exercised_assertions(*_guard(body, source))`
    unpacks the (guard, module) pair the helper returns, and refusing it
    would fail every specimen in this file for supplying the module the
    correct way.
    """
    # A STARRED ARGUMENT IS NOT PROOF ON ITS OWN. The justification for
    # accepting one was the ARITY of a particular helper -- `*_guard(body,
    # source)` unpacks a (guard, module) pair -- and the rule was written
    # about the `*`. `exercised_assertions(*sites)` with a one-element
    # `sites` supplies no module and was accepted. So the helper is named:
    # a starred call passes only when what is starred is a call to
    # something declared to return the pair.
    for argument in call.args:
        if not isinstance(argument, ast.Starred):
            continue
        inner = argument.value
        if (isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id in PAIR_HELPERS):
            return True
        return False
    # `**kw` was auto-accepted for the same reason and with as little
    # evidence; only an explicit `module=` counts, and only when what it
    # is given could be a module.
    for keyword in call.keywords:
        if keyword.arg == "module":
            return _could_be_a_module(keyword.value)
    # AN ARITY IS NOT A MODULE. `len(call.args) >= 2` was the whole test,
    # so `exercised_assertions(fn, None)` -- a one-token edit at either
    # consumer -- passed every wiring check while restoring the escape they
    # exist to close. Measured: the real consumer edited from `tree` to
    # `None`, all four wiring tests green, and the screen's answer moving
    # from 0 to 2 on the `_OFF = False` specimen.
    return len(call.args) >= 2 and _could_be_a_module(call.args[1])


def test_every_pair_helper_really_returns_a_pair():
    """`PAIR_HELPERS` is a list of names; this binds it to the property.

    The comment beside it says a starred call passes only when what is
    starred returns the (guard, module) pair. Nothing checked that, so
    `f(*_guard())` passed and so would any consumer's own one-tuple
    `_guard`. Each named helper is read here: it must exist, and every
    `return` it makes must be a two-element tuple.
    """
    for name in sorted(PAIR_HELPERS):
        found = []
        for module in sorted((ROOT / "tests").rglob("*.py")):
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and node.name == name):
                    found.append((module, node))
        assert found, (
            name + " is named as a helper returning the (guard, module) "
            "pair and is defined nowhere under tests/"
        )
        for module, function in found:
            returns = [
                node for node in ast.walk(function)
                if isinstance(node, ast.Return) and node.value is not None
            ]
            assert returns, (
                str(module.name) + "::" + name + " returns nothing, so a "
                "starred call on it supplies no module"
            )
            for node in returns:
                # ARITY IS NOT A MODULE HERE EITHER. This counted elements
                # under a message reading "does not supply a module", so
                # `return function, None` passed -- the identical defect
                # repaired fourteen lines above in `_supplies_the_module`,
                # with `_could_be_a_module` sitting between them unused.
                pair = (isinstance(node.value, ast.Tuple)
                        and len(node.value.elts) == 2)
                assert pair and _could_be_a_module(node.value.elts[1]), (
                    str(module.name) + "::" + name + " line "
                    + str(node.lineno) + " does not return a two-element "
                    "tuple whose second element could be a module, so "
                    "`*" + name + "(...)` does not supply one"
                )


SCREEN_NAMING = [
    ("the bare entry point",
     "from guard_evidence import exercised_assertions" + NL
     + "def t():" + NL + "    exercised_assertions(fn)", True),
    ("through the module",
     "import guard_evidence" + NL
     + "def t():" + NL + "    guard_evidence.executed_nodes(fn)", True),
    ("renamed at the import",
     "from guard_evidence import exercised_assertions as _screen" + NL
     + "def t():" + NL + "    _screen(fn)", True),
    ("renamed by assignment",
     "from guard_evidence import exercised_assertions" + NL
     + "S = exercised_assertions" + NL
     + "def t():" + NL + "    S(fn)", True),

    # ---- and the direction that must NOT change ---------------------
    ("an unrelated function of a similar name",
     "def t():" + NL + "    exercise(fn)", False),
    ("an attribute of something else",
     "def t():" + NL + "    recorder.count(fn)", False),
]


@pytest.mark.parametrize(
    ("label", "source", "seen"), SCREEN_NAMING,
    ids=[case[0] for case in SCREEN_NAMING],
)
def test_the_screen_is_recognised_however_it_is_named(
    label: str, source: str, seen: bool,
):
    """A rename is not a different function.

    The filter knew two spellings, so
    `from guard_evidence import exercised_assertions as _screen` followed
    by `_screen(fn)` was invisible. Measured inside the real consumer:
    the alias added, the module argument dropped, all five wiring controls
    green, and the screen's answer on an `_OFF = False` guard moving from
    0 to 2. The previous repair closed a spelling class by adding a
    spelling, which leaves the class open.
    """
    tree = ast.parse(source + NL)
    local_names = screen_local_names(tree)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert calls, label
    found = any(_asks_the_screen(call, local_names) for call in calls)
    assert found is seen, (
        label + ": the filter " + ("missed" if seen else "flagged")
        + " this call:" + NL + source
    )


PAIR_SHAPES = [
    ("the pair", "def _p(b, s):" + NL + "    return guard, module", True),
    ("a pair whose second element is None",
     "def _p(b, s):" + NL + "    return guard, None", False),
    ("a pair of literals", "def _p(b, s):" + NL + "    return 1, 2", False),
    ("a single value", "def _p(b, s):" + NL + "    return guard", False),
    ("a three-tuple",
     "def _p(b, s):" + NL + "    return guard, module, extra", False),
]


@pytest.mark.parametrize(
    ("label", "source", "supplies"), PAIR_SHAPES,
    ids=[case[0] for case in PAIR_SHAPES],
)
def test_a_pair_helper_must_return_something_that_could_be_a_module(
    label: str, source: str, supplies: bool, tmp_path: Path, monkeypatch,
):
    """The helper check counted elements under a message about modules.

    `return function, None` passed -- arity two, second element a value
    that cannot be a module -- which is the identical defect repaired
    fourteen lines above in `_supplies_the_module`, with
    `_could_be_a_module` sitting between them and unused.
    """
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "guard_evidence.py").write_text("", encoding="utf-8", newline="")
    (tests / "test_helper.py").write_text(
        source.replace("_p", "_guard") + NL, encoding="utf-8", newline="",
    )
    monkeypatch.setattr("test_false_green_audit.ROOT", tmp_path, raising=True)

    if supplies:
        test_every_pair_helper_really_returns_a_pair()
        return
    with pytest.raises(AssertionError, match="could be a module|two-element"):
        test_every_pair_helper_really_returns_a_pair()


def test_no_call_anywhere_asks_the_screen_without_the_module():
    """Every call site in every consumer, not one function in each.

    `test_every_consumer_of_the_screen_passes_the_module` reads the single
    function `SCREEN_CONSUMERS` names per module. This reads them all, so a
    new call written anywhere in a consumer is covered the moment it is
    written rather than when someone remembers to add it to a list.
    """
    unwired = []
    for relative in screen_consumers():
        for function, call in screen_call_sites(relative):
            if not _supplies_the_module(call):
                unwired.append(
                    relative + "::" + function + " line " + str(call.lineno)
                )
    assert unwired == [], (
        "these calls ask the screen without the module, so a module-level "
        "constant is invisible to them and a guard folded by one can be "
        "credited with executing something: " + repr(unwired)
    )


def test_every_consumer_of_the_screen_passes_the_module():
    """A module-level constant is invisible to a screen not given the module.

    Measured: dropping the module argument at either consumer left every
    specimen table GREEN, because the tables construct their own module and
    pass it. The tables prove the SCREEN; only this proves the CALLERS.

    Without it, one deleted argument restores the escape a review demonstrated
    end to end -- `_OFF = False` at module level, the guard body indented under
    `if _OFF:`, pristine RED to gutted GREEN with the marker intact.
    """
    unwired = []
    for relative, name in SCREEN_CONSUMERS:
        source = (ROOT / relative).read_text(encoding="utf-8")
        tree = ast.parse(source)
        function = next(
            (node for node in ast.walk(tree)
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name == name),
            None,
        )
        assert function is not None, relative + " no longer defines " + name
        # ONE filter AND ONE MODULE RULE, both shared with
        # `screen_call_sites`. Removing the duplicated call detector left
        # the module-supply rule duplicated and DIVERGENT: this one did not
        # understand `*` at all, so a starred call was always flagged, and
        # the two controls gave opposite verdicts on the same construct.
        # One of them was right by accident of crudeness, which is not the
        # same as being right.
        local_names = screen_local_names(tree)
        calls = [
            node for node in ast.walk(function)
            if isinstance(node, ast.Call) and _asks_the_screen(node, local_names)
        ]
        assert calls, relative + "::" + name + " no longer asks the screen"
        for call in calls:
            if not _supplies_the_module(call):
                unwired.append(
                    relative + "::" + name + " line " + str(call.lineno)
                )
    assert unwired == [], (
        "these consumers ask the screen without giving it the module, so a "
        "module-level constant is invisible and a guard indented under one "
        "counts assertions it does not execute: " + repr(unwired)
    )


#: (guard body, failing things executed) for the TERMINATION axis.
#:
#: Four lines at the top of any guard, every assertion left in place --
#: `try: / return / except Exception: / pass` -- gutted 40 of 40 FG owners
#: with identical counts pristine and gutted, and 4 of the 5 bodies carrying
#: all 41 catalogue kills. `_terminates` said it was "RECURSIVE THROUGH
#: COMPOUND STATEMENTS" and recursed through two of six.
TERMINATION_SPECIMENS = [
    ("try:" + NL + "    return" + NL + "except Exception:" + NL + "    pass" + NL
     + "assert real", 0),
    ("try:" + NL + "    return" + NL + "finally:" + NL + "    pass" + NL
     + "assert real", 0),
    # `finally` TERMINATING IS THE ONLY REASON THIS TRY TERMINATES. Every
    # other zero above leaves via the body, so the `finalbody` rule was never
    # the deciding factor and removing it left the suite green -- a rule no
    # specimen could exercise.
    ("try:" + NL + "    risky()" + NL + "finally:" + NL + "    return" + NL
     + "assert real", 0),
    ("match value:" + NL + "    case _:" + NL + "        return" + NL
     + "assert real", 0),
    ("while True:" + NL + "    return" + NL + "assert real", 0),
    ("for _ in [1]:" + NL + "    return" + NL + "assert real", 0),
    ("if cond:" + NL + "    return" + NL + "else:" + NL + "    return" + NL
     + "assert real", 0),

    # ---- and the direction that must NOT change -------------------------
    # `finally` runs on every path, so its assertion executes.
    ("try:" + NL + "    return" + NL + "finally:" + NL + "    assert real", 1),
    # A handler runs only if something raised, so the block may fall through.
    ("try:" + NL + "    risky()" + NL + "except Exception:" + NL + "    return" + NL
     + "assert real", 1),
    # A `raise` IS interceptable, unlike a `return`.
    ("try:" + NL + "    raise Boom()" + NL + "except Exception:" + NL + "    pass" + NL
     + "assert real", 1),
    # No catch-all case, so the match may fall through.
    ("match value:" + NL + "    case 1:" + NL + "        return" + NL
     + "assert real", 1),
    ("while cond:" + NL + "    return" + NL + "assert real", 1),

    # `break` AND `continue` LEAVE THE LOOP, NOT THE BLOCK AROUND IT, and this
    # screen said otherwise for one round. Teaching `_terminates` to recurse
    # through `for` and `while` -- so a loop whose body always returns can end
    # a block -- carried `break` and `continue` out with it, and every
    # assertion after such a loop was judged dead. That is the screen FAILING A
    # GENUINE GUARD, the one direction this module says it never can.
    #
    # The rows above pin the loop clauses with `return` only, so both of them
    # pointed the same way and nothing held the other side down. These do.
    ("while True:" + NL + "    break" + NL + "assert real", 1),
    ("for _ in [1]:" + NL + "    continue" + NL + "assert real", 1),
    ("for _ in (1,):" + NL + "    break" + NL + "assert real" + NL
     + "assert other", 2),
    ("while True:" + NL + "    if cond:" + NL + "        break" + NL
     + "    step()" + NL + "assert real", 1),
    ("with ctx():" + NL + "    while True:" + NL + "        break" + NL
     + "assert real", 1),
    # A `break` that is NOT inside a loop still ends its block: the flag has to
    # distinguish the two, and a rule that simply stopped counting `break`
    # would pass every row above while losing this one.
    ("break" + NL + "assert real", 0),
    ("continue" + NL + "assert real", 0),
    ("with ctx():" + NL + "    break" + NL + "assert real", 0),
    ("for _ in rows:" + NL + "    return" + NL + "assert real", 1),
    ("if cond:" + NL + "    return" + NL + "assert real", 1),
]


@pytest.mark.parametrize(("body", "expected"), TERMINATION_SPECIMENS)
def test_the_screen_knows_which_statements_end_a_block(body: str, expected: int):
    """Every zero gutted 40 of 40 FG owners with every gate green.

    THE ROWS EXPECTING A LIVE COUNT are the half that makes this a rule
    rather than a
    blunt instrument: `finally` runs on every path, a handler runs only if
    something raised, a `raise` is interceptable where a `return` is not, a
    `match` without a catch-all may fall through, and `break`/`continue`
    leave the LOOP rather than the block around it.

    THE COUNT THAT STOOD HERE SAID SEVEN and the table had grown to twelve
    non-zero rows, because the loop specimens were added later and the
    sentence was not. It is gone rather than corrected: a number typed
    beside a table nobody parses has now rotted in three separate comments
    in this repository, and the reasons are the part worth stating anyway.
    """
    counted = exercised_assertions(*_guard(body))
    assert counted == expected, (
        "the screen says this guard executes " + str(counted) + " failing "
        "thing(s); it executes " + str(expected) + ":" + NL + body
    )


def test_every_statement_type_can_be_asked_whether_it_terminates():
    """The FOURTH vocabulary axis, and the only one that had no completeness check.

    `executed_nodes` dispatch, `_decide` folding and `ARITHMETIC` operators are
    all derived against the grammar. `_terminates` was not, and it decided two
    compound statements out of six while claiming to be recursive through all
    of them. `TryStar` and `Match` were missing from it for as long as they
    have existed, exactly as they were missing from the dispatch axis before
    that axis was derived.

    So the same question is asked here: every `ast.stmt` subclass is either
    handled by `_terminates` or listed in `NON_TERMINATING_STATEMENTS` with the
    reason it cannot end a block.
    """
    import inspect  # noqa: PLC0415

    import guard_evidence  # noqa: PLC0415
    from guard_evidence import NON_TERMINATING_STATEMENTS  # noqa: PLC0415

    source = inspect.getsource(guard_evidence._terminates)
    handled = {
        node.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name) and node.value.id == "ast"
    }
    handled |= {"Try", "TryStar", "Match"}  # reached via TRY_NODES / MATCH_NODE
    every = {
        node.__name__ for node in vars(ast).values()
        if isinstance(node, type) and issubclass(node, ast.stmt)
        and node is not ast.stmt
    }
    unaccounted = sorted(every - handled - set(NON_TERMINATING_STATEMENTS))
    assert unaccounted == [], (
        "these statement types are neither decided by `_terminates` nor "
        "declared unable to end a block, so whether code after them counts is "
        "an accident: " + repr(unaccounted)
    )
    phantom = sorted(set(NON_TERMINATING_STATEMENTS) - every)
    assert phantom == [], (
        "these declared statement types do not exist in this Python: "
        + repr(phantom)
    )


def test_every_statement_type_is_dispatched_or_declared():
    """Three rounds of enumerating shapes by hand, three rounds of missing one.

        round 2   taught the screen `1 == 1`, `not False`, `'a' in 'abc'`
        round 3   the walker credited `if False:` bodies
        round 4   `except*` and `match` had no dispatch at all

    Each time I added the shape a reviewer named and believed the list
    complete. `ast.TryStar` (3.11) and `ast.Match` (3.10) were missing for
    exactly as long as they have existed, and a guard measured a real
    kill-bearing body gutted under `except* AssertionError: pass` as still
    carrying four proofs.

    THE QUESTION IS ASKED OF THE GRAMMAR NOW. Every `ast.stmt` subclass must be
    either dispatched by `executed_nodes` or listed in
    `UNDISPATCHED_STATEMENTS` with the reason falling through is safe. A new
    statement type in a future Python is a red test on the day the interpreter
    ships it, not a finding three review rounds later.

    This is the technique `DELIBERATELY_UNFOLDED_OPERATORS` already applied to
    `ast.operator`, where it holds. It was applied to one axis out of three.
    """
    from guard_evidence import UNDISPATCHED_STATEMENTS  # noqa: PLC0415

    every = {
        node.__name__ for node in vars(ast).values()
        if isinstance(node, type) and issubclass(node, ast.stmt)
        and node is not ast.stmt
    }
    dispatched = _dispatched_statement_names() & every
    declared = set(UNDISPATCHED_STATEMENTS) & every
    unaccounted = sorted(every - dispatched - declared)
    assert unaccounted == [], (
        "these statement types are neither dispatched by the walker nor "
        "declared safe to fall through, so the screen's behaviour on them is "
        "an accident rather than a decision: " + repr(unaccounted)
    )
    phantom = sorted(set(UNDISPATCHED_STATEMENTS) - every)
    assert phantom == [], (
        "these declared statement types do not exist in this Python, so the "
        "declaration is stale: " + repr(phantom)
    )


def test_every_expression_type_is_folded_or_declared():
    """The same question, on the expression axis.

    `JoinedStr` and `Subscript` were in neither table, which is how
    `assert f"{1} == {2}"` -- fixed at parse time, one character from a real
    assertion, and reading exactly like one -- was credited as real while the
    identical `assert "1 == 2"` was caught.
    """
    from guard_evidence import UNFOLDED_EXPRESSIONS  # noqa: PLC0415

    every = {
        node.__name__ for node in vars(ast).values()
        if isinstance(node, type) and issubclass(node, ast.expr)
        and node is not ast.expr
    }
    folded = _folded_expression_names() & every
    declared = set(UNFOLDED_EXPRESSIONS) & every
    unaccounted = sorted(every - folded - declared)
    assert unaccounted == [], (
        "these expression types are neither folded nor declared as a gap, so "
        "the folder's stated limits are not its real limits: "
        + repr(unaccounted)
    )
    phantom = sorted(set(UNFOLDED_EXPRESSIONS) - every)
    assert phantom == [], (
        "these declared expression types do not exist in this Python: "
        + repr(phantom)
    )


def test_the_screen_never_raises_on_any_guard_in_the_suite():
    """The third outcome the module denied having.

    `guard_evidence` says undecided "always resolves toward 'this is a real
    assertion' -- the screen can miss a vacuous guard, it can never fail a
    genuine one." There was a third: crash. `len()` on a folded non-sequence
    raised `TypeError` straight out, so every consumer ERRORED rather than
    reaching a verdict, and `for _ in rows` with `rows` bound to `None`, an
    int, or a bool was enough.

    Run over every top-level test function in `tests/`, which is the corpus the
    screen is actually pointed at.
    """
    checked = 0
    for module in sorted((ROOT / "tests").glob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            checked += 1
            try:
                # WITH THE MODULE, which is how every consumer calls it.
                # Without it this proved the property only for the
                # module-less path -- the one production does not use --
                # and left `module_constants`, `name_aliases` and the
                # whole scoping pass out of the sweep entirely.
                exercised_assertions(node, tree)
            except Exception as exc:  # noqa: BLE001 - the point of the test
                raise AssertionError(
                    "the screen raised on " + module.name + "::" + node.name
                    + " -- " + type(exc).__name__ + ": " + str(exc)
                ) from exc
    assert checked > 500, (
        "only " + str(checked) + " functions were screened; the corpus is "
        "smaller than the suite, so this measured almost nothing"
    )


def test_the_folders_gaps_are_exactly_the_ones_it_declares():
    """A list of examples cannot say whether the list is complete.

    `UNDECIDED_BY_DESIGN` asserts four expressions are not folded. That is
    worth having and it is not completeness: a fifth unfolded shape simply
    would not appear in it, which is how `True or compute()` sat inside the
    declared vocabulary being mis-decided while the prose beside the list
    claimed the gaps were exhaustive.

    This asks the question the other way round. Every binary operator the
    language has must be either IN the folder's arithmetic table or NAMED as a
    deliberate gap with a reason. A new operator is then a red test rather than
    a silent widening.
    """
    from guard_evidence import ARITHMETIC  # noqa: PLC0415

    every = {
        node.__name__ for node in vars(ast).values()
        if isinstance(node, type) and issubclass(node, ast.operator)
        and node is not ast.operator
    }
    folded = {node.__name__ for node in ARITHMETIC}
    declared = set(DELIBERATELY_UNFOLDED_OPERATORS)
    unaccounted = sorted(every - folded - declared)
    assert unaccounted == [], (
        "these binary operators are neither folded nor declared as a gap, so "
        "the folder's stated limits are not its real limits: " + repr(unaccounted)
    )
    phantom = sorted(declared & folded)
    assert phantom == [], (
        "these operators are declared as deliberate gaps AND folded, so the "
        "declaration is stale: " + repr(phantom)
    )


def _assertion(source: str) -> tuple:
    """(test expression, enclosing function) for `assert <source>`."""
    function = ast.parse(
        chr(10).join(["def guard():", "    assert " + source, ""])
    ).body[0]
    return function.body[0].test, function


#: (guard body, is the assertion fixed at parse time).
#:
#: A NAME BOUND ONLY TO LITERALS, seen through an operator. The Name rule fired
#: only when the whole test WAS a bare Name, so every row marked True below
#: except the first was credited as a real assertion -- one token away from the
#: shape that was live in `tests/test_mutation_catalogue.py`.
NAME_BINDING_SPECIMENS = [
    ("flag = True" + NL + "assert flag", True),
    ("flag = True" + NL + "assert flag == True", True),
    ("flag = True" + NL + "assert flag is True", True),
    ("gone = False" + NL + "assert not gone", True),
    ("flag = True" + NL + "assert flag and True", True),
    ("flag = True" + NL + "assert flag != False", True),
    ("count = 2" + NL + "assert count > 1", True),

    # NOT fixed: the name is computed, or rebound from something that is not a
    # literal. A guard that computes a value and asserts it is a real guard,
    # whatever its first binding was.
    ("flag = compute()" + NL + "assert flag", False),
    ("flag = True" + NL + "flag = compute()" + NL + "assert flag == True", False),
    ("flag = True" + NL + "flag += 1" + NL + "assert flag", False),
    ("for flag in rows:" + NL + "    pass" + NL + "assert flag", False),
    ("with open(path) as flag:" + NL + "    pass" + NL + "assert flag", False),
    ("assert flag == True", False),
]


@pytest.mark.parametrize(("body", "fixed"), NAME_BINDING_SPECIMENS)
def test_a_name_bound_only_to_literals_is_as_fixed_as_a_literal(body: str, fixed: bool):
    """`assert flag == True` where `flag = True` is not an assertion.

    Both directions, because the wrong answer in the other direction is worse:
    calling a computed value vacuous would fail a genuine guard for a property
    it does not have. So a name is folded ONLY when every binding of it in the
    guard is a constant literal, and any other kind of binding -- a call, a loop
    target, a `with` target, an augmented assignment -- disqualifies it
    outright rather than merely being overwritten.
    """
    guard, module = _guard(body)
    test = next(node for node in ast.walk(guard) if isinstance(node, ast.Assert)).test
    assert _cannot_fail(test, guard, module) is fixed, (
        "this guard body was judged " + ("fixed" if not fixed else "real")
        + " at parse time:" + NL + body
    )


@pytest.mark.parametrize("source", VACUOUS_ASSERTIONS)
def test_an_assertion_fixed_at_parse_time_is_called_vacuous(source: str):
    """Every shape here defeats a marked guard entirely, and cheaply.

    `assert True` is the one everybody names, and it is not the interesting
    one. A review gutted a declared guard to `assert 1 == 1`, kept its marker,
    and the audit reported the class proven: all eight certification nodes
    passed, rc 0, collection identical to pristine, and nothing anywhere
    checked the property the class exists for.

    The screen answered only for a bare `ast.Constant` then, so `1 == 1`,
    `not False` and `'a' in 'abc'` each walked straight through.
    """
    test, function = _assertion(source)
    assert _cannot_fail(test, function), (
        "`assert " + source + "` has the same value on every run, and the "
        "screen credits it as a proof. A guard can be gutted to exactly this, "
        "keep its marker, and the audit will report its class proven."
    )


@pytest.mark.parametrize("source", REAL_ASSERTIONS)
def test_an_assertion_that_reads_state_is_left_alone(source: str):
    """The screen must be too permissive, never too strict.

    `_fold` has no branch for Name, Call, Attribute or Subscript, so anything
    reading state is undecided by construction rather than by a filter in
    front of it -- and undecided means "real" at every call site.
    """
    test, function = _assertion(source)
    assert not _cannot_fail(test, function), (
        "`assert " + source + "` depends on state the suite computes, and the "
        "screen called it vacuous. A genuine guard would be failed for a "
        "property it does not have."
    )


@pytest.mark.parametrize("source", UNDECIDED_BY_DESIGN)
def test_the_folder_stops_where_it_says_it_stops(source: str):
    """The documented gap, asserted rather than described.

    These are fixed at parse time and the screen credits them anyway. That is
    a real hole and it is written down instead of implied: `**`, the shifts,
    sequence arithmetic and operands past 2**32 are absent from the vocabulary
    because folding them is unbounded work on source this file does not own.

    Asserted in the AFFIRMATIVE so that closing the gap later cannot happen
    silently -- extending the vocabulary turns this test red and forces the
    list above to be rewritten.
    """
    test, function = _assertion(source)
    assert not _cannot_fail(test, function), (
        "`assert " + source + "` is now decided by the folder. That is an "
        "improvement, and it has to be recorded: move it out of "
        "UNDECIDED_BY_DESIGN into VACUOUS_ASSERTIONS."
    )


#: Guard bodies, and how many failing things each one EXECUTES.
#:
#: Every zero here is a real edit an adversary can make to a marked guard: the
#: node stays, the marker stays, collection is identical, and the audit reports
#: the class proven. Seven of them were measured GREEN end to end on FG01
#: before the counter stopped confusing containment with execution.
EXECUTION_SPECIMENS = [
    # --- executes a real proof --------------------------------------------
    ("assert result == 4", 1),
    ("assert a" + NL + "assert b", 2),
    ("raise AssertionError('no')", 1),
    ("with pytest.raises(ValueError):" + NL + "    boom()", 1),
    ("pytest.fail('unreachable')", 1),
    ("if flag:" + NL + "    assert real", 1),
    ("for row in rows:" + NL + "    assert row", 1),
    ("try:" + NL + "    assert real" + NL + "finally:" + NL + "    clean()", 1),
    # TWO: the assertion, and the re-raise that keeps it fatal. A handler that
    # re-raises does not swallow, which is what separates this from the same
    # shape ending in `pass` further down.
    ("try:" + NL + "    assert real" + NL + "except AssertionError:" + NL
     + "    raise", 2),
    ("try:" + NL + "    assert real" + NL + "except ValueError:" + NL
     + "    pass", 1),

    # --- executes nothing that can fail ------------------------------------
    ("if False:" + NL + "    assert real", 0),
    ("if False:" + NL + "    raise AssertionError('never')", 0),
    ("while False:" + NL + "    raise AssertionError('never')", 0),
    ("for _ in ():" + NL + "    raise AssertionError('never')", 0),
    ("for _ in []:" + NL + "    assert real", 0),
    ("if True:" + NL + "    pass" + NL + "else:" + NL
     + "    raise AssertionError('never')", 0),
    ("def _inner():" + NL + "    assert real", 0),
    ("check = lambda: (_ for _ in ()).throw(AssertionError('x'))", 0),
    ("try:" + NL + "    assert real" + NL + "except AssertionError:" + NL
     + "    pass", 0),
    ("try:" + NL + "    assert real" + NL + "except Exception:" + NL
     + "    pass", 0),
    ("try:" + NL + "    assert real" + NL + "except:" + NL + "    pass", 0),
    ("assert True", 0),
    ("assert 1 == 1", 0),
    ("pass", 0),

    # --- the substring scan that credited a filename ------------------------
    ("with io.StringIO('raises.txt') as handle:" + NL + "    handle.read()", 0),
    ("with open(base / 'no-raises-here') as handle:" + NL + "    handle.read()", 0),
    ("record.fail(reason)", 0),
    ("if False:" + NL + "    record.fail(reason)", 0),
]


def _guard(body: str, module_source: str = "") -> tuple:
    """(guard, module) for `body`, optionally under module-level source.

    Returns BOTH, because a module-level constant is in scope inside the guard
    and the screen cannot see one it is not given. A review added a single
    `_OFF = False` above a real guard and indented the body under `if _OFF:`;
    it went from pristine RED to gutted GREEN.
    """
    lines = ["def guard():", '    """A docstring."""']
    lines += ["    " + line if line.strip() else line for line in body.split(NL)]
    source = module_source + (NL if module_source else "") + NL.join(lines) + NL
    module = ast.parse(source)
    guard = next(node for node in module.body
                 if isinstance(node, ast.FunctionDef) and node.name == "guard")
    return guard, module


@pytest.mark.parametrize(("body", "expected"), EXECUTION_SPECIMENS)
def test_the_counter_measures_what_a_guard_executes(body: str, expected: int):
    """Containment is not execution, and `ast.walk` only answers containment.

    This is the COMPOSITION, and the composition is where the gap lived. The
    helpers each had unit tests over synthetic snippets and each was correct;
    nothing measured what they added up to, so reachability was applied to one
    of four clauses and understood one of five statement forms. Changing `if`
    to `while`, or wrapping the assertions instead of a raise, walked straight
    through a green helper suite.

    A zero here is not academic. It is a one-line edit that leaves the guard
    collected, its marker in place, its name unchanged, and the audit reporting
    its class proven.
    """
    counted = exercised_assertions(*_guard(body))
    assert counted == expected, (
        "the counter says this guard executes " + str(counted) + " failing "
        "thing(s); it executes " + str(expected) + ":" + NL + body
    )


#: Shapes a third review round demonstrated, each measured GREEN end to end on
#: a real gutted guard before the screen moved into `tests/guard_evidence.py`.
ROUND_THREE_SPECIMENS = [
    # A NAME AWAY FROM THE LITERAL. The walker called the folder without the
    # guard's constant bindings, so any `ast.Name` was undecidable and BOTH
    # sides of the branch were credited -- the identical defect this repository
    # had just repaired one function away, in `cannot_fail`.
    ("dead = False" + NL + "if dead:" + NL + "    assert real", 0),
    ("alive = True" + NL + "if alive:" + NL + "    pass" + NL + "else:" + NL
     + "    assert real", 0),
    ("empty = ()" + NL + "for _ in empty:" + NL + "    assert real", 0),

    # A HANDLER FOR A BODY THAT CANNOT RAISE NEVER RUNS.
    ("try:" + NL + "    pass" + NL + "except Exception:" + NL
     + "    raise AssertionError('never')", 0),
    # `rethrows` decided by CONTAINMENT credited a raise nothing executes.
    ("try:" + NL + "    assert real" + NL + "except AssertionError:" + NL
     + "    if False:" + NL + "        raise", 0),
    ("try:" + NL + "    assert real" + NL + "except AssertionError:" + NL
     + "    def _n():" + NL + "        raise", 0),
    # `contextlib.suppress` swallows exactly as the handler does and is never
    # an `ast.Try`, so the handler rule could not see it.
    ("with contextlib.suppress(AssertionError):" + NL + "    assert real", 0),

    # NOTHING AFTER AN UNCONDITIONAL EXIT EXECUTES. The old screen looked for
    # `ast.Return` as the FIRST statement only.
    ("pytest.skip('nope')" + NL + "assert real", 0),
    ("if True:" + NL + "    return" + NL + "assert real", 0),

    # SHORT-CIRCUITING. Evaluating every operand eagerly let one undecidable
    # operand poison a result that is fixed either way.
    ("assert True or compute()", 0),
    ("assert compute() or True", 0),
    ("assert not (compute() and False)", 0),
    ("assert 1 if True else 0", 0),

    # ---- and the other direction, which is the louder wrong answer --------
    # A MUTABLE CONTAINER IS NOT FIXED. Extending bindings to literal
    # containers so `empty = ()` folds also folded this, and reported that a
    # 60-kill-point atomicity sweep -- the guard for FG39, single use across
    # two durable stores -- asserts nothing.
    ("disagreed = []" + NL + "for k in rows:" + NL + "    disagreed.append(k)" + NL
     + "assert disagreed == []", 1),
    ("found = {}" + NL + "assert found == {}", 1),
    ("if cond:" + NL + "    return" + NL + "assert real", 1),
    ("try:" + NL + "    compute()" + NL + "except Exception:" + NL
     + "    raise AssertionError('x')", 1),
    ("assert compute() or other()", 1),
    ("assert x if cond else y", 1),
    ("rows = [1]" + NL + "for _ in rows:" + NL + "    assert real", 1),
]


#: Shapes a FOURTH review round demonstrated, each verified on a copy.
#:
#: Two of them are exception-group and match statements, which had no dispatch
#: for as long as they have existed in Python. Two more are inside the folder's
#: own literal vocabulary. One CRASHED the screen outright, in a module whose
#: docstring says it "can never fail a genuine one".
ROUND_FOUR_SPECIMENS = [
    # `except*` is `ast.TryStar`, a different node from `ast.Try`.
    ("try:" + NL + "    assert real" + NL + "except* AssertionError:" + NL
     + "    pass", 0),
    ("try:" + NL + "    assert real" + NL + "except* Exception:" + NL
     + "    pass", 0),
    # ... and a handler that does NOT swallow still counts.
    ("try:" + NL + "    assert real" + NL + "except* ValueError:" + NL
     + "    pass", 1),

    # An f-string with nothing to interpolate is a literal. The identical
    # `assert "a message"` was caught; this was not.
    ("assert f'a message'", 0),
    ("assert f'{1} == {2}'", 0),
    ("assert f'{value}'", 1),

    # A literal indexed by a literal is a literal.
    ("assert (1, 2)[0]", 0),
    ("assert 'abc'[0] == 'a'", 0),
    ("assert [1, 2][0]", 0),
    ("assert {1: 2}[1]", 0),
    ("assert rows[0]", 1),

    # THE CRASH. `len()` on a folded non-sequence raised `TypeError` out of the
    # screen, so consumers errored rather than reaching a verdict.
    ("rows = None" + NL + "for _ in rows:" + NL + "    assert real", 1),
    ("count = 3" + NL + "for _ in count:" + NL + "    assert real", 1),

    # A chained assignment bound a COMPUTED name to the constant `None`,
    # because the disqualifying branch returned `None` rather than the
    # not-a-literal sentinel -- and a genuine guard was refused.
    ("results = report['x'] = run()" + NL + "if results:" + NL
     + "    assert results == expected", 1),
]


#: (module-level source, guard body, failing things executed).
#:
#: A CONSTANT ONE SCOPE, ONE ALIAS OR ONE UNPACK AWAY. `dead = False; if dead:`
#: was pinned and its three synonyms were not, so a rule about the shape was in
#: fact a rule about the spelling. The module-level form was demonstrated end
#: to end: ONE added line and an indent took FG21's owner from pristine RED to
#: gutted GREEN, marker intact, node intact, collection identical.
SCOPED_BINDING_SPECIMENS = [
    ("_OFF = False", "if _OFF:" + NL + "    assert real", 0),
    ("_ON = True", "if _ON:" + NL + "    pass" + NL + "else:" + NL
     + "    assert real", 0),
    ("", "dead = False" + NL + "gone = dead" + NL + "if gone:" + NL
     + "    assert real", 0),
    ("", "dead = False" + NL + "gone = dead" + NL + "far = gone" + NL
     + "if far:" + NL + "    assert real", 0),
    ("", "first, second = False, True" + NL + "if first:" + NL
     + "    assert real", 0),

    # --- and the other direction, which must stay credited ---------------
    ("_ON = True", "if _ON:" + NL + "    assert real", 1),
    ("", "first, second = False, True" + NL + "if second:" + NL
     + "    assert real", 1),
    ("", "src = compute()" + NL + "alias = src" + NL + "if alias:" + NL
     + "    assert real", 1),
    # A local rebinding disqualifies the module-level constant.
    ("_OFF = False", "_OFF = compute()" + NL + "if _OFF:" + NL
     + "    assert real", 1),
    ("_LIMIT = 3", "assert rows == _LIMIT", 1),
]


#: (label, module-level source, guard body, exercised assertions).
#:
#: FG42. Every one of the zeros catches exactly what `except AssertionError:`
#: catches, and every one of them was invisible to a rule that asked how the
#: class was SPELLED. The ones are the over-reach control: a narrow handler, an
#: alias to a narrow class, a handler that re-raises, and `suppress` of
#: something that is not an assertion are all REAL, and a screen that called
#: them swallowed would refuse genuine guards -- which is FG41, one row over.
SWALLOWING_ALIAS_SPECIMENS = [
    ("the pinned spelling", "",
     "try:" + NL + "    assert real" + NL + "except AssertionError:" + NL
     + "    pass", 0),
    ("a module-level alias", "_Err = AssertionError",
     "try:" + NL + "    assert real" + NL + "except _Err:" + NL + "    pass", 0),
    ("a chain of two aliases", "_A = AssertionError" + NL + "_B = _A",
     "try:" + NL + "    assert real" + NL + "except _B:" + NL + "    pass", 0),
    ("an alias to a tuple", "_S = (AssertionError,)",
     "try:" + NL + "    assert real" + NL + "except _S:" + NL + "    pass", 0),
    ("a tuple built by a constructor", "",
     "try:" + NL + "    assert real" + NL + "except tuple([AssertionError]):"
     + NL + "    pass", 0),
    ("an alias bound inside the guard", "",
     "_L = Exception" + NL + "try:" + NL + "    assert real" + NL
     + "except _L:" + NL + "    pass", 0),
    ("an alias of contextlib.suppress", "_Q = contextlib.suppress",
     "with _Q(AssertionError):" + NL + "    assert real", 0),
    ("suppress splatting an aliased tuple", "_S = (AssertionError,)",
     "with contextlib.suppress(*_S):" + NL + "    assert real", 0),
    ("suppress imported bare", "",
     "with suppress(AssertionError):" + NL + "    assert real", 0),

    # ---- and the direction that must NOT change -------------------------
    ("a narrow handler does not swallow", "",
     "try:" + NL + "    assert real" + NL + "except ValueError:" + NL
     + "    pass", 1),
    ("an alias to a narrow class does not", "_N = ValueError",
     "try:" + NL + "    assert real" + NL + "except _N:" + NL + "    pass", 1),
    ("suppressing a narrow class does not", "",
     "with contextlib.suppress(ValueError):" + NL + "    assert real", 1),
    # The assertion AND the re-raise both count, which is why this is 2.
    ("a handler that re-raises does not", "",
     "try:" + NL + "    assert real" + NL + "except Exception:" + NL
     + "    raise", 2),
    # ---- round 9: the escapes the FG42 repair itself left open ----------
    #
    # THE FIRST TWO ARE THE REPAIR'S OWN HOLES, found by a fresh lens after
    # FG42 was closed. Both were measured gutting real audited guards with the
    # screen reporting identical counts pristine and gutted.
    #
    # An ATTRIBUTE was resolved through the BARE-NAME map, and `.get(k,
    # default)` replaces rather than widens -- so two module lines that never
    # touch the guard moved `suppress` OUT of the set. That is resolution
    # working in the unsafe direction, which is the opposite of what
    # `denoted_names` claimed.
    ("an attribute is not the bare name it ends with",
     "import contextlib" + NL + "_fallback = object" + NL + "suppress = _fallback",
     "with contextlib.suppress(AssertionError):" + NL + "    assert real", 0),
    # `import ... as` IS a rename, and FG42 is the class about a rename. Every
    # row above spells its alias `name = expr`, the one spelling that had been
    # repaired -- a table built entirely out of the fixed case.
    ("except through an import alias",
     "from builtins import AssertionError as _Err",
     "try:" + NL + "    assert real" + NL + "except _Err:" + NL + "    pass", 0),
    ("suppress through an import alias",
     "from contextlib import suppress as quiet",
     "with quiet(AssertionError):" + NL + "    assert real", 0),
    ("a module imported under another name",
     "import contextlib as ctx",
     "with ctx.suppress(AssertionError):" + NL + "    assert real", 0),
    ("an aliased alias, two imports deep",
     "from contextlib import suppress as quiet" + NL + "hush = quiet",
     "with hush(AssertionError):" + NL + "    assert real", 0),

    # ---- and the direction that must NOT change -------------------------
    # THE LOCAL BINDING WINS, which is the scoping Python has. The first
    # version of `name_aliases` said so and UNIONED the two instead, so this
    # guard -- which really does fail -- was reported as executing nothing.
    ("a local rebind of a module alias is a genuine guard",
     "_E = AssertionError",
     "_E = ValueError" + NL + "try:" + NL + "    assert real" + NL
     + "except _E:" + NL + "    pass", 1),
    ("and the same shape pointing the other way still swallows",
     "_E = ValueError",
     "_E = Exception" + NL + "try:" + NL + "    assert real" + NL
     + "except _E:" + NL + "    pass", 0),
    ("an attribute of an unrelated object is not a suppression",
     "",
     "with recorder.suppress(AssertionError):" + NL + "    assert real", 0),
]


@pytest.mark.false_green("FG42")
@pytest.mark.parametrize(
    ("label", "module_source", "body", "expected"), SWALLOWING_ALIAS_SPECIMENS,
    ids=[case[0] for case in SWALLOWING_ALIAS_SPECIMENS],
)
def test_a_swallowing_handler_is_found_however_the_class_is_named(
    label: str, module_source: str, body: str, expected: int,
):
    """A rename must not turn a swallowed assertion back into a proof.

    The screen already resolves aliases to a fixed point for the FOLDING axis
    and says, in its own docstring, that a rule catching the pinned spelling
    and not its synonyms is a rule about the spelling. It did not apply that to
    the SWALLOWING axis, and every specimen in the tables that reached this
    code spelled the class literally -- so the escape had no case pointing at
    it in a module built out of exactly such cases.
    """
    counted = exercised_assertions(*_guard(body, module_source))
    assert counted == expected, (
        label + ": the screen says this guard executes " + str(counted)
        + " failing thing(s); it executes " + str(expected) + ":" + NL
        + (module_source + NL if module_source else "") + body
    )


#: (label, module-level source, guard body, exercised assertions).
#:
#: ONE INDENT WAS ENOUGH TO ESCAPE BOTH ROUND-9 REPAIRS. `module_scope_statements`
#: yields a compound statement AND the statements inside it, so a rule that
#: walked the whole subtree recorded a binding from the `Assign` and then
#: disqualified it from the enclosing `If` in the same pass. Measured on a real
#: audited guard: the identical gut passed or failed purely on whether the added
#: line sat at column 0.
#:
#: `module_scope_statements` exists for exactly this -- its docstring says a
#: constant under `if TYPE_CHECKING:` or inside `try: ... except ImportError:`
#: was invisible -- and every specimen written for it put the binding at column
#: 0, so the one case it was built for was the one case unpinned.
NESTED_MODULE_SPECIMENS = [
    ("a constant at column 0, as every earlier specimen spelled it",
     "_OFF = False",
     "if _OFF:" + NL + "    assert real" + NL + "    assert other", 0),
    ("the same constant one indent deep",
     "if True:" + NL + "    _OFF = False",
     "if _OFF:" + NL + "    assert real" + NL + "    assert other", 0),
    ("under the conditional import the docstring names",
     "if TYPE_CHECKING:" + NL + "    _OFF = False",
     "if _OFF:" + NL + "    assert real", 0),
    ("under try/except ImportError, the other case it names",
     "try:" + NL + "    _OFF = False" + NL + "except ImportError:" + NL
     + "    _OFF = False",
     "if _OFF:" + NL + "    assert real", 0),
    ("an alias one indent deep",
     "if True:" + NL + "    _Swallow = AssertionError",
     "try:" + NL + "    assert real" + NL + "except _Swallow:" + NL + "    pass", 0),
    ("an alias under a guarded import",
     "try:" + NL + "    _Swallow = AssertionError" + NL + "except ImportError:"
     + NL + "    _Swallow = Exception",
     "try:" + NL + "    assert real" + NL + "except _Swallow:" + NL + "    pass", 0),

    # ---- and the direction that must NOT change -------------------------
    # A NESTED STATEMENT STILL DISQUALIFIES WHAT IT BINDS. The repair is
    # "visit each statement once", not "stop disqualifying" -- and a rule that
    # simply dropped the enclosing statement would lose these.
    ("a loop target still disqualifies the constant",
     "_OFF = False" + NL + "for _OFF in candidates():" + NL + "    pass",
     "if _OFF:" + NL + "    assert real" + NL + "    assert other", 2),
    ("a nested loop target too",
     "if True:" + NL + "    _OFF = False" + NL + "for _OFF in candidates():" + NL
     + "    pass",
     "if _OFF:" + NL + "    assert real" + NL + "    assert other", 2),
    ("a with-target nested under a conditional",
     "_OFF = False" + NL + "if ready():" + NL + "    with open('f') as _OFF:" + NL
     + "        pass",
     "if _OFF:" + NL + "    assert real" + NL + "    assert other", 2),
    ("a live constant still credits its branch", "_ON = True",
     "if _ON:" + NL + "    assert real", 1),
]


@pytest.mark.parametrize(
    ("label", "module_source", "body", "expected"), NESTED_MODULE_SPECIMENS,
    ids=[case[0] for case in NESTED_MODULE_SPECIMENS],
)
def test_a_module_binding_is_seen_wherever_it_sits(
    label: str, module_source: str, body: str, expected: int,
):
    """Column 0 and one indent deep must answer the same.

    Both axes at once -- the folding axis and the alias axis -- because both
    read the same statement walk and both had the same hole.
    """
    counted = exercised_assertions(*_guard(body, module_source))
    assert counted == expected, (
        label + ": the screen says this guard executes " + str(counted)
        + " failing thing(s); it executes " + str(expected) + ":" + NL
        + (module_source + NL if module_source else "") + body
    )


def test_a_parameter_shadowing_a_module_alias_is_not_that_alias():
    """The repair `constant_bindings` has, on the axis that lacked it.

    `constant_bindings` disqualifies parameters and says so; `name_aliases` was
    written later for the same scoping question and never read `function.args`.
    Measured: module `_E = AssertionError` with `def guard(_E=ValueError)`
    resolved `_E` to AssertionError and reported a guard that really does raise
    as executing nothing.
    """
    module = ast.parse(
        "_E = AssertionError" + NL + NL
        + "def guard(_E=ValueError):" + NL
        + '    """A docstring."""' + NL
        + "    try:" + NL
        + "        assert real" + NL
        + "    except _E:" + NL
        + "        pass" + NL
    )
    guard = next(node for node in module.body if isinstance(node, ast.FunctionDef))
    assert exercised_assertions(guard, module) == 1, (
        "a parameter was resolved to the module-level alias it shadows, and a "
        "live guard was reported as executing nothing"
    )
    # The control: WITHOUT the parameter the same source really is swallowed,
    # so the specimen is decided by the shadowing and not by anything else.
    shadowless = ast.parse(
        "_E = AssertionError" + NL + NL
        + "def guard():" + NL
        + '    """A docstring."""' + NL
        + "    try:" + NL
        + "        assert real" + NL
        + "    except _E:" + NL
        + "        pass" + NL
    )
    bare = next(node for node in shadowless.body if isinstance(node, ast.FunctionDef))
    assert exercised_assertions(bare, shadowless) == 0


#: A module-level name whose literal binding is not its ONLY binding.
#:
#: Every one of these was reported DEAD -- indistinguishable from the genuinely
#: dead `_OFF = False` control above -- because the module pass read `ast.Assign`
#: and `continue`d past every other statement without disqualifying anything.
#: The docstring said such a name was "excluded outright"; the function pass did
#: that, the module pass did not, and no specimen crossed the two.
#:
#: FG41. The direction matters: this is the screen refusing a GENUINE guard, not
#: crediting a gutted one. It cannot let a false green through, which is why it
#: survived four rounds of specimens that were all aimed the other way.
REBOUND_MODULE_SPECIMENS = [
    ("recomputed after the literal", "FLAG = False" + NL + "FLAG = _detect()",
     "if FLAG:" + NL + "    assert real"),
    ("augmented", "COUNT = 0" + NL + "COUNT += 1",
     "if COUNT:" + NL + "    assert real"),
    ("rebound by a loop", "STATE = False" + NL + "for STATE in candidates():"
     + NL + "    pass", "if STATE:" + NL + "    assert real"),
    ("annotated later", "READY = False" + NL + "READY: bool = _detect()",
     "if READY:" + NL + "    assert real"),
    ("shadowed by an import", "enabled = False" + NL
     + "from config import enabled", "if enabled:" + NL + "    assert real"),
    ("shadowed by a def", "handler = False" + NL + "def handler():" + NL
     + "    return True", "if handler:" + NL + "    assert real"),
    ("bound again by a with", "session = False" + NL + "with open('f') as session:"
     + NL + "    pass", "if session:" + NL + "    assert real"),
    ("bound again by a walrus", "seen = False" + NL + "print(seen := _detect())",
     "if seen:" + NL + "    assert real"),
    ("caught into the name", "err = False" + NL + "try:" + NL + "    _boot()"
     + NL + "except Exception as err:" + NL + "    pass",
     "if err:" + NL + "    assert real"),
    ("declared under a conditional import", "FAST = False" + NL
     + "if _has_c_extension():" + NL + "    FAST = _load()",
     "if FAST:" + NL + "    assert real"),
]


@pytest.mark.false_green("FG41")
@pytest.mark.parametrize(
    ("label", "module_source", "body"), REBOUND_MODULE_SPECIMENS,
    ids=[case[0] for case in REBOUND_MODULE_SPECIMENS],
)
def test_a_module_name_bound_twice_is_not_a_constant(
    label: str, module_source: str, body: str,
):
    """A second binding disqualifies the name, whatever statement performs it.

    Each specimen is a REAL guard: the branch can be taken, so the assertion
    under it must be credited. The last one is the shape that makes this more
    than theoretical -- a module-level feature flag set once at import time
    under a conditional is ordinary Python, and its literal default is not its
    value.
    """
    counted = exercised_assertions(*_guard(body, module_source))
    assert counted == 1, (
        label + ": the screen says this guard executes nothing, so a real "
        "assertion would be reported as a false green:" + NL
        + module_source + NL + body
    )


def test_a_parameter_shadowing_a_module_constant_is_not_that_constant():
    """The name the guard reads is its own parameter, not the module's.

    Separate from the table because `_guard` builds a guard with no parameters,
    and this defect is only visible on one that has them.
    """
    module = ast.parse(
        "ready = False" + NL + NL
        + "def guard(ready):" + NL
        + '    """A docstring."""' + NL
        + "    if ready:" + NL
        + "        assert real" + NL
    )
    guard = next(node for node in module.body if isinstance(node, ast.FunctionDef))
    assert exercised_assertions(guard, module) == 1, (
        "a parameter was folded to the module-level default that it shadows"
    )
    # The control: WITHOUT the parameter the same source is genuinely dead, so
    # the specimen is decided by the shadowing and not by anything else.
    shadowless = ast.parse(
        "ready = False" + NL + NL
        + "def guard():" + NL
        + '    """A docstring."""' + NL
        + "    if ready:" + NL
        + "        assert real" + NL
    )
    bare = next(node for node in shadowless.body if isinstance(node, ast.FunctionDef))
    assert exercised_assertions(bare, shadowless) == 0


def test_a_guard_that_declares_global_is_not_folded_to_the_module_value():
    """`global X` says the guard may rebind X, and the screen must believe it."""
    module = ast.parse(
        "STATE = False" + NL + NL
        + "def guard():" + NL
        + '    """A docstring."""' + NL
        + "    global STATE" + NL
        + "    STATE = _detect()" + NL
        + "    if STATE:" + NL
        + "        assert real" + NL
    )
    guard = next(node for node in module.body if isinstance(node, ast.FunctionDef))
    assert exercised_assertions(guard, module) == 1


def test_symtable_agrees_that_these_are_all_the_module_bindings():
    """`bound_names` is checked against CPython's own binding analysis.

    THE COMPLETENESS AXIS FOR `bound_names`, and deliberately not another table
    maintained by hand. Four hand-maintained vocabularies already sit in this
    module; a fifth would have the same failure mode as the first four, which is
    that a grammar change nobody notices leaves it silently short.

    `symtable` is the binding analysis the interpreter itself performs. Any name
    it reports as bound in a module's own scope that `bound_names` does not
    collect is a name that could stay a "constant" while something rebinds it --
    the exact direction that refuses a genuine guard.

    Run over every module in `tests/` and `src/`, so the corpus is real code
    rather than specimens chosen to pass.

    WHAT IT CANNOT REACH, because "the completeness axis for this screen"
    claimed more than a set difference can do. `collected` is the union of
    `bound_names` over every module statement, and that union INCLUDES the
    literal `Assign` -- so a name that is bound literally here AND rebound
    invisibly elsewhere is never in `reported - collected`. A `global`
    declaration inside a function is exactly that shape; it is handled in
    `module_constants` directly rather than caught here, and this test
    would not have noticed if it were not.
    """
    import symtable  # noqa: PLC0415

    from guard_evidence import bound_names, module_scope_statements  # noqa: PLC0415

    checked = 0
    for path in sorted([*(ROOT / "tests").rglob("*.py"), *(ROOT / "src").rglob("*.py")]):
        source = path.read_text(encoding="utf-8")
        try:
            table = symtable.symtable(source, str(path), "exec")
        except SyntaxError:  # pragma: no cover - the corpus parses
            continue
        module = ast.parse(source)
        collected: set = set()
        for node in module_scope_statements(module):
            collected |= bound_names(node)
        reported = {
            symbol.get_name() for symbol in table.get_symbols()
            if symbol.is_assigned() or symbol.is_imported()
        }
        missing = reported - collected
        assert not missing, (
            str(path.relative_to(ROOT)) + ": CPython binds " + repr(sorted(missing))
            + " in this module's own scope and `bound_names` does not collect "
            "it, so such a name would keep a stale literal value and fold a "
            "branch that is live"
        )
        checked += 1
    assert checked > 100, (
        "the corpus collapsed to " + str(checked) + " modules, so this proves "
        "much less than it reads as proving"
    )


@pytest.mark.parametrize(
    ("module_source", "body", "expected"), SCOPED_BINDING_SPECIMENS,
)
def test_a_constant_in_any_scope_is_as_fixed_as_a_local_one(
    module_source: str, body: str, expected: int,
):
    """The pinned spelling and its synonyms must answer the same.

    The five expecting 1 are the guard against over-reach: an alias of a
    computed value, the true half of an unpack, and a name the guard rebinds
    locally are all REAL, and folding them would fail a genuine guard.
    """
    counted = exercised_assertions(*_guard(body, module_source))
    assert counted == expected, (
        "the screen says this guard executes " + str(counted) + " failing "
        "thing(s); it executes " + str(expected) + ":" + NL
        + (module_source + NL if module_source else "") + body
    )


@pytest.mark.parametrize(("body", "expected"), ROUND_FOUR_SPECIMENS)
def test_the_screen_answers_the_shapes_a_fourth_round_demonstrated(
    body: str, expected: int,
):
    """Every zero was credited, and two of these crashed the screen.

    The ones expecting 1 are the louder half: a genuine guard refused for a
    property it has. The `report['x'] = run()` row is exactly that, and it is
    here because the disqualifying branch of a binding rule returned `None`
    where it meant "not a literal".
    """
    counted = exercised_assertions(*_guard(body))
    assert counted == expected, (
        "the screen says this guard executes " + str(counted) + " failing "
        "thing(s); it executes " + str(expected) + ":" + NL + body
    )


@pytest.mark.parametrize(("body", "expected"), ROUND_THREE_SPECIMENS)
def test_the_screen_answers_the_shapes_a_third_round_demonstrated(
    body: str, expected: int,
):
    """Every zero here was measured GREEN on a real gutted guard.

    Not hypothetical shapes: each was applied to the FG01 owner body with the
    marker kept, the node kept and collection identical to pristine, and the
    audit reported the class proven.

    The ones expecting 1 matter at least as much. Refusing a genuine guard is
    the louder wrong answer, and the mutable-container row is there because
    this screen briefly did exactly that to the FG39 atomicity sweep.
    """
    counted = exercised_assertions(*_guard(body))
    assert counted == expected, (
        "the screen says this guard executes " + str(counted) + " failing "
        "thing(s); it executes " + str(expected) + ":" + NL + body
    )


#: `ast` functions that render a tree as TEXT.
#:
#: `unparse` was missing and carries the identical defect: `"raises" in
#: ast.unparse(node)` matches inside a string constant exactly as the dumped
#: form does, so `io.StringIO("raises.txt")` reads as an expected-refusal block
#: -- the false green FG40 records, one function name away from the one that
#: was checked.
RENDERING_FUNCTIONS = frozenset({"dump", "unparse"})

#: Public `str` methods that do NOT answer "does this text contain that text",
#: each with the reason it cannot.
#:
#: THE COMPLETENESS AXIS FOR THIS RULE, and the reason it is written as an
#: exemption table rather than as a list of the dangerous ones. The scan used
#: to name seven methods it knew about; `.partition`, `.removeprefix`,
#: `.split` and `.replace` are the same question and none was listed, and
#: nothing could have told anyone that. Derived against `dir(str)` by
#: `test_every_string_method_is_a_question_or_declared_not_to_be`, so a method
#: added to `str` is a red test rather than a silent hole.
#:
#: The transformations are safe because they PRODUCE text rather than
#: interrogate it, and `_is_dumped_tree` follows them, so the question they
#: feed is still caught one call later.
#:
#: FIVE OF THESE REASONS SAID "takes no needle" AND WERE FALSE.
#: `str.strip`, `lstrip`, `rstrip`, `splitlines` and `join` all accept an
#: argument, and `rstrip` discriminates on it -- `'abca'.rstrip(x)` differs
#: by `x`. They are safe for the OTHER reason in that sentence, which is
#: the one that is actually load-bearing, and they now say so.
#:
#: The only check over these reasons was `len(reason) > 10`, under a
#: message reading "is exempted without a reason that says why it cannot
#: ask a containment question" -- a length test named as a semantic one, in
#: this module. `test_every_safe_method_still_leads_to_a_caught_question`
#: replaces the pretence with the measurement: for each exempted method,
#: a question asked after it must still be caught. That was stated before it was true
#: of `format`, `format_map` and `join`: following happened through the
#: RECEIVER, and for those three the rendered tree is an argument while the
#: receiver is the template or the separator. `_TEXT_FROM_ARGUMENTS` is the
#: half that was missing.
SAFE_STRING_METHODS = {
    "capitalize":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "casefold":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "center":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "encode":
        "produces bytes and takes no needle; a question asked of the result "
        "is caught where it is asked",
    "expandtabs":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "format":
        "substitutes into a template it is called on, and the template is "
        "not the rendered tree being interrogated",
    "format_map":
        "substitutes into a template it is called on, and the template is "
        "not the rendered tree being interrogated",
    "isalnum":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "isalpha":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "isascii":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "isdecimal":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "isdigit":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "isidentifier":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "islower":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "isnumeric":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "isprintable":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "isspace":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "istitle":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "isupper":
        "asks about the characters of the whole string, never whether a "
        "given substring occurs in it",
    "join":
        "combines the argument sequence and takes no needle of its own",
    "ljust":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "lower":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "lstrip":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "maketrans":
        "builds a translation table and inspects nothing",
    "rjust":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "rstrip":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "splitlines":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "strip":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "swapcase":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "title":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "upper":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
    "zfill":
        "returns text, and `_is_dumped_tree` follows the receiver through "
        "it, so a question asked of the result is caught one call later",
}

#: Everything else `str` offers takes a needle and answers a question about it.
_SUBSTRING_METHODS = frozenset(
    name for name in dir(str)
    if not name.startswith("_") and name not in SAFE_STRING_METHODS
)

#: `re` entry points that take a haystack.
#:
#: Module-level (`re.search(pattern, text)`) the haystack is the SECOND
#: argument; on a compiled pattern (`re.compile(p).search(text)`) it is the
#: FIRST. The scan only ever looked at the second, so the compiled form walked
#: through.
_REGEX_SEARCHES = frozenset({"findall", "finditer", "fullmatch", "match",
                             "search", "split", "sub", "subn"})

#: Text-producing methods that take the rendered tree as an ARGUMENT.
#:
#: `format`, `format_map` and `join` are exempted from being QUESTIONS
#: because they produce text rather than interrogate it -- which is true,
#: and the exemption's stated ground was that `_is_dumped_tree` follows
#: them so the question they feed is caught one call later. It followed
#: receivers only, and for these three the rendered tree is an argument
#: while the receiver is the template or the separator. Measured: all
#: three carried FG21's retired spelling straight past the scan.
_TEXT_FROM_ARGUMENTS = frozenset({"format", "format_map", "join"})


#: Callables that ask containment without being a method of the text.
_CONTAINMENT_FUNCTIONS = frozenset({"contains"})


def _dumped_tree_names(tree: ast.AST) -> set:
    """Names bound to the text of a rendered AST, to a fixed point.

    `rendered = ast.dump(node)` then `"x" in rendered` is the same test one
    line apart, and the scan that named the property saw only the one-line
    form. Chains are followed because `a = ast.dump(n); b = a` is not a
    different idea.
    """
    bound: set = set()
    for _ in range(3):
        widened = set(bound)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not _is_dumped_tree(node.value, widened):
                continue
            widened |= {
                target.id for target in node.targets
                if isinstance(target, ast.Name)
            }
        if widened == bound:
            break
        bound = widened
    return bound


def _is_dumped_tree(expression, bound: set) -> bool:
    """Is this expression the TEXT of a rendered AST?"""
    if isinstance(expression, ast.Name):
        return expression.id in bound
    if isinstance(expression, ast.Call):
        callee = expression.func
        named = (callee.attr if isinstance(callee, ast.Attribute)
                 else getattr(callee, "id", ""))
        if named in RENDERING_FUNCTIONS:
            return True
        # `str(ast.dump(n))` is the rendered tree wearing a conversion.
        if named == "str" and len(expression.args) == 1:
            return _is_dumped_tree(expression.args[0], bound)
        # `"{}".format(ast.dump(n))`, `"".join([ast.dump(n)])` -- the
        # rendered tree reached as an ARGUMENT, with the template or the
        # separator as receiver. The exemption table justified these three
        # by saying `_is_dumped_tree` follows them, and it followed only
        # RECEIVERS, so all three were a way to ask the question with the
        # rule looking the other way.
        if named in _TEXT_FROM_ARGUMENTS:
            # ANYWHERE IN THE ARGUMENT, because `join` takes a list and
            # `format_map` takes a dict -- the tree is one container
            # deep, and checking only the argument itself missed both.
            supplied = [*expression.args,
                        *(keyword.value for keyword in expression.keywords)]
            return any(
                _is_dumped_tree(inner, bound)
                for argument in supplied for inner in ast.walk(argument)
            )
        # `ast.dump(n).lower()`, `...strip()` -- still the rendered tree, one
        # transformation further away.
        if isinstance(callee, ast.Attribute):
            return _is_dumped_tree(callee.value, bound)
    if isinstance(expression, ast.JoinedStr):
        return any(
            _is_dumped_tree(part.value, bound)
            for part in expression.values
            if isinstance(part, ast.FormattedValue)
        )
    if isinstance(expression, ast.BinOp):
        return (_is_dumped_tree(expression.left, bound)
                or _is_dumped_tree(expression.right, bound))
    return False


def _is_the_re_module(expression) -> bool:
    """Is this the `re` module itself, rather than a compiled pattern?"""
    if isinstance(expression, ast.Name):
        return expression.id == "re"
    return isinstance(expression, ast.Attribute) and expression.attr == "re"


def substring_tests_against_a_dumped_tree(tree: ast.AST) -> list:
    """Line numbers where this module asks a text question about a rendered AST.

    ONE implementation, because the specimens below and the scan over `tests/`
    must be the same rule. A specimen table checking a private copy of a rule
    is FG40 -- "a repaired rule, when a second copy of it was left standing" --
    and that is the class this very scan exists to enforce.
    """
    bound = _dumped_tree_names(tree)
    found: list = []
    for node in ast.walk(tree):
        # `<literal> in <a rendered tree>` -- a membership test against text,
        # standing in for a question about structure.
        if isinstance(node, ast.Compare):
            if any(
                isinstance(op, (ast.In, ast.NotIn)) for op in node.ops
            ) and any(_is_dumped_tree(side, bound) for side in node.comparators):
                found.append(node.lineno)
            continue
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        if not isinstance(callee, ast.Attribute):
            # `operator.contains(haystack, needle)` as a bare name.
            if (getattr(callee, "id", "") in _CONTAINMENT_FUNCTIONS
                    and node.args and _is_dumped_tree(node.args[0], bound)):
                found.append(node.lineno)
            continue
        # `.find(...)`, `.count(...)`, `.partition(...)` ask the same question
        # with a method instead of an operator.
        if (callee.attr in _SUBSTRING_METHODS
                and _is_dumped_tree(callee.value, bound)):
            found.append(node.lineno)
            continue
        if (callee.attr in _CONTAINMENT_FUNCTIONS and node.args
                and _is_dumped_tree(node.args[0], bound)):
            found.append(node.lineno)
            continue
        if callee.attr in _REGEX_SEARCHES:
            # Module-level: the haystack is the second argument and the first
            # is a pattern, which is a legitimate use of a rendered tree.
            # Compiled: the pattern is already bound and the haystack is first.
            haystack = node.args[1:2] if _is_the_re_module(callee.value) else node.args[0:1]
            if any(_is_dumped_tree(argument, bound) for argument in haystack):
                found.append(node.lineno)
    return sorted(found)


@pytest.mark.false_green("FG40")
def test_no_module_reimplements_the_evidence_screen():
    """The rule has ONE home, because three rounds found it repaired in one
    place and intact in another.

        round 2   `cannot_fail` taught to fold literal-bound names
        round 3   the walker was calling the folder WITHOUT those bindings
        round 3   `test_killed_by_validation._defensive_evidence` was the
                  pre-repair implementation of all four clauses, governing
                  every kill in the mutation catalogue

    Extracting the rule in round 2 made this worse rather than better: it
    created a canonical implementation and left the old copy standing, which is
    FG40 -- "a repaired rule, when a second copy of it was left standing".

    WHAT THIS MEASURES, exactly: a substring test against a dumped AST, in
    whatever form it is written. It used to measure ONE form -- `x in
    <expr>.dump(...)` as a single expression -- so all of these passed while
    being the same test:

        rendered = ast.dump(n); "demo_command" in rendered
        from ast import dump; "demo_command" in dump(n)
        ast.dump(n).find("demo_command") >= 0
        ast.dump(n).count("demo_command") > 0
        re.search("demo_command", ast.dump(n))

    The local-variable form is the same clause one line apart, and this
    module's own subject is that a rule naming a spelling is a rule about the
    spelling. The three limits below are deliberate; that was not one of them.
    That is
    the one retired spelling with no legitimate reading -- `ast.dump` renders a
    tree as text and asking whether a name appears in that text cannot tell
    executable code from a string constant, which is FG21's own class. It
    credited `with io.StringIO("raises.txt")` as an expected-refusal block.

    WHAT IT DOES NOT MEASURE, said plainly rather than implied: the other three
    retired clauses. `ast.dump` used for tree COMPARISON is correct and live in
    `tests/mutation_validity.py`; `.attr == "..."` is ordinary AST matching
    almost everywhere it appears; and "counts evidence by containment" is not a
    spelling at all. A scan claiming to catch those would be matching text and
    calling it structure -- the exact substitution this module refuses.

    So this closes the one clause a machine can decide, and the other three are
    held by there being a single implementation for consumers to import.
    """
    home = ROOT / "tests/guard_evidence.py"
    assert home.is_file(), "the shared screen is gone; every consumer is a copy"

    offenders = []
    for module in sorted((ROOT / "tests").glob("*.py")):
        if module.name == "guard_evidence.py":
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        offenders += [
            module.name + ":" + str(line)
            for line in substring_tests_against_a_dumped_tree(tree)
        ]
    assert offenders == [], (
        "a substring test against a dumped AST is executable outside "
        "tests/guard_evidence.py. It cannot tell code from a string constant, "
        "and it credited `io.StringIO('raises.txt')` as an expected-refusal "
        "block the last time it was written: " + repr(offenders)
    )


#: (label, whole module source, exercised assertions in `guard`).
#:
#: HALF A REPAIR. `is_pytest_call` once matched any attribute call named
#: `fail`, so `record.fail(reason)` counted as a proof. That was fixed by
#: requiring a `pytest` receiver -- and the BARE-NAME branch, which exists so
#: `from pytest import raises` still works, was left matching any function of
#: that name at all. A locally defined `fail` or `raises` was credited as a
#: thing that can fail, and a locally defined `skip` truncated the block.
#:
#: The four ones are why the branch cannot simply be deleted: `from pytest
#: import raises` is real, and refusing it would fail genuine guards, which is
#: FG41.
PYTEST_NAME_SPECIMENS = [
    ("a locally defined fail is not pytest.fail",
     "def fail(msg):" + NL + "    pass" + NL + NL
     + "def guard():" + NL + '    """d."""' + NL + "    fail('nothing')", 0),
    ("a locally defined raises is not pytest.raises",
     "import contextlib" + NL + NL + "@contextlib.contextmanager" + NL
     + "def raises(kind):" + NL + "    yield" + NL + NL
     + "def guard():" + NL + '    """d."""' + NL
     + "    with raises(ValueError):" + NL + "        pass", 0),
    ("a locally defined skip does not end the block",
     "def skip(reason):" + NL + "    pass" + NL + NL
     + "def guard():" + NL + '    """d."""' + NL + "    skip('later')" + NL
     + "    assert real", 1),

    # ---- and the direction the branch exists for ------------------------
    ("pytest.fail through the module", "import pytest" + NL + NL
     + "def guard():" + NL + '    """d."""' + NL + "    pytest.fail('real')", 1),
    ("fail imported from pytest", "from pytest import fail" + NL + NL
     + "def guard():" + NL + '    """d."""' + NL + "    fail('real')", 1),
    ("raises imported from pytest", "from pytest import raises" + NL + NL
     + "def guard():" + NL + '    """d."""' + NL
     + "    with raises(ValueError):" + NL + "        pass", 1),
    ("skip imported from pytest DOES end the block",
     "from pytest import skip" + NL + NL
     + "def guard():" + NL + '    """d."""' + NL + "    skip('later')" + NL
     + "    assert real", 0),
]


@pytest.mark.parametrize(
    ("label", "source", "expected"), PYTEST_NAME_SPECIMENS,
    ids=[case[0] for case in PYTEST_NAME_SPECIMENS],
)
def test_a_bare_name_counts_only_when_it_came_from_pytest(
    label: str, source: str, expected: int,
):
    """Whole modules, because the import is what decides the question."""
    module = ast.parse(source + NL)
    guard = next(
        node for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "guard"
    )
    counted = exercised_assertions(guard, module)
    assert counted == expected, (
        label + ": the screen says this guard executes " + str(counted)
        + " failing thing(s); it executes " + str(expected)
    )


#: (label, source, is it a text question about a dumped tree).
#:
#: The twelve TRUE rows are all the same test; the scan knew one of them, and
#: the local-variable form is that one clause exactly one line apart. The five
#: FALSE rows are the over-reach control, and the first of them matters most:
#: `ast.dump(a) == ast.dump(b)` is tree COMPARISON, it is correct, and it is
#: live in `tests/mutation_validity.py`. A scan that flagged it would be
#: matching text and calling it structure -- the substitution this module
#: refuses -- so widening the rule had to leave it alone.
DUMPED_TREE_SPECIMENS = [
    ("the pinned spelling", '"demo_command" in ast.dump(n)', True),
    ("a local variable",
     "rendered = ast.dump(n)" + NL + 'x = "demo_command" in rendered', True),
    ("a chain of two locals",
     "a = ast.dump(n)" + NL + "b = a" + NL + 'x = "demo_command" in b', True),
    ("dump imported bare",
     "from ast import dump" + NL + 'x = "demo_command" in dump(n)', True),
    ("find", 'x = ast.dump(n).find("demo_command") >= 0', True),
    ("index", 'x = ast.dump(n).index("demo_command")', True),
    ("count", 'x = ast.dump(n).count("demo_command") > 0', True),
    ("startswith", 'x = ast.dump(n).startswith("Call")', True),
    ("re.search", 'x = re.search("demo_command", ast.dump(n))', True),
    ("re.findall", 'x = re.findall("demo_command", ast.dump(n))', True),
    ("one method further away", 'x = "demo_command" in ast.dump(n).lower()', True),
    ("inside an f-string", 'x = "demo_command" in f"{ast.dump(n)}"', True),
    ("not in", 'x = "demo_command" not in ast.dump(n)', True),

    # ---- and the direction that must NOT change -------------------------
    ("tree comparison, which is correct", "x = ast.dump(a) == ast.dump(b)", False),
    ("two dumps bound and compared",
     "a = ast.dump(x)" + NL + "b = ast.dump(y)" + NL + "z = a == b", False),
    ("a substring of ordinary text", 'x = "demo_command" in source', False),
    ("re.search over ordinary text", 'x = re.search("demo_command", source)', False),
    ("a dump used as the PATTERN, not the haystack",
     "x = re.search(ast.dump(n), source)", False),
    # ---- round 9: forms a fresh lens walked straight through -------------
    #
    # `ast.unparse` carries the IDENTICAL defect and was simply not named:
    # `"raises" in ast.unparse(io.StringIO("raises.txt"))` is True, which is
    # the exact false green FG40 records. The rest are one method call apart
    # from rows already above them, in a rule whose docstring says it measures
    # the question "in whatever form it is written".
    ("unparse instead of dump", 'x = "demo_command" in ast.unparse(n)', True),
    ("a str() conversion in between",
     'x = "demo_command" in str(ast.dump(n))', True),
    ("split", 'x = len(ast.dump(n).split("demo_command")) > 1', True),
    ("partition", 'x = ast.dump(n).partition("demo_command")[1]', True),
    ("removeprefix", 'x = ast.dump(n).removeprefix("demo_command")', True),
    ("replace", 'x = ast.dump(n).replace("demo_command", "") != ast.dump(n)', True),
    # The haystack moves to the FIRST argument once the pattern is compiled,
    # and the scan only ever looked at the second.
    ("a compiled pattern", 'x = re.compile("demo_command").search(ast.dump(n))', True),
    ("operator.contains", 'x = operator.contains(ast.dump(n), "demo_command")', True),
    ("unparse reached through a local",
     "rendered = ast.unparse(n)" + NL + 'x = "demo_command" in rendered', True),

    # ---- and the direction that must NOT change -------------------------
    ("unparse compared, which is correct",
     "x = ast.unparse(a) == ast.unparse(b)", False),
    ("a transformation with no question after it", "x = ast.dump(n).lower()", False),
    ("join takes no needle", 'x = ", ".join(parts)', False),
    ("through format", 'x = "demo_command" in "{}".format(ast.dump(n))', True),
    ("through join of a list", 'x = "demo_command" in "".join([ast.dump(n)])', True),
    ("through format_map of a dict",
     'x = "demo_command" in "{a}".format_map({"a": ast.dump(n)})', True),
    ("through join of a comprehension",
     'x = "demo_command" in "".join(ast.dump(k) for k in ns)', True),
    ("a join of ordinary parts is not a question",
     'x = ", ".join(parts)', False),
    ("a format of ordinary text is not a question",
     'x = "{}".format(name)', False),
]


@pytest.mark.parametrize(
    ("label", "source", "is_a_text_question"), DUMPED_TREE_SPECIMENS,
    ids=[case[0] for case in DUMPED_TREE_SPECIMENS],
)
def test_a_text_question_about_a_dumped_tree_is_found_however_it_is_written(
    label: str, source: str, is_a_text_question: bool,
):
    """Driven through the scan the gate runs, not through a copy of its rule."""
    found = substring_tests_against_a_dumped_tree(ast.parse(source))
    assert bool(found) is is_a_text_question, (
        label + ": the scan " + ("missed" if is_a_text_question else "flagged")
        + " this:" + NL + source
    )


def test_every_string_method_is_a_question_or_declared_not_to_be():
    """The completeness axis this rule did not have.

    `_SUBSTRING_METHODS` was seven names somebody thought of. `.partition`,
    `.removeprefix`, `.split` and `.replace` ask exactly the same question and
    none was listed; nothing in the repository could have said so. The four
    vocabularies in `tests/guard_evidence.py` are each derived against the
    grammar for precisely this reason, and this one was not derived against
    anything.

    It is now an EXEMPTION table checked against `dir(str)`, so a method added
    to `str` -- or removed from the exemptions without a reason -- is a red
    test rather than a silent hole.
    """
    public = {name for name in dir(str) if not name.startswith("_")}
    classified = set(SAFE_STRING_METHODS) | set(_SUBSTRING_METHODS)
    assert public - classified == set(), (
        "these `str` methods are neither treated as a text question nor "
        "declared safe, so a rendered tree could be interrogated with one and "
        f"nothing would notice: {sorted(public - classified)}"
    )
    assert classified - public == set(), (
        "these are classified and are not `str` methods, so the table has "
        f"drifted from the type it is about: {sorted(classified - public)}"
    )
    assert not (set(SAFE_STRING_METHODS) & set(_SUBSTRING_METHODS)), (
        "a method is both a question and declared not to be"
    )
    for name, reason in SAFE_STRING_METHODS.items():
        # A LENGTH, NAMED AS AN EXPLANATION -- so it says what it is.
        # Whether a reason explains is not decidable here; that a method
        # is genuinely safe IS, and
        # `test_every_safe_method_still_leads_to_a_caught_question`
        # measures it.
        assert reason.strip(), name + " is exempted with no reason at all"


#: Exempted methods that take the rendered tree as an ARGUMENT rather than
#: as a receiver, so the specimen below has to be built the other way up.
_ARGUMENT_SHAPED = _TEXT_FROM_ARGUMENTS

#: An exempted method that inspects nothing and takes no text at all.
STATIC_STRING_METHODS = frozenset({"maketrans"})


@pytest.mark.parametrize(
    "method", sorted(set(SAFE_STRING_METHODS) - STATIC_STRING_METHODS),
)
def test_every_safe_method_still_leads_to_a_caught_question(method: str):
    """Exempting a method is a claim that the question survives it.

    That claim was prose, and five of the reasons giving it were false.
    Here it is the measurement: for every exempted method, a rendered tree
    put through it and then asked a text question is still flagged. A
    method for which that stops being true is a hole, and this goes red
    rather than a reviewer having to re-derive the reasons.
    """
    if method in _ARGUMENT_SHAPED:
        source = (
            'x = "demo_command" in "{}".' + method + "([ast.dump(n)])"
            if method == "join"
            else 'x = "demo_command" in "{}".' + method + "(ast.dump(n))"
        )
    else:
        source = 'x = "demo_command" in ast.dump(n).' + method + "()"
        try:
            ast.parse(source)
        except SyntaxError:  # pragma: no cover - every name parses
            pytest.fail(method + " produced unparseable specimen source")
    found = substring_tests_against_a_dumped_tree(ast.parse(source))
    assert found, (
        method + " is exempted as a transformation the question survives, "
        "and a question asked after it is NOT caught: " + source
    )


def test_the_inventory_is_exactly_the_known_classes():
    """Set equality, so a class cannot be dropped to make the audit smaller.

    Nine became fifteen when Task 14 audited the proof system itself. Fifteen
    became twenty-six when the Lens A/B/C remediation was mined for every
    mechanism it had actually produced. None of these is a hazard someone
    imagined -- every one is a green result this repository really produced from
    machinery that had not measured what it claimed.

    Eleven of the fourteen newly-catalogued mechanisms needed new classes; three
    mapped onto FG08, FG13 and FG14. The test for "does this need its own ID"
    was never whether the words sounded similar, but whether an existing
    specimen could actually CATCH the defect. FG17 and FG18 are the sharpest
    example: a module standing in for a node, and a node's credit going to a
    different node, fail different guards, and neither specimen proves the other.

    Compared against EXPECTED_FALSE_GREEN_CLASSES rather than a literal range,
    so the inventory and the pin cannot drift apart -- and by SET, never by
    count, because "twenty-six classes" is satisfied by any twenty-six strings.
    That substitution is FG14, so expressing this inventory as a count would be
    the defect naming itself.
    """
    assert {item.ident for item in INVENTORY} == EXPECTED_FALSE_GREEN_CLASSES
    assert len(INVENTORY) == len(EXPECTED_FALSE_GREEN_CLASSES)
    for item in INVENTORY:
        assert len(item.false_claim) > 20 and len(item.root_cause) > 20, item.ident
        module, _, node = item.owner.partition("::")
        assert (ROOT / module).exists(), item.ident
        assert f"def {node}(" in (ROOT / module).read_text(encoding="utf-8"), item.ident


# --------------------------------------------------------------------------
# FG01 / FG02 -- fixture and prerequisite truth
# --------------------------------------------------------------------------


def _authenticated(grant) -> tuple[bool, str]:
    from signing import trust_store  # noqa: PLC0415

    from nornyx_forge.approval_trust import authenticate_action_grant  # noqa: PLC0415

    signer = authenticate_action_grant(grant, trust_store=trust_store())
    return signer.signer_authenticated, signer.reason


def _request():
    from test_governance_failure import TEST_REVISION  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        canonical_action_request,
    )

    return canonical_action_request(
        mission_id="CASE-FG", risk="high", subject_revision=TEST_REVISION,
        descriptor=ActionDescriptor(
            operation="issue refund", resource="customer:omar",
            destination="zone.external_customer",
            parameters={"amount": 100, "currency": "USD"},
        ),
        attempt=1,
    )


@pytest.mark.false_green("FG01")
def test_fg01_a_wrong_keyword_breaks_the_signature():
    """The historical mistake, reproduced exactly.

    `signed_grant` signs the canonical payload and THEN applies `**overrides`.
    Passing `approver_role=` instead of `role=` therefore rewrites a signed
    field after signing: the grant carries the default role under a signature
    that no longer matches. Every case built that way refused for a broken
    signature while its name claimed a role or domain conclusion.

    The guard is to authenticate first. Here it must reject the malformed
    fixture, which is what stops the DENY downstream from being read as
    evidence.
    """
    from signing import signed_grant  # noqa: PLC0415

    request = _request()
    correct = signed_grant(request, approval_id="FG01-OK", role="architecture_reviewer")
    authentic, reason = _authenticated(correct)
    assert authentic is True, f"the control fixture is itself broken: {reason}"
    assert correct["approver_role"] == "architecture_reviewer"

    wrong = signed_grant(
        request, approval_id="FG01-BAD", approver_role="architecture_reviewer"
    )
    assert wrong["approver_role"] == "architecture_reviewer", (
        "the override did not land, so this no longer reproduces FG01"
    )
    authentic, reason = _authenticated(wrong)
    assert authentic is False, (
        "the wrong keyword produced an authenticating grant, so FG01 can no "
        "longer be detected by authenticating first"
    )
    assert "signature invalid" in reason, reason


@pytest.mark.false_green("FG02")
def test_fg02_a_tampered_signature_is_caught_as_a_prerequisite():
    """A negative authority test must not be satisfied by a broken signature."""
    from signing import signed_grant  # noqa: PLC0415

    grant = dict(signed_grant(_request(), approval_id="FG02", role="operations_owner"))
    assert _authenticated(grant)[0] is True

    grant["signature"] = "AAAA" + grant["signature"][4:]
    authentic, reason = _authenticated(grant)
    assert authentic is False
    assert "APPROVAL_NOT_AUTHENTICATED" in reason, reason


# --------------------------------------------------------------------------
# FG03 / FG07 / FG08 -- the mutation contract, self-attacked
# --------------------------------------------------------------------------


@pytest.mark.false_green("FG03")
def test_fg03_a_comment_target_is_refused():
    """The token exists in a comment BEFORE the executable line.

    This is the shape that made a retired policy token, and a bare role name,
    each mutate prose for as long as the explaining comment existed.
    """
    source = "# risk: low is the interesting value\nrisk = 'low'\n"
    with pytest.raises(InvalidMutation, match="TARGET IS INERT"):
        check_mutation("probe.py", source, source.replace("risk: low", "risk: high"),
                       "risk: low", 1)


def test_fg03_the_same_token_in_the_executable_line_is_admitted():
    """The control: the guard must not refuse a genuine executable target."""
    source = "# risk is interesting\nrisk = 'low'\n"
    check_mutation("probe.py", source, source.replace("'low'", "'high'"), "'low'", 1)


@pytest.mark.false_green("FG07")
def test_fg07_a_stale_anchor_is_refused():
    """Zero edits is INVALID_MUTATION, never a survivor."""
    source = "value = 1\n"
    with pytest.raises(InvalidMutation, match="TARGET NOT FOUND"):
        check_mutation("probe.py", source, source, "value = 999", 1)


def test_fg07_a_no_op_replacement_is_refused():
    """And a replacement that changes nothing semantically."""
    source = "value = 1\n"
    with pytest.raises(InvalidMutation, match="TARGET UNCHANGED"):
        check_mutation("probe.py", source, source, "value = 1", 1)


@pytest.mark.false_green("FG08")
def test_fg08_an_unisolated_child_is_refused():
    """Origin is proven, never inferred from how the environment was built."""
    import os  # noqa: PLC0415
    import tempfile  # noqa: PLC0415

    import test_historical_reproof as historical  # noqa: PLC0415

    tree = historical._plain_copy(Path(tempfile.mkdtemp()))
    saved = os.environ.pop("PYTHONPATH", None)
    try:
        with pytest.raises(AssertionError, match="INVALID_MUTATION_ENVIRONMENT"):
            historical._prove_resolution(tree, isolate=False)
        # And the positive control, so the guard is not simply always-refusing.
        historical._prove_resolution(tree, isolate=True)
    finally:
        if saved is not None:
            os.environ["PYTHONPATH"] = saved


# --------------------------------------------------------------------------
# FG04 -- restoration must be byte-exact
# --------------------------------------------------------------------------


def _restored(before: dict[Path, bytes]) -> list[str]:
    """Paths whose bytes differ from what was captured."""
    return sorted(p.name for p, data in before.items() if p.read_bytes() != data)


@pytest.mark.false_green("FG04")
def test_fg04_partial_restoration_is_detected(tmp_path: Path):
    """Restoring some files is not restoring the workspace.

    The historical failure regenerated step one of a three-step causal order and
    called it cleanup; recorded hashes then described artifacts that had moved,
    and three unrelated tests failed as if the baseline had regressed.
    """
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    first.write_bytes(b'{"generated_at": "T0"}')
    second.write_bytes(b'{"recorded_hash": "H0"}')
    captured = {first: first.read_bytes(), second: second.read_bytes()}

    first.write_bytes(b'{"generated_at": "T1"}')
    second.write_bytes(b'{"recorded_hash": "H1"}')

    # A partial restore -- only the first artifact -- must NOT read as restored.
    first.write_bytes(captured[first])
    assert _restored(captured) == ["b.json"], (
        "a partial restoration was reported as complete"
    )

    second.write_bytes(captured[second])
    assert _restored(captured) == [], "byte-exact restoration was not detected"


# --------------------------------------------------------------------------
# FG05 -- paired observations must not share consumable state
# --------------------------------------------------------------------------


@pytest.mark.false_green("FG05")
def test_fg05_a_shared_ledger_contaminates_the_pair(tmp_path: Path):
    """The second half must not inherit the first half's spent grant.

    Reproduced directly: the same request released twice in ONE workspace. The
    second attempt is refused for REPLAY, which a paired test would misread as
    the trust or role conclusion it was actually trying to draw.
    """
    from signing import trust_store  # noqa: PLC0415
    from test_trust_snapshot import _release_under  # noqa: PLC0415

    first, released, spent = _release_under(tmp_path, trust_store(), workspace="shared")
    assert first.effect == "ALLOW" and released == ["released"] and spent is True

    second, again, _ = _release_under(tmp_path, trust_store(), workspace="shared")
    assert second.effect == "DENY", "the ledger did not stop a replay at all"
    assert again == []
    assert "already" in second.reason.lower() or "spent" in second.reason.lower(), (
        f"the second refusal is not a replay refusal: {second.reason}"
    )

    # The guard: a separate workspace decides on its own merits.
    third, released_again, _ = _release_under(
        tmp_path, trust_store(), workspace="isolated"
    )
    assert third.effect == "ALLOW", (
        "an isolated workspace inherited the first workspace's ledger, so paired "
        "observations cannot be trusted"
    )
    assert released_again == ["released"]


# --------------------------------------------------------------------------
# FG06 -- convergence is not oscillation
# --------------------------------------------------------------------------


def _is_stable(samples: list[str]) -> bool:
    """Post-settlement stability: one value across every sample."""
    return len(set(samples)) == 1


@pytest.mark.false_green("FG06")
def test_fg06_convergence_is_told_apart_from_oscillation():
    """A -> B -> B -> B is convergence. A -> B -> A -> B is not.

    The historical mistake sampled before the state had settled and read the
    difference as instability. The model settles first and then requires one
    value; both shapes are checked so the guard cannot pass by always agreeing.
    """
    converging = ["A"] + ["B"] * 10
    oscillating = ["A", "B"] * 5 + ["A"]

    assert not _is_stable(converging), "sanity: the unsettled sample differs"
    assert _is_stable(converging[1:]), (
        "convergence was misreported as instability after settling"
    )
    assert not _is_stable(oscillating[1:]), (
        "a period-two cycle was accepted as a fixed point"
    )
    assert len(converging[1:]) >= 10, "fewer than ten post-settlement samples"


# --------------------------------------------------------------------------
# FG09 -- possession does not discriminate; consumption does
# --------------------------------------------------------------------------


@pytest.mark.false_green("FG09")
def test_fg09_possession_does_not_discriminate(tmp_path: Path):
    """Two stores that DECIDE differently are indistinguishable by possession.

    That is the whole point: `boundary.action_trust_store is X` is true for both
    a trusting store and a store that refuses the signer, so a possession check
    cannot tell them apart. Only the behavioural differential can.
    """
    from signing import other_signer, trust_store  # noqa: PLC0415
    from test_trust_snapshot import _release_under  # noqa: PLC0415

    from nornyx_forge.approval_trust import ApprovalTrustStore  # noqa: PLC0415

    trusting = trust_store()
    refusing = ApprovalTrustStore.for_test([other_signer(("operations_owner",))])

    # POSSESSION: both are equally "carried", so this proves nothing.
    assert trusting is not refusing
    assert isinstance(trusting, ApprovalTrustStore)
    assert isinstance(refusing, ApprovalTrustStore)

    # CONSUMPTION: the decision separates them.
    allowed, released, _ = _release_under(tmp_path, trusting, workspace="trusting")
    refused, not_released, not_spent = _release_under(
        tmp_path, refusing, workspace="refusing"
    )
    assert allowed.effect == "ALLOW" and released == ["released"]
    assert refused.effect == "DENY", (
        "the boundary decided alike for two stores that disagree, so it is not "
        "consulting the store it holds"
    )
    assert not_released == [] and not_spent is False


# --------------------------------------------------------------------------
# 12K -- the self-attack matrix, reported as one result
# --------------------------------------------------------------------------


#: Classes whose defect has no executable reproduction YET, each with the
#: reason. A class is in exactly one of three terminal states: it carries a
#: `reproduces` triple, it is SPECIFICATION_ONLY, or it is named here.
#:
#: This list is not an exemption. It is the honest form of "not migrated",
#: and `test_every_false_green_class_has_a_terminal_classification` fails the
#: moment a class belongs to none of the three -- which is what a new entry
#: added without thought would do.
#:
#: WHY THESE ARE PENDING rather than done: reproducing a false-green class
#: mechanically means reintroducing the pattern that made a test lie, and for
#: most of these the pattern lives in the SHAPE of a proof rather than in a
#: line that can be swapped. FG33 could be reproduced because its class is
#: "a result, when the run did not finish", and the binding that prevents it
#: is a literal `timeout=` argument. The rest need a per-class edit that has
#: to be derived one at a time -- deliberately not a bulk migration, for the
#: same reason the attack catalogue refused one.
PENDING_REPRODUCTION = frozenset(
    item.ident for item in ()
) | frozenset({
    "FG01", "FG02", "FG03", "FG05", "FG07", "FG08", "FG09", "FG10", "FG11",
    "FG12", "FG13", "FG14", "FG15", "FG16", "FG17", "FG18", "FG19", "FG20",
    "FG21", "FG23", "FG24", "FG25", "FG26", "FG27", "FG28", "FG29",
    "FG30", "FG31", "FG32", "FG34", "FG35", "FG36", "FG37", "FG38", "FG39",
})


#: WHICH classes carry a reproduction, pinned by identity.
#:
#: The contract below asserted only `reproduced` non-empty. With exactly one
#: live reproduction that let the whole contract be re-pointed at a different
#: class with everything green -- which is how a bogus triple was demonstrated
#: passing. Membership is now a diff, the same way `EXPECTED_FALSE_GREEN_CLASSES`
#: is.
EXPECTED_REPRODUCED = frozenset({
    "FG22", "FG33", "FG40",
    # Round 7. Both are defects in the screen itself, so both reproductions
    # are single-line reverts inside `tests/guard_evidence.py` -- one puts
    # the old module pass back, one stops resolving a name through its
    # aliases. Adding to this set is the progress the assertion below asks
    # to be argued with rather than absorbed.
    "FG41", "FG42",
})


def test_the_reproduction_contract_asks_for_attribution():
    """Removing the attribution question is invisible to every other control.

    Measured: deleting `expected_property=expected` from the contract's call
    left BOTH reproductions GREEN, because the real reproductions do fail for
    the right reason -- so nothing that runs them can notice the question is no
    longer being asked. The two controls that DO discriminate work by naming
    the WRONG property, which only proves the question is asked when it is.

    That is the shape this whole module exists to refuse: a check whose absence
    produces no signal. So the question is required in two places at once --
    every reproduction must carry a property, and the contract must pass it.
    """
    missing = sorted(
        item.ident for item in INVENTORY
        if item.reproduces and not (len(item.reproduces) == 5 and item.reproduces[4])
    )
    assert missing == [], (
        "these reproductions carry no property for the failure to concern, so "
        f"any failure of the right node would be credited: {missing}"
    )

    source = Path(__file__).read_text(encoding="utf-8")
    contract = next(
        node for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef)
        and node.name == "test_a_reproduced_defect_turns_its_own_marked_guard_red"
    )
    calls = [
        node for node in ast.walk(contract)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "require_caused_failure"
    ]
    assert calls, "the contract no longer calls require_caused_failure at all"
    assert all(
        any(keyword.arg == "expected_property" for keyword in call.keywords)
        for call in calls
    ), (
        "the contract calls require_caused_failure WITHOUT expected_property, "
        "so a failure of the right node for an unrelated reason is credited as "
        "the class's own defect. That helper's docstring says so itself: "
        '"same node failed" is weaker than "same node failed BECAUSE the '
        'intended assertion was violated".'
    )


def test_every_false_green_class_has_a_terminal_classification():
    """B9-P2-1. Every class is reproduced, specified, or declared pending.

    The inventory's `root_cause` and `guard` are prose. A review found two
    markers on nodes that could not fail for the control their class names,
    and no amount of prose would have caught either.

    So a class must now be in exactly ONE of three terminal states, and the
    third is a declaration rather than a silence:

        reproduces          an executable defect the guard must go red under
        SPECIFICATION_ONLY  a guard that pins an algorithm, not this system
        PENDING_REPRODUCTION  no reproduction derived yet, named as such

    A class in none of them fails here. A class in two of them fails here.
    That is what keeps "not migrated" from turning into "exempt" the way an
    optional attribution once did in the attack catalogue.
    """
    idents = {item.ident for item in INVENTORY}
    reproduced = {item.ident for item in INVENTORY if item.reproduces is not None}

    unclassified = sorted(
        idents - reproduced - SPECIFICATION_ONLY - PENDING_REPRODUCTION
    )
    assert unclassified == [], (
        "these false-green classes have no terminal classification: they name "
        "no executable reproduction, are not declared specification-only, and "
        "are not declared pending. A class in none of the three is one nobody "
        f"has decided about: {unclassified}"
    )

    overlapping = sorted(
        (reproduced & SPECIFICATION_ONLY)
        | (reproduced & PENDING_REPRODUCTION)
        | (SPECIFICATION_ONLY & PENDING_REPRODUCTION)
    )
    assert overlapping == [], (
        f"these classes carry two terminal classifications at once: {overlapping}"
    )

    stray = sorted((SPECIFICATION_ONLY | PENDING_REPRODUCTION) - idents)
    assert stray == [], (
        f"these classifications name a class the inventory does not list: {stray}"
    )

    assert reproduced == EXPECTED_REPRODUCED, (
        "the set of classes carrying an executable reproduction changed. That "
        "is a diff to argue with, not a side effect: adding one is progress, "
        "and removing one silently is how a contract stops measuring "
        f"anything. expected {sorted(EXPECTED_REPRODUCED)}, found "
        f"{sorted(reproduced)}"
    )


@pytest.mark.parametrize(
    "item",
    [entry for entry in INVENTORY if entry.reproduces is not None],
    ids=[entry.ident for entry in INVENTORY if entry.reproduces is not None],
)
def test_a_reproduced_defect_turns_its_own_marked_guard_red(item, tmp_path: Path):
    """The class's own defect must make its marked guard fail, FOR ITS REASON.

    THE FIRST VERSION OF THIS CONTRACT ASSERTED `returncode != 0` AND NOTHING
    ELSE, and that is not attribution. A review gave a class the triple
    `("tests/test_absence_is_not_success.py", "def test_", "def zzz_")` --
    which has nothing to do with that class and simply deletes every test in
    the module -- and the contract CREDITED it. `pytest <owner>` exits 4 with
    "no tests ran" when the node is gone, and 4 is not zero.

    That is FG11 ("a kill, when the named test node no longer exists") and
    FG19 ("the right node failed for an unrelated reason") committed inside
    the contract that certifies the FG inventory.

    It also skipped admissibility rules the sibling runner enforces on every
    mutation, so the same edit could have targeted a comment (FG03) or a stale
    anchor matching nothing (FG07). Both are asked here now.

    PRODUCTION SCOPE (FG16) IS DELIBERATELY NOT ASKED, and saying otherwise was
    itself a false claim in this docstring. `require_production_mutation_scope`
    would REFUSE both live reproductions: FG33 targets
    `tests/mutation_workspace.py` and FG22's owner is a test module, because
    two of these classes are defects IN the test machinery and a reproduction
    of them has to edit the test machinery. The rule is right and the exemption
    is real; what was wrong was listing it among the questions asked.

    The questions this contract does ask, in the order the campaign asks them:

        the target exists, is executable, and matches EXACTLY n times
        the guard passes on the pristine tree
        the guard FAILS under the defect
        the EXACT owner node failed, in the CALL phase -- not errored,
          not absent, not some other node in the same file
        and it failed FOR THE INTENDED PROPERTY, which is the question
          `expected_property` exists to ask and which this contract used
          to leave unasked
    """
    import subprocess  # noqa: PLC0415

    from mutation_validity import check_mutation  # noqa: PLC0415
    from mutation_workspace import require_caused_failure  # noqa: PLC0415

    relative, before, after, count, expected = item.reproduces
    target = ROOT / relative
    assert target.is_file(), f"{item.ident}: {relative} is not in the tree"
    text = target.read_text(encoding="utf-8")

    # FG03 + FG07: an executable target, present exactly as many times as the
    # reproduction says. A comment target or a stale anchor is refused here
    # rather than producing a mutant that changes nothing.
    check_mutation(relative, text, text.replace(before, after), before, count)

    report = tmp_path / "damaged.xml"

    def guard(report_path=None) -> subprocess.CompletedProcess:
        command = [sys.executable, "-m", "pytest", item.owner, "-q", "-o",
                   "addopts=", "-p", "no:randomly", "--no-header"]
        if report_path is not None:
            command += ["--junit-xml", str(report_path)]
        return subprocess.run(  # noqa: S603
            command, cwd=ROOT, capture_output=True, text=True, timeout=2400,
            encoding="utf-8", errors="replace", check=False,
        )

    pristine = target.read_bytes()
    try:
        healthy = guard()
        assert healthy.returncode == 0, (
            f"{item.ident}: the marked guard does not pass on the pristine "
            f"tree, so this measures nothing: {healthy.stdout[-300:]}"
        )
        target.write_bytes(text.replace(before, after).encode("utf-8"))
        damaged = guard(report)
    finally:
        target.write_bytes(pristine)

    assert target.read_bytes() == pristine, (
        f"{item.ident}: the reproduction did not restore {relative}"
    )
    assert damaged.returncode != 0, (
        f"{item.ident}: the class's own defect was reproduced in {relative} "
        f"({count} site(s)) and the guard the inventory names as its proof "
        "STAYED GREEN. That guard cannot fail for the control this class is "
        f"about: {damaged.stdout[-400:]}"
    )
    # THE EXACT NODE, IN THE CALL PHASE. This is what separates "the guard
    # failed" from "something in that file went wrong" -- and from "the node
    # was not there to run", which exits non-zero and proves nothing at all.
    require_caused_failure(report, item.owner, damaged.stdout,
                           expected_property=expected)




def test_every_false_green_class_has_a_self_attack_that_trips_its_guard():
    """The matrix. Each class names a test that exists and really runs.

    This does not re-run them -- the suite does -- it asserts none can vanish
    while the inventory still claims nine guarded classes.

    A NAME IS NOT A TEST. This checked that `def <node>(` appeared in the source
    and that the guard string was long enough, so gutting any self-attack's body
    to `pass` left all nine reported as guarded: the audit that exists to catch
    proofs which assert nothing could itself be reduced to nine that assert
    nothing. Each named function is now parsed and required to carry at least
    one assertion or an expected-refusal block.

    Still not proof that the assertion is the right one -- only the suite
    running can show that -- but it is the difference between a body and a
    placeholder, which is what the finding was about.
    """
    import ast  # noqa: PLC0415

    for item in INVENTORY:
        module, _, node = item.owner.partition("::")
        source = (ROOT / module).read_text(encoding="utf-8")
        assert f"def {node}(" in source, f"{item.ident}: {node} is gone"
        assert len(item.guard) > 15, f"{item.ident} names no guard"

        tree = ast.parse(source, filename=module)
        found = [
            fn for fn in ast.walk(tree)
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
            and fn.name == node
        ]
        assert len(found) == 1, f"{item.ident}: {node} is defined {len(found)} times"

        # `raise AssertionError(...)` and `pytest.fail(...)` count too. This
        # recognised only `assert` and `pytest.raises`, so
        # `test_every_compound_attack_is_proven_minimal` -- which re-runs every
        # compound without its last edit and raises AssertionError when one is
        # not minimal -- read as having no evidence at all. A counter that
        # misses a whole form of failure is the same defect as the bodies it
        # was written to catch.
        # AN EARLY RETURN MAKES EVERY ASSERTION BELOW IT UNREACHABLE.
        #
        # `return` as the first statement after the docstring left the real
        # assertions in place, so the counter found them and the guard passed
        # while executing none of them. Measured on FG01: 2 passed, rc 0.
        body = list(found[0].body)
        if body and isinstance(body[0], ast.Expr) and isinstance(
            body[0].value, ast.Constant
        ):
            body = body[1:]
        assert not (body and isinstance(body[0], ast.Return)), (
            f"{item.ident}: {node} returns before its first assertion, so the "
            "assertions below it never execute. A guard that returns early "
            "asserts nothing, whatever its body still contains."
        )
        # THE MODULE, so a module-level constant is in scope. A review added
        # ONE line -- `_OFF = False` -- and indented FG21's owner body under
        # `if _OFF:`; the guard went from pristine RED to gutted GREEN with the
        # marker intact, the node intact, and collection identical.
        exercised = exercised_assertions(found[0], tree)
        assert exercised >= 1, (
            f"{item.ident}: {node} contains no assertion that can fail. A "
            "self-attack that asserts nothing is the defect this inventory "
            "exists to find, and `assert True` is that defect wearing the "
            "shape of a proof."
        )
    assert len({item.owner for item in INVENTORY}) == len(INVENTORY), (
        "two catalogue entries share an owner, so one of them is proven by a "
        "test written for the other. The previous bound was `>= 9`, which 33 "
        "classes satisfy while sharing as few as nine owners between them."
    )


# --------------------------------------------------------------------------
# FG10-FG15. The classes Task 14 found in the PROOF SYSTEM itself.
#
# Every one of these was a green result produced by machinery that had not
# measured what it claimed. They are audited here the same way as FG01-FG09:
# the real guard is executed against the real defect, and the refusal must be
# the one the class names.
# --------------------------------------------------------------------------



def _counted_report(tmp_path: Path, counts: dict) -> Path:
    """A JUnit report contributing `counts[module]` passing tests per module."""
    cases = []
    for module, number in counts.items():
        classname = module.removesuffix(".py").replace("/", ".")
        cases.extend(
            f'<testcase classname="{classname}" name="test_{index}" '
            f'file="{module}"></testcase>'
            for index in range(number)
        )
    report = tmp_path / "counted.xml"
    report.write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<testsuites><testsuite name="pytest" tests="{sum(counts.values())}">'
        + "".join(cases)
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    return report


@pytest.mark.false_green("FG10")
def test_fg10_a_workspace_whose_baseline_already_fails_is_refused(tmp_path: Path):
    """FG10. A kill credited for a workspace where the proof already failed.

    Three classes -- H05, H07, H10 -- were credited kills in a copy that omitted
    `docs/`, `README.md`, `BRD.md`, `.github/` and `.git`. Their named tests
    failed there BEFORE any mutation, so `returncode != 0` was measuring the
    workspace.

    The guard runs the named test pristine and refuses the attempt if it does
    not pass. Attacked here with a workspace deliberately broken in the same way
    the old one was.
    """
    from mutation_workspace import (  # noqa: PLC0415
        AttackNotAdmissible,
        Outcome,
        faithful_copy,
        require_pristine_baseline,
    )

    tree = faithful_copy(tmp_path)
    node = "tests/test_scratch_containment.py::test_mkdtemp_is_contained_within_the_session_scratch"

    # Pristine, the baseline passes -- the control, without which the refusal
    # below could be "this guard refuses everything".
    require_pristine_baseline(tree, node)

    # Now break the workspace the way the old copy was broken: remove a file the
    # proof depends on. Nothing is mutated; the control is untouched.
    (tree / "tests" / "conftest.py").unlink()

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_pristine_baseline(tree, node)
    assert refusal.value.outcome is Outcome.INVALID_BASELINE, refusal.value.outcome
    assert "FAILS before any mutation" in str(refusal.value)


@pytest.mark.false_green("FG11")
def test_fg11_a_missing_test_node_is_not_a_kill(tmp_path: Path):
    """FG11. `pytest module::gone` exits 4 and was read as a failing test.

    H02 could report KILLED with its only proof deleted and the integrity gate
    fully intact: the exit code was non-zero, and the guard of the day searched
    stdout for "no tests ran", which that output does not contain.
    """
    from mutation_workspace import (  # noqa: PLC0415
        AttackNotAdmissible,
        Outcome,
        faithful_copy,
        require_node_exists,
    )

    tree = faithful_copy(tmp_path)

    # The control: a node that exists must be admitted.
    require_node_exists(
        tree,
        "tests/test_scratch_containment.py::test_mkdtemp_is_contained_within_the_session_scratch",
    )

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_node_exists(
            tree, "tests/test_scratch_containment.py::test_a_node_that_was_deleted"
        )
    assert refusal.value.outcome is Outcome.INVALID_TEST_TARGET, refusal.value.outcome
    assert "does not collect" in str(refusal.value)


@pytest.mark.false_green("FG12")
def test_fg12_an_undeclared_expected_failure_fails_the_census(tmp_path: Path):
    """FG12. A security proof with an off switch.

    The census skipped xfails outright, on the written ground that they were
    strict here. `xfail_strict` was configured nowhere, so one decorator could
    silence a failing integrity proof with the gate reporting PASS, zero
    unexpected skips and an unchanged collection count.
    """
    import sys as _sys  # noqa: PLC0415

    _sys.path.insert(0, str(ROOT / "scripts"))
    import check_test_coverage as census  # noqa: PLC0415

    assert census.EXPECTED_XFAILS == {}, (
        "the intended inventory is empty; an entry is a proof recorded as broken"
    )

    report = tmp_path / "report.xml"
    report.write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        '<testsuites><testsuite name="pytest" tests="1">'
        '<testcase classname="tests.test_security" name="test_a_control" '
        'file="tests/test_security.py">'
        '<skipped type="pytest.xfail" message="switched off"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    *_rest, unexpected_xfails, _errors = census.classify(report)

    assert unexpected_xfails == ["tests/test_security.py::test_a_control"], (
        f"an undeclared expected failure was not reported: {unexpected_xfails}"
    )
    assert census.evaluate(report, 0) != 0, "the gate accepted a silenced proof"

    # And strictness itself is configured, parsed rather than asserted about.
    import tomllib  # noqa: PLC0415

    options = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["tool"]["pytest"]["ini_options"]
    assert options.get("xfail_strict") is True, options.get("xfail_strict")


@pytest.mark.false_green("FG13")
def test_fg13_a_text_search_is_not_proof_of_mutant_origin(tmp_path: Path):
    """FG13. The origin proof matched an unrelated line.

    `assert "sys.path.insert(0" in source` passed for a module that had no
    production isolation code at all, because nearly every test module here
    opens with `sys.path.insert(0, str(ROOT / "tests"))`.
    """
    from mutation_workspace import (  # noqa: PLC0415
        AttackNotAdmissible,
        Outcome,
        faithful_copy,
        require_mutant_origin,
    )

    tree = faithful_copy(tmp_path)

    # The text search the old guard performed still succeeds -- on a file that
    # proves nothing about where production modules load from.
    probe = tree / "tests" / "unrelated_probe.py"
    probe.write_text(
        "import sys\nsys.path.insert(0, 'somewhere/else')\n", encoding="utf-8"
    )
    assert "sys.path.insert(0" in probe.read_text(encoding="utf-8"), (
        "the discredited check would pass here"
    )

    # The measurement does not. It asks the interpreter, in the workspace.
    require_mutant_origin(tree, ("nornyx_forge.nornyx_runtime",))

    # THE ESCAPE CLAUSE, which is the one this class is about.
    #
    # The first version of this self-attack deleted the module and asserted the
    # refusal. That passes whether or not the escape check exists, because an
    # absent module fails at the IMPORT step first -- so the test proved the
    # import path and left the clause it names untested. Measured: removing
    # `if not resolved or escaped` entirely, the old assertion still passed.
    #
    # Here the module imports perfectly well and simply resolves somewhere else,
    # which is the actual historical defect: an editable `.pth` outranking a
    # late `sys.path` insert, so the child ran production source while the
    # harness reported a mutant.
    elsewhere = tmp_path / "not_the_workspace"
    elsewhere.mkdir()
    with pytest.raises(AttackNotAdmissible) as refusal:
        require_mutant_origin(elsewhere, ("nornyx_forge.nornyx_runtime",))
    assert refusal.value.outcome is Outcome.INVALID_MUTATION_ENVIRONMENT, (
        refusal.value.outcome
    )
    assert "outside the mutant workspace" in str(refusal.value), str(refusal.value)


@pytest.mark.false_green("FG14")
def test_fg14_an_aggregate_floor_permits_deleting_critical_proofs(tmp_path: Path):
    """FG14. 43 tests deleted across six modules, total unchanged.

    Every module stayed PRESENT so `REQUIRED_MODULES` was satisfied, and the
    surviving modules had grown enough to keep the aggregate above the floor.
    A count cannot see which proofs went.
    """
    import sys as _sys  # noqa: PLC0415

    _sys.path.insert(0, str(ROOT / "scripts"))
    import check_test_coverage as census  # noqa: PLC0415
    import test_mutation_catalogue as catalogue  # noqa: PLC0415

    # Census: a module gutted to one test, padded elsewhere so the total holds.
    counts = dict(census.REQUIRED_MODULE_MINIMUMS)
    victim = "tests/test_action_binding.py"
    removed = counts[victim] - 1
    counts[victim] = 1
    counts["tests/test_filler.py"] = (
        census.MINIMUM_COLLECTED - sum(counts.values()) + removed + 1
    )
    assert sum(counts.values()) >= census.MINIMUM_COLLECTED, (
        "the aggregate floor must still pass, or this proves nothing"
    )
    assert census.evaluate(_counted_report(tmp_path, counts), 0) != 0, (
        "the gate accepted a run whose security module lost all but one test"
    )

    # Catalogue: the same shape, one level up. Deleting six attacks leaves the
    # floor satisfied and the identity check does not.
    survivors = {
        a.attack_id for a in catalogue.CATALOGUE
        if a.attack_id not in {"M9", "M10", "M11", "M12", "M13", "M14"}
    }
    assert len(survivors) >= catalogue.MINIMUM_ATTACKS, "the floor must still pass"
    assert sorted(catalogue.REQUIRED_ATTACK_IDS - survivors) == [
        "M10", "M11", "M12", "M13", "M14", "M9",
    ]


@pytest.mark.false_green("FG15")
def test_fg15_one_route_of_a_chain_is_not_the_property(tmp_path: Path):
    """FG15. Removing one guard, seeing the property hold, and calling it either.

    Distinct from every class above, and the reason it is retained separately:
    the mutation APPLIED, the mutant LOADED, the semantic property CHANGED
    locally, and the named test still passed. Nothing in FG01-FG14 catches that,
    because nothing about the attempt was invalid -- the inventory was.

    SURVIVED and KILLED are both wrong. The answer is DEFENCE_IN_DEPTH plus an
    enumeration, and the compound attack over every route is what decides.
    """
    import test_historical_reproof as historical  # noqa: PLC0415
    import test_mutation_catalogue as catalogue  # noqa: PLC0415

    routes = historical.GOVERNANCE_SURFACE_CHAIN
    assert len(routes) >= 2, "a chain with one route is not a chain"

    # Each route is recorded as defence-in-depth, never as a survivor.
    labels = {f"SURFACE-GUARD-{label}" for label, *_ in routes}
    assert labels <= catalogue.DEFENCE_IN_DEPTH_ATTACKS, sorted(labels)

    # The routes span more than one module, which is what a chain that only
    # named anchors in one file would have missed.
    assert len({relative for _label, relative, *_ in routes}) >= 2, (
        "every route is in one module, so a single-module chain would suffice "
        "and this class would be indistinguishable from FG07"
    )

    # The governance-surface family's compound must exist and must be the KILL.
    # Asserted BY NAME, not by counting: `len(compound) == 1` was true only
    # while H05 was mislabelled non-compound, so this passed for a reason that
    # had nothing to do with the surface chain -- a count agreeing with an
    # expectation by way of an unrelated error.
    compound = {a.attack_id for a in catalogue.CATALOGUE if a.compound}
    assert "SURFACE-WHOLE-CHAIN" in compound, sorted(compound)
    whole_chain = next(
        a for a in catalogue.CATALOGUE if a.attack_id == "SURFACE-WHOLE-CHAIN"
    )
    assert not whole_chain.defence_in_depth, (
        "the compound attack is the KILL; marking it defence-in-depth would "
        "leave the property with no kill at all"
    )


def test_the_mechanism_map_names_only_known_classes():
    """B-P3-4: `MECHANISM_TO_CLASS` was defined and read by nothing.

    A table nobody consults can name a class that does not exist, or map two
    mechanisms onto a retired ID, and stay green forever. It is documentation
    presented as data, and the difference between those is whether anything
    checks it.
    """
    unknown = sorted(
        f"{mechanism} -> {label}"
        for mechanism, label in MECHANISM_TO_CLASS.items()
        if label not in EXPECTED_FALSE_GREEN_CLASSES
    )
    assert unknown == [], (
        f"the mechanism map points at classes that do not exist: {unknown}"
    )


#: CLASSES WHOSE GUARD IS A SPECIFICATION, NOT A MEASUREMENT OF THIS SYSTEM.
#:
#: FG04 and FG06 assert over `_restored` and `_is_stable`, two helpers defined
#: in this file, against synthetic inputs. They prove the ALGORITHM is right --
#: a partial restore is not a restore; a settled series is not an oscillating
#: one -- and they do not measure that this repository applies it.
#:
#: That is not a defect to patch quietly, because there is nothing here to
#: point them at: a search of `src/` and `scripts/` finds no convergence
#: sampler and no restoration detector. The `settled` vocabulary in
#: `governed_subject.py` is contract resolution, a different sense of the word.
#: Both classes describe mistakes made by the ASSURANCE PROCESS -- sampling
#: before the state settled, regenerating step one of three and calling it
#: cleanup -- not code paths in the product.
#:
#: So they are declared as what they are, and the declaration is checked below
#: rather than left as a label. If someone later wires either guard to
#: repository code, `test_the_specification_only_guards_are_declared_as_such`
#: fails and this note has to be rewritten -- which is the point: the failure
#: mode being frozen out is an inventory that calls a specification a
#: measurement.
SPECIFICATION_ONLY = frozenset({"FG04", "FG06"})


def _audit_child_env(dump: Path) -> dict:
    """The environment the marker-collection child runs under.

    SEPARATED SO IT CAN BE MEASURED. The first test written for this checked
    the SOURCE for a substring, and matched its own docstring -- a comment
    satisfying a structural control, which is FG37 by name and the exact thing
    this module exists to refuse. What is testable is the dict this returns.
    """
    inherited = os.environ.get("PYTHONPATH", "")
    return dict(
        os.environ,
        FG_MARKER_DUMP=str(dump),
        PYTHONIOENCODING="utf-8",
        PYTHONPATH=os.pathsep.join(
            [str(ROOT / "tests")] + ([inherited] if inherited else [])
        ),
    )


def _declared_by_collection() -> dict:
    """Which COLLECTED node declares which FG class, read from pytest itself.

    NOT FROM SOURCE. The substring rule this replaces matched raw text --
    docstrings and comments included:

        if item.ident.lower() in node.lower() or item.ident in segment

    Measured across all 39 entries: 22 satisfied by the node NAME, 17 by PROSE
    ONLY -- including all six classes Task 12 minted -- and ZERO with the class
    id anywhere in executable code. A review then certified a class whose guard
    was gone, three ways: deleted and re-pointed at a meta-test whose docstring
    mentions the id; gutted to `assert True` and re-pointed at the owner-naming
    rule ITSELF, whose docstring names FG29, with collection unchanged at 1578;
    and replaced by a NESTED function of the same name, which pytest never
    collects. Twenty tests passed each time, and the census stayed green.

    That is FG37 ("a structural control, when a COMMENT satisfied it") and FG38
    ("a proven attack, when its proof was only DEFINED") -- the two classes
    Task 12 minted -- reproduced by the Task-12 guard written to close them.

    A marker is metadata on a node pytest ACTUALLY COLLECTED. A comment cannot
    carry one, and neither can a function pytest never sees, so both evasions
    close together and the declaration lives in ONE place instead of two that
    can drift.
    """
    dump = Path(tempfile.mkdtemp()) / "markers.tsv"
    # PREPENDED, NOT REPLACED.
    #
    # `-p` resolves a plugin by import, and `tests/` is on sys.path only via
    # conftest -- which has not run yet at plugin-load time. So this entry has
    # to be there. Setting it with `PYTHONPATH=` DISCARDED whatever the caller
    # had, which is the same substitution FG08/FG13 describe, operating inside
    # the audit that certifies FG08 and FG13.
    #
    # Measured: with a caller's PYTHONPATH holding a sentinel module, the child
    # reported `sentinel importable: False`; prepending gives True. The impact
    # is bounded today because markers live in tests/ and the link is measured
    # on the right tree either way -- but a harness that puts its own `src`
    # first, which is exactly how every mutant in this repository is isolated,
    # had that isolation silently removed.
    environment = _audit_child_env(dump)
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o",
         "addopts=", "-p", "no:randomly", "-p", "fg_marker_dump",
         "--no-header", "tests/"],
        cwd=ROOT, capture_output=True, text=True, timeout=1800, check=False,
        env=environment,
    )
    # A COLLECTION THAT FAILED CANNOT ESTABLISH A LINK.
    #
    # This checked only that the dump FILE existed. The plugin writes it from
    # `pytest_collection_modifyitems`, which runs over whatever collected
    # SUCCESSFULLY -- so a module that fails to import leaves a dump that looks
    # complete while the run was interrupted. Measured: a syntax error in
    # `tests/test_action_binding.py`, a module carrying no markers at all, gave
    # `--collect-only` rc=2 and "Interrupted", and these audits reported
    # 3 PASSED, EXIT 0.
    #
    # The inventory they certify is drawn from that collection. If a module
    # carrying markers had been the one to break, its classes would simply be
    # absent, and "absent" is indistinguishable here from "never declared".
    if done.returncode != 0:
        raise AssertionError(
            "pytest collection did not succeed, so the class-to-guard link is "
            f"established over an incomplete inventory: rc={done.returncode} "
            f"{done.stdout[-400:]} {done.stderr[-400:]}"
        )
    if not dump.exists():
        raise AssertionError(
            "collection produced no marker report, so the class-to-guard link "
            f"could not be established at all: rc={done.returncode} "
            f"{done.stdout[-400:]} {done.stderr[-400:]}"
        )
    declared: dict = {}
    for row in dump.read_text(encoding="utf-8").splitlines():
        ident, _, rest = row.partition(chr(9))
        nodeid, _, blocking = rest.partition(chr(9))
        if ident:
            declared.setdefault(ident, {})[nodeid.split("[")[0]] = blocking
    return declared


def test_every_false_green_class_is_declared_by_a_collected_guard():
    """The link is a USE, and the guard is proven to COLLECT.

    Two properties from one measurement, because they share the evidence: the
    marker names the class from INSIDE the guard, and a marker exists only on a
    node pytest collected.
    """
    declared = _declared_by_collection()

    missing = sorted(item.ident for item in INVENTORY
                     if item.ident not in declared)
    assert missing == [], (
        "these classes are declared by no collected guard, so nothing "
        "mechanically ties them to a proof -- such a class can be re-pointed "
        f"at any asserting node, or at one pytest never runs: {missing}"
    )

    stray = sorted(set(declared) - {item.ident for item in INVENTORY})
    assert stray == [], (
        f"these guards declare a class the inventory does not list: {stray}"
    )

    # EXACTLY ONE NODE, NOT "THE OWNER IS AMONG THEM".
    #
    # This asked whether the inventory's owner appeared IN the set of nodes
    # declaring the class. A module-level `pytestmark = pytest.mark.false_green
    # ("FGnn")` makes EVERY node in that module declare it, and the real owner
    # is still among them, so the check passed. Measured: one line added to
    # `tests/test_absence_is_not_success.py` gave `FG37 declared by 9 NODES`
    # and both audits reported 2 passed, green.
    #
    # A class certified by nine nodes, eight of which have nothing to do with
    # it, is not a link -- it is a claim that some node somewhere is relevant.
    # The sibling test catches a node declaring two CLASSES; nothing caught a
    # class declared by two NODES until this became equality.
    mismatched = []
    for item in INVENTORY:
        owner = item.owner.split("[")[0]
        nodes = sorted(declared[item.ident])
        if nodes != [owner]:
            mismatched.append(
                f"{item.ident}: inventory names {owner}, declared by "
                f"{nodes}"
            )
    assert mismatched == [], (
        "the inventory and the guards disagree about which node proves which "
        "class. Re-pointing an inventory row now requires moving the marker OFF "
        "the real guard, which leaves that guard undeclared: "
        + "; ".join(mismatched)
    )


def test_no_two_classes_are_declared_by_the_same_guard():
    """One guard, one class -- otherwise a single node certifies many."""
    declared = _declared_by_collection()
    owners: dict = {}
    for ident, nodes in declared.items():
        for node in nodes:
            owners.setdefault(node, []).append(ident)
    shared = {node: sorted(ids) for node, ids in owners.items() if len(ids) > 1}
    assert shared == {}, (
        f"these nodes declare more than one false-green class: {shared}"
    )


# --------------------------------------------------------------------------
# B9-P2-1 -- "THE MARKED NODE MUST GO RED UNDER ITS CLASS'S DEFECT"
#
# The right property, and only partly enforceable here. What was measured, so
# the next reader starts from evidence rather than from this paragraph:
#
# FG33 WAS A REAL INSTANCE AND IS FIXED. Its marker sat on
# `test_fg33_a_run_that_exceeds_its_timeout_raises_instead_of_returning`, which
# exercises CPython's own subprocess timeout. With all eight `timeout=`
# bindings stripped from `mutation_workspace.py` -- the class's own defect,
# reproduced -- that node stayed GREEN while
# `test_fg33_both_harness_entry_points_bound_their_runs` went RED. The marker
# and the inventory owner now name the second, and it is measured RED under
# the defect and green when it is restored. The entry's own note had described
# that node all along.
#
# FG26 DOES NOT REPRODUCE at this head. Gutting the conftest session guard's
# `assert introduced == []` turns the MARKED guard RED, along with its three
# unmarked siblings.
#
# THE STATIC SCREEN REPRODUCES AND IS NOT A FIT CRITERION. Screening for a
# marked guard that references no REPOSITORY name -- stdlib and pytest
# excluded -- gives 12 of 39, exactly the figure the review reported. But
# FG33's repaired guard IS ONE OF THE TWELVE, and it was just measured going
# red under its class's defect: it reads the harness's SOURCE, so it exercises
# repository content while referencing no repository NAME. Several others
# (FG31, FG38) are structural checks of the same kind. Enforcing the screen
# would demand rewriting twelve guards to satisfy a proxy that has already
# been shown to misclassify the one guard here proven sound, so it is NOT
# enforced, and this is why rather than an omission.
#
# WHAT REMAINS OPEN, NAMED: FG04 and FG06 assert over `_restored` and its
# sibling, two helpers defined in this file, over synthetic temporary files.
# They prove the ALGORITHM is right; they do not measure that this repository
# applies it. No production counterpart exists to point them at -- the nearest
# real mechanism is the conftest session guard, which is FG26's, already
# taken. Rewiring them at a guess would trade a disclosed gap for an
# undisclosed wrong attribution, which this inventory exists to refuse.
#
# The general property needs a per-class defect reproduction: 39 mutations of
# shared files, each run against one node. That is a harness, not a check, and
# it is the honest next step rather than something this comment supplies.
# --------------------------------------------------------------------------


def test_no_declared_guard_can_be_prevented_from_running():
    """B9-P2-3. COLLECTED IS NOT RUNS, and the catalogue said otherwise.

    FG38's own guard text read "collection is measured by asking pytest what
    it would actually RUN". `--collect-only` reports what pytest would
    COLLECT. `skip`, `skipif` and `xfail` are evaluated at setup, so a node
    carrying one is collected, is seen by `iter_markers`, satisfies every
    marker check in this module -- and never executes. A review added
    `@pytest.mark.skip` to a declared guard and measured 5 passed, exit 0,
    with the collection count unchanged.

    That is a property (runs) stated one step stronger than the property
    measured (collected), which is the substitution this whole inventory
    exists to refuse -- appearing in the inventory itself.

    `skipif` is refused alongside `skip` even though its condition may be
    false today: a guard whose execution depends on an expression evaluated
    at setup is a guard that can stop running without anything here changing.
    """
    declared = _declared_by_collection()
    blocked = sorted(
        f"{ident}: {node} carries @pytest.mark.{blocking}"
        for ident, nodes in declared.items()
        for node, blocking in nodes.items()
        if blocking
    )
    assert blocked == [], (
        "these declared guards are COLLECTED and would not RUN, so the class "
        "they certify is proven by a node that executes nothing: "
        + "; ".join(blocked)
    )


#: A module carrying NO false-green markers. Breaking it leaves the marker dump
#: looking complete while the collection that produced it failed -- which is
#: the whole point of the specimen below.
_MARKERLESS_MODULE = "tests/test_action_binding.py"


def test_a_collection_that_failed_cannot_establish_the_guard_link():
    """B9-P3-1. The audits certified a link over a collection that FAILED.

    `_declared_by_collection` checked only that the dump FILE existed. The
    plugin writes it from `pytest_collection_modifyitems`, which runs over
    whatever collected SUCCESSFULLY, so a module that fails to import leaves a
    dump that looks complete while the run was interrupted.

    Measured before the repair: a syntax error in a module carrying NO markers
    gave `--collect-only` rc=2 and "Interrupted", and the marker audits
    reported 3 PASSED, EXIT 0. Had a module carrying markers been the one to
    break, its classes would simply have been absent -- and "absent" is
    indistinguishable here from "never declared".

    THE SPECIMEN RUNS AGAINST THE REAL TREE, and that is not laziness. Two
    isolated vehicles were tried and BOTH measured the wrong thing:

      `mutation._materialize` carries only src/, tests/ and scripts/, so
      collection there is already incomplete before anything is broken;

      a detached git worktree does not isolate this at all -- `import
      test_false_green_audit` resolves to the REAL repository's copy, because
      its `tests/` is on sys.path, so `ROOT` points back home and the guard
      never sees the broken worktree. That is FG08/FG13's own mechanism, and
      it is exactly the defect B9-P3-2 records about this audit's child.

    So the break is made here and undone in a `finally`, with the restoration
    asserted. The module chosen carries no markers, which is the sharp case:
    the dump still looks complete.
    """
    import subprocess  # noqa: PLC0415

    node = (
        "tests/test_false_green_audit.py"
        "::test_every_false_green_class_is_declared_by_a_collected_guard"
    )

    def guard() -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", node, "-q", "-o", "addopts=",
             "-p", "no:randomly", "--no-header"],
            cwd=ROOT, capture_output=True, text=True, timeout=2400,
            encoding="utf-8", errors="replace", check=False,
        )

    target = ROOT / _MARKERLESS_MODULE
    pristine = target.read_bytes()
    try:
        healthy = guard()
        assert healthy.returncode == 0, (
            "the guard does not pass on the pristine tree, so this specimen "
            f"would prove nothing: {healthy.stdout[-400:]}"
        )
        rubble = chr(10).join(["", "", "def this_will_not_parse(:", "    pass", ""])
        target.write_bytes(pristine + rubble.encode("utf-8"))
        interrupted = guard()
    finally:
        target.write_bytes(pristine)

    assert target.read_bytes() == pristine, "the specimen did not restore the tree"
    assert interrupted.returncode != 0, (
        "a module that cannot be imported interrupted collection, and the "
        "audit still certified the class-to-guard link it drew from that "
        f"collection: {interrupted.stdout[-500:]}"
    )
    assert "collection did not succeed" in interrupted.stdout, (
        "the guard failed for some other reason, so this does not measure the "
        f"return-code check: {interrupted.stdout[-600:]}"
    )


def test_the_audit_child_preserves_a_caller_supplied_pythonpath(tmp_path: Path):
    """B9-P3-2. The audit discarded the isolation its own subject depends on.

    `_declared_by_collection` set `PYTHONPATH` by REPLACEMENT. The `tests/`
    entry is genuinely needed -- `-p` resolves a plugin by import and conftest
    has not run at plugin-load time -- but replacing threw away whatever the
    caller had.

    That is FG08/FG13's own mechanism operating inside the audit that certifies
    FG08 and FG13: a harness that puts its own `src` first, which is how every
    mutant here is isolated, had that isolation silently removed. Measured
    before the repair: a sentinel on the caller's PYTHONPATH came back
    `importable: False`.

    THE ENVIRONMENT IS MEASURED, NOT THE SOURCE. The first version of this test
    searched the module text for the old spelling and matched its own
    docstring -- a comment satisfying a structural control, FG37 by name.
    """
    import os  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "b9p32_sentinel.py").write_text("MARK = 1" + chr(10), encoding="utf-8")

    keep = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = str(extra)
    try:
        environment = _audit_child_env(tmp_path / "markers.tsv")
    finally:
        if keep is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = keep

    entries = environment["PYTHONPATH"].split(os.pathsep)
    assert str(ROOT / "tests") in entries, (
        "the plugin directory is gone from the child's path, so `-p "
        f"fg_marker_dump` cannot resolve at all: {entries}"
    )
    assert str(extra) in entries, (
        "the caller's PYTHONPATH was DISCARDED. A harness that puts its own "
        "src first -- which is how every mutant in this repository is isolated "
        f"-- would have that isolation silently removed: {entries}"
    )

    probe = (
        "import importlib.util;"
        "print(importlib.util.find_spec('b9p32_sentinel') is not None)"
    )
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe], cwd=ROOT, capture_output=True, text=True,
        timeout=600, env=environment, check=False,
    )
    assert done.stdout.strip() == "True", (
        "a child launched with this environment cannot import from the "
        f"caller's path: {done.stdout!r} {done.stderr[-200:]}"
    )


def test_a_module_level_marker_cannot_declare_a_class_for_every_node():
    """B9-P3-4. The link was membership, so nine nodes could declare one class.

    `test_every_false_green_class_is_declared_by_a_collected_guard` asked
    whether the inventory's owner appeared IN the set of nodes declaring the
    class. A module-level `pytestmark = pytest.mark.false_green("FGnn")` makes
    EVERY node in that module declare it and leaves the real owner among them,
    so the check passed.

    Measured before the repair: ONE line added to
    `tests/test_absence_is_not_success.py` gave `FG37 declared by 9 nodes`, and
    both audits reported 2 passed, green. A class certified by nine nodes,
    eight of them unrelated, is not a link.

    The sibling test catches a node declaring two CLASSES. Nothing caught a
    class declared by two NODES, which is the same drift in the other
    direction.

    The specimen is planted in the real tree and removed in a `finally`, with
    the restoration asserted -- the two isolated vehicles that would avoid that
    are recorded as dead ends in
    `test_a_collection_that_failed_cannot_establish_the_guard_link`.
    """
    import subprocess  # noqa: PLC0415

    node = (
        "tests/test_false_green_audit.py"
        "::test_every_false_green_class_is_declared_by_a_collected_guard"
    )
    target = ROOT / "tests" / "test_absence_is_not_success.py"

    def guard() -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", node, "-q", "-o", "addopts=",
             "-p", "no:randomly", "--no-header"],
            cwd=ROOT, capture_output=True, text=True, timeout=2400,
            encoding="utf-8", errors="replace", check=False,
        )

    pristine = target.read_bytes()
    try:
        healthy = guard()
        assert healthy.returncode == 0, (
            "the guard does not pass on the pristine tree: "
            + healthy.stdout[-300:]
        )
        text = pristine.decode("utf-8")
        tree = ast.parse(text)
        after_imports = max(
            statement.end_lineno for statement in tree.body
            if isinstance(statement, (ast.Import, ast.ImportFrom))
        )
        lines = text.split(chr(10))
        lines.insert(
            after_imports,
            'pytestmark = __import__("pytest").mark.false_green("FG37")',
        )
        target.write_bytes(chr(10).join(lines).encode("utf-8"))
        blanketed = guard()
    finally:
        target.write_bytes(pristine)

    assert target.read_bytes() == pristine, "the specimen did not restore the tree"
    assert blanketed.returncode != 0, (
        "a module-level marker made every node in that module declare FG37 and "
        "the audit still certified the class-to-guard link: "
        + blanketed.stdout[-500:]
    )
    assert "declared by" in blanketed.stdout, (
        "the guard failed for some other reason, so this does not measure the "
        f"one-to-one link: {blanketed.stdout[-500:]}"
    )


def test_the_specification_only_guards_are_declared_as_such():
    """FG04/FG06. An inventory must not call a specification a measurement.

    These two guards assert over helpers defined in this file against
    synthetic inputs. They are worth keeping -- the algorithms they pin are
    the ones the assurance process must follow -- but the inventory should not
    imply they measure this system, and `SPECIFICATION_ONLY` is where that is
    said.

    CHECKED IN BOTH DIRECTIONS, so the label cannot drift from the code:
    a declared entry must genuinely reference no repository name, and a guard
    that stops being a specification has to be removed from the set.

    NOT A GLOBAL SCREEN. Applying this criterion to all thirty-nine was
    measured and MISCLASSIFIED: it flags FG33, whose repaired guard reads the
    harness SOURCE and so exercises repository content while naming none of
    it. The criterion is sound for these two, which were examined
    individually, and is not a general test of relevance.

    THE BOUND, restated after a review measured the first version of it wrong.
    Static imports, DYNAMIC imports (`importlib.import_module`, `__import__`
    with a literal) and string literals naming a top-level repository
    directory are all recognised.

    What is still NOT recognised is a guard reading a module-local object that
    carries repository facts -- `INVENTORY` itself, say. Measured: wiring
    FG06's guard to `INVENTORY` leaves this GREEN; wiring it to `census`, to
    `importlib.import_module("nornyx_forge.approval_trust")`, or to
    `(ROOT / "src")` turns it RED. The earlier wording claimed this "catches a
    guard that starts importing the system", which was false while dynamic
    imports escaped it.
    """
    import ast  # noqa: PLC0415

    stdlib = {
        "operator",
    "os", "sys", "re", "json", "ast", "subprocess", "tempfile", "shutil",
        "sqlite3", "pathlib", "contextlib", "textwrap", "itertools", "time",
        "collections", "hashlib", "stat", "io", "math", "types", "typing",
        "datetime", "random", "pytest", "importlib", "copy", "uuid",
        "platform", "zipfile", "tarfile", "socket",
        # Stdlib the first version of this set missed, which made
        # `dataclasses`, `tomllib` and `__future__` read as repository names.
        "dataclasses", "tomllib", "__future__", "functools", "inspect",
        "textwrap", "string", "warnings", "traceback", "enum", "abc",
    }
    source = (ROOT / "tests" / "test_false_green_audit.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    repository_names: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] not in stdlib:
                repository_names |= {a.asname or a.name for a in node.names}
                repository_names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in stdlib:
                    repository_names.add((alias.asname or alias.name).split(".")[0])

    # A DYNAMIC IMPORT IS AN IMPORT. The first version of this collected names
    # only from `ast.Import` / `ast.ImportFrom`, and its own disclosure claimed
    # to catch "a guard that starts importing the system". Measured, appending
    # one line to FG06's guard:
    #
    #     assert len(INVENTORY) > 0                      rc 0  (disclosed bound)
    #     importlib.import_module("nornyx_forge...")     rc 0  NOT CAUGHT
    #     assert (ROOT / "src").is_dir()                 rc 0  NOT CAUGHT
    #     import check_test_coverage as census; ...      rc 1  control fires
    #
    # A guard importing production through `importlib` IS importing the system,
    # so that summary sentence was false. String arguments to `import_module`
    # and `__import__`, and string literals naming a top-level repository
    # directory, are read as repository references too.
    _REPOSITORY_DIRECTORIES = ("src", "scripts", "docs", ".nornyx", "tests")

    def _dynamic_repository_reference(function) -> list:
        found = []
        for node in ast.walk(function):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                if name in {"import_module", "__import__"} and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        if first.value.split(".")[0] not in stdlib:
                            found.append(f"import_module({first.value!r})")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                head = node.value.strip("/").split("/")[0]
                if head in _REPOSITORY_DIRECTORIES:
                    found.append(f"path {node.value!r}")
        return sorted(set(found))

    def touches_repository(function_name: str) -> list:
        function = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        )
        used = {n.id for n in ast.walk(function) if isinstance(n, ast.Name)}
        used |= {n.attr for n in ast.walk(function) if isinstance(n, ast.Attribute)}
        return sorted(used & repository_names)

    declared = sorted(SPECIFICATION_ONLY)
    assert declared, "the declaration emptied out, so it checks nothing"

    for ident in declared:
        item = next(entry for entry in INVENTORY if entry.ident == ident)
        module, _, name = item.owner.partition("::")
        assert module.endswith("test_false_green_audit.py"), (
            f"{ident} is declared specification-only but its guard lives in "
            f"{module}, which this test cannot parse"
        )
        function = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        )
        touched = touches_repository(name) + _dynamic_repository_reference(function)
        assert touched == [], (
            f"{ident} is declared specification-only and its guard now "
            f"references repository code {touched}. If that is deliberate, "
            "remove it from SPECIFICATION_ONLY and rewrite the note beside "
            "the set -- do not leave the inventory calling a measurement a "
            "specification, or the reverse."
        )


def test_a_consumer_in_a_subdirectory_keeps_its_path(tmp_path: Path, monkeypatch):
    """Discovery widened to `rglob` and the result was still a basename.

    `tests/nested/test_x.py` was reported as `tests/test_x.py`, so
    `screen_call_sites` opened a DIFFERENT FILE and the nested module's
    unchecked calls were never inspected -- while set equality hid it, because
    the duplicated flat name collapsed into an already-named entry. Half of a
    widening is how the escape it closed came back.
    """
    tests = tmp_path / "tests"
    (tests / "nested").mkdir(parents=True)
    (tests / "guard_evidence.py").write_text("", encoding="utf-8", newline="")
    (tests / "test_flat.py").write_text(
        "from guard_evidence import exercised_assertions" + chr(10)
        + "def test_ok():" + chr(10)
        + "    exercised_assertions(node, module)" + chr(10),
        encoding="utf-8", newline="",
    )
    (tests / "nested" / "test_flat.py").write_text(
        "from guard_evidence import exercised_assertions" + chr(10)
        + "def test_unwired():" + chr(10)
        + "    exercised_assertions(node)" + chr(10),
        encoding="utf-8", newline="",
    )
    monkeypatch.setattr("test_false_green_audit.ROOT", tmp_path, raising=True)

    discovered = screen_consumers()
    assert "tests/nested/test_flat.py" in discovered, discovered
    unwired = [
        relative + "::" + function
        for relative in discovered
        for function, call in screen_call_sites(relative)
        if not _supplies_the_module(call)
    ]
    assert unwired == ["tests/nested/test_flat.py::test_unwired"], unwired


UNSTARRED_CALLS = [
    ("a bare star of something that is not the pair", "f(*sites)", False),
    ("a star of an unknown call", "f(*collect())", False),
    ("keyword splat", "f(**options)", False),
    ("the helper that returns the pair", "f(*_guard(body, source))", True),
    ("both arguments given", "f(guard, module)", True),
    ("the module by keyword", "f(guard, module=module)", True),
    ("one argument and nothing else", "f(guard)", False),

    # THE ROWS THAT MAKE THE VALUE CHECK LOAD-BEARING. Without these,
    # every row above is decided by the star/keyword/arity logic alone --
    # measured, by replacing `_could_be_a_module` with `return True` and
    # watching all five wiring controls and all seven original rows stay
    # green while the round-12 P1 came back. A fix nothing fails without
    # is not a fix that has been tested; it is one that happened to be
    # written.
    ("a second argument that is None", "f(guard, None)", False),
    ("the module keyword given None", "f(guard, module=None)", False),
    ("a number in the module slot", "f(guard, 0)", False),
    ("an empty list in the module slot", "f(guard, [])", False),
    ("a string in the module slot", 'f(guard, "")', False),
    ("an f-string, which is a literal too", 'f(guard, f"")', False),
    ("a lambda", "f(guard, lambda: 1)", False),
    ("a comprehension", "f(guard, [x for x in y])", False),
    ("a boolean expression", "f(guard, not m)", False),
    # And the concession, stated as a row: a CALL could return a module,
    # so it is admitted, and this table says so rather than leaving a
    # reader to infer how far the check reaches.
    ("a call, whose value is unknowable here", "f(guard, build())", True),
]


@pytest.mark.parametrize(
    ("label", "source", "supplies"), UNSTARRED_CALLS,
    ids=[case[0] for case in UNSTARRED_CALLS],
)
def test_a_star_is_not_proof_that_a_module_was_supplied(
    label: str, source: str, supplies: bool,
):
    """The rule was written about the `*` and justified by a helper's arity.

    `exercised_assertions(*sites)` with a one-element `sites` supplies no
    module and was accepted; `f(**kw)` was accepted for the same reason and
    with as little evidence. What is starred now has to be a call to something
    declared to return the (guard, module) pair.
    """
    call = ast.parse(source).body[0].value
    assert _supplies_the_module(call) is supplies, label


def test_a_global_declaration_disqualifies_a_module_constant():
    """A `global` rebinds from a scope the module walk never visits.

    Measured: `_ON = True` with `def _arm(): global _ON; _ON = False` left
    `_ON` a constant, so `if _ON:` folded live and its body was credited
    whether or not `_arm()` had run.
    """
    module = ast.parse(
        "_ON = True" + NL + NL
        + "def _arm():" + NL
        + "    global _ON" + NL
        + "    _ON = False" + NL + NL
        + "def guard():" + NL
        + '    """A docstring."""' + NL
        + "    if _ON:" + NL
        + "        assert real" + NL
    )
    from guard_evidence import module_constants  # noqa: PLC0415

    assert "_ON" not in module_constants(module)
    guard = next(
        node for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "guard"
    )
    assert exercised_assertions(guard, module) == 1
    # The control: without the `global`, the constant folds as it always did.
    settled = ast.parse(
        "_ON = False" + NL + NL
        + "def guard():" + NL
        + '    """A docstring."""' + NL
        + "    if _ON:" + NL
        + "        assert real" + NL
    )
    bare = next(node for node in settled.body if isinstance(node, ast.FunctionDef))
    assert exercised_assertions(bare, settled) == 0
