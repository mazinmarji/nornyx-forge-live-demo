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

import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from mutation_validity import InvalidMutation, check_mutation  # noqa: E402


@dataclass(frozen=True)
class FalseGreen:
    ident: str
    false_claim: str
    root_cause: str
    guard: str
    owner: str


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
        "tests/test_evidence_binding.py::test_the_baseline_can_be_defeated_for_adversarial_runs",
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
        "tests/test_probe_containment.py"
        "::test_fg33_a_run_that_exceeds_its_timeout_raises_instead_of_returning",
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
        exercised = sum(
            1
            for child in ast.walk(found[0])
            if isinstance(child, (ast.Assert, ast.Raise))
            or (
                isinstance(child, ast.withitem)
                and isinstance(child.context_expr, ast.Call)
                and "raises" in ast.dump(child.context_expr)
            )
            or (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "fail"
            )
        )
        assert exercised >= 1, (
            f"{item.ident}: {node} contains no assertion and no expected "
            "refusal, so it would pass with its body deleted. A self-attack "
            "that asserts nothing is the defect this inventory exists to find."
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


def test_every_false_green_owner_names_the_class_it_owns():
    """An owner must SAY which class it proves, or re-pointing is invisible.

    The idents are pinned by set -- FG14's lesson, applied correctly. The
    OWNERS were pinned only by cardinality: module exists, node defined exactly
    once, at least one assertion, owners distinct. A review re-pointed FG29 --
    "a violated property, when the mutant crashed instead of deciding" -- at
    `tests/test_skip_gate.py::test_a_clean_report_passes` and measured BOTH
    inventory tests still PASSED. Any 33 distinct singly-defined asserting
    nodes satisfy the audit, and `assert True` satisfies the AST counter.

    That is the identity-versus-count substitution one level up from where it
    was fixed. An owner whose source carries its own class id cannot be
    silently re-pointed at an unrelated test.
    """
    import ast  # noqa: PLC0415

    unnamed = []
    for item in INVENTORY:
        module, _, node = item.owner.partition("::")
        source = (ROOT / module).read_text(encoding="utf-8")
        function = next(
            (found for found in ast.walk(ast.parse(source))
             if isinstance(found, ast.FunctionDef) and found.name == node),
            None,
        )
        if function is None:
            unnamed.append(f"{item.ident}: {item.owner} does not exist")
            continue
        segment = ast.get_source_segment(source, function) or ""
        if item.ident.lower() in node.lower() or item.ident in segment:
            continue
        unnamed.append(f"{item.ident}: {item.owner} never names it")

    assert unnamed == [], (
        "these catalogue entries point at a test that says nothing about the "
        "class it is supposed to prove, so the entry could be re-pointed at "
        f"any asserting node and this audit would stay green: {unnamed}"
    )
