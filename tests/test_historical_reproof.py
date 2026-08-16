"""Task 10. Every historical security class, re-proved by removing its control.

The inventory below is DERIVED from this repository, not recalled: 87 non-rebind
remediation commits, 43 distinct security-critical test modules named by
`check_test_coverage.REQUIRED_MODULES`, and the review records those commits
close. The count is whatever the repository proves; nothing here is padded to
reach a number.

A control is re-proved when removing it from PRODUCTION source makes the test
that names it FAIL, for the reason it names. Three outcomes, and no fourth:

    KILLED_VALIDLY   the mutant ran, the intended test failed, for the intended
                     reason
    SURVIVED         the mutant ran and the test still passed -- a real defect
                     until disproven
    INVALID_MUTATION the mutation did not reach an executable node, or the
                     mutant could not run. Never counted as a kill.

Two classes are re-proved by their own dedicated catalogues rather than
duplicated here, and are cross-referenced so deleting them is visible:
authority-domain collapse (14 mutations) and semantic-projection collapse (8).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from mutation_validity import InvalidMutation, check_mutation  # noqa: E402
from mutation_workspace import (  # noqa: E402
    AttackNotAdmissible,
    Outcome,
    faithful_copy,
    isolated_env,
    require_caused_failure,
    require_mutant_origin,
    require_node_exists,
    require_pristine_baseline,
    run_node,
)

RUNTIME = "src/nornyx_forge/nornyx_runtime.py"
OBSERVER = "src/nornyx_forge/subject_observer.py"
SUBJECT = "src/nornyx_forge/governed_subject.py"
TRUST = "src/nornyx_forge/approval_trust.py"
REFRESH = "scripts/refresh_governance_evidence.py"
ARCHGATE = "scripts/check_architecture.py"
CENSUS = "scripts/check_test_coverage.py"


def _read_current_floor() -> str:
    """The census's own MINIMUM_COLLECTED line, exactly as written."""
    import re  # noqa: PLC0415

    source = (ROOT / CENSUS).read_text(encoding="utf-8")
    found = re.findall(r"^MINIMUM_COLLECTED = \d+$", source, re.MULTILINE)
    assert len(found) == 1, (
        f"expected exactly one MINIMUM_COLLECTED assignment, found {len(found)}"
    )
    return found[0]


_CURRENT_FLOOR = _read_current_floor()


@dataclass(frozen=True)
class SecurityClass:
    """One historical defect class and the mutation that must revive it."""

    ident: str
    defect: str
    prop: str
    control: str
    #: (relative path, anchor, replacement, occurrences)
    mutation: tuple[str, str, str, int] | None
    #: pytest node id whose failure IS the proof
    test: str
    expect: str
    severity: str
    #: Set when the class is re-proved by a dedicated catalogue module.
    delegated_to: str = ""
    side_effects: tuple[str, ...] = field(default_factory=tuple)
    #: Further edits applied WITH `mutation`, for a property whose
    #: enforcement has independent routes. Removing one route is
    #: defence-in-depth evidence, not a kill.
    extra_mutations: tuple = ()
    #: Set when AST inequality is not enough to show the control is gone.
    semantic_effect: str = ""


INVENTORY = (
    SecurityClass(
        ident="H01 runtime security context never reaches the boundary",
        defect="flows ran unestablished; the boundary resolved its own anchors per use",
        prop="the boundary judges with the context the application established",
        control="demo_app.agentic passes frozen_action_trust from the context",
        # `None or X` was the first attempt and is a SEMANTIC NO-OP: the parse
        # tree changes, the value does not. That is the blind spot of an
        # AST-difference check, and `semantic_effect` below is what closes it.
        # This removes the wiring outright, so the boundary falls back to
        # resolving trust for itself and stops answering from the object the
        # application froze. Measured by object identity: it holds in the
        # baseline and does not under the mutant.
        mutation=("src/demo_app/agentic.py",
                  "            frozen_action_trust=(\n"
                  "                security_context.action_approval_trust\n"
                  "                if security_context is not None\n"
                  "                else None\n"
                  "            ),",
                  "            frozen_action_trust=None,", 1),
        semantic_effect=(
            "demo_app.agentic must stop handing the boundary the frozen store"
        ),
        test="tests/test_trust_snapshot.py::test_the_established_context_carries_the_frozen_store",
        expect="the boundary answers from a store the application did not freeze",
        severity="P1",
    ),
    SecurityClass(
        ident="H02 governance integrity observed but not consumed",
        defect="a compromised governance surface still released consequential effects",
        prop="integrity gates the effect, not just the report",
        control="nornyx_runtime._official refuses when integrity does not authorize",
        mutation=(RUNTIME,
                  "            if integrity is None or not integrity.authorizes_consequential_action:",
                  "            if False and (integrity is None or not integrity.authorizes_consequential_action):", 1),
        test="tests/test_governance_integrity_authority.py::test_a_compromised_runtime_releases_nothing",
        expect="a compromised runtime released the effect",
        severity="P1",
        side_effects=("callback 0", "ledger unchanged", "grant unconsumed"),
    ),
    SecurityClass(
        ident="H03 missing governance surface read as intact",
        defect="a missing contracts directory produced integrity `intact`",
        prop="absence is unavailability, never soundness",
        control="observe_governance_integrity refuses a non-directory",
        # Both unavailable returns, because they are independently redundant:
        # removing only the is_dir guard leaves the empty-directory guard to
        # catch a missing directory (glob yields nothing). Measured, not assumed.
        mutation=(OBSERVER,
                  "    if not contracts_dir.is_dir():",
                  "    if False and not contracts_dir.is_dir():", 1),
        test="tests/test_absence_is_not_success.py::test_an_unobservable_governance_surface_is_unavailable",
        expect="the diagnostic no longer names the missing directory",
        severity="P1",
    ),
    SecurityClass(
        ident="H04 empty governance surface read as intact",
        defect="an empty contracts directory produced integrity `intact`",
        prop="an empty required collection authorizes nothing",
        control="observe_governance_integrity refuses an empty directory",
        mutation=(OBSERVER,
                  "    if not contracts:",
                  "    if False and not contracts:", 1),
        test="tests/test_absence_is_not_success.py::test_an_unobservable_governance_surface_is_unavailable",
        expect="the diagnostic no longer names the empty surface",
        severity="P1",
    ),
    SecurityClass(
        ident="H05 required governed contract absent produces a traceback",
        defect="verify() raised FileNotFoundError while a missing FILE refused cleanly",
        prop="absence is reported in the tool's vocabulary, never as a crash",
        control="the approval-wiring loop records absence and continues",
        # TWO clauses, not one, and `FileNotFoundError` IS an `OSError` -- so
        # disabling the first leaves the second catching the same absence and
        # the refusal is unchanged. Measured: single-clause removal produced
        # byte-identical output to pristine, which is why this reported as a
        # SURVIVOR under the new baseline. It was a mis-specified attack, not an
        # unproven control. Both routes are removed together, and the historical
        # traceback returns (rc=1, FileNotFoundError propagating out of verify).
        mutation=(REFRESH,
                  "        except FileNotFoundError:",
                  "        except (FileNotFoundError,) if False else ():", 1),
        extra_mutations=((REFRESH,
                          "        except OSError as exc:",
                          "        except (OSError,) if False else () as exc:", 1),),
        test="tests/test_task8_closure.py::test_the_verifier_refuses_missing_governed_content_without_crashing",
        expect="the verifier crashed instead of refusing",
        severity="P2",
    ),
    SecurityClass(
        ident="H06 anti-shrink floor weakened",
        defect="a green run executed 139 of 202 tests; the floor once allowed a third to vanish",
        prop="the suite cannot quietly get smaller",
        control="check_test_coverage.MINIMUM_COLLECTED, guarded at 90% of collected",
        # Anchored on the CURRENT floor, read from the census itself. A literal
        # went stale the moment the suite grew and the floor was raised, and the
        # harness then refused it as a stale anchor -- correctly, but it fails
        # the gate for maintenance rather than for a defect. Deriving it keeps
        # the anchor exact while tracking a value that legitimately moves.
        mutation=(CENSUS, _CURRENT_FLOOR, "MINIMUM_COLLECTED = 1", 1),
        test="tests/test_skip_gate.py::test_the_floor_sits_below_the_current_suite_and_above_nothing",
        expect="a floor of 1 leaves the whole suite deletable",
        severity="P1",
    ),
    SecurityClass(
        ident="H07 dynamic process-capability bypass",
        defect="seven dynamic spellings acquired subprocess while the gate reported clean",
        prop="capability is what a module HOLDS, not how it spelled the import",
        control="check_architecture._dynamically_imported_module resolves every spelling",
        mutation=(ARCHGATE,
                  "    if not is_dynamic:\n        return None",
                  "    if True or not is_dynamic:\n        return None", 1),
        test="tests/test_process_capability.py::test_acquiring_process_capability_is_refused",
        expect="a dynamic acquisition was accepted",
        severity="P1",
    ),
    SecurityClass(
        ident="H08 trust re-read after bootstrap",
        defect="editing the trust file between two requests changed who the second trusted",
        prop="long-lived authority consumers answer from an immutable snapshot",
        control="NornyxActionBoundary prefers frozen_action_trust over any path",
        mutation=(RUNTIME,
                  "            self.action_trust_store = frozen_action_trust",
                  "            self.action_trust_store = ApprovalTrustStore.load(\n"
                  "                Path(trust.approver_store) if trust is not None else None,\n"
                  "                domain=ACTION_TRUST_DOMAIN,\n"
                  "            )", 1),
        test="tests/test_trust_snapshot.py::test_two_requests_through_one_context_see_the_same_trust",
        expect="replacing the trust file changed who a running context trusted",
        severity="P1",
    ),
    SecurityClass(
        ident="H09 temporal approval validation removed",
        defect="a governance approval window was signed and never evaluated",
        prop="a signed window that is not judged bounds nothing",
        control="verify_governance_approval evaluates [generated, expires) against a trusted clock",
        mutation=(TRUST,
                  "    if moment >= expires:",
                  "    if False and moment >= expires:", 1),
        test="tests/test_governance_approval_verifier.py::test_an_expired_approval_is_refused",
        expect="an expired governance approval authenticated",
        severity="P1",
    ),
    SecurityClass(
        ident="H10 ledger continuity / replay epoch",
        defect="a reset ledger forgot spent grants without saying so",
        prop="a grant issued before the ledger existed cannot be proven unspent",
        control="ApprovalLedger.consume refuses with GRANT_PREDATES_LEDGER",
        mutation=(RUNTIME,
                  '                f"{GRANT_PREDATES_LEDGER}: the approval was issued at "',
                  '                f"OK: the approval was issued at "', 1),
        test="tests/test_approval_ledger.py",
        expect="the continuity refusal no longer names its code",
        severity="P1",
    ),
    SecurityClass(
        ident="H11 authority-domain collapse",
        defect="one membership answered governance approval and consequential release",
        prop="membership in one trust domain never implies authority in another",
        control="two independently provisioned domains, refused on mismatch",
        mutation=None,
        delegated_to="tests/test_domain_collapse_mutations.py",
        test="tests/test_domain_collapse_mutations.py::test_the_collapse_is_visible",
        expect="14 dedicated mutations, all killed",
        severity="P1",
    ),
    SecurityClass(
        ident="H12 semantic projection omission or collapse",
        defect="the projection could hide a decision-changing authored change",
        prop="Nornyx divergence implies semantic-identity divergence",
        control="semantic_projection plus the aggregate, mutation-tested",
        mutation=None,
        delegated_to="tests/test_semantic_binding_theorem.py",
        test="tests/test_semantic_binding_theorem.py::test_the_projection_attack_is_killed",
        expect="8 dedicated projection attacks, all killed",
        severity="P1",
    ),
    SecurityClass(
        ident="H13 inspection subject self-reference",
        defect="a diagnostic embedded the current subject in an artifact inside it",
        prop="evidence ABOUT a subject never becomes part of it",
        control="the stale-attestation diagnostic carries no current subject",
        # THE UNSAFE STATE, defined before touching code: a stale attestation
        # names S_old while the tree presents S_current, and that mismatch must
        # stay observable. It must not be rewritable so the stale attestation
        # appears to belong to S_current.
        #
        # The mutation rebinds exactly that -- the diagnostic reports the
        # CURRENT subject instead of the attested one. That sentence lands in
        # `verdict_basis`, inside the evidence set the subject is computed from,
        # so the subject becomes a function of itself.
        #
        # The observable consequence is a FIXED POINT that stops holding.
        # Measured pristine: regenerating over an unchanged tree presents the
        # same subject twice (sha256:5ebd5a18... both times). Under the mutation
        # it cannot, because the artifact carrying the sentence is inside the
        # subject the sentence describes -- and no attestation can then name the
        # subject the next run will present.
        # FIRST ATTEMPT MEASURED AND REJECTED. Rebinding the assignment --
        # `attested_subject = subject_digest` -- makes the comparison always
        # equal, so the diagnostic never fires. That removes the staleness CHECK
        # rather than rebinding the stale IDENTITY, which is a different unsafe
        # state and not this one. It survived, correctly.
        #
        # This keeps the comparison and rebinds only the value the message
        # carries, which is the historical defect exactly.
        mutation=(REFRESH,
                  'f"{path.name} attests to subject {attested_subject}, which is "',
                  'f"{path.name} attests to subject {subject_digest}, which is "', 1),
        semantic_effect=(
            "the stale-attestation diagnostic must stop naming the attested "
            "subject and start naming the current one"
        ),
        # AIMED BY BODY REACHABILITY, which is stricter than statement
        # reachability and had to be, twice over.
        #
        # Probing the ASSIGNMENT said reached -- it runs for every attestation.
        # Probing the `if` said reached -- the probe plants BEFORE a statement,
        # so it proves control arrives, not that the branch is entered. Only
        # probing INSIDE the branch body separated the nodes: the fixed-point
        # test reports INVALID_TEST_AIM because its attestations are never
        # stale, and this node reports BODY REACHED because it deliberately
        # moves the subject out from under one.
        test="tests/test_independent_inspection.py::test_moving_the_subject_makes_the_inspection_stale",
        expect="a stale attestation is described as belonging to the current subject",
        severity="P1",
    ),
    SecurityClass(
        ident="H14 independent review self-reports pass",
        defect="independence was read off the artifact being judged",
        prop="independence is derived from authenticated identities",
        control="_authenticated_inspections discards what does not authenticate",
        # HIGHEST SCRUTINY. This is the class that put three forged
        # `"reviewer": "forged", "verdict": "pass"` records into a commit and
        # made the tree's own integrity verdict false. Removing the discard
        # accepts every attestation on disk, authenticated or not -- which IS
        # "independence read off the artifact being judged".
        mutation=(REFRESH,
                  "        if not ok:",
                  "        if False:", 1),
        # RE-AIMED, and the first aim is the finding. Pointed at
        # test_an_inspection_nobody_can_authenticate_establishes_nothing, this
        # mutation SURVIVED.
        #
        # The reason was NOT unreachability, which is what it looked like and
        # what was first written here. `require_baseline_clause_reached` plants
        # a raise at this clause and both nodes fail carrying the marker, so the
        # clause EXECUTES under either test. The first aim survived because the
        # discard is REDUNDANT there -- another route rejects the same
        # attestation -- which is FG15 proper: defence in depth, not a test that
        # never arrives.
        #
        # Worth stating plainly because the two look identical from a green
        # baseline and a surviving mutant, and only the probe tells them apart.
        #
        # This node genuinely reaches the clause: the store vouches for the
        # builder, every earlier check passes, and only the discard stands
        # between a builder-signed attestation and an accepted inspection. Its
        # own docstring records the same defect happening before, when identity
        # mismatch fired first and the builder branch was never reached.
        test="tests/test_independent_inspection.py::test_the_builder_cannot_satisfy_an_inspector_role",
        expect="a builder-signed attestation is accepted as an inspection",
        severity="P1",
    ),
    SecurityClass(
        ident="H15 verifier governed-dependency deletion",
        defect="deleting a governed module the tool imports produced a traceback",
        prop="a missing governed module is a refusal, not a crash",
        control="_refuse_missing_governed_module",
        # TRACED FROM THE OBSERVABLE, not from the helper's name -- which is how
        # the two earlier attempts went wrong.
        #
        # Deleting src/nornyx_forge/reviewer_trust.py and running --verify
        # produces exit 2 and a structured refusal naming the absent module.
        # That message is built in exactly one place, and it is this helper.
        #
        # The earlier aim failed because the test named for this class deletes a
        # governed FILE or CONTRACT -- neither raises ModuleNotFoundError, so
        # the helper never ran. No test in this suite deleted a MODULE, so the
        # control had no proof at all. One was written.
        #
        # Anchored on the helper's own first statement rather than a call site:
        # the bare call appears twice and the surrounding text is inside an
        # import's parentheses, which is not a statement boundary. The hardened
        # probe reports INVALID_MUTATION_ENVIRONMENT for that anchor and
        # CLAUSE REACHED for this one, which is exactly the distinction it was
        # built to make.
        # The bare call site appears TWICE, so `check_mutation` refused it as
        # ambiguous rather than silently taking the first. The anchor carries
        # the preceding import to be unique -- which is the honest fix, since
        # the two sites guard different imports and mutating "whichever came
        # first" would be a different attack each time the file is edited.
        #
        # The distinction under test is SEMANTIC, not the exit code. Baseline: a
        # missing governed module produces a governed refusal that names the
        # absent content. Mutant: the raw ModuleNotFoundError escapes. Both
        # terminate unsuccessfully, and only one of them describes anything --
        # which is why `test_the_verifier_refuses_missing_governed_content_
        # without_crashing` asserts on the refusal's content and not on rc.
        mutation=(REFRESH,
                  '    if (exc.name or "").split(".")[0] not in {"governed_content", "nornyx_forge"}:',
                  "    if True:", 1),
        test="tests/test_absence_is_not_success.py::test_a_deleted_governed_module_is_refused_not_crashed",
        expect="a missing governed module escapes as an uncontrolled traceback",
        severity="P2",
    ),
    SecurityClass(
        ident="H16 git unavailable read as a clean tree",
        defect="an unreachable git reported no unstaged governed paths",
        prop="an unanswerable question is not an answer of 'clean'",
        control="_unstaged_governed_paths refuses when git cannot be run",
        # HIGHEST SCRUTINY. The fourth instance in this repository of required
        # evidence being absent and read as successful empty verification. The
        # historical code was `except Exception: return []`; this puts the empty
        # return back, ahead of the refusal, so an unreachable git once again
        # answers "no unstaged governed paths" -- which reads as a clean tree.
        mutation=(REFRESH,
                  "        raise SystemExit(\n"
                  '            f"git could not be run ({exc}). A clean governed '
                  'tree cannot be "',
                  "        return []\n"
                  "        raise SystemExit(\n"
                  '            f"git could not be run ({exc}). A clean governed '
                  'tree cannot be "', 1),
        test="tests/test_absence_is_not_success.py::test_an_unrunnable_git_is_not_a_clean_tree",
        expect="an unrunnable git reports a clean governed tree",
        severity="P1",
    ),
    SecurityClass(
        ident="H17 missing review_binding read as verified",
        defect="a missing binding passed verification silently",
        prop="nothing to verify against is not a passing verification",
        control="the verifier consumes verify_review_binding's problems",
        # AIMED BY MEASUREMENT, not by name. The obvious node --
        # test_a_missing_review_binding_is_not_a_passing_verification -- DELETES
        # the binding, so `verify_review_binding` is never called there and the
        # absent-binding refusal comes from a different path entirely.
        # `require_baseline_clause_reached` reported INVALID_TEST_AIM for it,
        # which is exactly what that outcome exists to say: the node is real, it
        # passes, and it is looking somewhere else.
        #
        # This node keeps the binding and removes one claim from it, so the
        # function runs, detects the defect, and the enclosing verifier consumes
        # the result. That is the chain the attack has to break.
        mutation=(REFRESH,
                  "        binding_problems = verify_review_binding(binding)",
                  "        binding_problems = []", 1),
        test="tests/test_evidence_integrity_verifier.py::test_a_binding_missing_a_claim_is_refused",
        expect="a binding missing an integrity claim passes verification",
        severity="P1",
    ),
    SecurityClass(
        ident="H18 evidence recomputation removed",
        defect="a recorded verdict was read back instead of recomputed",
        prop="assurance is recomputed over what is on disk",
        control="verify_review_binding refuses a derived field that disagrees",
        # MEASURED, and it overturned the earlier verdict. This was recorded as
        # defence-in-depth with an incomplete inventory after attacking
        # `recompute_binding_claims`. Cumulative suppression showed why that
        # failed: for a forged-approval binding that route is INERT. It decides
        # nothing, so removing it changed nothing, and the conclusion drawn from
        # its survival was about the wrong control entirely.
        #
        # Suppressing this clause ALONE takes a binding claiming
        # `production_approval: granted` and `human_review: performed` to
        # status pass, integrity intact, zero problems -- the defined unsafe
        # state, reached in one route.
        #
        # `recompute_binding_claims`, the manifest-digest check and the
        # governed-input check were each measured and add nothing here. They are
        # left out: a compound whose components are not independently relevant
        # is a padded inventory, not stronger evidence.
        # AIMED BY MEASUREMENT. The obvious node --
        # test_recomputation_reads_artifacts_not_the_binding -- is STRUCTURAL: it
        # parses the source with `ast` and never executes the function, so
        # `require_baseline_clause_reached` reported INVALID_TEST_AIM. A test can
        # describe a property perfectly and still never run the code that holds
        # it; a structural test is the clearest case of that, and the previous
        # `test` field here did not even name a node.
        #
        # This node forges the binding and requires a refusal, so recomputation
        # actually runs and its answer decides the verdict.
        #
        # Circularity is reintroduced in two edits: read the binding, then let
        # its recorded values win. A forged binding then agrees with itself,
        # which is exactly what "recomputing a claim by reading the claim" means.
        mutation=(REFRESH,
                  "        if claimed != derived:",
                  "        if False:", 1),
        test="tests/test_evidence_integrity_verifier.py::test_forging_the_binding_itself_is_refused",
        expect="a forged binding verifies using the assertions it supplies about itself",
        severity="P1",
    ),
    SecurityClass(
        ident="H19 scope completeness / governed deletion",
        defect="a smaller governed set computed a smaller subject and called it verified",
        prop="a declared member that is absent refuses, never shrinks",
        control="SubjectScope completeness, SUBJECT_SCOPE_INCOMPLETE",
        # Clause reachability MEASURED before registering, and both candidate
        # nodes reach it. This one is chosen because its own subject IS the
        # completeness refusal: a declared member is removed and the observer
        # must refuse rather than compute a smaller subject and call it verified.
        mutation=(OBSERVER,
                  "    if missing:",
                  "    if False and missing:", 1),
        test="tests/test_subject_scope.py::test_missing_declared_content_refuses_rather_than_shrinking",
        expect="a tree missing declared content computes a smaller subject and verifies it",
        severity="P1",
    ),
)

#: Measured, and honest about why each is not yet a valid kill. Recorded as
#: data so the set cannot grow silently -- an entry here is a debt, not an
#: exemption, and `test_the_unproven_set_is_exactly_what_was_measured` fails if
#: anything is added without a reason.
NOT_YET_KILLED = {
    # H03/H04 are ONE root property reached through two surfaces, and no single
    # guard mutation can kill either: three independent routes produce
    # `unavailable`. They are proven together by a COMPOUND mutation below --
    # `test_disabling_the_whole_chain_recreates_the_historical_unsafe_state` --
    # which is why they are excluded from the single-mutation runner rather than
    # left unproven.
    # H03 and H04 are ONE root property reached through two hostile surfaces,
    # and no single-guard mutation can kill either: four independent routes
    # produce a refusal. That is no longer an assertion -- Task 11R measured it.
    #
    #   suppress nothing        -> R1/R2 refuse, each naming its own reason
    #   suppress R1             -> R2 becomes decisive, diagnostic changes
    #   suppress R1+R2          -> R3 becomes decisive, diagnostic changes
    #   suppress R1+R2+R3       -> R4 becomes decisive, and RAISES
    #   suppress R1+R2+R3+R4    -> `intact` over zero verified claims
    #
    # Only the last stage is the historical unsafe state. The third produces a
    # CRASH, so a compound stopping there would turn a test red without ever
    # reaching the defect -- and would have been credited as a kill.
    #
    # `test_the_governance_surface_route_inventory_is_complete` pins every stage
    # and `test_no_route_in_the_inventory_is_inert` refuses a padded inventory,
    # so the compound below is minimal by measurement rather than by assertion.
    "H13": (
        "MEASURED, NOT KILLED, and the gap is precise. The mutation is correct "
        "-- it rebinds the stale-attestation diagnostic to name the CURRENT "
        "subject, which is the historical defect exactly -- and the branch it "
        "sits in genuinely executes under "
        "test_moving_the_subject_makes_the_inspection_stale, proven by probing "
        "INSIDE the branch body rather than at the `if`. "
        "It survives because that test asserts the VERDICT (the inspection is "
        "stale, independence withdrawn) and not the diagnostic's wording. "
        "Rebinding the wording does not change the verdict. "
        "The real unsafe state is SUBJECT DRIFT: the sentence lands in "
        "verdict_basis, inside the evidence set the subject is computed from, "
        "so two regenerations over an unchanged tree stop agreeing. Detecting "
        "that needs a stale attestation present AND two regenerations compared "
        "-- and no test does both. The fixed-point test regenerates twice but "
        "its attestations are never stale (INVALID_TEST_AIM at the branch "
        "body); the staleness test has a stale attestation but regenerates "
        "once. "
        "Same shape as H15: the control is real, the defect is real, and the "
        "combination that would detect it is untested. The test to write is "
        "known -- settle, attach a signed attestation, move the subject, "
        "regenerate twice, require the subject unchanged -- and is not written "
        "here rather than claimed."
    ),
    "H03": (
        "PROVEN BY COMPOUND, with a measured route inventory. Four independent "
        "routes were enumerated by cumulative suppression, each shown decisive "
        "by the diagnostic changing when the previous one was removed, and the "
        "full set shown to reach `intact` over zero verified claims -- the "
        "historical unsafe state. Excluded from the single-mutation runner "
        "because no single guard can kill it, which is a property of the "
        "system rather than a gap in the campaign; the kill is "
        "SURFACE-WHOLE-CHAIN."
    ),
    "H04": (
        "the same measured inventory, reached from the empty-directory surface "
        "instead of the absent one. Suppressing the empty-directory guard alone "
        "leaves the surface unavailable via the routes behind it."
    ),
}

DIRECT = tuple(
    item for item in INVENTORY
    if item.mutation is not None and item.ident.split()[0] not in NOT_YET_KILLED
)
PENDING = tuple(
    item for item in INVENTORY
    if item.mutation is not None and item.ident.split()[0] in NOT_YET_KILLED
)
DELEGATED = tuple(item for item in INVENTORY if item.mutation is None)

#: Independently written, so shrinking INVENTORY fails rather than passing.
EXPECTED_IDS = frozenset(
    f"H{n:02d}" for n in range(1, 20)
)


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------


#: WHY MUTANT ISOLATION NEEDS ITS OWN PROOF.
#:
#: The obvious harness -- copy the tree, mutate `src/`, run the named test in
#: the copy -- silently measures the ORIGINAL source in this repository. The
#: package is installed editable, so
#: `site-packages/__editable__.nornyx_forge_live_demo-*.pth` puts the real `src`
#: on `sys.path` during site initialisation, and a test module's own
#: `sys.path.insert` runs later than conftest's imports.
#:
#: Measured, both directions, by printing `__file__` from inside pytest:
#:
#:     no PYTHONPATH            -> .../nornyx-forge-live-demo/src/...  REAL
#:     PYTHONPATH=<mutant>/src  -> .../tmp.../tree/src/...             MUTANT
#:
#: PYTHONPATH entries precede site-packages, so they outrank the .pth. That is
#: the fix, and it is not taken on faith: every run below PROVES where the
#: module resolved before its result is allowed to count. A run that loads the
#: real source is INVALID_MUTATION_ENVIRONMENT, never a kill and never a
#: survivor.
#:
#: This also corrected an earlier false-green CANDIDATE. Under the unisolated
#: harness, disabling the expiry clause left `test_an_expired_approval_is_refused`
#: passing, which looked like a test refusing on a clause it does not name.
#: Isolated, the same mutation FAILS that test. The test was sound; the harness
#: was not.
RESOLUTION_PROBE = (
    "import nornyx_forge.approval_trust as m, nornyx_forge.subject_observer as o;"
    "print(m.__file__);print(o.__file__)"
)


def _mutated_tree(destination: Path, item: SecurityClass) -> Path:
    """A faithful workspace with exactly one admitted mutation applied."""
    tree = faithful_copy(destination)
    for relative, anchor, replacement, count in (item.mutation, *item.extra_mutations):
        target = tree / relative
        before = target.read_text(encoding="utf-8")
        after = before.replace(anchor, replacement)
        check_mutation(relative, before, after, anchor, count)
        target.write_text(after, encoding="utf-8", newline="")
    return tree


def _plain_copy(destination: Path) -> Path:
    """An unmutated faithful workspace, for callers that want one."""
    return faithful_copy(destination)


def _isolated_env(tree: Path) -> dict:
    return isolated_env(tree)


def _prove_resolution(tree: Path, *, isolate: bool = True) -> None:
    """Origin proof, READ from the loaded module rather than grepped.

    A text search for `sys.path.insert(0` matches an unrelated line; only asking
    the interpreter where a module actually came from proves anything.
    """
    if not isolate:
        import os  # noqa: PLC0415

        env = {**os.environ}
        env.pop("PYTHONPATH", None)
        completed = subprocess.run(  # noqa: S603
            [sys.executable, "-c",
             "import nornyx_forge.approval_trust as m; print(m.__file__)"],
            cwd=tree, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=env, timeout=300,
        )
        resolved = [x.strip() for x in completed.stdout.splitlines() if x.strip()]
        raise AssertionError(
            "INVALID_MUTATION_ENVIRONMENT -- production modules resolved outside "
            "the mutant workspace: " + str(resolved)
        )
    require_mutant_origin(tree, PRODUCTION_MODULES)


def _prove_semantic_effect(tree: Path, item: SecurityClass) -> None:
    """Show the VALUE changed, not merely the syntax.

    `None or X` passes every structural check and removes nothing, which is why
    AST inequality is never accepted alone where a class records an effect.
    """
    source = (tree / item.mutation[0]).read_text(encoding="utf-8")
    assert item.mutation[2].strip().replace(" ", "") in source.replace(" ", ""), (
        item.ident + ": INVALID_MUTATION -- the replacement is absent from the "
        "mutant, so the semantic effect was not produced: " + item.semantic_effect
    )


PRODUCTION_MODULES = (
    "nornyx_forge.approval_trust",
    "nornyx_forge.subject_observer",
    "nornyx_forge.nornyx_runtime",
)


@pytest.mark.parametrize("item", DIRECT, ids=[i.ident for i in DIRECT])
def test_removing_the_control_revives_the_defect(item: SecurityClass, tmp_path: Path):
    """KILLED_VALIDLY, and only after every earlier step is shown to hold.

    The protocol, in order. Each failure ends the attempt with its OWN outcome
    rather than being counted as a kill:

        1 the named node EXISTS                 INVALID_TEST_TARGET
        2 it PASSES pristine                    INVALID_BASELINE
        3 the mutation reaches executable code  INVALID_MUTATION
        4 the mutant is what loads              INVALID_MUTATION_ENVIRONMENT
        5 the semantic effect is present        INVALID_MUTATION
        6 the SAME node runs and fails          KILLED_VALIDLY

    Step 2 is the one that was missing, and it is the one that mattered: without
    it `returncode != 0` credited a kill for a broken workspace, and three
    classes were certified that way while their controls went unproven.
    """
    pristine = faithful_copy(tmp_path / "pristine")
    try:
        require_node_exists(pristine, item.test)
        require_pristine_baseline(pristine, item.test)
    except AttackNotAdmissible as exc:
        pytest.fail(item.ident + ": " + str(exc))

    try:
        tree = _mutated_tree(tmp_path / "mutant", item)
    except InvalidMutation as exc:
        pytest.fail(item.ident + ": " + Outcome.INVALID_MUTATION.value + " -- " + str(exc))

    try:
        require_node_exists(tree, item.test)
        require_mutant_origin(tree, PRODUCTION_MODULES)
    except AttackNotAdmissible as exc:
        pytest.fail(item.ident + ": " + str(exc))

    if item.semantic_effect:
        _prove_semantic_effect(tree, item)

    report = tree.parent / f"{item.ident.replace('/', '_')}.xml"
    completed = run_node(tree, item.test, report=report)
    output = completed.stdout + completed.stderr

    if completed.returncode in (4, 5):
        pytest.fail(
            item.ident + ": " + Outcome.INVALID_TEST_TARGET.value
            + " -- the node stopped collecting under the mutant: " + output[-400:]
        )
    assert "INTERNALERROR" not in output, (
        item.ident + ": " + Outcome.INVALID_MUTATION_ENVIRONMENT.value
        + " -- " + output[-400:]
    )
    assert completed.returncode != 0, (
        item.ident + " " + Outcome.SURVIVED.value + ". Removing the control ("
        + item.control + ") left " + item.test + " passing, so that test is not "
        "what proves this property. " + output[-400:]
    )
    # A non-zero exit says the run was not clean. It does not say the CONTROL
    # was reached: an ImportError in the mutant exits non-zero too, and Lens B
    # collected a kill that way by re-aiming H06 at an unrelated rename. The
    # JUnit report distinguishes a failed assertion from an error, which the
    # summary prose does not.
    try:
        require_caused_failure(report, item.test, output)
    except AttackNotAdmissible as refusal:
        pytest.fail(item.ident + ": " + str(refusal))


# --------------------------------------------------------------------------
# The mutant-origin invariant, self-tested in BOTH directions
# --------------------------------------------------------------------------

#: Prints where each production module actually came from.
_ORIGIN_PROBE = (
    "import nornyx_forge.approval_trust as a, nornyx_forge.subject_observer as o,"
    " nornyx_forge.nornyx_runtime as r;"
    "print(a.__file__);print(o.__file__);print(r.__file__)"
)


def _origins(tree: Path, *, isolate: bool) -> list[str]:
    import os  # noqa: PLC0415

    env = {**os.environ}
    if isolate:
        env["PYTHONPATH"] = str(tree / "src")
    else:
        env.pop("PYTHONPATH", None)
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _ORIGIN_PROBE],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env, timeout=300,
    )
    assert completed.returncode == 0, completed.stderr[-400:]
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _plain_copy(destination: Path) -> Path:
    tree = destination / "tree"
    tree.mkdir(parents=True, exist_ok=True)
    for name in ("src", "tests", "scripts", ".nornyx"):
        shutil.copytree(ROOT / name, tree / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"))
    for name in ("pyproject.toml", "Dockerfile", "docker-compose.yml", ".dockerignore"):
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, tree / name)
    return tree


def test_an_unisolated_child_loads_the_real_repository_source(tmp_path: Path):
    """Direction one, and the reason every result needs an origin proof.

    Without PYTHONPATH the editable `.pth` wins even though the child runs with
    the copy as its working directory. This is the exact condition under which
    a mutation silently measures the original -- asserted, so nobody assumes the
    copy is enough.
    """
    tree = _plain_copy(tmp_path)
    resolved = _origins(tree, isolate=False)

    assert resolved, "the probe printed nothing"
    assert all(str(ROOT) in path for path in resolved), (
        f"expected the REAL source without isolation, got {resolved}"
    )
    assert not any(str(tree) in path for path in resolved)


def test_an_isolated_child_loads_the_mutant_workspace(tmp_path: Path):
    """Direction two: PYTHONPATH outranks the .pth, so the mutant is measured."""
    tree = _plain_copy(tmp_path)
    resolved = _origins(tree, isolate=True)

    assert resolved
    assert all(str(tree) in path for path in resolved), (
        f"isolation failed; production modules came from {resolved}"
    )
    assert not any(
        str(ROOT / "src") in path for path in resolved
    ), "a production module escaped to the real source"


def test_breaking_precedence_is_reported_as_an_invalid_environment(tmp_path: Path):
    """And the guard itself must fire, or it is decoration.

    `_prove_resolution` is what stands between "the mutant said so" and "the
    original said so". Here isolation is deliberately withheld, and the guard
    must refuse rather than let the run proceed.
    """
    tree = _plain_copy(tmp_path)

    import os  # noqa: PLC0415

    saved = os.environ.pop("PYTHONPATH", None)
    try:
        with pytest.raises(AssertionError, match="INVALID_MUTATION_ENVIRONMENT"):
            _prove_resolution(tree, isolate=False)
    finally:
        if saved is not None:
            os.environ["PYTHONPATH"] = saved


# --------------------------------------------------------------------------
# The governance-surface enforcement chain (H03 / H04)
# --------------------------------------------------------------------------

#: H03 and H04 are ONE root property -- absence is not success -- reached
#: through TWO surfaces: a directory that is not there, and a directory that is
#: there and empty. They keep separate historical IDs because they were found
#: and fixed separately, and because the operator response differs. They share
#: one compound mutation, because the property is shared and mutating one guard
#: proves nothing while the others stand.
#:
#: Three INDEPENDENT routes produce `unavailable`, measured by removing them one
#: at a time and finding the property still held:
#: Every INDEPENDENT route that stops an absent or empty governance surface
#: reporting `intact`, with the module each lives in.
#:
#: Route D arrived later, when `GovernanceIntegrityState` was made to perform
#: the constructor refusal its docstring had always described. It is in a
#: different module from the other three, which is why this carries a path: the
#: property is defended across a file boundary, and a chain that could only name
#: anchors in the observer would have missed it.
#:
#: The compound test found it, not a reviewer. Disabling A, B and C stopped
#: producing the unsafe state and started producing a refusal from D, and the
#: test declined to credit a kill on the grounds that the inventory must be
#: incomplete. It was.
GOVERNANCE_SURFACE_CHAIN = (
    ("A", OBSERVER, "    if not contracts_dir.is_dir():",
     "the directory is not there"),
    ("B", OBSERVER, "    if not contracts:",
     "the directory holds no contracts"),
    ("C", OBSERVER, "    if not verified:",
     "nothing in it could be verified"),
    ("D", SUBJECT,
     "        if self.status == INTEGRITY_INTACT and self.verified_claims < 1:",
     "the state itself refuses to be intact having verified nothing"),
)


@pytest.mark.parametrize(
    ("label", "relative", "anchor", "condition"),
    GOVERNANCE_SURFACE_CHAIN,
    ids=[case[0] for case in GOVERNANCE_SURFACE_CHAIN],
)
def test_removing_one_guard_leaves_the_property_protected(
    tmp_path: Path, label: str, relative: str, anchor: str, condition: str
):
    """Positive defence-in-depth evidence, stated per route.

    This is the opposite of a kill and is recorded as such: each guard can be
    removed and an absent or empty governance surface STILL refuses, because
    the other two remain. That is why no single-guard mutation could ever be a
    valid H03/H04 kill, and why the compound mutation below is required.
    """
    tree = _plain_copy(tmp_path)
    module = tree / relative
    before = module.read_text(encoding="utf-8")
    stripped = anchor.lstrip()
    indent = anchor[: len(anchor) - len(stripped)]
    after = before.replace(anchor, indent + "if False and " + stripped[len("if "):], 1)
    check_mutation(relative, before, after, anchor, 1)
    module.write_text(after, encoding="utf-8", newline="")

    _prove_resolution(tree)
    for surface in ("missing", "empty"):
        assert _surface_status(tree, surface) != "intact", (
            f"removing guard {label} ({condition}) left a {surface} governance "
            "surface reporting intact"
        )


def _surface_status(tree: Path, surface: str) -> str:
    """What the observer says about an absent or empty contracts directory."""
    import os  # noqa: PLC0415

    script = (
        "import sys, tempfile;"
        "from pathlib import Path;"
        "from nornyx_forge.subject_observer import observe_governance_integrity as g;"
        + (
            "print(g(Path('definitely-not-here')).status)"
            if surface == "missing"
            else "print(g(Path(tempfile.mkdtemp())).status)"
        )
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env={**os.environ, "PYTHONPATH": str(tree / "src")},
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr[-400:]
    return completed.stdout.strip()


@pytest.mark.parametrize("surface", ["missing", "empty"])
def test_disabling_the_whole_chain_recreates_the_historical_unsafe_state(
    tmp_path: Path, surface: str
):
    """H03/H04 KILLED_VALIDLY, by attacking the property rather than one guard.

    All three enforcement routes are removed together, the mutant is proven to
    be what loads, and THEN the historical unsafe state is established directly:
    an absent or empty governance surface reporting `intact`. Only after that is
    the regression test run, and it must fail.

    Nothing about production is weakened to achieve this -- the mutation lives
    in a throwaway copy.
    """
    tree = _plain_copy(tmp_path)
    for _label, relative, anchor, _condition in GOVERNANCE_SURFACE_CHAIN:
        module = tree / relative
        text = module.read_text(encoding="utf-8")
        stripped = anchor.lstrip()
        indent = anchor[: len(anchor) - len(stripped)]
        mutated = text.replace(anchor, indent + "if False and " + stripped[len("if "):], 1)
        check_mutation(relative, text, mutated, anchor, 1)
        module.write_text(mutated, encoding="utf-8", newline="")

    _prove_resolution(tree)

    # The historical unsafe boundary, established BEFORE the regression test.
    assert _surface_status(tree, surface) == "intact", (
        f"the compound mutation did not recreate the unsafe state for a "
        f"{surface} surface, so the enforcement inventory is incomplete and "
        "this cannot count as a kill"
    )

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest",
         "tests/test_absence_is_not_success.py::test_an_unobservable_governance_surface_is_unavailable",
         "-p", "no:cacheprovider", "-q", "-p", "no:warnings", "--tb=line"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=_isolated_env(tree), timeout=900,
    )
    output = completed.stdout + completed.stderr
    assert "INTERNALERROR" not in output and "no tests ran" not in output, output[-500:]
    assert completed.returncode != 0, (
        "H03/H04 SURVIVED: the governance surface reports intact when absent, "
        f"and the regression test still passes.\n{output[-400:]}"
    )


# --------------------------------------------------------------------------
# The nine delegated classes, audited rather than assumed
# --------------------------------------------------------------------------


def test_every_delegated_class_names_an_attack_that_still_exists():
    """Delegation is part of the proof chain, so it is checked.

    A catalogue that was deleted, renamed, or emptied would leave the delegating
    class silently unproven. Each delegated entry must name a module that exists
    and a test function that is really in it.
    """
    missing: list[str] = []
    for item in DELEGATED:
        module, _, node = item.test.partition("::")
        path = ROOT / module
        if not path.exists():
            missing.append(f"{item.ident}: {module} is gone")
            continue
        if node and f"def {node.split('[')[0]}(" not in path.read_text(encoding="utf-8"):
            missing.append(f"{item.ident}: {module} no longer defines {node}")
    assert missing == [], missing


def test_the_delegated_catalogues_prove_mutant_origin_where_they_mutate(tmp_path):
    """A catalogue that mutates production without isolation proves nothing.

    This used to be `assert "sys.path.insert(0" in source` -- a text search that
    matches the unrelated `sys.path.insert(0, str(ROOT / "tests"))` at the top of
    almost every test module here. It passed for a module that had no production
    isolation code at all, so it certified nothing it claimed to.

    Asked of the interpreter instead: materialize a catalogue workspace, import
    the production modules the way that catalogue's probe does, and read
    `__file__`. The property turns out to hold -- `authority_probe.py` inserts
    its own `src` at position 0, which outranks the editable-install `.pth` --
    but it holds as a measured fact rather than as a matched string.
    """
    import json  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    from mutation import _materialize  # noqa: PLC0415

    tree = _materialize(tmp_path)
    spy = tree / "tests" / "origin_spy.py"
    spy.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        "ROOT = Path(__file__).resolve().parents[1]\n"
        "sys.path.insert(0, str(ROOT / 'src'))\n"
        "sys.path.insert(0, str(ROOT / 'tests'))\n"
        "import nornyx_forge.nornyx_runtime as rt\n"
        "import nornyx_forge.approval_trust as at\n"
        "import nornyx_forge.subject_bootstrap as sb\n"
        "print(json.dumps([rt.__file__, at.__file__, sb.__file__]))\n",
        encoding="utf-8",
    )

    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(spy)],
        capture_output=True, text=True, cwd=str(tree), timeout=300,
        encoding="utf-8", errors="replace",
    )
    assert completed.returncode == 0, (
        "the origin probe did not run, so isolation was not measured:\n"
        + completed.stderr[-800:]
    )

    origins = json.loads(completed.stdout.strip().splitlines()[-1])
    root = tree.resolve()
    # Resolved, never substring-matched: Windows returns the same directory in
    # 8.3 short form and long form, and comparing the text calls that an escape.
    escaped = [p for p in origins if root not in Path(p).resolve().parents]
    assert not escaped, (
        "production modules resolved OUTSIDE the catalogue workspace, so those "
        f"mutations measured the real source: {escaped}"
    )


def test_an_erroring_mutant_is_not_a_kill(tmp_path: Path):
    """B-P2-3. A non-zero exit is not evidence that the control was reached.

    Lens B re-aimed H06 at an unrelated rename and collected a kill on an
    ImportError. Nothing about the control was removed, or even executed -- the
    module never finished importing -- and `returncode != 0` could not tell the
    difference.

    Built as a real pytest run rather than a hand-written report, so the thing
    being classified is what pytest actually emits for an import failure.
    """
    module = tmp_path / "test_broken.py"
    module.write_text(
        "import a_module_that_does_not_exist  # noqa: F401\n\n\n"
        "def test_something():\n    assert True\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.xml"
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "test_broken.py", "-q",
         "-p", "no:cacheprovider", "-p", "no:warnings",
         "--junit-xml", str(report)],
        cwd=tmp_path, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=600,
    )

    assert completed.returncode != 0, (
        "the import failure exited 0, so this case cannot show what it is for"
    )

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(report, "test_broken.py", completed.stdout)
    assert refusal.value.outcome is Outcome.INVALID_MUTATION, refusal.value.outcome
    assert "ERRORED" in str(refusal.value)


def test_a_genuinely_failing_assertion_is_admitted(tmp_path: Path):
    """The control. A checker that refused every non-zero run would also pass
    the case above while making every real kill unprovable."""
    module = tmp_path / "test_failing.py"
    module.write_text(
        "def test_the_control():\n    assert False, 'the control did not hold'\n",
        encoding="utf-8",
    )
    report = tmp_path / "report.xml"
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "test_failing.py", "-q",
         "-p", "no:cacheprovider", "-p", "no:warnings",
         "--junit-xml", str(report)],
        cwd=tmp_path, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=600,
    )

    assert completed.returncode != 0
    require_caused_failure(report, "test_failing.py", completed.stdout)


def test_a_passing_run_is_reported_as_survived(tmp_path: Path):
    """The third direction: no failure and no error is a SURVIVOR, and must be
    named as one rather than folded into 'not killed'."""
    module = tmp_path / "test_passing.py"
    module.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    report = tmp_path / "report.xml"
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "test_passing.py", "-q",
         "-p", "no:cacheprovider", "-p", "no:warnings",
         "--junit-xml", str(report)],
        cwd=tmp_path, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=600,
    )

    with pytest.raises(AttackNotAdmissible) as refusal:
        require_caused_failure(report, "test_passing.py", "")
    assert refusal.value.outcome is Outcome.SURVIVED


# --------------------------------------------------------------------------
# The recorded metadata must be compared to something, or deleted.
# --------------------------------------------------------------------------

#: What a declared side effect means, as a token the killing test must assert on.
#:
#: `side_effects` was recorded on one class and read by nothing. A claim nobody
#: checks is not weaker evidence than a claim that is checked -- it is a
#: different kind of thing, and printing it beside real results makes it look
#: like the same kind. Either the killing test asserts it or the class must
#: stop claiming it.
SIDE_EFFECT_TOKENS = {
    "callback 0": "calls == []",
    "ledger unchanged": "spent is False",
    "grant unconsumed": "spent is False",
}

#: The severities this inventory may use. A free-text field cannot be wrong,
#: which is another way of saying it cannot be checked.
KNOWN_SEVERITIES = frozenset({"P1", "P2", "P3"})


def test_every_recorded_severity_is_from_the_closed_vocabulary():
    """`severity` was recorded and never read, so any string would have done."""
    unknown = sorted(
        f"{item.ident.split()[0]}={item.severity!r}"
        for item in INVENTORY
        if item.severity not in KNOWN_SEVERITIES
    )
    assert unknown == [], f"severities outside {sorted(KNOWN_SEVERITIES)}: {unknown}"


def test_every_class_states_a_distinct_expectation():
    """`expect` is the reason the killing test should fail.

    Never compared to anything, so a class could carry an empty string or the
    same sentence as its neighbour and nothing would notice. Distinctness is
    what makes it a statement about THIS class rather than boilerplate.
    """
    blank = [item.ident.split()[0] for item in INVENTORY if not item.expect.strip()]
    assert blank == [], f"these classes state no expectation: {blank}"

    seen: dict[str, str] = {}
    duplicates: list[str] = []
    for item in INVENTORY:
        ident = item.ident.split()[0]
        if item.expect in seen:
            duplicates.append(f"{ident} repeats {seen[item.expect]}")
        seen[item.expect] = ident
    assert duplicates == [], duplicates


def test_every_declared_side_effect_is_asserted_by_its_killing_test():
    """A recorded side effect must be one the named test actually checks.

    H02 claims `callback 0`, `ledger unchanged` and `grant unconsumed`. Those
    are exactly the observations that make an integrity refusal meaningful --
    and nothing verified that the test named beside them asserts any of it.
    """
    unbacked: list[str] = []
    for item in INVENTORY:
        if not item.side_effects:
            continue
        module, _, _node = item.test.partition("::")
        source = (ROOT / module).read_text(encoding="utf-8")
        ident = item.ident.split()[0]
        for effect in item.side_effects:
            token = SIDE_EFFECT_TOKENS.get(effect)
            if token is None:
                unbacked.append(f"{ident}: {effect!r} has no declared token")
            elif token not in source:
                unbacked.append(f"{ident}: {module} does not assert {token!r}")
    assert unbacked == [], unbacked


def test_a_side_effect_nobody_asserts_would_be_caught():
    """The self-attack. The check above must fail on an unbacked claim."""
    token = SIDE_EFFECT_TOKENS.get("a side effect that is never asserted")
    assert token is None, "the probe effect must be undeclared"

    source = (ROOT / "tests/test_governance_integrity_authority.py").read_text(
        encoding="utf-8"
    )
    assert "spent is False" in source, (
        "the backing assertion H02 claims has disappeared, so the mapping above "
        "is describing a test that no longer checks it"
    )
    assert "calls == []" in source


# --------------------------------------------------------------------------
# What this inventory does NOT attack, stated rather than implied.
# --------------------------------------------------------------------------

#: The two delegation targets that are MUTATION CATALOGUES. Delegating to one of
#: these means the class is attacked: hostile edits are applied and a control is
#: shown to be load-bearing.
ATTACKING_CATALOGUES = frozenset(
    {
        "tests/test_domain_collapse_mutations.py",
        "tests/test_semantic_binding_theorem.py",
    }
)

#: Classes this inventory COVERS WITH TESTS but does not attack, and why that is
#: recorded rather than quietly implied.
#:
#: `delegated_to` was one field doing two jobs. H11 and H12 point at mutation
#: catalogues; H13-H19 point at ordinary test modules. Both read as "re-proved
#: elsewhere", so a nineteen-class inventory presented itself as attacked while
#: seven of those classes had no hostile representation anywhere -- and the
#: unified catalogue's 35 attacks contain none for them.
#:
#: Being covered by tests is not nothing. It is just not the same claim.
COVERED_BUT_UNATTACKED = {
}


def test_the_unattacked_classes_are_named_rather_than_implied():
    """A class with tests but no attack must say so.

    The failure this prevents is a reader taking "19 classes re-proved" and "35
    attacks" as covering the same ground. They do not: seven classes contribute
    no attack at all.
    """
    unattacked = {
        item.ident.split()[0]
        for item in INVENTORY
        if not item.mutation and item.delegated_to not in ATTACKING_CATALOGUES
    }

    assert unattacked == set(COVERED_BUT_UNATTACKED), (
        "the set of classes covered-but-unattacked has changed.\n"
        f"  measured: {sorted(unattacked)}\n"
        f"  recorded: {sorted(COVERED_BUT_UNATTACKED)}\n"
        "Either an attack was added -- remove it from COVERED_BUT_UNATTACKED -- "
        "or a class lost one and must be recorded here."
    )


def test_every_unattacked_class_still_names_a_real_covering_module():
    """Unattacked is not unwatched. Each must point at a module that exists."""
    missing: list[str] = []
    for item in INVENTORY:
        ident = item.ident.split()[0]
        if ident not in COVERED_BUT_UNATTACKED:
            continue
        assert item.delegated_to, f"{ident} names no covering module at all"
        if not (ROOT / item.delegated_to).exists():
            missing.append(f"{ident}: {item.delegated_to} is gone")
    assert missing == [], missing


def test_the_attacked_classes_really_delegate_to_mutation_catalogues():
    """The other half: a class counted as attacked must point at a catalogue.

    Without this, moving a class from an attacking catalogue to an ordinary test
    module would silently reclassify it as attacked-by-nothing while the
    accounting still counted it.
    """
    for item in INVENTORY:
        ident = item.ident.split()[0]
        if item.mutation or ident in COVERED_BUT_UNATTACKED:
            continue
        assert item.delegated_to in ATTACKING_CATALOGUES, (
            f"{ident} is counted as attacked but delegates to "
            f"{item.delegated_to!r}, which is not a mutation catalogue"
        )


# --------------------------------------------------------------------------
# Task 11R. The governance-surface route inventory, measured and pinned.
# --------------------------------------------------------------------------

#: The probe run inside each mutant workspace. Reports, per hostile state, the
#: status, the verified count, and the first 60 characters of the diagnostic --
#: (200 chars: at 80 the phrase that identifies R3 was clipped mid-word)
#: which is how the DECISIVE route is identified: when a route is suppressed,
#: the next route answers and the diagnostic changes.
_SURFACE_PROBE = '''
import sys, tempfile
sys.path.insert(0, "src")
from pathlib import Path
from nornyx_forge.subject_observer import observe_governance_integrity
work = Path(tempfile.mkdtemp())
missing = work / "gone"
empty = work / "empty"; empty.mkdir(parents=True)
for label, path in (("MISSING", missing), ("EMPTY", empty)):
    try:
        s = observe_governance_integrity(path)
        first = (s.problems[0] if s.problems else "")
        print(label + "|" + s.status + "|" + str(s.verified_claims) + "|" + first[:200])
    except Exception as exc:
        print(label + "|RAISED " + type(exc).__name__ + "|-|" + str(exc)[:200])
'''


def _surface_observation(tree: Path) -> dict[str, tuple[str, str, str]]:
    """(status, verified, diagnostic) per hostile state, from the mutant tree."""
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _SURFACE_PROBE],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=isolated_env(tree), timeout=600,
    )
    assert completed.returncode == 0, completed.stderr[-300:]
    observed: dict[str, tuple[str, str, str]] = {}
    for line in completed.stdout.strip().splitlines():
        label, status, verified, diagnostic = line.split("|", 3)
        observed[label] = (status, verified, diagnostic)
    assert set(observed) == {"MISSING", "EMPTY"}, observed
    return observed


def test_the_governance_surface_route_inventory_is_complete(tmp_path: Path):
    """TASK 11R. Every independently effective route, and nothing else.

    An inventory is not complete because someone found three checks. It is
    complete when cumulative suppression of exactly the enumerated routes
    reaches the DEFINED HISTORICAL UNSAFE STATE -- here, an absent or empty
    governance surface reporting `intact` -- and no unrelated control had to be
    removed to get there.

    Each stage below asserts which route BECAME DECISIVE, measured by the
    diagnostic changing. A check whose removal changes nothing is not a route,
    however plausible it looks.

    The third stage is why this test exists. With R1, R2 and R3 removed the
    observer RAISES rather than returning `intact`: a compound that stopped
    there would turn a test red without ever reaching the unsafe state, and
    would have been credited as a kill. Only removing R4 as well produces
    `intact` over nothing -- the sentence "every claim was checked and matched"
    said about zero claims.
    """
    tree = faithful_copy(tmp_path)

    # BASELINE. Both hostile states refuse, each naming its own reason.
    baseline = _surface_observation(tree)
    assert baseline["MISSING"][0] == "unavailable", baseline["MISSING"]
    assert baseline["EMPTY"][0] == "unavailable", baseline["EMPTY"]
    assert "is not a directory" in baseline["MISSING"][2], baseline["MISSING"]
    assert "holds no contracts" in baseline["EMPTY"][2], baseline["EMPTY"]

    stages: list[tuple[str, dict[str, tuple[str, str, str]]]] = []
    for label, relative, anchor, condition in GOVERNANCE_SURFACE_CHAIN:
        module = tree / relative
        text = module.read_text(encoding="utf-8")
        stripped = anchor.lstrip()
        indent = anchor[: len(anchor) - len(stripped)]
        mutated = text.replace(anchor, indent + "if False and " + stripped[len("if "):], 1)
        check_mutation(relative, text, mutated, anchor, 1)
        module.write_text(mutated, encoding="utf-8", newline="")
        stages.append((f"{label} ({condition})", _surface_observation(tree)))

    assert len(stages) == 4, [name for name, _ in stages]

    # R1 suppressed: R2 answers for the MISSING case, so the reason changes.
    after_r1 = stages[0][1]
    assert after_r1["MISSING"][0] == "unavailable", after_r1["MISSING"]
    assert "holds no contracts" in after_r1["MISSING"][2], (
        "removing the is_dir guard did not hand the decision to the "
        f"empty-directory guard: {after_r1['MISSING']}"
    )

    # R1+R2 suppressed: R3 answers, and says the surface records no digests.
    after_r2 = stages[1][1]
    assert after_r2["MISSING"][0] == "unavailable", after_r2["MISSING"]
    assert "records no evidence digests" in after_r2["MISSING"][2], after_r2["MISSING"]

    # R1+R2+R3 suppressed: R4 answers, and it REFUSES BY RAISING. Not the
    # unsafe state -- a crash, which is why the inventory cannot stop here.
    after_r3 = stages[2][1]
    for label in ("MISSING", "EMPTY"):
        assert after_r3[label][0].startswith("RAISED"), after_r3[label]
        assert "nothing was checked" in after_r3[label][2], after_r3[label]

    # All four suppressed: the historical unsafe state, exactly.
    after_r4 = stages[3][1]
    for label in ("MISSING", "EMPTY"):
        status, verified, _diagnostic = after_r4[label]
        assert status == "intact", (
            f"{label}: removing every enumerated route did not reach the unsafe "
            f"state, so the inventory is INCOMPLETE: {after_r4[label]}"
        )
        assert verified == "0", (
            f"{label}: reported intact having verified {verified} claims, which "
            "is not the historical defect"
        )


def test_no_route_in_the_inventory_is_inert(tmp_path: Path):
    """A route that changes nothing when removed is not a route.

    Guards against the inventory being padded with plausible-looking checks
    that never decide anything -- which would make the compound look minimal
    while removing more than it needed to.
    """
    tree = faithful_copy(tmp_path)
    previous = _surface_observation(tree)
    inert: list[str] = []

    for label, relative, anchor, _condition in GOVERNANCE_SURFACE_CHAIN:
        module = tree / relative
        text = module.read_text(encoding="utf-8")
        stripped = anchor.lstrip()
        indent = anchor[: len(anchor) - len(stripped)]
        mutated = text.replace(anchor, indent + "if False and " + stripped[len("if "):], 1)
        module.write_text(mutated, encoding="utf-8", newline="")
        observed = _surface_observation(tree)
        if observed == previous:
            inert.append(label)
        previous = observed

    assert inert == [], (
        f"these routes changed nothing when suppressed, so they are not "
        f"independently effective and do not belong in the inventory: {inert}"
    )
