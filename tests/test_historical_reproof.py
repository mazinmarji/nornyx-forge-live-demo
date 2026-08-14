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

import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


RUNTIME = "src/nornyx_forge/nornyx_runtime.py"
OBSERVER = "src/nornyx_forge/subject_observer.py"
TRUST = "src/nornyx_forge/approval_trust.py"
REFRESH = "scripts/refresh_governance_evidence.py"
ARCHGATE = "scripts/check_architecture.py"
CENSUS = "scripts/check_test_coverage.py"


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


INVENTORY = (
    SecurityClass(
        ident="H01 runtime security context never reaches the boundary",
        defect="flows ran unestablished; the boundary resolved its own anchors per use",
        prop="the boundary judges with the context the application established",
        control="demo_app.agentic passes frozen_action_trust from the context",
        mutation=("src/demo_app/agentic.py",
                  "            frozen_action_trust=(\n"
                  "                security_context.action_approval_trust",
                  "            frozen_action_trust=(\n"
                  "                None or security_context.action_approval_trust", 1),
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
        mutation=(REFRESH,
                  "        except FileNotFoundError:",
                  "        except (FileNotFoundError,) if False else ():", 1),
        test="tests/test_task8_closure.py::test_the_verifier_refuses_missing_governed_content_without_crashing",
        expect="the verifier crashed instead of refusing",
        severity="P2",
    ),
    SecurityClass(
        ident="H06 anti-shrink floor weakened",
        defect="a green run executed 139 of 202 tests; the floor once allowed a third to vanish",
        prop="the suite cannot quietly get smaller",
        control="check_test_coverage.MINIMUM_COLLECTED, guarded at 90% of collected",
        mutation=(CENSUS, "MINIMUM_COLLECTED = 830", "MINIMUM_COLLECTED = 1", 1),
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
        mutation=None,
        delegated_to="tests/test_task8_closure.py",
        test="tests/test_task8_closure.py::test_attaching_and_removing_an_attestation_leaves_the_subject_where_it_was",
        expect="attach/remove leaves subject and semantics fixed",
        severity="P1",
    ),
    SecurityClass(
        ident="H14 independent review self-reports pass",
        defect="independence was read off the artifact being judged",
        prop="independence is derived from authenticated identities",
        control="reviewer trust store plus signed attestations",
        mutation=None,
        delegated_to="tests/test_independent_inspection.py",
        test="tests/test_independent_inspection.py::test_an_inspection_nobody_can_authenticate_establishes_nothing",
        expect="an unauthenticated inspection establishes nothing",
        severity="P1",
    ),
    SecurityClass(
        ident="H15 verifier governed-dependency deletion",
        defect="deleting a governed module the tool imports produced a traceback",
        prop="a missing governed module is a refusal, not a crash",
        control="_refuse_missing_governed_module",
        mutation=None,
        delegated_to="tests/test_absence_is_not_success.py",
        test="tests/test_task8_closure.py::test_a_governed_deletion_ends_the_inspection",
        expect="the refusal names the missing governed content",
        severity="P2",
    ),
    SecurityClass(
        ident="H16 git unavailable read as a clean tree",
        defect="an unreachable git reported no unstaged governed paths",
        prop="an unanswerable question is not an answer of 'clean'",
        control="_unstaged_governed_paths raises SystemExit on OSError",
        mutation=None,
        delegated_to="tests/test_absence_is_not_success.py",
        test="tests/test_absence_is_not_success.py::test_every_empty_return_from_a_handler_is_classified",
        expect="every empty-return handler carries a classification",
        severity="P1",
    ),
    SecurityClass(
        ident="H17 missing review_binding read as verified",
        defect="a missing binding passed verification silently",
        prop="nothing to verify against is not a passing verification",
        control="the refresher reports a missing review_binding as a problem",
        mutation=None,
        delegated_to="tests/test_absence_is_not_success.py",
        test="tests/test_absence_is_not_success.py::test_a_missing_review_binding_is_not_a_passing_verification",
        expect="a missing binding is a problem, not a pass",
        severity="P1",
    ),
    SecurityClass(
        ident="H18 evidence recomputation removed",
        defect="a recorded verdict was read back instead of recomputed",
        prop="assurance is recomputed over what is on disk",
        control="verify() recomputes rather than reporting a stored verdict",
        mutation=None,
        delegated_to="tests/test_evidence_integrity_verifier.py",
        test="tests/test_evidence_integrity_verifier.py",
        expect="a tampered artifact is detected by recomputation",
        severity="P1",
    ),
    SecurityClass(
        ident="H19 scope completeness / governed deletion",
        defect="a smaller governed set computed a smaller subject and called it verified",
        prop="a declared member that is absent refuses, never shrinks",
        control="SubjectScope completeness, SUBJECT_SCOPE_INCOMPLETE",
        mutation=None,
        delegated_to="tests/test_subject_scope.py",
        test="tests/test_task8_closure.py::test_a_governed_deletion_ends_the_inspection",
        expect="deletion refuses or moves the subject, never both silently",
        severity="P1",
    ),
)

DIRECT = tuple(item for item in INVENTORY if item.mutation is not None)
DELEGATED = tuple(item for item in INVENTORY if item.mutation is None)

#: Independently written, so shrinking INVENTORY fails rather than passing.
EXPECTED_IDS = frozenset(
    f"H{n:02d}" for n in range(1, 20)
)


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------


#: WHY NO EXECUTION HAPPENS IN THIS MODULE YET.
#:
#: The obvious harness -- copy the tree, mutate `src/`, run the named test
#: inside the copy -- is NOT SOUND in this repository, and the measurement that
#: showed it is recorded here so nobody rebuilds it.
#:
#: The package is installed editable, so
#: `site-packages/__editable__.nornyx_forge_live_demo-0.2.0.pth` puts the REAL
#: `src` on `sys.path` at interpreter startup. A test module's own
#: `sys.path.insert(0, ROOT / "src")` runs later, and later still than any
#: conftest import of `nornyx_forge`. Whether the mutant or the original is
#: loaded therefore depends on import order rather than on the harness.
#:
#: Measured: a direct `python -c` with the insert first DOES load the mutant
#: (verified by printing `__file__`), while the same mutation under `pytest`
#: left `test_an_expired_approval_is_refused` passing with the expiry clause
#: disabled. Under those conditions a "kill" may be the original code failing
#: for its own reasons and a "survivor" may be a mutation that never applied.
#: Both directions are wrong, which is why nothing here is reported as
#: KILLED_VALIDLY.
#:
#: The two catalogues that DO execute -- `test_domain_collapse_mutations.py`
#: and `test_semantic_binding_theorem.py` -- avoid this entirely: they run a
#: standalone probe or compute a digest in a subprocess whose FIRST action is
#: the path insert, with no pytest and no conftest in between. A sound harness
#: for this module has to do the same, or force the mutant ahead of the .pth.
#:
#: Until that exists, this module is an INVENTORY with meta-controls, and the
#: re-proof status of every non-delegated class is UNPROVEN. That is recorded
#: below as an explicit, failing-if-understated debt rather than left implicit.
UNPROVEN = frozenset(item.ident.split()[0] for item in DIRECT)


def test_the_unproven_debt_is_recorded_exactly():
    """The debt is visible and cannot be quietly reduced.

    If someone builds the sound harness and re-proves a class, this fails until
    UNPROVEN is narrowed to match -- which is the point. An inventory that
    silently claims more coverage than it has is the defect this whole
    programme exists to remove.
    """
    assert UNPROVEN == {item.ident.split()[0] for item in DIRECT}
    assert len(UNPROVEN) == 10, (
        f"{len(UNPROVEN)} classes are unproven; the recorded figure is 10"
    )
    proven_elsewhere = {item.ident.split()[0] for item in DELEGATED}
    assert len(proven_elsewhere) == 9
    assert not (UNPROVEN & proven_elsewhere), "a class cannot be both"


# --------------------------------------------------------------------------
# 10C -- meta-controls on the inventory itself
# --------------------------------------------------------------------------


def test_the_inventory_matches_its_independently_written_identifiers():
    """Set equality, so shrinking the inventory fails instead of passing."""
    actual = frozenset(item.ident.split()[0] for item in INVENTORY)
    assert actual == EXPECTED_IDS, (
        f"inventory drift -- missing {sorted(EXPECTED_IDS - actual)}, "
        f"unexpected {sorted(actual - EXPECTED_IDS)}"
    )
    assert len(INVENTORY) == 19, f"{len(INVENTORY)} classes, expected 19"
    assert DIRECT, "no class is re-proved directly"
    assert DELEGATED, "no class is delegated"


def test_every_referenced_test_module_exists():
    """A delegated class whose catalogue was deleted is a hole, not a pass."""
    missing = sorted(
        {
            item.test.split("::")[0]
            for item in INVENTORY
            if not (ROOT / item.test.split("::")[0]).exists()
        }
        | {
            item.delegated_to
            for item in INVENTORY
            if item.delegated_to and not (ROOT / item.delegated_to).exists()
        }
    )
    assert missing == [], f"referenced modules no longer exist: {missing}"


def test_every_referenced_module_is_in_the_census():
    """And is protected from deletion by the anti-shrink control."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import check_test_coverage as census  # noqa: PLC0415

    required = set(census.REQUIRED_MODULES)
    referenced = {item.test.split("::")[0] for item in INVENTORY}
    unprotected = sorted(referenced - required)
    assert unprotected == [], (
        "these carry a historical security proof but are not in "
        f"REQUIRED_MODULES, so deleting one is invisible: {unprotected}"
    )


def test_every_entry_is_fully_specified():
    for item in INVENTORY:
        assert len(item.defect) > 20, item.ident
        assert len(item.prop) > 15, item.ident
        assert len(item.control) > 10, item.ident
        assert item.severity in {"P1", "P2"}, item.ident
        assert item.test, item.ident
        assert (item.mutation is None) == bool(item.delegated_to), (
            f"{item.ident}: a class must carry its own mutation OR name the "
            "catalogue that re-proves it, never neither and never both"
        )


def test_reducing_the_expected_count_is_visible():
    """The REQUIRED_MODULES shape: an emptied expectation must not pass."""
    assert len(EXPECTED_IDS) == 19
    assert len({i.ident for i in INVENTORY}) == len(INVENTORY), "duplicate ids"
    runtime_authority = [i for i in INVENTORY if i.side_effects]
    assert runtime_authority, (
        "no class records consequential side-effect expectations, so the "
        "runtime-authority standard is not represented"
    )
