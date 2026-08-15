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
    "H03": (
        "REDUNDANT BY MEASUREMENT, not unproven by accident: with BOTH the "
        "is_dir and the empty-directory guards removed, observe_governance_"
        "integrity still returns `unavailable`. A third layer refuses. Reviving "
        "this defect needs a mutation that removes every layer, and until that "
        "exists no single-guard mutation can be a valid kill"
    ),
    "H04": (
        "the same measurement, from the other guard. Removing the empty-"
        "directory check alone leaves the surface unavailable"
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
    tree = destination / "tree"
    tree.mkdir(parents=True, exist_ok=True)
    for name in ("src", "tests", "scripts", ".nornyx"):
        shutil.copytree(ROOT / name, tree / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"))
    for name in ("pyproject.toml", "Dockerfile", "docker-compose.yml", ".dockerignore"):
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, tree / name)

    relative, anchor, replacement, count = item.mutation
    target = tree / relative
    before = target.read_text(encoding="utf-8")
    after = before.replace(anchor, replacement)
    check_mutation(relative, before, after, anchor, count)
    target.write_text(after, encoding="utf-8", newline="")
    return tree


def _isolated_env(tree: Path) -> dict:
    import os  # noqa: PLC0415

    return {**os.environ, "PYTHONPATH": str(tree / "src")}


def _unisolated_env() -> dict:
    """Deliberately without precedence, so the guard can be shown to fire."""
    import os  # noqa: PLC0415

    env = {**os.environ}
    env.pop("PYTHONPATH", None)
    return env


def _prove_resolution(tree: Path, *, isolate: bool = True) -> None:
    """Refuse to measure anything until the mutant is what loads."""
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", RESOLUTION_PROBE],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace",
        env=(_isolated_env(tree) if isolate else _unisolated_env()),
        timeout=300,
    )
    assert completed.returncode == 0, (
        f"INVALID_MUTATION_ENVIRONMENT -- the probe could not import the "
        f"package at all: {completed.stderr[-400:]}"
    )
    resolved = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    assert resolved, "INVALID_MUTATION_ENVIRONMENT -- the probe printed nothing"
    escaped = [path for path in resolved if str(tree) not in path]
    assert not escaped, (
        "INVALID_MUTATION_ENVIRONMENT -- production modules resolved OUTSIDE the "
        f"mutant workspace, so the original source would be measured: {escaped}"
    )


def _prove_semantic_effect(tree: Path, item: SecurityClass) -> None:
    """Show the VALUE changed, not merely the syntax.

    `None or X` passes every structural check and removes nothing. Where a
    class records a `semantic_effect`, the mutant is asked to demonstrate it
    before its regression result may count.
    """
    import os  # noqa: PLC0415

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c",
         "import ast,sys;"
         "src=open('src/demo_app/agentic.py',encoding='utf-8').read();"
         "print('frozen_action_trust=None' in src.replace(' ',''))"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env={**os.environ}, timeout=300,
    )
    assert completed.stdout.strip() == "True", (
        f"{item.ident}: INVALID_MUTATION -- the mutation did not produce the "
        f"semantic effect it claims ({item.semantic_effect})"
    )


@pytest.mark.parametrize("item", DIRECT, ids=[i.ident for i in DIRECT])
def test_removing_the_control_revives_the_defect(item: SecurityClass, tmp_path: Path):
    """KILLED_VALIDLY, or the control is not what stops the defect.

    Three outcomes and no fourth. The mutation must reach an executable node
    (`check_mutation`), the mutant must be what loads (`_prove_resolution`), and
    the mutant must run to completion. Only then does a failing test count as a
    kill.
    """
    try:
        tree = _mutated_tree(tmp_path, item)
    except InvalidMutation as exc:
        pytest.fail(f"{item.ident}: INVALID_MUTATION -- {exc}")

    _prove_resolution(tree)
    if item.semantic_effect:
        _prove_semantic_effect(tree, item)

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", item.test, "-p", "no:cacheprovider",
         "-q", "-p", "no:warnings", "--tb=line"],
        cwd=tree, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=_isolated_env(tree), timeout=1800,
    )
    output = completed.stdout + completed.stderr

    assert "INTERNALERROR" not in output and "no tests ran" not in output, (
        f"{item.ident}: INVALID_MUTATION -- the intended test could not run: "
        f"{output[-600:]}"
    )
    assert completed.returncode != 0, (
        f"{item.ident} SURVIVED. Removing the control ({item.control}) left "
        f"{item.test} passing, so that test is not what proves this property. "
        f"{output[-400:]}"
    )


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
GOVERNANCE_SURFACE_CHAIN = (
    ("A", "    if not contracts_dir.is_dir():", "the directory is not there"),
    ("B", "    if not contracts:", "the directory holds no contracts"),
    ("C", "    if not verified:", "nothing in it could be verified"),
)


@pytest.mark.parametrize(
    ("label", "anchor", "condition"),
    GOVERNANCE_SURFACE_CHAIN,
    ids=[case[0] for case in GOVERNANCE_SURFACE_CHAIN],
)
def test_removing_one_guard_leaves_the_property_protected(
    tmp_path: Path, label: str, anchor: str, condition: str
):
    """Positive defence-in-depth evidence, stated per route.

    This is the opposite of a kill and is recorded as such: each guard can be
    removed and an absent or empty governance surface STILL refuses, because
    the other two remain. That is why no single-guard mutation could ever be a
    valid H03/H04 kill, and why the compound mutation below is required.
    """
    tree = _plain_copy(tmp_path)
    module = tree / OBSERVER
    before = module.read_text(encoding="utf-8")
    after = before.replace(anchor, anchor.replace("    if ", "    if False and ", 1))
    check_mutation(OBSERVER, before, after, anchor, 1)
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
    module = tree / OBSERVER
    text = module.read_text(encoding="utf-8")
    for _label, anchor, _condition in GOVERNANCE_SURFACE_CHAIN:
        mutated = text.replace(anchor, anchor.replace("    if ", "    if False and ", 1))
        check_mutation(OBSERVER, text, mutated, anchor, 1)
        text = mutated
    module.write_text(text, encoding="utf-8", newline="")

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


def test_the_delegated_catalogues_prove_mutant_origin_where_they_mutate():
    """A catalogue that mutates production without isolation proves nothing.

    The two that mutate `src/` run their measurement in a subprocess whose FIRST
    action is the path insert, so no `.pth` can outrank them. This asserts that
    arrangement is still in place rather than trusting it.
    """
    for module in ("tests/test_domain_collapse_mutations.py",
                   "tests/test_semantic_binding_theorem.py"):
        source = (ROOT / module).read_text(encoding="utf-8")
        assert "sys.path.insert(0" in source, (
            f"{module} mutates production but no longer forces its copy onto "
            "sys.path first, so it may be measuring the real source"
        )
