"""Two subjects, two layers, and the mutations that must move each one.

There are TWO identities in this system and conflating them is a way to prove
nothing while appearing thorough:

    INSPECTION SUBJECT        what a reviewer attested to. Digests the AUTHORED
                              contract semantics plus the evidence manifest with
                              provenance ignored.

    RUNTIME AUTHORITY SUBJECT what a consequential grant is bound to. Digests
                              scope id, SCOPE DEFINITION, RUNTIME AUTHORITY
                              CONFIG, governed input and settled contracts.

A scope narrowing or a governance-mode change must move the RUNTIME subject. It
need not move the inspection subject, because a reviewer inspected authored
contract semantics and those did not change. Asserting the wrong one either
fails for the wrong reason or passes for the wrong reason.

    subject_digest = H(scope_id, scope_definition_digest,
                       runtime_authority_config_digest,
                       governed_input_digest, settled_contracts_digest)

Every test below names which subject it is measuring.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from nornyx_forge.governed_subject import (  # noqa: E402
    REPOSITORY_SCOPE,
    GovernedSubjectError,
    RuntimeAuthorityConfig,
    subject_digest,
)

INPUT_DIGEST = "sha256:" + "1" * 64
SETTLED_DIGEST = "sha256:" + "2" * 64


def _runtime_subject(scope=REPOSITORY_SCOPE, config=None) -> str:
    return subject_digest(
        scope=scope,
        config=config or RuntimeAuthorityConfig("nornyx", "sequential"),
        input_digest=INPUT_DIGEST,
        settled_digest=SETTLED_DIGEST,
    )


# --------------------------------------------------------------------------
# 8A -- scope-definition mutation
# --------------------------------------------------------------------------

#: Each entry mutates ONE scope-semantic element. Not the id, not a comment: the
#: fields that decide which artifacts constitute the governed authority surface.
SCOPE_MUTATIONS = [
    (
        "a governed root is added",
        lambda s: replace(s, required_roots=(*s.required_roots, "src/extra_governed")),
    ),
    (
        "a governed root is removed",
        lambda s: replace(s, required_roots=s.required_roots[:-1]),
    ),
    (
        "a required contract is dropped",
        lambda s: replace(s, required_contracts=s.required_contracts[:-1]),
    ),
    (
        "an exclusion is widened",
        lambda s: replace(s, excluded_paths=(*s.excluded_paths, "src/")),
    ),
    (
        "the authority universe is narrowed",
        lambda s: replace(s, authority_universe=s.authority_universe[:-1]),
    ),
    (
        "an authority class stops counting as authority",
        lambda s: replace(s, authority_classes=(".py",)),
    ),
    (
        "content is reclassified as non-authoritative",
        lambda s: replace(s, non_authoritative=(*s.non_authoritative, "src/")),
    ),
]


@pytest.mark.parametrize(
    ("label", "mutate"), SCOPE_MUTATIONS, ids=[case[0] for case in SCOPE_MUTATIONS]
)
def test_a_scope_semantic_change_moves_the_runtime_subject(label: str, mutate):
    """8A. Changing what the governed surface IS must change what authority binds.

    The scope id is deliberately held constant in every case. If identity alone
    carried the meaning, a scope could be narrowed to cover half the repository
    while every grant issued against the old surface still bound -- authority
    over a smaller surface, presented as authority over the original one.
    """
    baseline_definition = REPOSITORY_SCOPE.definition_digest()
    baseline_subject = _runtime_subject()

    mutated = mutate(REPOSITORY_SCOPE)
    assert mutated.scope_id == REPOSITORY_SCOPE.scope_id, (
        "this case changed the scope id, so a moved subject would prove only "
        "that the id is bound -- which is not the property under test"
    )
    assert mutated.canonical_definition() != REPOSITORY_SCOPE.canonical_definition(), (
        f"{label}: the canonical definition did not change, so this mutation "
        "touched nothing semantic"
    )

    assert mutated.definition_digest() != baseline_definition, (
        f"{label}: the scope definition changed but its digest did not"
    )
    assert _runtime_subject(scope=mutated) != baseline_subject, (
        f"{label}: the governed authority surface was redefined and the runtime "
        "subject did not move, so a grant issued against the old surface would "
        "still bind"
    )


def test_the_scope_definition_digest_is_order_independent():
    """A reordering is not a redefinition, and must not read as one.

    Without this the test above would pass for a digest over raw field order,
    which would make every harmless reformat look like a security event and
    train readers to ignore the signal.
    """
    reordered = replace(
        REPOSITORY_SCOPE, required_roots=tuple(reversed(REPOSITORY_SCOPE.required_roots))
    )
    assert reordered.definition_digest() == REPOSITORY_SCOPE.definition_digest()
    assert _runtime_subject(scope=reordered) == _runtime_subject()


# --------------------------------------------------------------------------
# 8B -- runtime authority configuration mutation
# --------------------------------------------------------------------------

AUTHORITY_MUTATIONS = [
    ("policy backend", ("nornyx", "sequential"), ("deterministic_demo", "sequential")),
    ("execution backend", ("nornyx", "sequential"), ("nornyx", "crewai")),
    ("both", ("nornyx", "crewai"), ("deterministic_demo", "sequential")),
]


@pytest.mark.parametrize(
    ("label", "before", "after"),
    AUTHORITY_MUTATIONS,
    ids=[case[0] for case in AUTHORITY_MUTATIONS],
)
def test_an_authority_config_change_moves_the_runtime_subject(label, before, after):
    """8B. The governance mode is authority-bearing even though it is not authored.

    The same packaged bytes under a different governance mode are not the same
    thing to approve: one routes decisions through Nornyx, the other through a
    cooperative fallback. Binding the mode into the subject is what stops an
    approval of the strict deployment from covering the permissive one.
    """
    first, second = RuntimeAuthorityConfig(*before), RuntimeAuthorityConfig(*after)

    assert first.canonical_definition() != second.canonical_definition(), label
    assert first.digest() != second.digest(), (
        f"{label}: the authority configuration changed and its digest did not"
    )
    assert _runtime_subject(config=first) != _runtime_subject(config=second), (
        f"{label}: the governance mode changed and the runtime authority subject "
        "did not, so an approval of one mode would cover the other"
    )


def test_an_unreadable_authority_config_refuses_rather_than_defaulting():
    """A mode that cannot be parsed must not silently become a mode.

    Falling back to a default here would let a typo select the permissive
    backend, and the subject would then attest to a configuration nobody chose.
    """
    with pytest.raises(GovernedSubjectError, match="unknown policy backend"):
        RuntimeAuthorityConfig("NOT_A_BACKEND", "sequential")
    with pytest.raises(GovernedSubjectError, match="unknown execution backend"):
        RuntimeAuthorityConfig("nornyx", "NOT_A_BACKEND")


def test_a_grant_bound_to_the_old_configuration_no_longer_releases(tmp_path: Path):
    """8B, at the effect boundary. The consequence, not the digest.

    A digest that changes proves the binding exists. It does not prove anything
    refuses. So a grant is signed against the subject produced by one governance
    mode and presented to a boundary running under another, and the effect must
    not occur.
    """
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import (  # noqa: PLC0415
        TEST_REVISION,
        _permissive_boundary,
    )

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        canonical_action_request,
    )

    descriptor = ActionDescriptor(
        operation="issue refund",
        resource="customer:omar",
        destination="zone.external_customer",
        parameters={"amount": 100, "currency": "USD"},
    )
    #: The subject a DIFFERENT authority configuration would produce. Everything
    #: else about the grant is correct: signature, domain, role, window.
    stale_revision = _runtime_subject(
        config=RuntimeAuthorityConfig("deterministic_demo", "crewai")
    )
    assert stale_revision != TEST_REVISION

    stale_request = canonical_action_request(
        mission_id="CASE-CONFIG",
        risk="high",
        subject_revision=stale_revision,
        descriptor=descriptor,
        attempt=1,
    )
    boundary = _permissive_boundary(tmp_path, as_of="2026-08-03T00:00:00Z")
    live_request = canonical_action_request(
        mission_id="CASE-CONFIG",
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=descriptor,
        attempt=1,
    )

    calls: list[str] = []
    decision, _detail = boundary.evaluate_and_execute(
        mission_id="CASE-CONFIG",
        risk="high",
        action=lambda: (calls.append("released"), "done")[1],
        action_approval=signed_grant(
            stale_request, approval_id="ACT-CONFIG", role="operations_owner"
        ),
        action_descriptor=descriptor,
        attempt=1,
    )

    assert decision.effect == "DENY", decision.reason
    assert "subject_revision does not match this request" in decision.reason, (
        f"refused, but not on the subject binding: {decision.reason}"
    )
    assert calls == [], "a grant bound to another authority configuration released"
    assert (
        boundary.approval_ledger.lookup(request_digest=live_request.digest) is None
    ), "the grant was consumed by a run that must not start"
    assert (
        boundary.approval_ledger.lookup(request_digest=stale_request.digest) is None
    ), "the stale grant was spent"


def test_the_same_grant_releases_against_its_own_subject(tmp_path: Path):
    """The control. Otherwise the DENY above could be any unrelated refusal."""
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import (  # noqa: PLC0415
        TEST_REVISION,
        _permissive_boundary,
    )

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        canonical_action_request,
    )

    descriptor = ActionDescriptor(
        operation="issue refund",
        resource="customer:omar",
        destination="zone.external_customer",
        parameters={"amount": 100, "currency": "USD"},
    )
    request = canonical_action_request(
        mission_id="CASE-CONFIG",
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=descriptor,
        attempt=1,
    )
    boundary = _permissive_boundary(tmp_path, as_of="2026-08-03T00:00:00Z")

    calls: list[str] = []
    decision, _detail = boundary.evaluate_and_execute(
        mission_id="CASE-CONFIG",
        risk="high",
        action=lambda: (calls.append("released"), "done")[1],
        action_approval=signed_grant(
            request, approval_id="ACT-CONFIG", role="operations_owner"
        ),
        action_descriptor=descriptor,
        attempt=1,
    )

    assert decision.effect == "ALLOW", decision.reason
    assert calls == ["released"]


# --------------------------------------------------------------------------
# 8D -- approval attachment must not redefine what it authorizes
# --------------------------------------------------------------------------


def test_attaching_a_grant_does_not_move_the_subject_it_authorizes(tmp_path: Path):
    """8D. The self-reference that would make every grant instantly stale.

    If presenting a grant moved the subject the grant names, no approval could
    ever be valid: attach it, the subject changes, the grant is stale. The
    inspection subject had exactly that defect once -- a diagnostic embedded the
    current subject in an artifact inside that subject -- so the shape is not
    hypothetical.

    Measured across a real release: the runtime subject the boundary judges
    against is identical before and after a grant is presented and spent.
    """
    from signing import signed_grant  # noqa: PLC0415
    from test_governance_failure import (  # noqa: PLC0415
        TEST_REVISION,
        _permissive_boundary,
    )

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        ActionDescriptor,
        canonical_action_request,
    )

    descriptor = ActionDescriptor(
        operation="issue refund",
        resource="customer:omar",
        destination="zone.external_customer",
        parameters={"amount": 100, "currency": "USD"},
    )
    boundary = _permissive_boundary(tmp_path, as_of="2026-08-03T00:00:00Z")
    before = boundary.runtime_subject.governed_subject_digest

    request = canonical_action_request(
        mission_id="CASE-SELFREF",
        risk="high",
        subject_revision=TEST_REVISION,
        descriptor=descriptor,
        attempt=1,
    )
    calls: list[str] = []
    decision, _detail = boundary.evaluate_and_execute(
        mission_id="CASE-SELFREF",
        risk="high",
        action=lambda: (calls.append("released"), "done")[1],
        action_approval=signed_grant(
            request, approval_id="ACT-SELFREF", role="operations_owner"
        ),
        action_descriptor=descriptor,
        attempt=1,
    )

    assert decision.effect == "ALLOW", decision.reason
    assert calls == ["released"]
    assert boundary.approval_ledger.lookup(request_digest=request.digest) is not None

    after = boundary.runtime_subject.governed_subject_digest
    assert after == before, (
        "presenting and spending a grant moved the subject that grant names, so "
        "no approval could ever remain valid for the thing it authorizes"
    )


def test_spending_a_grant_does_not_move_the_inspection_subject(tmp_path: Path):
    """8D, the other identity. Approval state is not authored governance semantics.

    A reviewer attested to what the contracts SAY. Attaching an approval changes
    the approval state and the assurance outcome -- it must not change what was
    inspected, or every attestation would be invalidated by the act it exists to
    enable.
    """
    import subprocess  # noqa: PLC0415

    def inspection_subject() -> str:
        completed = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0,'scripts');"
                "import refresh_governance_evidence as r;"
                "print(r.current_inspection_subject())",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        return completed.stdout.strip()

    before = inspection_subject()
    test_attaching_a_grant_does_not_move_the_subject_it_authorizes(tmp_path)
    assert inspection_subject() == before, (
        "releasing a consequential effect moved the INSPECTION subject, so an "
        "attestation would be invalidated by ordinary governed operation"
    )
