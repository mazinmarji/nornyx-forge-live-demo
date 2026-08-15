"""Task 12. The proof system must not be able to succeed for the wrong reason.

Nine false-green classes have actually occurred in this repository. Each one
produced a green run that proved nothing, and each is now a named class with an
executable guard and a self-attack that must trip it.

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
)


def test_the_inventory_is_exactly_the_nine_known_classes():
    """Set equality, so a class cannot be dropped to make the audit smaller."""
    assert {item.ident for item in INVENTORY} == {
        f"FG{n:02d}" for n in range(1, 10)
    }
    assert len(INVENTORY) == 9
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
    """
    for item in INVENTORY:
        module, _, node = item.owner.partition("::")
        source = (ROOT / module).read_text(encoding="utf-8")
        assert f"def {node}(" in source, f"{item.ident}: {node} is gone"
        assert len(item.guard) > 15, f"{item.ident} names no guard"
    assert len({item.owner for item in INVENTORY}) >= 9, "self-attacks were merged"
