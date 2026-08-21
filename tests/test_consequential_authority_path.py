"""R6: a consequential act must genuinely REACH approval authority.

Driven on the real caller path -- `NornyxActionBoundary.evaluate_and_execute`,
the entry a consequential boundary actually uses -- rather than by calling
`verify_action_approval` directly. That distinction is the point: the clauses
are joined inside the boundary, and a proof that calls the verifier itself
demonstrates the verifier, not the path.

FOUR PROPERTIES, ONE COMPOSITION. Individually most are covered elsewhere in
this suite. What was not pinned anywhere is that they hold TOGETHER on one
boundary, in sequence, with the EFFECT observed rather than the decision alone:

    no grant        refused, and the effect does not run          fail-closed
    valid grant     released                                      authority reached
    same grant again  refused, and the effect still ran ONCE      single use
    synthetic grant refused, and the effect does not run          no self-approval

THE EFFECT COUNTER IS THE LOAD-BEARING PART. A decision of DENY is not the same
fact as an effect not happening, and this repository has already recorded one
defect where a refusal was returned after the effect had run. Counting
invocations measures what actually happened.

MEASURED WHILE WRITING THIS, and recorded because the correction matters: my
first synthetic grant altered `key_id`, which the verifier never reads -- it
resolves the signer on `signer_key_id`. That probe reported a forged grant
being ALLOWED, and the finding was mine, not the code's. The case below alters
the field the lookup actually uses.
"""

from __future__ import annotations

from pathlib import Path

from signing import signed_grant  # noqa: E402
from test_governance_failure import _permissive_boundary  # noqa: E402

from nornyx_forge.nornyx_runtime import ActionDescriptor, canonical_action_request

NOW = "2026-08-03T00:00:00Z"
DESCRIPTOR = ActionDescriptor(
    operation="issue refund",
    resource="customer:omar",
    destination="zone.external_customer",
    parameters={"amount": 5000, "currency": "USD"},
)


class _Effect:
    """Counts real invocations. `DENY` and "did not run" are different facts."""

    def __init__(self) -> None:
        self.runs = 0

    def __call__(self) -> str:
        self.runs += 1
        return "released"


def _boundary(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    return _permissive_boundary(root, as_of=NOW)


def _request(boundary, attempt: int = 1):
    subject = boundary.runtime_subject
    return canonical_action_request(
        mission_id="CASE-R6", risk="high",
        subject_revision=subject.governed_subject_digest if subject else "",
        descriptor=DESCRIPTOR, attempt=attempt,
    )


def _release(boundary, effect, approval, attempt: int = 1):
    return boundary.evaluate_and_execute(
        mission_id="CASE-R6", risk="high", action=effect,
        action_descriptor=DESCRIPTOR, attempt=attempt, action_approval=approval,
    )[0]


def test_a_consequential_act_without_a_grant_is_refused_and_does_not_run(
    tmp_path: Path,
) -> None:
    """Fail-closed, measured on the effect and not only on the decision."""
    effect = _Effect()
    decision = _release(_boundary(tmp_path), effect, None)
    assert decision.effect == "DENY", decision
    assert decision.code == "HUMAN_APPROVAL_REQUIRED", decision.code
    assert effect.runs == 0, (
        "the boundary refused and the consequential effect ran anyway"
    )


def test_a_valid_grant_actually_reaches_approval_authority(tmp_path: Path) -> None:
    """THE POSITIVE CONTROL, and it carries the whole module.

    Every refusal here is satisfied by a boundary that refuses everything. If
    this fails, the others prove nothing at all -- and a boundary that can never
    release is not fail-closed, it is broken.
    """
    boundary = _boundary(tmp_path)
    effect = _Effect()
    decision = _release(boundary, effect, signed_grant(_request(boundary)))
    assert decision.effect == "ALLOW", decision
    assert effect.runs == 1, "a valid grant did not release the effect"


def test_the_same_grant_presented_twice_releases_exactly_once(
    tmp_path: Path,
) -> None:
    """Single use, through the boundary rather than at the ledger API."""
    boundary = _boundary(tmp_path)
    effect = _Effect()
    grant = signed_grant(_request(boundary))

    first = _release(boundary, effect, grant)
    assert first.effect == "ALLOW" and effect.runs == 1

    second = _release(boundary, effect, grant)
    assert second.effect == "DENY", second
    assert effect.runs == 1, (
        "one human approval released the consequential effect twice through "
        "the real boundary"
    )


def test_a_grant_signed_by_a_key_in_no_store_is_refused(tmp_path: Path) -> None:
    """No synthetic authority: a well-formed grant is not a trusted one.

    `signer_key_id` is the field the verifier resolves against the trust store.
    Naming a key that is in no store must refuse -- otherwise anyone able to
    produce a correctly shaped artifact could release a consequential effect,
    which is self-approval with extra steps.
    """
    boundary = _boundary(tmp_path)
    effect = _Effect()
    forged = dict(signed_grant(_request(boundary)))
    forged["signer_key_id"] = "not-in-any-store"

    decision = _release(boundary, effect, forged)
    assert decision.effect == "DENY", decision
    assert decision.code == "APPROVAL_NOT_AUTHENTICATED", decision.code
    assert effect.runs == 0, "a grant from an untrusted signer released an effect"


def test_altering_a_field_the_verifier_never_reads_does_not_grant_authority(
    tmp_path: Path,
) -> None:
    """The control for the case above, and for my own mistake.

    `key_id` is carried on the artifact and is NOT what the signer is resolved
    by. A probe that alters it produces a grant which is still valid -- and
    reading that as "a forged grant was allowed" would be a finding about the
    probe. Pinned so the distinction between the two fields stays visible.
    """
    boundary = _boundary(tmp_path)
    effect = _Effect()
    still_valid = dict(signed_grant(_request(boundary)))
    still_valid["key_id"] = "not-in-any-store"

    decision = _release(boundary, effect, still_valid)
    assert decision.effect == "ALLOW", (
        "altering `key_id` changed the verdict, so it IS consulted somewhere -- "
        "in which case the synthetic-grant case above is testing the wrong field"
    )
    assert effect.runs == 1
