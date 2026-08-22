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

import pytest
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


def _ledger_codes_in_source() -> set:
    """Every code the ledger puts at the head of a refusal, read from the AST.

    A reason in this class is built as `f"{CODE}: ..."`. Collecting the name in
    that leading slot is what makes the set DERIVED rather than a second list
    to keep in step with the first -- and the first list is exactly what went
    stale, carrying five of eight codes.

    `ast.IfExp` is handled because one site chooses between two codes inline:
    `f"{self.UNWRITABLE if readonly else self.UNREADABLE}: ..."`.
    """
    import ast  # noqa: PLC0415

    from nornyx_forge import nornyx_runtime  # noqa: PLC0415

    source = Path(nornyx_runtime.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    ledger = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ApprovalLedger"
    )

    def named(expr):
        if isinstance(expr, ast.IfExp):
            return [n for part in (expr.body, expr.orelse) for n in named(part)]
        name = getattr(expr, "attr", getattr(expr, "id", None))
        return [name] if name else []

    found = set()
    for node in ast.walk(ledger):
        if not (isinstance(node, ast.JoinedStr) and node.values):
            continue
        head, rest = node.values[0], node.values[1:]
        if not isinstance(head, ast.FormattedValue):
            continue
        if not (rest and isinstance(rest[0], ast.Constant)
                and str(rest[0].value).startswith(":")):
            continue
        for name in named(head.value):
            value = getattr(nornyx_runtime.ApprovalLedger, name, None)
            if value is None:
                value = getattr(nornyx_runtime, name, None)
            if isinstance(value, str):
                found.add(value)
    return found


def test_every_code_the_ledger_emits_survives_to_the_decision():
    """A9-P2-4. The boundary's list was five of eight, and nothing said so.

    The three it omitted -- `APPROVAL_LEDGER_MISSING`, `_UNREADABLE`,
    `_UNWRITABLE` -- are the ledger's own codes for a store that is absent,
    corrupt or unwritable, and the class comment beside them says they are
    distinct "because the operator response differs". The boundary flattened
    all three into HUMAN_APPROVAL_REQUIRED, which tells an operator to obtain
    an approval when the correct action is to investigate a tampered replay
    store -- and no approval they obtain can fix a read-only ledger.

    Compared in BOTH directions, so this fails whether a code is added to the
    ledger and not to the tuple, or removed and left behind.
    """
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        LEDGER_DECISION_CODES,
    )

    emitted = _ledger_codes_in_source()
    carried = set(LEDGER_DECISION_CODES)
    assert emitted, "no ledger reason codes were found at all; the parse failed"
    assert emitted - carried == set(), (
        "the ledger emits these codes and the boundary does not carry them, "
        "so each arrives at the decision as HUMAN_APPROVAL_REQUIRED: "
        f"{sorted(emitted - carried)}"
    )
    assert carried - emitted == set(), (
        "the boundary carries codes the ledger never emits, so the tuple has "
        f"drifted from the source it is meant to mirror: {sorted(carried - emitted)}"
    )


@pytest.mark.parametrize(
    ("label", "sabotage", "expected"),
    [
        ("deleted", "delete", "APPROVAL_LEDGER_UNREADABLE"),
        ("frozen by a trigger", "freeze", "APPROVAL_LEDGER_UNREADABLE"),
        ("read-only", "readonly", "APPROVAL_LEDGER_UNWRITABLE"),
    ],
)
def test_a_damaged_ledger_is_not_reported_as_a_missing_approval(
    label: str, sabotage: str, expected: str, tmp_path: Path,
) -> None:
    """A9-P2-4, on the real boundary with a VALID grant.

    Each of these was `HUMAN_APPROVAL_REQUIRED` before the boundary carried
    the ledger's own codes. The grant is valid every time -- the refusal is
    about the STORE, and the code has to say so.
    """
    import os  # noqa: PLC0415
    import sqlite3  # noqa: PLC0415
    import stat  # noqa: PLC0415
    from contextlib import closing  # noqa: PLC0415

    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        approval_ledger_path,
    )

    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    boundary = _permissive_boundary(root, as_of=NOW)
    grant = signed_grant(_request(boundary))
    path = approval_ledger_path(root)

    if sabotage == "delete":
        for suffix in ("", "-wal", "-shm"):
            sibling = path.with_name(path.name + suffix)
            if sibling.exists():
                sibling.unlink()
    elif sabotage == "freeze":
        with closing(sqlite3.connect(path)) as conn:
            conn.execute(
                "CREATE TRIGGER freeze BEFORE INSERT ON consumed_approvals"
                " BEGIN SELECT RAISE(IGNORE); END"
            )
            conn.commit()
    else:
        os.chmod(path, stat.S_IREAD)

    effect = _Effect()
    try:
        decision = _release(boundary, effect, grant)
    finally:
        if sabotage == "readonly" and path.exists():
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)

    assert decision.effect == "DENY", decision
    assert effect.runs == 0, "a damaged ledger released a consequential effect"
    assert decision.code == expected, (
        f"a {label} ledger reported {decision.code!r}. A damaged replay store "
        "is not 'nobody approved': an operator told to obtain an approval will "
        f"obtain one and be refused again. reason: {decision.reason[:200]}"
    )
