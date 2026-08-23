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


class _Raising:
    """An effect that is released and then fails, outcome unknown."""

    runs = 0

    def __call__(self) -> str:
        type(self).runs += 1
        raise RuntimeError("payment gateway timed out after debit")


def _reports(root: Path) -> list:
    return sorted((root / "evidence/runtime/nornyx").glob("*.report.json"))


def _records_a_release(path: Path) -> bool:
    import json  # noqa: PLC0415

    body = json.loads(path.read_text(encoding="utf-8"))
    if body.get("effect_release"):
        return True
    return "tool_invoked" in (body.get("observations") or [])


@pytest.mark.parametrize("effect_type", ["raises", "returns"])
def test_a_retry_never_destroys_the_record_that_the_effect_ran(
    effect_type: str, tmp_path: Path,
) -> None:
    """Lens A P1-1. The surviving record said the act was WITHHELD. It ran.

    `_emit_evidence` keys both artifacts on (mission, attempt) and `write_json`
    truncates. The A11 repair moved the collision from missions down to
    attempts and left the sharpest case: re-evaluating THE SAME attempt. That
    is not an adversary -- it is a client retrying after a transport failure,
    with the stable mission id the retry model presumes.

    Measured before the repair, with the effect raising after the grant was
    spent: the report carrying `effect_release {released true, completed
    false, outcome unknown}` -- the one artifact an operator needs most,
    because whether the payment happened is unknown -- was REPLACED on the
    retry by a record saying human approval is required. Surviving artifacts
    mentioning the release: none.

    Both release shapes are pinned, because they leave different traces:
    `effect_release` when the effect raised, a `tool_invoked` observation when
    it returned.
    """
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    boundary = _permissive_boundary(root, as_of=NOW)
    grant = signed_grant(_request(boundary))
    effect = _Raising() if effect_type == "raises" else _Effect()

    try:
        _release(boundary, effect, grant)
    except RuntimeError:
        pass  # the raising case; the grant is spent either way

    released = [path for path in _reports(root) if _records_a_release(path)]
    assert len(released) == 1, (
        f"the first evaluation left no record of the release: {_reports(root)}"
    )

    # The client retries the SAME mission and the SAME attempt.
    second = _release(boundary, _Effect(), grant)
    assert second.effect == "DENY", second

    survived = [path for path in _reports(root) if _records_a_release(path)]
    assert len(survived) == 1, (
        "the retry DESTROYED the record that a consequential effect was "
        "released. What survives now says the act was withheld and human "
        f"approval is required, and the act ran: {_reports(root)}"
    )
    assert len(_reports(root)) == 2, (
        "the refusal did not get a record of its own beside the release: "
        f"{_reports(root)}"
    )


def test_a_replayed_grant_reaches_the_decision_with_its_own_code(
    tmp_path: Path,
) -> None:
    """Lens A P2-1. The ledger's central refusal had no code at all.

    Both replay refusals were plain prose, so `withheld_code` kept its
    `HUMAN_APPROVAL_REQUIRED` default and a REPLAYED grant arrived
    indistinguishable from one that was never approved -- the exact collapse
    `LEDGER_DECISION_CODES` was introduced to repair, still live for the case
    the ledger exists to detect.

    The derivation test could not see it either: it AST-matches `f"{CODE}: ..."`
    reasons, so it only ever finds codes that ALREADY EXIST. A completeness
    check that cannot report a missing code is not one, which is why this
    measures the decision rather than the code set.
    """
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    boundary = _permissive_boundary(root, as_of=NOW)
    grant = signed_grant(_request(boundary))
    effect = _Effect()

    first = _release(boundary, effect, grant)
    assert first.effect == "ALLOW", first
    assert effect.runs == 1

    replay = _release(boundary, effect, grant)
    assert replay.effect == "DENY", replay
    assert replay.code == "APPROVAL_ALREADY_CONSUMED", (
        "a replayed grant still reports the code that means nobody approved. "
        "An operator told to obtain an approval will obtain one, present it, "
        f"and be refused again: {replay.code} / {replay.reason[:160]}"
    )
    assert effect.runs == 1, "the replay released the effect a second time"

    # The same act under a DIFFERENT, valid grant.
    second_grant = signed_grant(_request(boundary), approval_id="ACT-SECOND")
    again = _release(boundary, effect, second_grant)
    assert again.effect == "DENY", again
    assert again.code == "ACTION_ALREADY_RELEASED", again.code
    assert effect.runs == 1


def test_no_pending_request_is_written_for_a_digest_that_cannot_be_consumed(
    tmp_path: Path,
) -> None:
    """Lens A P2-4. The artifact asked for an approval that cannot work.

    `UNIQUE(request_digest)` means a digest already consumed can never be
    consumed again by any grant. The pending artifact was emitted whenever an
    act was withheld and a request existed, including after a release -- and
    its note reads "Approving a different attempt releases nothing", which
    asserts that approving THIS one does.

    Measured: signing that exact digest with a new valid grant gave DENY,
    "this action was already released ... a further approval cannot release it
    again". A real human approval ceremony spent on a request that cannot work.

    The positive control is first: when no approval exists, the artifact is
    exactly what an approver needs and must still be written.
    """
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    boundary = _permissive_boundary(root, as_of=NOW)
    pending = root / "evidence/runtime/pending"

    # POSITIVE CONTROL: no grant at all -- an approval genuinely would release.
    refused = _release(boundary, _Effect(), None)
    assert refused.effect == "DENY", refused
    assert pending.is_dir() and list(pending.glob("*")), (
        "no pending request was written for an act that a human approval "
        "could still release, which is what the artifact is for"
    )
    # CONTENT, NOT FILENAMES. The artifact is keyed on the attempt, so a
    # replay OVERWRITES it and the file list is unchanged either way -- the
    # first version of this test compared names and stayed green with the
    # repair removed, which is a control that cannot fail.
    before = {
        path.name: path.read_bytes() for path in pending.glob("*")
    }

    grant = signed_grant(_request(boundary))
    effect = _Effect()
    assert _release(boundary, effect, grant).effect == "ALLOW"
    _release(boundary, effect, grant)

    after = {path.name: path.read_bytes() for path in pending.glob("*")}
    changed = sorted(
        name for name in set(before) | set(after)
        if before.get(name) != after.get(name)
    )
    assert changed == [], (
        "a pending request was written or rewritten for a digest "
        "UNIQUE(request_digest) can never accept again, telling an operator "
        "to spend a human approval ceremony that cannot work: " + str(changed)
    )
