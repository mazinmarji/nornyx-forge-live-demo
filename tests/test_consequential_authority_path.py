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

import ast
import sqlite3
from contextlib import closing
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
    # THE CLASS AND THE MODULE-LEVEL HELPERS THAT BUILD ITS REFUSALS.
    #
    # Scoped to `ApprovalLedger` alone, this reported LEDGER_BUSY as "carried
    # but never emitted" -- because contention's refusal is built by
    # `_busy_refusal`, a module-level helper shared by the ledger path and the
    # witness path. A derivation that cannot see where a refusal is built
    # reports the boundary as having drifted when it has not.
    ledger_class = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ApprovalLedger"
    )
    helpers = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.endswith("_refusal")
    ]
    ledger = ast.Module(body=[ledger_class, *helpers], type_ignores=[])

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


def test_a_tampered_ledger_reaches_the_decision_as_a_ledger_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """The DECISION, not the source. This is what an operator actually reads.

    The structural check runs once when the ledger is opened and again inside
    the transaction that consumes the grant, because the runtime directory is
    bind-mounted read-write and gitignored -- an object can be installed on
    `consumed_approvals` between the two. Occupying that window is the whole
    specimen.

    Measured before the repair:

        effect      DENY          it fails safe, which is why this was P2
        callbacks   0             the act genuinely did not run
        code        HUMAN_APPROVAL_REQUIRED
        reason      "... is unusable: APPROVAL_LEDGER_UNREADABLE, ..."

    The correct code was IN the reason and the classifier read position 0 only.
    `HUMAN_APPROVAL_REQUIRED` tells an operator to go and obtain an approval.
    They will obtain one, present it, and be refused again, because no approval
    can fix a ledger carrying a hostile object.

    THE REPAIR IS TWO INDEPENDENT HALVES AND THE CONTROL SAYS SO. Measured by
    reverting each:

        the return site loses its code          still green
        the classifier goes back to startswith  still green
        BOTH reverted together                  RED, HUMAN_APPROVAL_REQUIRED

    So this is defence in depth, and either half alone closes the defect. That
    is worth stating precisely rather than claiming the test catches either
    regression on its own, which it demonstrably does not. The structural
    check beside it is what notices a return site losing its code; this one is
    what notices the decision carrying the wrong one.
    """
    import nornyx_forge.nornyx_runtime as runtime  # noqa: PLC0415

    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    boundary = _permissive_boundary(root, as_of=NOW)
    grant = signed_grant(_request(boundary))
    effect = _Effect()

    real = runtime._assert_ledger_structure
    calls = {"n": 0}

    def tampered(conn, path, code):
        calls["n"] += 1
        if calls["n"] == 1:
            return real(conn, path, code)
        raise runtime.NornyxRuntimeUnavailable(
            f"action approval ledger at {path} is unusable: {code}, "
            "an unexpected object is defined on it"
        )

    monkeypatch.setattr(runtime, "_assert_ledger_structure", tampered)
    decision = _release(boundary, effect, grant)

    assert decision.effect == "DENY", decision
    assert effect.runs == 0, "the effect ran against a ledger that cannot be read"
    assert decision.code != "HUMAN_APPROVAL_REQUIRED", (
        "a ledger carrying a hostile object was reported as a missing human "
        "approval. The operator will obtain one, present it, and be refused "
        "again: " + str(decision.code) + " / " + str(decision.reason)[:200]
    )
    assert decision.code == runtime.ApprovalLedger.UNREADABLE, (
        "the decision names " + str(decision.code) + "; the ledger raised "
        + runtime.ApprovalLedger.UNREADABLE
    )


def _ledger_code_at(text: str) -> bool:
    """Does this literal begin with one of the ledger's decision codes?"""
    from nornyx_forge.nornyx_runtime import LEDGER_DECISION_CODES  # noqa: PLC0415

    return any(text.startswith(code) for code in LEDGER_DECISION_CODES)


def _raises_lead_with_a_code(caught, module) -> bool:
    """Every `raise <Type>(...)` of the caught type leads with a code."""
    types = set()
    for element in (caught.elts if isinstance(caught, ast.Tuple) else [caught]):
        if isinstance(element, ast.Name):
            types.add(element.id)
    raised = [
        node for node in ast.walk(module)
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name) and node.exc.func.id in types
    ]
    def leads(expression) -> bool:
        # A raise may build its message by concatenation -- the migration
        # refusal appends a measured list of journal modes -- so unwrap the
        # left spine before asking where the code is.
        while isinstance(expression, ast.BinOp):
            expression = expression.left
        return (
            isinstance(expression, ast.JoinedStr)
            and bool(expression.values)
            and isinstance(expression.values[0], ast.FormattedValue)
        ) or (
            isinstance(expression, ast.Constant)
            and _ledger_code_at(str(expression.value))
        )

    return bool(raised) and all(
        node.exc.args and leads(node.exc.args[0]) for node in raised
    )


def _leads_with_a_code(expression, module, cls, handlers) -> bool:
    """Can this refusal message be seen to lead with a decision code?

    Resolves one level of indirection, because the ledger legitimately routes
    some refusals through a helper, an attribute, or an exception:

        f"{CODE}: ..."                  yes, directly
        self.unavailable_reason         resolve the attribute's assignments
        self._continuity_mismatch(...)  resolve the method's returns
        str(exc)                        resolve that exception's raise sites
        _ledger_code_in(...)            it reads the code out of the message

    Anything it cannot resolve is NOT credited. Over-strictness here costs a
    comment at a call site; under-strictness costs an operator being told to
    obtain an approval for a ledger that no approval can fix.
    """
    if isinstance(expression, ast.JoinedStr) and expression.values:
        head = expression.values[0]
        if isinstance(head, ast.FormattedValue):
            return True
        if isinstance(head, ast.Constant) and _ledger_code_at(str(head.value)):
            return True
        return False
    if isinstance(expression, ast.BinOp):
        return _leads_with_a_code(expression.left, module, cls, handlers)
    if isinstance(expression, ast.Constant):
        return _ledger_code_at(str(expression.value))
    if isinstance(expression, ast.Attribute):
        assignments = [
            node for node in ast.walk(cls)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Attribute)
                    and target.attr == expression.attr
                    for target in node.targets)
        ]
        return bool(assignments) and all(
            _leads_with_a_code(node.value, module, cls, handlers)
            for node in assignments
        )
    if isinstance(expression, ast.Call):
        func = expression.func
        if isinstance(func, ast.Name) and func.id in {"_ledger_code_in", "_with_code"}:
            return True
        if isinstance(func, ast.Name):
            # A MODULE-LEVEL HELPER, resolved the same way a method is. The
            # resolver handled `self._x(...)` and not `_x(...)`, so moving a
            # refusal into a shared helper -- which is what stopped contention
            # being diagnosed as damage -- read as a refusal with no code.
            helper = next(
                (node for node in ast.walk(module)
                 if isinstance(node, ast.FunctionDef) and node.name == func.id),
                None,
            )
            if helper is not None:
                returns = [
                    node.value for node in ast.walk(helper)
                    if isinstance(node, ast.Return) and node.value is not None
                ]
                return bool(returns) and all(
                    _leads_with_a_code(value, module, cls, handlers)
                    for value in returns
                )
        if isinstance(func, ast.Name) and func.id == "str" and expression.args:
            # THE ENCLOSING HANDLER, not a name -> type map. Nearly every
            # handler in this class binds `exc`, so a map keyed on the bound
            # name silently resolves to whichever handler `ast.walk` reached
            # last -- a resolver that answers confidently about the wrong
            # exception is worse than one that declines.
            caught = handlers.get(id(expression))
            return caught is not None and _raises_lead_with_a_code(caught, module)
        if isinstance(func, ast.Attribute):
            method = next(
                (node for node in ast.walk(cls)
                 if isinstance(node, ast.FunctionDef) and node.name == func.attr),
                None,
            )
            if method is not None:
                returns = [
                    node.value for node in ast.walk(method)
                    if isinstance(node, ast.Return) and node.value is not None
                ]
                return bool(returns) and all(
                    _leads_with_a_code(value, module, cls, handlers)
                    for value in returns
                )
    return False


def test_no_ledger_refusal_reaches_the_decision_without_its_code():
    """A completeness check that cannot report a MISSING code is not one.

    Its sibling, test_every_code_the_ledger_emits_survives_to_the_decision,
    derives its set by AST-matching reason heads of the form `f"{CODE}: ..."`,
    so it can only ever find codes that ALREADY EXIST. It is structurally
    incapable of reporting a refusal that carries no code at all. This
    repository wrote that sentence down -- "A completeness check that cannot
    report a MISSING code is not one" -- and then left one such site standing.

    MEASURED AT THAT SITE, by occupying the window between the structural
    re-read and the in-transaction re-check:

        effect DENY, callbacks 0        it fails safe
        code   HUMAN_APPROVAL_REQUIRED  and tells the wrong story
        reason "... is unusable: APPROVAL_LEDGER_UNREADABLE, ..."

    The correct code was IN the message and the classifier matched position 0
    only. An operator reading HUMAN_APPROVAL_REQUIRED obtains a fresh approval,
    presents it, and is refused again, because the ledger is carrying a hostile
    object that no approval can fix.

    So this walks every refusal `return False, <message>` in `ApprovalLedger`
    and requires the message to be traceable to a code, which is the question
    the other test cannot ask.
    """
    import nornyx_forge.nornyx_runtime as runtime  # noqa: PLC0415

    module = ast.parse(Path(runtime.__file__).read_text(encoding="utf-8"))
    cls = next(node for node in ast.walk(module)
               if isinstance(node, ast.ClassDef) and node.name == "ApprovalLedger")
    # Every expression inside an `except` block, mapped to THAT block's type.
    handlers = {}
    for node in ast.walk(cls):
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            for statement in node.body:
                for inner in ast.walk(statement):
                    handlers[id(inner)] = node.type
    codeless = []
    for node in ast.walk(cls):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Tuple):
            continue
        parts = node.value.elts
        if len(parts) != 2:
            continue
        first = parts[0]
        if not (isinstance(first, ast.Constant) and first.value is False):
            continue
        if not _leads_with_a_code(parts[1], module, cls, handlers):
            codeless.append("nornyx_runtime.py:" + str(node.lineno))
    assert codeless == [], (
        "these ledger refusals reach the decision with no code the classifier "
        "can read, so they arrive as HUMAN_APPROVAL_REQUIRED, indistinguishable "
        "from a grant nobody ever approved. An operator will obtain an "
        "approval, present it, and be refused again: " + repr(codeless)
    )


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
    """THE PRODUCTION PREDICATE, not a copy of it.

    This was a reimplementation reading `body["observations"]` -- a key the
    real recorder never emits -- so the test agreed with the production
    function only by coincidence, and kept agreeing after production was fixed
    to read `counts_by_type`. A test that reimplements the rule it is checking
    measures the reimplementation.

    `_reports_a_release` is the function `_emit_evidence` actually consults
    before it decides whether truncating an artifact is safe, so asking it is
    the only way this test is about the shipped decision.
    """
    from nornyx_forge.nornyx_runtime import _reports_a_release  # noqa: PLC0415

    return _reports_a_release(path)


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


def _production_validate_keys() -> set:
    """Every key the REAL `validate_runtime_events` can put in a report.

    Extracted from the installed package by AST rather than by calling it,
    because calling it needs an authorizer this checkout cannot load.
    """
    import ast as _ast  # noqa: PLC0415
    import inspect  # noqa: PLC0415

    from nornyx.agentic import validate_runtime_events  # noqa: PLC0415

    tree = _ast.parse(inspect.getsource(validate_runtime_events))
    keys: set = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Dict):
            keys |= {
                key.value for key in node.keys
                if isinstance(key, _ast.Constant) and isinstance(key.value, str)
            }
    return keys


#: Keys `_emit_evidence` merges into the report itself, on top of `validate()`.
FORGE_ADDED_KEYS = frozenset({
    "nornyx_decision", "action_approval_present", "action_binding",
    "approval_authentication", "effect_release",
})


def test_the_evidence_double_produces_the_shape_production_produces():
    """A double that drifts from its contract turns every test into a test of
    the double.

    MEASURED: `_Recorder.validate()` returned `{"status", "observations"}`.
    `observations` appears NOWHERE in the installed `nornyx.agentic` -- the
    real `validate_runtime_events` returns `counts_by_type`, `tools_executed`,
    `event_count` and sixteen others. `_Recorder` is the only recorder any test
    installs, so:

      * `_reports_a_release` read `observations` and `events`, neither of which
        production emits, and its "returns" case was green against a shape that
        cannot occur;
      * on the real path a retry of the same attempt TRUNCATED the report
        recording that a consequential effect had run, leaving one artifact
        saying the act was withheld. It ran.

    So the double's keys must be producible by production. This does not
    require the double to be complete -- a double may emit a subset -- only
    that every key it emits is one production could emit, plus the keys the
    Forge merges in itself.
    """
    from test_governance_failure import _Recorder  # noqa: PLC0415

    double = _Recorder()
    double.record_observation("tool_invoked")
    produced = set(double.validate())
    allowed = _production_validate_keys() | FORGE_ADDED_KEYS
    invented = sorted(produced - allowed)
    assert invented == [], (
        "the evidence double emits keys the production recorder never does, so "
        "every assertion reading them is about the double: " + repr(invented)
    )


def test_the_release_detector_reads_only_keys_production_can_emit():
    """The consumer side of the same contract.

    `_reports_a_release` decides whether `_emit_evidence` may TRUNCATE an
    artifact. Reading a key production never emits means the answer is "no
    release recorded" on every real report, and the record of a released
    effect is destroyed by the next retry.

    Read from the source rather than by exercising it, so a key that is only
    consulted on an unusual branch is still caught.
    """
    import ast as _ast  # noqa: PLC0415
    import inspect  # noqa: PLC0415

    from nornyx_forge import nornyx_runtime  # noqa: PLC0415

    tree = _ast.parse(inspect.getsource(nornyx_runtime._reports_a_release))
    consulted: set = set()
    for node in _ast.walk(tree):
        if (isinstance(node, _ast.Call)
                and isinstance(node.func, _ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], _ast.Constant)
                and isinstance(node.args[0].value, str)):
            consulted.add(node.args[0].value)
    assert consulted, "the detector consults no key at all, so it decides nothing"
    allowed = _production_validate_keys() | FORGE_ADDED_KEYS
    invented = sorted(consulted - allowed)
    assert invented == [], (
        "the release detector consults keys production never emits, so a real "
        "report never looks like a release and the next retry truncates it: "
        + repr(invented)
    )


#: (label, the code the decision carries, may a pending request be written?)
#:
#: A pending artifact says "Sign this exact request_digest with
#: scripts/issue_action_approval.py", and its note adds "Approving a different
#: attempt releases nothing" -- which asserts that approving THIS one does. For
#: six of these that assertion is false: `_commit_consumption` refuses them
#: before the insert and independently of the grant, so no signature clears
#: them.
#:
#: Worse for LEDGER_ROLLED_BACK: the real remedy mints a LATER epoch, so an
#: approval signed in response to the artifact is then refused a second time as
#: GRANT_PREDATES_LEDGER. The artifact named neither the remedy nor the order.
PENDING_REQUEST_CASES = [
    ("nobody has approved", "HUMAN_APPROVAL_REQUIRED", True),
    ("the grant predates the epoch", "GRANT_PREDATES_LEDGER", True),
    ("already consumed", "APPROVAL_ALREADY_CONSUMED", False),
    ("already released", "ACTION_ALREADY_RELEASED", False),
    ("history was rolled back", "LEDGER_ROLLED_BACK", False),
    ("continuity unknown", "LEDGER_CONTINUITY_UNKNOWN", False),
    ("continuity migration required", "LEDGER_CONTINUITY_MIGRATION_REQUIRED", False),
    ("the ledger is missing", "APPROVAL_LEDGER_MISSING", False),
    ("the ledger is unreadable", "APPROVAL_LEDGER_UNREADABLE", False),
    ("the ledger is unwritable", "APPROVAL_LEDGER_UNWRITABLE", False),
]


@pytest.mark.parametrize(
    ("label", "code", "may_write"), PENDING_REQUEST_CASES,
    ids=[case[0] for case in PENDING_REQUEST_CASES],
)
def test_a_pending_request_is_written_only_when_an_approval_would_clear_it(
    label: str, code: str, may_write: bool,
):
    """Six refusals invited a human approval ceremony that cannot work.

    The predecessor was a two-code blocklist -- the two cases someone had
    noticed -- so every ledger fault wrote "Sign this exact request_digest".
    A declared POSITIVE set means a code added later defaults to "an approval
    cannot clear this", which is the safe direction: the cost of being wrong
    is a missing convenience artifact, not a wasted approval ceremony.

    Asserted against the production tuple rather than by driving ten ledger
    faults, because what decides the artifact IS this membership test -- the
    boundary reads `withheld_code in APPROVAL_CLEARABLE_CODES`. The end-to-end
    case below drives the real boundary for the one that matters most.
    """
    from nornyx_forge.nornyx_runtime import APPROVAL_CLEARABLE_CODES  # noqa: PLC0415

    assert (code in APPROVAL_CLEARABLE_CODES) is may_write, (
        label + ": a pending request "
        + ("is not written when an approval WOULD release the act"
           if may_write else
           "tells an operator to sign a digest this refusal will never accept")
    )


def test_a_rolled_back_ledger_does_not_invite_a_signing_ceremony(tmp_path: Path):
    """The end-to-end case, through the real boundary.

    Measured before the repair: release one grant, restore the ledger from a
    backup, then present a FRESH, never-presented, valid grant for attempt 2.

        attempt 2 : DENY LEDGER_ROLLED_BACK, effect ran 0 times
        pending   : REQ-...attempt-2.request.json written
                    note: "Sign this exact request_digest ..."

    The operator signs it. The remedy for a rolled-back ledger mints a later
    epoch, so that approval is then refused again as GRANT_PREDATES_LEDGER.
    Two ceremonies, no release, and the artifact named neither the remedy nor
    the ordering.
    """
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    boundary = _permissive_boundary(root, as_of=NOW)
    pending = root / "evidence/runtime/pending"

    first = _release(boundary, _Effect(), signed_grant(_request(boundary)))
    assert first.effect == "ALLOW", first

    ledger = root / "evidence/runtime/action_approvals.sqlite3"
    with closing(sqlite3.connect(ledger)) as conn:
        conn.execute("DELETE FROM consumed_approvals")
        conn.commit()

    before = sorted(path.name for path in pending.glob("*")) if pending.is_dir() else []
    effect = _Effect()
    # THE GRANT AND THE RELEASE MUST NAME THE SAME ATTEMPT, or the boundary
    # refuses on the binding first and never reaches the ledger -- which is
    # a correct refusal measuring the wrong thing.
    decision = _release(boundary, effect,
                        signed_grant(_request(boundary, attempt=2)),
                        attempt=2)
    after = sorted(path.name for path in pending.glob("*")) if pending.is_dir() else []

    assert decision.effect == "DENY", decision
    assert effect.runs == 0, "a rolled-back ledger released an effect"
    assert decision.code == "LEDGER_ROLLED_BACK", decision.code
    assert after == before, (
        "a rolled-back ledger wrote a pending request. An operator following "
        "it spends a human approval ceremony on a digest the ledger refuses "
        f"before it ever reads the grant: {sorted(set(after) - set(before))}"
    )
