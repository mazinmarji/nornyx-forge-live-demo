"""Where governed authority comes from, and what it refuses.

Three review findings converge here, because they were one mistake wearing three
hats: authority was taken from whatever the caller or the environment said.

* replay was keyed on ``approval_id``, a label the presenter chooses;
* the evaluation instant came from ``FORGE_RUNTIME_AS_OF``;
* the governed revision came from ``FORGE_RUNTIME_REVISION``.

Every test here sets the two retired variables to hostile values and proves they
are inert. They are never `monkeypatch`ed away — the point is that they can be
present and still do nothing.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from nornyx_forge.nornyx_runtime import (
    GOVERNED_REVISION_MISMATCH,
    GOVERNED_REVISION_UNVERIFIED,
    ActionDescriptor,
    ApprovalLedger,
    RuntimeContext,
    actual_revision,
    canonical_action_request,
    runtime_as_of,
    runtime_revision,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from signing import signed_grant  # noqa: E402
from test_governance_failure import _permissive_boundary  # noqa: E402

#: The retired overrides. Set hostile in every test, expected to do nothing.
RETIRED_TIME_ENV = "FORGE_RUNTIME_AS_OF"
RETIRED_REVISION_ENV = "FORGE_RUNTIME_REVISION"
HOSTILE_TIME = "2026-08-03T00:00:00Z"
REVISION_A = "git:" + "a" * 40

DESCRIPTOR = ActionDescriptor(
    operation="issue refund",
    resource="customer:omar",
    destination="zone.external_customer",
    parameters={"amount": 5000, "currency": "USD"},
)


@pytest.fixture(autouse=True)
def hostile_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both retired variables, set to values that would once have worked."""
    monkeypatch.setenv(RETIRED_TIME_ENV, HOSTILE_TIME)
    monkeypatch.setenv(RETIRED_REVISION_ENV, REVISION_A)


def _git_repo(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    (work / ".nornyx/contracts").mkdir(parents=True)
    for command in (
        ["init", "-q"],
        ["config", "user.email", "fixture@example.invalid"],
        ["config", "user.name", "fixture"],
    ):
        subprocess.run(["git", "-C", str(work), *command], capture_output=True, check=True)
    (work / "source.txt").write_text("governed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(work), "add", "-A"], capture_output=True, check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "-qm", "one"], capture_output=True, check=True
    )
    return work


def _declare(work: Path, revision: str) -> None:
    (work / ".nornyx/contracts/runtime_network.nyx").write_text(
        f"governance_evidence:\n  subject_revision: {revision}\n", encoding="utf-8"
    )


def _request(revision: str, *, attempt: int = 1, mission: str = "CASE-1"):
    return canonical_action_request(
        mission_id=mission,
        risk="high",
        subject_revision=revision,
        descriptor=DESCRIPTOR,
        attempt=attempt,
    )


def _grant(
    request,
    *,
    approval_id: str = "ACT-1",
    generated: str = "2026-08-02T00:00:00Z",
    expires: str = "2026-08-05T00:00:00Z",
) -> dict[str, object]:
    """A correctly signed grant for exactly this request.

    Signed through the shared fixture rather than hand-built: these tests are
    about replay identity and trusted clocks, so the signature must be genuinely
    valid or they would all be measuring the authentication refusal instead.
    """
    return signed_grant(
        request, approval_id=approval_id, generated_at=generated, expires_at=expires
    )


def _release(work: Path, context: RuntimeContext, grant, request=None, *, attempt: int = 1):
    """Drive one consequential release. Returns (decision, callback count, rows)."""
    ledger_path = work / "ledger.sqlite3"
    boundary = _permissive_boundary(work, runtime_context=context)
    boundary.approval_ledger = ApprovalLedger(ledger_path)
    ran: list[int] = []
    decision, _ = boundary.evaluate_and_execute(
        mission_id=(request.mission_id if request is not None else "CASE-1"),
        risk="high",
        action=lambda: ran.append(1) or "ran",
        action_approval=grant,
        action_request=request,
        action_descriptor=None if request is not None else DESCRIPTOR,
        attempt=attempt,
    )
    rows = sqlite3.connect(ledger_path).execute(
        "SELECT COUNT(*) FROM consumed_approvals"
    ).fetchone()[0]
    return decision, len(ran), rows


# --------------------------------------------------------------------------
# Replay identity
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "approval_id"),
    [
        ("same identifier", "ACT-1"),
        ("relabelled", "ACT-0002"),
        ("whitespace-changed identifier", "ACT-1 "),
        ("arbitrary identifier", "anything-at-all"),
    ],
)
def test_one_attempt_releases_once_whatever_the_grant_is_called(
    label: str, approval_id: str, tmp_path: Path
):
    """`approval_id` is a label, not authority. Changing it must change nothing.

    Keying single use on it meant one approved refund executed as many times as
    the presenter cared to rename it.
    """
    work = _git_repo(tmp_path)
    context = RuntimeContext.for_test(work, at="2026-08-03T00:00:00Z", revision=REVISION_A)
    request = _request(REVISION_A)

    first, ran, _ = _release(work, context, _grant(request), request)
    assert first.effect == "ALLOW" and ran == 1

    second, ran, rows = _release(work, context, _grant(request, approval_id=approval_id), request)
    assert second.effect == "DENY", f"{label} released a second time"
    assert ran == 0
    assert rows == 1, "a refused replay wrote a second ledger row"


def test_an_old_grant_cannot_authorize_a_new_attempt(tmp_path: Path):
    work = _git_repo(tmp_path)
    context = RuntimeContext.for_test(work, at="2026-08-03T00:00:00Z", revision=REVISION_A)
    first = _request(REVISION_A, attempt=1)
    assert _release(work, context, _grant(first), first)[0].effect == "ALLOW"

    second = _request(REVISION_A, attempt=2)
    decision, ran, _ = _release(work, context, _grant(first), second, attempt=2)
    assert decision.effect == "DENY"
    assert ran == 0


def test_a_retry_stays_inside_its_mission(tmp_path: Path):
    """A fresh attempt with its own approval, without inventing a new mission.

    At-most-once must not mean at-most-ever: a refund that failed in transit is
    retried, and forcing a new mission to do it would push operators into
    fabricating identifiers.
    """
    work = _git_repo(tmp_path)
    context = RuntimeContext.for_test(work, at="2026-08-03T00:00:00Z", revision=REVISION_A)
    first = _request(REVISION_A, attempt=1)
    assert _release(work, context, _grant(first), first)[0].effect == "ALLOW"

    second = _request(REVISION_A, attempt=2)
    decision, ran, rows = _release(
        work, context, _grant(second, approval_id="ACT-2"), second, attempt=2
    )
    assert decision.effect == "ALLOW", decision.evidence.get("action_binding")
    assert ran == 1
    assert rows == 2
    assert first.mission_id == second.mission_id
    assert first.attempt_id != second.attempt_id


# --------------------------------------------------------------------------
# Trusted time
# --------------------------------------------------------------------------


def test_the_retired_time_variable_cannot_move_the_clock():
    live = runtime_as_of()
    assert live[:4] != "2026-08-03"[:4] or live != HOSTILE_TIME
    assert runtime_as_of() != HOSTILE_TIME


@pytest.mark.parametrize(
    ("label", "generated", "expires"),
    [
        ("expired", "2026-08-02T00:00:00Z", "2026-08-05T00:00:00Z"),
        ("not yet valid", "2099-01-01T00:00:00Z", "2099-01-05T00:00:00Z"),
    ],
)
def test_a_grant_outside_its_window_cannot_be_revived(
    label: str, generated: str, expires: str, tmp_path: Path
):
    """The hostile variable names an instant where the expired grant is live."""
    work = _git_repo(tmp_path)
    revision = actual_revision(work)
    assert revision is not None
    _declare(work, revision)

    request = _request(revision)
    decision, ran, rows = _release(
        work,
        RuntimeContext.trusted(work),
        _grant(request, generated=generated, expires=expires),
        request,
    )
    assert decision.effect == "DENY", f"{label} grant was released"
    assert ran == 0
    assert rows == 0


def test_the_ledger_timestamp_comes_from_the_trusted_context(tmp_path: Path):
    """A backdated consumption record is a backdated audit trail."""
    work = _git_repo(tmp_path)
    pinned = "2027-03-04T05:06:07Z"
    context = RuntimeContext.for_test(work, at=pinned, revision=REVISION_A)
    request = _request(REVISION_A)
    assert _release(work, context, _grant(request, expires="2027-03-09T00:00:00Z",
                                          generated="2027-03-03T00:00:00Z"),
                    request)[0].effect == "ALLOW"

    stored = sqlite3.connect(work / "ledger.sqlite3").execute(
        "SELECT consumed_at FROM consumed_approvals"
    ).fetchone()[0]
    assert stored == pinned
    assert stored != HOSTILE_TIME


# --------------------------------------------------------------------------
# Trusted revision
# --------------------------------------------------------------------------


def test_the_retired_revision_variable_cannot_set_the_revision(tmp_path: Path):
    work = _git_repo(tmp_path)
    assert runtime_revision(work) == "git:unbound"
    assert actual_revision(work) != REVISION_A
    assert RuntimeContext.trusted(work).actual_revision != REVISION_A


def test_a_mismatched_checkout_is_refused_and_named(tmp_path: Path):
    """Declared A, checked out B: the contract does not get to decide."""
    work = _git_repo(tmp_path)
    _declare(work, REVISION_A)
    context = RuntimeContext.trusted(work)

    assert context.revision_verified is False
    assert context.declared_revision == REVISION_A
    assert context.actual_revision not in (None, REVISION_A)

    decision, ran, rows = _release(work, context, _grant(_request(REVISION_A)), _request(REVISION_A))
    assert decision.code == GOVERNED_REVISION_MISMATCH
    assert ran == 0
    assert rows == 0, "a revision refusal consumed the approval"


def test_an_unverifiable_revision_is_refused_but_named_differently(tmp_path: Path):
    """No git, as in a built container. Distinct from a mismatch, distinct remedy."""
    work = tmp_path / "image"
    (work / ".nornyx/contracts").mkdir(parents=True)
    _declare(work, REVISION_A)
    context = RuntimeContext.trusted(work)

    assert context.actual_revision is None
    assert context.revision_verified is False
    assert context.declared_revision == REVISION_A

    decision, ran, rows = _release(work, context, _grant(_request(REVISION_A)), _request(REVISION_A))
    assert decision.code == GOVERNED_REVISION_UNVERIFIED
    assert decision.code != GOVERNED_REVISION_MISMATCH
    assert ran == 0
    assert rows == 0
    assert decision.evidence["revision_verified"] is False
    assert decision.evidence["actual_revision"] is None


def test_an_unverifiable_revision_does_not_stop_the_application(tmp_path: Path):
    """Lack of verification blocks revision-bound authority, not the app.

    Deliberately not "low risk always runs": Nornyx still evaluates the
    capability and any zone crossing independently, and may refuse for its own
    reasons. What is asserted here is only that the *revision* check does not
    reach beyond consequential authority.
    """
    work = tmp_path / "image"
    (work / ".nornyx/contracts").mkdir(parents=True)
    _declare(work, REVISION_A)

    boundary = _permissive_boundary(work, runtime_context=RuntimeContext.trusted(work))
    decision, result = boundary.evaluate_and_execute(
        mission_id="CASE-LOW", risk="low", action=lambda: "done"
    )
    assert decision.effect == "ALLOW"
    assert result == "done"


def test_a_verified_checkout_releases(tmp_path: Path):
    """The controls must not block the case they exist to permit."""
    work = _git_repo(tmp_path)
    revision = actual_revision(work)
    assert revision is not None
    _declare(work, revision)
    context = RuntimeContext.trusted(work)
    assert context.revision_verified is True

    now = runtime_as_of()
    request = _request(revision)
    decision, ran, _ = _release(
        work,
        context,
        # Inside the P7D cap and around the live clock, since this context
        # deliberately uses the real one.
        _grant(request, generated=_shift(now, hours=-1), expires=_shift(now, days=1)),
        request,
    )
    assert decision.effect == "ALLOW", decision.evidence.get("action_binding")
    assert ran == 1


def _shift(moment: str, *, days: int = 0, hours: int = 0) -> str:
    from datetime import datetime, timedelta

    parsed = datetime.fromisoformat(moment.replace("Z", "+00:00")) + timedelta(
        days=days, hours=hours
    )
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Test-seam containment
# --------------------------------------------------------------------------


def test_the_production_constructor_has_no_time_or_revision_parameter():
    """One seam. `as_of=` was a second door onto the same room."""
    import inspect

    from nornyx_forge.nornyx_runtime import NornyxActionBoundary

    parameters = set(inspect.signature(NornyxActionBoundary.__init__).parameters)
    assert "as_of" not in parameters
    assert "runtime_context" in parameters


def test_no_production_source_constructs_a_test_context():
    """The intended topology, made enforceable.

    Python cannot make `for_test` unreachable, so this asserts the thing that
    actually matters: no shipped code path constructs one. A reviewer should not
    have to take that on trust.
    """
    root = Path(__file__).resolve().parents[1]
    offenders = [
        str(path.relative_to(root))
        for path in sorted((root / "src").rglob("*.py"))
        if "RuntimeContext.for_test(" in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        "RuntimeContext.for_test is a test seam and must not appear in shipped "
        f"code: {offenders}"
    )


def test_the_retired_environment_names_are_gone_from_the_runtime():
    """Not renamed, not relocated — absent."""
    source = (
        Path(__file__).resolve().parents[1] / "src/nornyx_forge/nornyx_runtime.py"
    ).read_text(encoding="utf-8")
    assert RETIRED_TIME_ENV not in source
    assert RETIRED_REVISION_ENV not in source
    assert "os.getenv" not in source.split("def runtime_as_of")[1].split("def runtime_revision")[0]


def test_a_test_context_is_marked_as_one(tmp_path: Path):
    assert RuntimeContext.for_test(tmp_path).for_test_only is True
    assert RuntimeContext.trusted(tmp_path).for_test_only is False


def test_a_backdated_lock_regeneration_cannot_revive_an_action_approval(tmp_path: Path):
    """Evidence-generation time and action-authority time are different clocks.

    ``prepare_runtime_contract(as_of=...)`` still takes an explicit instant: it
    regenerates the lock, and a reproducible regeneration is a legitimate thing
    to ask for. The invariant that matters is directional — that argument must
    never become the clock an action approval is judged against.

    Driven with a deliberately absurd backdate, far enough before the grant's
    window that reviving it would be unmistakable.
    """
    from nornyx_forge import nornyx_runtime

    work = _git_repo(tmp_path)
    revision = actual_revision(work)
    assert revision is not None
    _declare(work, revision)

    # A grant that expired long ago by the real clock.
    request = _request(revision)
    grant = _grant(request, generated="2020-01-01T00:00:00Z", expires="2020-01-05T00:00:00Z")

    # Regenerate the lock as of a moment inside that dead window.
    seen: list[tuple[str, ...]] = []

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    original_run = nornyx_runtime.subprocess.run
    original_which = nornyx_runtime.shutil.which
    nornyx_runtime.shutil.which = lambda _name: "nornyx"
    nornyx_runtime.subprocess.run = lambda command, **_k: (
        seen.append(tuple(command)) or _Completed()
    )
    try:
        nornyx_runtime.prepare_runtime_contract(work, as_of="2020-01-02T00:00:00Z")
    finally:
        nornyx_runtime.subprocess.run = original_run
        nornyx_runtime.shutil.which = original_which

    assert seen, "the regeneration did not run"
    assert any("2020-01-02T00:00:00Z" in command for command in seen)

    # The action boundary is unmoved: it judges against the trusted clock.
    decision, ran, rows = _release(work, RuntimeContext.trusted(work), grant, request)
    assert decision.effect == "DENY", "a backdated regeneration revived an approval"
    assert ran == 0
    assert rows == 0
