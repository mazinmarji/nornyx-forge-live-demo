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

from nornyx_forge.governed_subject import RuntimeSubject
from nornyx_forge.nornyx_runtime import (
    ActionDescriptor,
    ApprovalLedger,
    RuntimeContext,
    canonical_action_request,
    runtime_as_of,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from signing import LEDGER_ESTABLISHED, signed_grant  # noqa: E402
from test_governance_failure import _permissive_boundary  # noqa: E402

#: The retired overrides. Set hostile in every test, expected to do nothing.
RETIRED_TIME_ENV = "FORGE_RUNTIME_AS_OF"
RETIRED_REVISION_ENV = "FORGE_RUNTIME_REVISION"
HOSTILE_TIME = "2026-08-03T00:00:00Z"
REVISION_A = "git:" + "a" * 40

#: The subject these tests authorize against. Authority is content identity now,
#: so a fixture states one explicitly rather than deriving it from a checkout —
#: the old tests pinned a git revision, which no longer decides anything.
SUBJECT = RuntimeSubject(
    scope_id="forge.test-fixture.v1",
    scope_definition_digest="sha256:" + "c" * 64,
    runtime_authority_config_digest="sha256:" + "d" * 64,
    governed_revision_digest="sha256:" + "e" * 64,
    governed_subject_digest="sha256:" + "f" * 64,
    subject_verified=True,
)

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


def _request(revision: str = "", *, attempt: int = 1, mission: str = "CASE-1"):
    """Build the request the boundary would build for the fixture subject."""
    return canonical_action_request(
        mission_id=mission,
        risk="high",
        subject_revision=revision or SUBJECT.governed_subject_digest,
        descriptor=DESCRIPTOR,
        attempt=attempt,
        subject_scope_id=SUBJECT.scope_id,
        governed_revision_digest=SUBJECT.governed_revision_digest,
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
    boundary.runtime_subject = SUBJECT
    boundary.approval_ledger = ApprovalLedger.provision(ledger_path, established_at=LEDGER_ESTABLISHED)
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
    request = _request()

    first, ran, _ = _release(work, context, _grant(request), request)
    assert first.effect == "ALLOW" and ran == 1

    second, ran, rows = _release(work, context, _grant(request, approval_id=approval_id), request)
    assert second.effect == "DENY", f"{label} released a second time"
    assert ran == 0
    assert rows == 1, "a refused replay wrote a second ledger row"


def test_an_old_grant_cannot_authorize_a_new_attempt(tmp_path: Path):
    work = _git_repo(tmp_path)
    context = RuntimeContext.for_test(work, at="2026-08-03T00:00:00Z", revision=REVISION_A)
    first = _request(attempt=1)
    assert _release(work, context, _grant(first), first)[0].effect == "ALLOW"

    second = _request(attempt=2)
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
    first = _request(attempt=1)
    assert _release(work, context, _grant(first), first)[0].effect == "ALLOW"

    second = _request(attempt=2)
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
    revision = "sha256:" + "a" * 64  # any subject identity; the window is under test
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
    request = _request()
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
    # AST, NOT SUBSTRING. `"RuntimeContext.for_test(" in source` cannot tell a
    # CALL from a docstring that names the seam while explaining why production
    # must not use it -- and the moment such a docstring was written, this went
    # red on prose. That is the use/mention confusion two other modules here
    # exist to refuse, and a guard is not exempt from it.
    #
    # Strictly stronger, not weaker: an actual call node is found however it is
    # spaced or line-broken, and a mention in a comment, docstring or string
    # literal is correctly ignored.
    import ast  # noqa: PLC0415

    root = Path(__file__).resolve().parents[1]
    offenders = []
    # THE CALLEE, NOT THE RECEIVER. This also required the receiver to be the
    # bare name `RuntimeContext`, and a review measured what that costs: of six
    # spellings, ONE was caught.
    #
    #   CAUGHT     RuntimeContext.for_test(...)
    #   INVISIBLE  nornyx_runtime.RuntimeContext.for_test(...)
    #   INVISIBLE  RC.for_test(...)                     aliased on import
    #   INVISIBLE  Ctx = RuntimeContext; Ctx.for_test(...)
    #   INVISIBLE  getattr(RuntimeContext, "for_test")(...)
    #   INVISIBLE  self.runtime_context.for_test(...)
    #
    # The sibling guard in `test_authority_domains.py` has matched on
    # `id or attr` alone since it was written and catches all of ITS variants.
    # The correct predicate was in the tree; this one was narrower for no
    # reason anybody recorded. There are no legitimate `for_test` calls under
    # `src/`, so matching the name alone is exactly right and not over-broad.
    for path in sorted((root / "src").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name == "for_test":
                offenders.append(f"{path.relative_to(root)}:{node.lineno}")
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
    # `approval_ledger_path` legitimately reads its configured location; R3
    # makes that a bootstrap value. What must not return is an env read that
    # supplies *authority* — revision or evaluation time.
    source = source.replace("os.getenv(APPROVAL_LEDGER_ENV)", "<ledger-path-configuration>")
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
    from nornyx_forge import nornyx_cli_adapter, runtime_preparation

    work = _git_repo(tmp_path)
    # Authority is the fixture subject; the lock's regeneration instant is what
    # this test drives, and it must not become the clock a grant is judged by.
    request = _request()
    grant = _grant(request, generated="2020-01-01T00:00:00Z", expires="2020-01-05T00:00:00Z")

    # Regenerate the lock as of a moment inside that dead window.
    seen: list[tuple[str, ...]] = []

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    original_run = nornyx_cli_adapter.subprocess.run
    original_which = runtime_preparation.shutil.which
    runtime_preparation.shutil.which = lambda _name: "nornyx"
    nornyx_cli_adapter.subprocess.run = lambda command, **_k: (
        seen.append(tuple(command)) or _Completed()
    )
    try:
        runtime_preparation.prepare_runtime_contract(work, as_of="2020-01-02T00:00:00Z")
    finally:
        nornyx_cli_adapter.subprocess.run = original_run
        runtime_preparation.shutil.which = original_which

    assert seen, "the regeneration did not run"
    assert any("2020-01-02T00:00:00Z" in command for command in seen)

    # The action boundary is unmoved: it judges against the trusted clock.
    decision, ran, rows = _release(work, RuntimeContext.trusted(work), grant, request)
    assert decision.effect == "DENY", "a backdated regeneration revived an approval"
    assert ran == 0
    assert rows == 0


def test_medium_risk_exercises_the_low_risk_capability():
    """A19: the risk vocabulary has four levels and the capability model two.

    `medium` is accepted by the HTTP surface and maps to
    `execute_low_risk_action`, which the runtime contract declares as
    `risk: low` with no required gates and no required approvals. A reviewer
    reading a four-level vocabulary could reasonably expect `medium` to sit
    somewhere between; it does not.

    This asserts the mapping rather than arguing about it. Moving `medium`
    across the line would be a real authorization change, and it should be a
    diff that fails here first.
    """
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        HIGH_RISK_LEVELS,
        RISK_LEVELS,
        exercised_capability,
    )

    assert RISK_LEVELS == {"low", "medium", "high", "critical"}
    assert HIGH_RISK_LEVELS == {"high", "critical"}
    assert exercised_capability("medium") == "execute_low_risk_action"
    assert exercised_capability("low") == "execute_low_risk_action"
    assert exercised_capability("high") == "execute_high_risk_effect"
    assert exercised_capability("critical") == "execute_high_risk_effect"
