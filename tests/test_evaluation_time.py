"""Evaluation time is a governed fact, and comes from trusted sources.

The revision tests that lived here are gone with the model they described.
`test_no_environment_value_can_supply_a_revision` was the clearest example of
what this repository keeps producing: a name asserting a universal, a body
checking two retired `FORGE_*` strings, and `GIT_DIR` walking straight through
the property the name claimed. Its real successors are in
`test_subject_provenance.py`, where hostile git environments are actually run
against the digests that now carry authority.
The Nornyx evaluation instant must be real, and pinnable only by a test.

A hardcoded instant silently judged every approval against a fixed moment, so a
seven-day expiry could never actually elapse and an approval issued later than
the pin would be evaluated against a time before it was made.

The first fix replaced it with ``FORGE_RUNTIME_AS_OF``, which was worse in a
quieter way: an environment variable is ambient authority, so anything in the
process could revive an expired approval and the resulting evidence looked
identical to an honest run. Determinism now arrives through
``RuntimeContext.for_test``, and these tests assert that the retired variables
do nothing — they are set, not cleared.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from nornyx_forge import nornyx_cli_adapter, runtime_preparation
from nornyx_forge.nornyx_runtime import (
    NornyxActionBoundary,
    RuntimeContext,
    runtime_as_of,
)
from nornyx_forge.runtime_preparation import prepare_runtime_contract

ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REVISION = "git:" + "a" * 40

#: Retired. Named here only so the tests can prove setting them changes nothing.
RETIRED_TIME_ENV = "FORGE_RUNTIME_AS_OF"
RETIRED_REVISION_ENV = "FORGE_RUNTIME_REVISION"


def test_default_evaluation_instant_is_the_real_now(monkeypatch: pytest.MonkeyPatch):
    # Set, not cleared: the live clock must win over a hostile pin.
    monkeypatch.setenv(RETIRED_TIME_ENV, "2030-01-01T00:00:00Z")
    before = datetime.now(timezone.utc) - timedelta(seconds=5)
    value = runtime_as_of()
    after = datetime.now(timezone.utc) + timedelta(seconds=5)
    assert ISO_Z.match(value), value
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert before <= parsed <= after


def test_only_an_explicit_argument_pins_the_instant(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(RETIRED_TIME_ENV, "2030-01-01T00:00:00Z")
    assert runtime_as_of("2026-08-02T09:30:00+00:00") == "2026-08-02T09:30:00Z"


def test_the_environment_no_longer_pins_the_instant(monkeypatch: pytest.MonkeyPatch):
    """The retired variable is inert, not merely deprioritised."""
    monkeypatch.setenv(RETIRED_TIME_ENV, "2026-08-02T09:30:00Z")
    assert runtime_as_of() != "2026-08-02T09:30:00Z"


def test_offset_timestamps_are_normalised_to_utc():
    assert runtime_as_of("2026-08-02T13:30:00+04:00") == "2026-08-02T09:30:00Z"


@pytest.mark.parametrize(
    "bad", ["2026-08-02T09:30:00", "not-a-time", "2026-13-45", "", "   "]
)
def test_ambiguous_or_invalid_instants_fail_closed(
    bad: str, monkeypatch: pytest.MonkeyPatch
):
    """A bad pin must raise, never silently fall back to the live clock.

    Includes the set-but-blank case: an operator who exported the variable and
    got the value wrong should see an error, not the live clock.
    """
    with pytest.raises(ValueError):
        runtime_as_of(bad)
    # And the same bad value in the retired variable is simply ignored.
    monkeypatch.setenv(RETIRED_TIME_ENV, bad)
    assert ISO_Z.match(runtime_as_of())


def test_every_nornyx_step_receives_the_same_instant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """check, generate, lock and lock-check must agree on the evaluation time."""
    # Preparation moved to `runtime_preparation`, and its process execution to
    # `nornyx_cli_adapter`, when the domain process-execution prohibition made
    # the old placement visible. The patch targets follow.
    monkeypatch.setattr(runtime_preparation.shutil, "which", lambda _name: "nornyx")
    seen: list[tuple[str, ...]] = []

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(command, **_kwargs):
        seen.append(tuple(command))
        return _Completed()

    monkeypatch.setattr(nornyx_cli_adapter.subprocess, "run", _fake_run)
    prepare_runtime_contract(tmp_path, as_of="2026-08-02T09:30:00Z")

    assert len(seen) == 4
    for command in seen:
        assert "--as-of" in command, command
        assert command[command.index("--as-of") + 1] == "2026-08-02T09:30:00Z"
    assert seen[0][1] == "check", "the initial check must be time-pinned too"


def test_boundary_records_the_instant_it_evaluated_at(tmp_path: Path):
    """Through the one seam, which a caller has to name at the call site."""
    boundary = NornyxActionBoundary(
        tmp_path,
        allow_fallback=True,
        runtime_context=RuntimeContext.for_test(tmp_path, at="2026-08-02T09:30:00Z"),
    )
    assert boundary.as_of == "2026-08-02T09:30:00Z"
    assert boundary.runtime_context.for_test_only is True


def test_seven_day_expiry_rule_is_not_weakened():
    """The module's P7D cap must remain intact in the installed Nornyx package."""
    nornyx = pytest.importorskip("nornyx", reason="requires the demo extra")
    profile = (
        Path(nornyx.__file__).resolve().parent
        / "profiles_data/module_agentic_network_governance.yaml"
    )
    assert profile.exists(), profile
    text = profile.read_text(encoding="utf-8")
    assert "expires_after: P7D" in text
    # The approval must also still refuse non-human authority.
    for denied in ("ai_tool", "autonomous_agent", "model", "generated_output"):
        assert denied in text


def test_no_first_party_module_reads_a_retired_time_or_revision_override():
    """Retired means retired everywhere, and by structure rather than by line.

    Both variables were removed from the runtime, and the evidence tool went on
    honouring `FORGE_RUNTIME_AS_OF` as a fallback for `--as-of`. That mattered:
    `generated_at` is what the agentic-network approval window is measured from,
    so an instant nobody had to declare could move when an approval appeared to
    have been granted.

    The first version of this test required the variable name and the reading
    verb on the same physical line. An independent review defeated it in two
    lines -- bind the name to a constant, read it on the next -- and a module
    under `src/` doing exactly the forbidden thing was invisible.

    So the match is on the module's syntax tree: if a retired name appears as a
    string anywhere in a module that also touches the environment, that module
    is flagged. Deliberately blunt in the safe direction. A false positive is a
    comment away from being resolved; a false negative is an authority-relevant
    override nobody can see.
    """
    import ast

    root = Path(__file__).resolve().parents[1]
    retired = {RETIRED_TIME_ENV, RETIRED_REVISION_ENV}
    offenders: list[str] = []

    for directory in ("src", "scripts"):
        for source in sorted((root / directory).rglob("*.py")):
            try:
                tree = ast.parse(source.read_text(encoding="utf-8"))
            except SyntaxError:  # pragma: no cover - a broken file fails elsewhere
                continue

            names: set[str] = set()
            touches_environment = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if node.value in retired:
                        names.add(node.value)
                elif isinstance(node, ast.Attribute) and node.attr in {
                    "getenv",
                    "environ",
                }:
                    touches_environment = True
                elif isinstance(node, ast.Name) and node.id in {"getenv", "environ"}:
                    touches_environment = True

            if names and touches_environment:
                offenders.append(f"{source.relative_to(root)} ({', '.join(sorted(names))})")

    assert offenders == [], (
        "a retired override name appears in a module that reads the "
        "environment, so time or revision may be aimed from outside: "
        + ", ".join(offenders)
    )


# --------------------------------------------------------------------------
# A09 -- the boundary read the trusted clock ONCE, at construction.
#
# `self.as_of = self.runtime_context.now()` in `__init__` meant every approval
# window the boundary ever judged was judged at the instant the object was
# built. A grant that expired during the run was still evaluated against a
# stale clock.
#
# The reason it went unnoticed is the ordering an independent review named:
# the only test of this instant constructed the boundary with
# `RuntimeContext.for_test(at=...)` -- the DECLARED pin -- so it could not
# observe that the production path pinned itself as well. A test that builds
# the object the one way the property holds proves nothing about the other way.
# --------------------------------------------------------------------------


def test_a09_a_production_boundary_reads_the_clock_at_each_decision(tmp_path: Path):
    """No `for_test`, no pinned instant: the real construction path.

    Sleeping is the measurement. A monotonic assertion would pass on a pinned
    value too, because a constant is trivially not-decreasing.
    """
    from test_governance_failure import _permissive_boundary  # noqa: PLC0415

    boundary = _permissive_boundary(tmp_path)
    first = boundary.as_of
    time.sleep(2)
    second = boundary.as_of

    assert second != first, (
        "the boundary answered with the same instant two seconds apart, so it "
        "is judging approval windows against the moment it was constructed "
        f"rather than the moment of the decision: {first}"
    )
    assert second > first, f"the trusted clock went backwards: {first} -> {second}"


def test_a09_a_pinned_context_is_still_deterministic(tmp_path: Path):
    """The positive control, and the reason the fix is safe.

    `RuntimeContext.for_test(at=...)` pins `now()`, so reading it per decision
    changes nothing for deterministic tests. If this ever fails, the repair has
    made the boundary non-reproducible and every temporal proof around it is
    measuring wall-clock noise.
    """
    from test_governance_failure import _permissive_boundary  # noqa: PLC0415

    pinned = "2026-08-03T00:00:00Z"
    boundary = _permissive_boundary(tmp_path, as_of=pinned)
    first = boundary.as_of
    time.sleep(1)
    assert first == pinned, first
    assert boundary.as_of == pinned, "a pinned context stopped being pinned"


def test_a09_the_instant_is_not_a_stored_attribute():
    """Structural, so the assignment cannot quietly come back.

    A `self.as_of = ...` in `__init__` restores the defect exactly, and the
    behavioural test above would then need two seconds of sleep to notice. This
    notices immediately.
    """
    import inspect  # noqa: PLC0415

    from nornyx_forge import nornyx_runtime  # noqa: PLC0415

    # THE ASSIGNMENT, not any mention. `__init__` legitimately READS `as_of`
    # when it loads the authorizer -- `validation_as_of=self.as_of` -- and that
    # read now goes through the property. Forbidding the identifier outright
    # flagged those two lines, which is the use/mention confusion this
    # repository has two modules dedicated to refusing. It does not get a pass
    # for being in my own test.
    source = inspect.getsource(nornyx_runtime.NornyxActionBoundary.__init__)
    stored = [
        line.strip() for line in source.splitlines()
        if re.match(r"\s*self\.as_of\s*=", line)
    ]
    assert stored == [], (
        "the boundary stores its evaluation instant at construction again, so "
        f"every decision it makes is judged at the moment it was built: {stored}"
    )
    assert isinstance(
        inspect.getattr_static(nornyx_runtime.NornyxActionBoundary, "as_of"), property
    ), "as_of is no longer a property, so it is not read at the decision"
