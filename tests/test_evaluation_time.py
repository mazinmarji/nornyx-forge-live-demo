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
