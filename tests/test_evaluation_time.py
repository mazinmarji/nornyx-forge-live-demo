"""The Nornyx evaluation instant must be real by default and pinnable for tests.

A hardcoded instant silently judged every approval against a fixed moment, so a
seven-day expiry could never actually elapse and an approval issued later than
the pin would be evaluated against a time before it was made.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from nornyx_forge import nornyx_runtime
from nornyx_forge.nornyx_runtime import (
    RUNTIME_AS_OF_ENV,
    RUNTIME_REVISION_ENV,
    NornyxActionBoundary,
    prepare_runtime_contract,
    runtime_as_of,
    runtime_revision,
)

ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REVISION = "git:" + "a" * 40


def test_default_evaluation_instant_is_the_real_now(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(RUNTIME_AS_OF_ENV, raising=False)
    before = datetime.now(timezone.utc) - timedelta(seconds=5)
    value = runtime_as_of()
    after = datetime.now(timezone.utc) + timedelta(seconds=5)
    assert ISO_Z.match(value), value
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert before <= parsed <= after


def test_explicit_argument_pins_the_instant(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(RUNTIME_AS_OF_ENV, "2030-01-01T00:00:00Z")
    # An explicit argument wins over the environment.
    assert runtime_as_of("2026-08-02T09:30:00+00:00") == "2026-08-02T09:30:00Z"


def test_environment_pins_the_instant(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(RUNTIME_AS_OF_ENV, "2026-08-02T09:30:00Z")
    assert runtime_as_of() == "2026-08-02T09:30:00Z"


def test_offset_timestamps_are_normalised_to_utc(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(RUNTIME_AS_OF_ENV, raising=False)
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
    monkeypatch.delenv(RUNTIME_AS_OF_ENV, raising=False)
    with pytest.raises(ValueError):
        runtime_as_of(bad)
    monkeypatch.setenv(RUNTIME_AS_OF_ENV, bad)
    with pytest.raises(ValueError):
        runtime_as_of()


def test_unreadable_contract_yields_unbound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A non-UTF-8 contract must not raise out of the evidence-labelling path."""
    monkeypatch.delenv(RUNTIME_REVISION_ENV, raising=False)
    contract = tmp_path / nornyx_runtime.RUNTIME_CONTRACT
    contract.parent.mkdir(parents=True)
    contract.write_bytes(b"\xff\xfe\x00 not utf-8 \xc3\x28")
    assert runtime_revision(tmp_path) == "git:unbound"


def test_revision_is_read_from_the_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(RUNTIME_REVISION_ENV, raising=False)
    contract = tmp_path / nornyx_runtime.RUNTIME_CONTRACT
    contract.parent.mkdir(parents=True)
    contract.write_text(
        "agentic_network:\n"
        "  id: network.test\n"
        f"  subject_revision: {REVISION}\n",
        encoding="utf-8",
    )
    assert runtime_revision(tmp_path) == REVISION


def test_revision_is_unbound_without_a_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Absent a contract, evidence says unbound rather than claiming a binding."""
    monkeypatch.delenv(RUNTIME_REVISION_ENV, raising=False)
    assert runtime_revision(tmp_path) == "git:unbound"


def test_malformed_revision_override_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv(RUNTIME_REVISION_ENV, "not-a-revision")
    assert runtime_revision(tmp_path) == "git:unbound"


def test_every_nornyx_step_receives_the_same_instant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """check, generate, lock and lock-check must agree on the evaluation time."""
    monkeypatch.setattr(nornyx_runtime.shutil, "which", lambda _name: "nornyx")
    seen: list[tuple[str, ...]] = []

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(command, **_kwargs):
        seen.append(tuple(command))
        return _Completed()

    monkeypatch.setattr(nornyx_runtime.subprocess, "run", _fake_run)
    prepare_runtime_contract(tmp_path, as_of="2026-08-02T09:30:00Z")

    assert len(seen) == 4
    for command in seen:
        assert "--as-of" in command, command
        assert command[command.index("--as-of") + 1] == "2026-08-02T09:30:00Z"
    assert seen[0][1] == "check", "the initial check must be time-pinned too"


def test_boundary_records_the_instant_it_evaluated_at(tmp_path: Path):
    boundary = NornyxActionBoundary(
        tmp_path, allow_fallback=True, as_of="2026-08-02T09:30:00Z"
    )
    assert boundary.as_of == "2026-08-02T09:30:00Z"


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
