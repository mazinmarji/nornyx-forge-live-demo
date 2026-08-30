"""The pre-registered Codex/Claude equivalence proof, executed.

EVERY CRITERION HERE WAS FROZEN FIRST. The projection, the task set, the
ending set, the allowed and forbidden differences, and the consumer scope all
come from docs/governance/PROVIDER_EQUIVALENCE_PREREG.md, committed before
any test in this file existed — git ordering is the proof that the criteria
could not be tuned to fit the results.

What a green run here licenses, exactly: contract-level equivalence across
the frozen task and ending sets, plus neutrality of every consumer of
provider results or identity that exists at this head (the normalizer, the
capsule's provider acceptance, the registry). What it does NOT license:
behavioral equivalence of the underlying models — no real model runs here —
and lifecycle-driven equivalence, which has no consumer to prove yet.

The hostile specimens are this slice's load-bearing proof: each doctors an
input that individual-result validation ALONE would accept, and asserts the
harness's own comparison goes red on it. A proof whose checks cannot fail is
a tautology; these show the checks failing.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest

from nornyx_forge.capsule import AUTHORITATIVE_FIELDS, CapsuleValidationError
from nornyx_forge.claude_worker import ClaudeCodeWorker
from nornyx_forge.codex_worker import CodexWorker
from nornyx_forge.provider_contract import (
    ProviderError,
    ProviderResult,
    ProviderTask,
    validate_adapter_identity,
)
from nornyx_forge.providers import (
    ClaudeProviderAdapter,
    CodexProviderAdapter,
    get_provider,
)

# Native session emissions — each CLI's own convention, per the frozen
# ending set: Claude's JSON object, Codex's JSONL thread event. The VALUES
# differ on purpose; the projection compares presence, never value.
CLAUDE_SESSION_STDOUT = '{"session_id": "eq-claude-1"}'
CODEX_SESSION_STDOUT = '{"type": "thread.started", "thread_id": "eq-codex-1"}'

ALLOWED_DIFFERENCES = {"provider", "command", "output", "session_id"}


def _fake_cli(tmp_path: Path, name: str, *, exit_code: int = 0,
              sleep_seconds: int = 0, stdout: str = "") -> str:
    """A controlled executable the real workers can actually run."""
    if os.name == "nt":
        path = tmp_path / f"{name}.bat"
        lines = ["@echo off"]
        if sleep_seconds:
            lines.append(f"ping -n {sleep_seconds + 1} 127.0.0.1 >nul")
        if stdout:
            lines.append(f"echo {stdout}")
        lines.append(f"exit /b {exit_code}")
        path.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8", newline="")
    else:
        path = tmp_path / f"{name}.sh"
        lines = ["#!/bin/sh"]
        if sleep_seconds:
            lines.append(f"sleep {sleep_seconds}")
        if stdout:
            lines.append(f"printf '%s\\n' '{stdout}'")
        lines.append(f"exit {exit_code}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")
        path.chmod(0o755)
    return str(path)


def _adapter(provider: str, tmp_path: Path, ending: str):
    """Both real adapters over per-provider fakes emitting native conventions."""
    session = CLAUDE_SESSION_STDOUT if provider == "claude" else CODEX_SESSION_STDOUT
    if ending == "ok":
        cli = _fake_cli(tmp_path, f"ok-{provider}", stdout=session)
    elif ending == "error":
        # The same chosen nonzero exit for both, per the frozen ending set.
        cli = _fake_cli(tmp_path, f"err-{provider}", exit_code=5, stdout="broke")
    elif ending == "timeout":
        cli = _fake_cli(tmp_path, f"slow-{provider}", sleep_seconds=3, stdout=session)
    elif ending == "unavailable":
        cli = str(tmp_path / f"absent-{provider}")
    else:  # pragma: no cover - the parametrization is closed
        raise AssertionError(ending)
    if provider == "claude":
        return ClaudeProviderAdapter(ClaudeCodeWorker(cli))
    return CodexProviderAdapter(CodexWorker(cli))


# The frozen task set. T4 exists to drive the timeout ending.
def _frozen_task(name: str, workspace: Path) -> ProviderTask:
    tasks = {
        "T1": dict(goal="equivalence probe: report and exit",
                   allowed_tools=("Read",), max_turns=1, timeout_seconds=30),
        "T2": dict(goal="g" * 8000,
                   allowed_tools=("Read",), max_turns=1, timeout_seconds=30),
        "T3": dict(goal="equivalence probe with a wider allowlist",
                   allowed_tools=("Read", "Write", "Bash"), max_turns=3,
                   timeout_seconds=30),
        "T4": dict(goal="equivalence probe against a tight budget",
                   allowed_tools=("Read",), max_turns=1, timeout_seconds=1),
    }
    return ProviderTask(role="builder", workspace=str(workspace), **tasks[name])


def _projection(result: ProviderResult) -> dict:
    """The frozen definition of equal — nothing more, nothing less."""
    return {
        "success": result.success,
        "failure_class": result.failure_class,
        "returncode": result.returncode,
        "session_present": result.session_id is not None,
        "role": result.role,
        "goal": result.goal,
    }


def _assert_equivalent(a: ProviderResult, b: ProviderResult) -> None:
    assert _projection(a) == _projection(b), (
        f"forbidden difference between {a.provider} and {b.provider}: "
        f"{_projection(a)} != {_projection(b)}"
    )


def _decision(consumer, value) -> tuple:
    """A consumer's DECISION as comparable data: accepted, or refused with a
    type. What an accepting consumer returns may legitimately differ per
    provider (the registry returns a different adapter for each name — an
    allowed difference); the decision itself may not."""
    try:
        consumer(value)
        return ("accepted",)
    except Exception as refusal:  # noqa: BLE001 - the type IS the datum
        return ("refused", type(refusal))


def _assert_neutral(consumer, claude_flavored, codex_flavored) -> None:
    assert _decision(consumer, claude_flavored) == _decision(consumer, codex_flavored), (
        "a consumer decision differed by provider"
    )


# ---------------------------------------------------------------------------
# The matrix: every frozen (task, ending) pair, both adapters, equal projection
# ---------------------------------------------------------------------------

FROZEN_PAIRS = [
    ("T1", "ok"), ("T1", "unavailable"), ("T1", "error"),
    ("T2", "ok"), ("T2", "unavailable"), ("T2", "error"),
    ("T3", "ok"), ("T3", "unavailable"), ("T3", "error"),
    ("T4", "timeout"),
]


@pytest.mark.parametrize(("task_name", "ending"), FROZEN_PAIRS)
def test_every_frozen_pair_projects_equally_across_both_adapters(
        tmp_path: Path, task_name: str, ending: str):
    task = _frozen_task(task_name, tmp_path)
    claude_result = _adapter("claude", tmp_path, ending).run_task(task)
    codex_result = _adapter("codex", tmp_path, ending).run_task(task)
    claude_result.validate()
    codex_result.validate()
    _assert_equivalent(claude_result, codex_result)


def test_the_allowed_differences_are_the_only_differences(tmp_path: Path):
    """The exactness half of the proof: outside the pre-named allowed set,
    every field of the two results is EQUAL — not equivalent, equal."""
    task = _frozen_task("T1", tmp_path)
    claude_result = _adapter("claude", tmp_path, "ok").run_task(task)
    codex_result = _adapter("codex", tmp_path, "ok").run_task(task)
    claude_fields = dataclasses.asdict(claude_result)
    codex_fields = dataclasses.asdict(codex_result)
    differing = {name for name in claude_fields
                 if claude_fields[name] != codex_fields[name]}
    assert differing <= ALLOWED_DIFFERENCES, (
        f"fields outside the pre-registered allowed set differ: "
        f"{sorted(differing - ALLOWED_DIFFERENCES)}"
    )


# ---------------------------------------------------------------------------
# Hostile specimens: the harness must catch what validation alone accepts
# ---------------------------------------------------------------------------

def test_a_class_divergence_validates_alone_but_the_harness_catches_it(
        tmp_path: Path):
    """The pre-registration's own warning, executed: a result claiming the
    timeout class over returncode 5 passes validate(), because validation
    checks success/class agreement, not class/returncode consistency. Only
    the projection comparison refuses it — which is why it is load-bearing."""
    task = _frozen_task("T1", tmp_path)
    genuine = _adapter("codex", tmp_path, "error").run_task(task)
    doctored = dataclasses.replace(genuine, provider="claude",
                                   failure_class="timeout")
    doctored.validate()  # accepted alone: the divergence is invisible here
    with pytest.raises(AssertionError, match="forbidden difference"):
        _assert_equivalent(doctored, genuine)


def test_a_success_divergence_is_caught(tmp_path: Path):
    task = _frozen_task("T1", tmp_path)
    honest_failure = _adapter("codex", tmp_path, "error").run_task(task)
    green_over_red = ProviderResult(
        provider="claude", role=task.role, goal=task.goal, success=True,
        output="", failure_class="ok", returncode=0,
    )
    green_over_red.validate()
    with pytest.raises(AssertionError, match="forbidden difference"):
        _assert_equivalent(green_over_red, honest_failure)


def test_an_invented_session_is_caught(tmp_path: Path):
    """Presence must match: one adapter recording a session where the other
    records absence is a forbidden difference, whatever the values."""
    task = _frozen_task("T1", tmp_path)
    with_session = _adapter("claude", tmp_path, "ok").run_task(task)
    assert with_session.session_id is not None
    silent = dataclasses.replace(with_session, provider="codex", session_id=None)
    silent.validate()
    with pytest.raises(AssertionError, match="forbidden difference"):
        _assert_equivalent(with_session, silent)


def test_a_provider_biased_consumer_is_caught():
    """The neutrality check must itself be falsifiable: a consumer that
    refuses one declared provider and accepts the other must go red."""
    def biased(value):
        if value["name"] == "codex":
            raise CapsuleValidationError("no reason but the name")
        return None

    with pytest.raises(AssertionError, match="differed by provider"):
        _assert_neutral(biased, {"name": "claude"}, {"name": "codex"})


# ---------------------------------------------------------------------------
# Consumer neutrality: every consumer that exists at this head
# ---------------------------------------------------------------------------

def test_the_capsule_accepts_both_providers_through_one_acceptance():
    """The capsule's provider field — the one place provider identity enters
    canonical state — accepts both declared names with the same shape rule,
    through the public validator registry."""
    accept_provider = AUTHORITATIVE_FIELDS["provider"]
    _assert_neutral(accept_provider, {"name": "claude"}, {"name": "codex"})
    assert _decision(accept_provider, {"name": "claude"})[0] == "accepted"


def test_the_capsule_refuses_undeclared_and_malformed_identically():
    accept_provider = AUTHORITATIVE_FIELDS["provider"]
    for bad in ({"name": "gemini"}, {"name": "Claude"}, {"name": "Codex"},
                {"name": "claude", "extra": 1}, "claude", {}):
        with pytest.raises(CapsuleValidationError):
            accept_provider(bad)


def test_the_registry_is_symmetric_between_the_declared_names():
    """Both names resolve through the same identity validation; an undeclared
    name is refused the same way whichever adapters exist."""
    _assert_neutral(get_provider, "claude", "codex")
    for adapter_name in ("claude", "codex"):
        validate_adapter_identity(get_provider(adapter_name))
    with pytest.raises(ProviderError, match="not a declared provider name"):
        get_provider("gemini")
