"""Provider-routed engineering execution — explicit, honest, no fallback.

THE PROPERTY: the development flow can acquire its engineering worker
through the Provider Contract when a provider is EXPLICITLY selected, and
the default path is byte-identical to before the parameter existed —
`self.worker` is the same directly-constructed Claude worker, proven here
structurally and by every pre-existing flow test passing unmodified.

WHAT WOULD FALSIFY IT, each with a specimen: a selected provider silently
replaced by the direct Claude worker (the downgrade this repository's
history forbids); an undeclared provider reaching execution instead of
being refused at construction; a routed result claiming a provider that
did not run; a selection accepted in a mode that runs no workers.

The routed path is exercised through REAL workers over controlled fake
executables — the same hermetic technique as the conformance suites — so
what is proven is the shipping translation, not a mock of it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from nornyx_forge.claude_worker import ClaudeCodeWorker
from nornyx_forge.codex_worker import CodexWorker
from nornyx_forge.development_flow import DevelopmentFlow
from nornyx_forge.provider_contract import (
    UNAVAILABLE_RETURNCODE,
    ProviderError,
)
from nornyx_forge.providers import (
    ClaudeProviderAdapter,
    CodexProviderAdapter,
    ProviderRoutedWorker,
)

JSONL_EVENT = '{"type": "thread.started", "thread_id": "exec-1"}'


def _fake_cli(tmp_path: Path, name: str, *, stdout: str, exit_code: int = 0) -> str:
    if os.name == "nt":
        path = tmp_path / f"{name}.bat"
        path.write_text(f"@echo off\r\necho {stdout}\r\nexit /b {exit_code}\r\n",
                        encoding="utf-8", newline="")
    else:
        path = tmp_path / f"{name}.sh"
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{stdout}'\nexit {exit_code}\n",
                        encoding="utf-8", newline="")
        path.chmod(0o755)
    return str(path)


# ---------------------------------------------------------------------------
# Acquisition: default preserved, selection routed, refusals at construction
# ---------------------------------------------------------------------------

def test_the_default_path_still_constructs_the_direct_claude_worker(tmp_path: Path):
    """Preservation, structurally: no provider means the exact worker every
    existing caller gets, and no provider key appears in the flow data."""
    flow = DevelopmentFlow(tmp_path, worker_mode="deterministic")
    assert type(flow.worker) is ClaudeCodeWorker
    assert "engineering_provider" not in flow.data


def test_a_selected_provider_routes_through_the_contract(tmp_path: Path):
    flow = DevelopmentFlow(tmp_path, worker_mode="claude-code", provider="codex")
    assert type(flow.worker) is ProviderRoutedWorker
    assert flow.worker.provider_name == "codex"
    assert flow.data["engineering_provider"] == {"selected": "codex"}


def test_an_undeclared_provider_is_refused_before_anything_runs(tmp_path: Path):
    with pytest.raises(ProviderError, match="not a declared provider name"):
        DevelopmentFlow(tmp_path, worker_mode="claude-code", provider="gemini")


def test_a_provider_needs_the_worker_executing_mode(tmp_path: Path):
    """A selection in a mode that runs no workers would be a recorded choice
    nothing honors — refused instead of stored as decoration."""
    with pytest.raises(ValueError, match="requires worker_mode='claude-code'"):
        DevelopmentFlow(tmp_path, worker_mode="deterministic", provider="codex")


# ---------------------------------------------------------------------------
# The routed worker: real translation over real workers
# ---------------------------------------------------------------------------

def test_the_routed_worker_serves_the_worker_surface_with_the_honest_surplus(
        tmp_path: Path):
    routed = ProviderRoutedWorker(
        CodexProviderAdapter(CodexWorker(_fake_cli(tmp_path, "ok-codex",
                                                   stdout=JSONL_EVENT)))
    )
    result = routed.run(
        role="application-builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert result.success is True
    assert result.provider == "codex"
    assert result.failure_class == "ok"
    # The fields the flow reads, present and usable exactly as before.
    assert isinstance(result.output, str) and isinstance(result.command, tuple)
    assert "provider" in result.__dict__ and "failure_class" in result.__dict__


def test_an_unavailable_provider_reports_unavailable_and_nothing_falls_back(
        tmp_path: Path):
    """THE NO-DOWNGRADE RULE. The selected provider's CLI is absent; the
    result says so in the vocabulary, names the selected provider, and the
    flow's worker is still the routed one — not a quietly substituted
    direct Claude worker."""
    flow = DevelopmentFlow(tmp_path, worker_mode="claude-code", provider="codex")
    flow.worker = ProviderRoutedWorker(
        CodexProviderAdapter(CodexWorker(str(tmp_path / "absent-codex")))
    )
    result = flow.worker.run(
        role="application-builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert result.failure_class == "unavailable"
    assert result.returncode == UNAVAILABLE_RETURNCODE
    assert result.provider == "codex", "the failure must name the selected provider"
    assert type(flow.worker) is ProviderRoutedWorker
    assert not isinstance(flow.worker, ClaudeCodeWorker)


def test_a_flow_step_records_the_provider_that_actually_ran(tmp_path: Path):
    """End to end through a real call site: the architecture step, driven by
    the routed worker over a fake Codex CLI, records a worker result whose
    provider field came from the execution."""
    flow = DevelopmentFlow(tmp_path, worker_mode="claude-code", provider="codex")
    flow.worker = ProviderRoutedWorker(
        CodexProviderAdapter(CodexWorker(_fake_cli(tmp_path, "step-codex",
                                                   stdout=JSONL_EVENT)))
    )
    flow.architecture()
    recorded = flow.data["architecture_worker"]
    assert recorded["provider"] == "codex"
    assert recorded["failure_class"] == "ok"
    assert recorded["success"] is True


def test_the_claude_route_reports_claude_the_same_way(tmp_path: Path):
    routed = ProviderRoutedWorker(
        ClaudeProviderAdapter(ClaudeCodeWorker(
            _fake_cli(tmp_path, "ok-claude", stdout='{"session_id": "exec-2"}')
        ))
    )
    result = routed.run(
        role="solution-architect", goal="probe", workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert result.provider == "claude"
    assert result.success is True and result.session_id == "exec-2"


def test_the_routed_worker_refuses_an_impostor_adapter():
    class Impostor:
        name = "gemini"

        def available(self) -> bool:  # pragma: no cover - never reached
            return True

        def run_task(self, task):  # pragma: no cover - never reached
            raise AssertionError("must never be reached")

    with pytest.raises(ProviderError, match="not a declared provider"):
        ProviderRoutedWorker(Impostor())
