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

import json
import os
import re
import sys
from pathlib import Path

import pytest

from nornyx_forge import development_flow
from nornyx_forge.claude_worker import MALFORMED_INVOCATION_RETURNCODE, ClaudeCodeWorker
from nornyx_forge.codex_worker import CodexWorker
from nornyx_forge.development_flow import (
    COMPOSED_GOAL_MAX_CHARACTERS,
    REPAIR_DETAIL_TAIL_CHARACTERS,
    DevelopmentFlow,
    compose_repair_goal,
    failing_gate_details,
    sanitised_for_composition,
)
from nornyx_forge.models import GateResult, WorkerResult
from nornyx_forge.provider_contract import (
    UNAVAILABLE_RETURNCODE,
    ProviderError,
    ProviderTask,
)
from nornyx_forge.providers import (
    ClaudeProviderAdapter,
    CodexProviderAdapter,
    ProviderRoutedWorker,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from provider_specimens import emitting_cli as _emitting_cli  # noqa: E402

JSONL_EVENT = '{"type": "thread.started", "thread_id": "exec-1"}'

#: The composed goal's opening sentence, spelled ONCE in `src/` (pinned
#: below) and quoted here so the tests can reconstruct the un-capped
#: composition of ordinary text without re-implementing the function.
GOAL_OPENING = (
    "Repair only these failing gates for attempt {attempt}. "
    "Do not weaken governance, tests, architecture, or security checks.\n\n"
)

#: The Provider Contract's ceiling on a task goal, as `ProviderTask.validate`
#: enforces it. Pinned by test below against the contract itself, so the
#: number the flow's bound is measured against here is the contract's.
CONTRACT_GOAL_MAX_CHARACTERS = 8000

_OMISSION_MARKER = re.compile(r"\[\.\.\. (\d+) characters omitted \.\.\.\]")


def _fake_cli(tmp_path: Path, name: str, *, stdout: str, exit_code: int = 0,
              env_dump: Path | None = None) -> str:
    """A controlled provider executable. With `env_dump`, it also writes the
    environment IT RECEIVED to that file before answering, so a test can read
    what actually reached the child rather than what was meant to."""
    if os.name == "nt":
        dump = f'set > "{env_dump}"\r\n' if env_dump is not None else ""
        path = tmp_path / f"{name}.bat"
        path.write_text(f"@echo off\r\n{dump}echo {stdout}\r\nexit /b {exit_code}\r\n",
                        encoding="utf-8", newline="")
    else:
        dump = f"env > '{env_dump}'\n" if env_dump is not None else ""
        path = tmp_path / f"{name}.sh"
        path.write_text(f"#!/bin/sh\n{dump}printf '%s\\n' '{stdout}'\nexit {exit_code}\n",
                        encoding="utf-8", newline="")
        path.chmod(0o755)
    return str(path)


def _dumped_environment(dump: Path) -> dict[str, str]:
    """The `NAME=VALUE` lines the fake CLI wrote, as a mapping. Continuation
    lines of a multi-line value carry no `=` and are ignored: no variable this
    test sets has one, and a stray line must not become a name."""
    seen: dict[str, str] = {}
    for line in dump.read_text(encoding="utf-8", errors="replace").splitlines():
        name, separator, value = line.partition("=")
        if separator and name:
            seen[name] = value
    return seen


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


@pytest.mark.parametrize("provider", ["codex", "claude"])
def test_the_routed_provider_process_receives_no_forge_variable(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, provider: str):
    """Round-5 test P4-b (INV-B2, A-027). `_provider_env()` is what keeps
    Forge's operational variables -- and anything parked under Forge's own
    name -- out of the provider process. It was pinned in ONE module,
    `tests/test_control_plane_session.py`, which the windows-runtime CI job
    does not run: on that job the stripping was asserted by nothing, and the
    suites that actually exercise the routed path did not defend it.

    Pinned here on both routes, through the ROUTED worker over a real child
    process, reading the environment the child received rather than the one
    it was meant to receive. A decoy secret is parked in `FORGE_*` and in a
    bare `FORGE` -- the spelling a `startswith("FORGE_")` rule once let
    through -- and an ordinary variable, plus one whose name merely BEGINS
    with FORGE, must survive."""
    decoy = "decoy-secret-not-a-real-bearer-8a1f"
    monkeypatch.setenv("FORGE_WORKER_MODE", "claude-code")
    monkeypatch.setenv("FORGE_SECRET_DECOY", decoy)
    monkeypatch.setenv("FORGE", decoy)
    monkeypatch.setenv("ORDINARY_KEEP", "keep-me")
    monkeypatch.setenv("FORGERY_KEEP", "not-forges")
    dump = tmp_path / f"{provider}-child-env.txt"
    if provider == "codex":
        adapter = CodexProviderAdapter(CodexWorker(
            _fake_cli(tmp_path, "env-codex", stdout=JSONL_EVENT, env_dump=dump)))
    else:
        adapter = ClaudeProviderAdapter(ClaudeCodeWorker(
            _fake_cli(tmp_path, "env-claude", stdout='{"session_id": "env-1"}',
                      env_dump=dump)))
    result = ProviderRoutedWorker(adapter).run(
        role="application-builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert result.success is True and result.provider == provider, result
    assert dump.exists(), "the provider process did not report its environment"
    child = _dumped_environment(dump)
    assert child, "the environment dump was empty, so this pin measured nothing"
    assert not [key for key in child if key.upper().startswith("FORGE_")], sorted(child)
    assert "FORGE" not in {key.upper() for key in child}, sorted(child)
    assert decoy not in dump.read_text(encoding="utf-8", errors="replace"), (
        "the decoy secret reached the provider process")
    # The control: the environment was PASSED, not emptied. A child given
    # nothing would satisfy every assertion above and prove nothing.
    assert child.get("ORDINARY_KEEP") == "keep-me", sorted(child)
    assert child.get("FORGERY_KEEP") == "not-forges", (
        "a name that merely begins with FORGE was dropped")


def test_the_routed_worker_refuses_an_impostor_adapter():
    class Impostor:
        name = "gemini"

        def available(self) -> bool:  # pragma: no cover - never reached
            return True

        def run_task(self, task):  # pragma: no cover - never reached
            raise AssertionError("must never be reached")

    with pytest.raises(ProviderError, match="not a declared provider"):
        ProviderRoutedWorker(Impostor())


@pytest.mark.parametrize("provider", ["claude", "codex"])
def test_a_routed_task_reaches_the_argument_length_branch_through_its_tool_list(
    tmp_path: Path, provider: str
):
    """Round-5 security P2-NEW-1. Five sentences said the routed path never
    reaches the adapters' argument-too-long branch because
    `ProviderTask.validate` refuses a goal above 8000 characters first.
    `validate` bounds the GOAL; it bounds neither the tool list (each tool:
    a non-empty `str` with no comma -- no length rule, no count rule) nor
    the workspace path. So a routed task with a 12-character goal and a long
    `allowed_tools` passes the contract and reaches the operating system's
    refusal through the joined list: `--allowedTools a,b,...` on Claude,
    `Intended tools: a, b, ...` inside the prompt on Codex. Measured through
    the real routed worker on the Windows host: 90 tools joined to 36449
    characters ended in `error` (2) with `[WinError 206]` on both adapters.

    The specimen is refused on both CI platforms BY CONSTRUCTION: Windows
    bounds the whole line at 32767 characters; Linux bounds a SINGLE
    argument at `MAX_ARG_STRLEN` (131072 bytes) and answers `E2BIG`, and the
    joined list here is one argument of 150149 characters. The class and the
    sentence's three fragments are asserted, not the number. The fake CLI
    exits 0 with a session event, so a run that had spawned would have
    reported success. Not measured on macOS (not in the CI matrix), which
    bounds the total rather than one argument.
    """
    tools = tuple(f"tool{index:03d}" + "x" * 993 for index in range(150))
    goal = "twelve chars"
    assert len(",".join(tools)) >= 140_000 and len(goal) < CONTRACT_GOAL_MAX_CHARACTERS
    # The contract admits the task -- the sentences this test replaces said
    # it would not. Asked of the contract, not assumed.
    ProviderTask(role="builder", goal=goal, workspace=str(tmp_path),
                 allowed_tools=tools, max_turns=1, timeout_seconds=30).validate()

    cli = _fake_cli(tmp_path, f"ok-{provider}", stdout=JSONL_EVENT)
    adapter = (ClaudeProviderAdapter(ClaudeCodeWorker(cli)) if provider == "claude"
               else CodexProviderAdapter(CodexWorker(cli)))
    result = ProviderRoutedWorker(adapter).run(  # must not raise ProviderError
        role="builder", goal=goal, workspace=tmp_path,
        allowed_tools=tools, max_turns=1, timeout_seconds=30,
    )
    assert result.provider == provider
    assert result.success is False
    assert result.failure_class == "error", (result.failure_class, result.output[:200])
    assert result.returncode == MALFORMED_INVOCATION_RETURNCODE
    assert "exceeds the operating system's command-line length" in result.output, (
        result.output[:300]
    )
    assert f"across {len(result.command)} arguments" in result.output, result.output[:300]
    assert f"the goal alone {len(goal)} characters" in result.output, result.output[:300]
    assert "could not be started" not in result.output, (
        "the argument length was blamed on the executable"
    )


# ---------------------------------------------------------------------------
# Composition: provider output becomes the repair goal. A NUL in it must not
# become a NUL in the next invocation's arguments, and the composed goal must
# stay inside the Provider Contract's bound however the gates misbehave
# ---------------------------------------------------------------------------

def _worker_for(provider: str, cli: str):
    """The two shapes the flow's `self.worker` takes: the direct Claude worker
    (no provider selected) and the routed worker (a provider selected)."""
    if provider == "claude-direct":
        return ClaudeCodeWorker(cli)
    return ProviderRoutedWorker(CodexProviderAdapter(CodexWorker(cli)))


def _routed_for(provider: str, cli: str) -> ProviderRoutedWorker:
    """The ROUTED worker of the same provider family -- the surface whose
    `run` builds a `ProviderTask` and validates it, so a goal handed to it
    either passes the contract's bound or raises `ProviderError`."""
    if provider == "claude-direct":
        return ProviderRoutedWorker(ClaudeProviderAdapter(ClaudeCodeWorker(cli)))
    return ProviderRoutedWorker(CodexProviderAdapter(CodexWorker(cli)))


def _omitted_per_marker(text: str) -> list[int]:
    return [int(count) for count in _OMISSION_MARKER.findall(text)]


def _contract_refuses(goal: str) -> bool:
    """Whether the Provider Contract itself would refuse `goal` -- asked of
    the contract, not assumed from a number."""
    try:
        ProviderTask(role="builder", goal=goal, workspace="w",
                     allowed_tools=("Read",)).validate()
    except ProviderError as exc:
        assert "exceeds" in str(exc), exc
        return True
    return False


@pytest.mark.parametrize("provider", ["claude-direct", "codex-routed"])
def test_a_nul_in_provider_output_is_escaped_when_composed_into_the_repair_goal(
    tmp_path: Path, provider: str
):
    """The round-2 architecture finding, driven end to end through the real
    pieces: a fake provider writes `a\\x00b` to stdout and exits nonzero;
    the real worker carries the NUL into `WorkerResult.output` (correctly --
    the result is what the provider wrote, and NUL is valid UTF-8); the flow
    turns that into a failing `GateResult` and composes the repair goal from
    it. Before `compose_repair_goal` existed the NUL reached the goal, and
    `subprocess.run` raised `ValueError: embedded null character` out of the
    repair step. Now the record keeps the NUL and the GOAL carries its escape,
    and the composed goal is proven acceptable by handing it to a real worker.

    A focused test of the composing functions; `test_the_flows_repair_path_
    composes_the_goal_only_through_compose_repair_goal` drives `acceptance()`
    itself and proves the flow calls them with the failing gates.
    """
    nul_cli = _emitting_cli(tmp_path, "nul-output", b"a\x00b", exit_code=3)
    failed = _worker_for(provider, nul_cli).run(
        role="application-builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert failed.success is False and failed.returncode == 3
    assert "\x00" in failed.output, (
        "the specimen is not live: the provider's NUL did not reach the result"
    )

    gate = GateResult("application-builder", False, failed.output, failed.command, failed.returncode)
    failures = failing_gate_details([gate])
    assert "\x00" in failures, "the ledger's record of what the gate said must stay verbatim"
    goal = compose_repair_goal(1, [gate])
    assert "\x00" not in goal
    assert "a\\x00b" in goal, "the NUL is escaped legibly, not silently dropped"
    assert goal.startswith("Repair only these failing gates for attempt 1. ")
    assert not _omitted_per_marker(goal), "nothing was omitted from a short goal"

    # The composed goal is one the operating system accepts: a real worker
    # runs it. And the UNCOMPOSED text is not -- the negative control, which
    # the adapters now report rather than raise (the sibling repair).
    ok_cli = _fake_cli(tmp_path, "ok-after-repair", stdout='{"session_id": "r-1"}')
    accepted = _worker_for(provider, ok_cli).run(
        role="application-builder", goal=goal, workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert accepted.success is True, accepted.output
    refused = _worker_for(provider, ok_cli).run(
        role="application-builder", goal="Repair.\n\n" + failures, workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert refused.success is False
    assert refused.returncode == MALFORMED_INVOCATION_RETURNCODE
    assert "could not be formed" in refused.output


@pytest.mark.parametrize("provider", ["claude-direct", "codex-routed"])
def test_one_control_heavy_gate_cannot_push_the_composed_goal_past_the_contract(
    tmp_path: Path, provider: str
):
    """Round-3 security P2-1. The escaping expands every control character to
    four (`\\x00`), so ONE failing gate whose 2500-character tail is all NUL
    escapes to 10000 characters -- past the Provider Contract's 8000, which
    `ProviderTask.validate` enforces by raising `ProviderError` out of the
    routed worker's `run`, and `acceptance()` does not catch it. Provider-
    controlled text ended the flow with an exception.

    Driven from a real provider that floods stdout with NUL and exits
    nonzero, through the real worker, into a `GateResult`, and composed. The
    specimen is proven LIVE first: its un-capped escaped form is refused by
    the contract as it stands. The composed goal then stays within the
    flow's bound, carries a marker whose count is the count actually left
    out, keeps the ESCAPED end of the tail rather than any NUL, and the
    ROUTED worker -- the surface that validates -- runs it without raising.
    The ledger's record is untouched by any of this: it still holds the NUL
    and no marker.
    """
    flood = _emitting_cli(
        tmp_path, "nul-flood", b"\x00" * REPAIR_DETAIL_TAIL_CHARACTERS, exit_code=3
    )
    failed = _worker_for(provider, flood).run(
        role="application-builder", goal="probe", workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert failed.returncode == 3 and failed.output.count("\x00") == REPAIR_DETAIL_TAIL_CHARACTERS
    gate = GateResult("application-builder", False, failed.output, failed.command, failed.returncode)

    quoted_tail = gate.detail[-REPAIR_DETAIL_TAIL_CHARACTERS:]
    escaped_tail = sanitised_for_composition(quoted_tail)
    uncapped = GOAL_OPENING.format(attempt=1) + f"{gate.name}: {escaped_tail}"
    assert _contract_refuses(uncapped), (
        "the specimen is not live: the un-capped escaped goal passes the contract"
    )

    goal = compose_repair_goal(1, [gate])
    assert len(goal) <= COMPOSED_GOAL_MAX_CHARACTERS
    assert not _contract_refuses(goal)
    assert "\x00" not in goal
    (omitted,) = _omitted_per_marker(goal)
    marker = _OMISSION_MARKER.search(goal).group(0)
    entry = goal[len(GOAL_OPENING.format(attempt=1)):]
    assert entry.startswith(f"{gate.name}: {marker}")
    kept = entry[len(f"{gate.name}: {marker}"):]
    assert len(marker) + len(kept) == REPAIR_DETAIL_TAIL_CHARACTERS
    assert kept == escaped_tail[-len(kept):], "the kept part is the END of the escaped tail"
    assert omitted == len(escaped_tail) - len(kept), "the marker names the count actually omitted"

    record = failing_gate_details([gate])
    assert record == f"{gate.name}: {quoted_tail}"
    assert "\x00" in record and not _omitted_per_marker(record)

    ok_cli = _fake_cli(tmp_path, "ok-after-flood", stdout='{"session_id": "r-2"}')
    accepted = _routed_for(provider, ok_cli).run(  # must not raise ProviderError
        role="application-builder", goal=goal, workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert accepted.success is True, accepted.output
    with pytest.raises(ProviderError, match="exceeds"):
        _routed_for(provider, ok_cli).run(
            role="application-builder", goal=uncapped, workspace=tmp_path,
            allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
        )


def test_four_ordinary_failing_gates_compose_within_the_bound_and_the_record_does_not(
    tmp_path: Path,
):
    """The PRE-EXISTING shape, disclosed in the PR body of the earlier rounds
    and now closed: four failing gates quoting 2500 ordinary characters each
    were already more than the contract's 8000 before any escaping existed.
    Ordinary text escapes to itself, so the un-capped composition is exactly
    the opening sentence plus the ledger's record -- which lets this test
    reconstruct it without re-implementing the function -- and the contract
    refuses that. The composed goal is held to the flow's bound, keeps the
    START (the gates in the order they failed) behind a marker on its own
    line whose count is the count actually omitted, and the routed worker
    runs it. The record stays whole: every gate's full 2500 characters, no
    marker, longer than the contract allows, because it is evidence and not
    an argument.
    """
    gates = [
        GateResult(f"gate-{index}", False, f"{index}:" + "y" * 3000)
        for index in range(4)
    ]
    record = failing_gate_details(gates)
    assert len(record) > CONTRACT_GOAL_MAX_CHARACTERS
    for index in range(4):
        assert f"gate-{index}: " + "y" * REPAIR_DETAIL_TAIL_CHARACTERS in record
    assert not _omitted_per_marker(record)

    uncapped = GOAL_OPENING.format(attempt=3) + record
    assert _contract_refuses(uncapped), "the specimen is not live"

    goal = compose_repair_goal(3, gates)
    assert len(goal) == COMPOSED_GOAL_MAX_CHARACTERS
    assert not _contract_refuses(goal)
    (omitted,) = _omitted_per_marker(goal)
    marker = _OMISSION_MARKER.search(goal).group(0)
    assert goal.endswith("\n" + marker), "the total-bound marker sits last, on its own line"
    kept = goal[: -len("\n" + marker)]
    assert uncapped.startswith(kept), "the kept part is the START of the un-capped goal"
    assert omitted == len(uncapped) - len(kept), "the marker names the count actually omitted"
    assert "gate-0: " in goal and "gate-1: " in goal, "the earliest gates are the ones kept"

    ok_cli = _fake_cli(tmp_path, "ok-after-four", stdout=JSONL_EVENT)
    accepted = _routed_for("codex-routed", ok_cli).run(  # must not raise ProviderError
        role="application-builder", goal=goal, workspace=tmp_path,
        allowed_tools=("Read",), max_turns=1, timeout_seconds=30,
    )
    assert accepted.success is True, accepted.output


def test_each_gates_escaped_tail_is_bounded_on_its_own_so_one_cannot_crowd_out_the_rest():
    """The per-gate bound is what makes the total bound fair: a hostile gate
    whose tail escapes to four times its length is cut back to the length its
    raw tail would have had, so a quiet gate after it is quoted whole. And a
    gate that PASSED is not quoted at all."""
    hostile = GateResult("hostile", False, "\x1b" * REPAIR_DETAIL_TAIL_CHARACTERS)
    quiet = GateResult("quiet", False, "verdict: FAILED because of x")
    passed = GateResult("green", True, "all good")
    goal = compose_repair_goal(2, [hostile, quiet, passed])
    assert "quiet: verdict: FAILED because of x" in goal
    assert "green" not in goal and "all good" not in goal
    body = goal[len(GOAL_OPENING.format(attempt=2)):]
    hostile_entry, quiet_entry = body.split("\n\n")
    assert quiet_entry == "quiet: verdict: FAILED because of x"
    assert len(hostile_entry) == len("hostile: ") + REPAIR_DETAIL_TAIL_CHARACTERS
    assert hostile_entry.endswith("\\x1b") and "\x1b" not in goal
    (omitted,) = _omitted_per_marker(goal)
    assert omitted == 4 * REPAIR_DETAIL_TAIL_CHARACTERS - (
        REPAIR_DETAIL_TAIL_CHARACTERS - len(_OMISSION_MARKER.search(goal).group(0))
    )


def test_the_composed_goal_bound_sits_under_the_contracts_own_with_headroom():
    """The flow's bound is measured against the CONTRACT's, asked of the
    contract: a goal of exactly the flow's bound validates, a goal one over
    the contract's does not, and the gap is wide enough that a longer
    opening sentence cannot close it unnoticed. If `ProviderTask.validate`
    ever moved its ceiling, this is the test that would say so."""
    assert not _contract_refuses("g" * COMPOSED_GOAL_MAX_CHARACTERS)
    assert not _contract_refuses("g" * CONTRACT_GOAL_MAX_CHARACTERS)
    assert _contract_refuses("g" * (CONTRACT_GOAL_MAX_CHARACTERS + 1))
    assert CONTRACT_GOAL_MAX_CHARACTERS - COMPOSED_GOAL_MAX_CHARACTERS >= 500
    assert len(GOAL_OPENING.format(attempt=99)) < 500


def test_composition_escapes_every_c0_control_except_layout():
    """The exact character set: NUL and every other C0 control is replaced
    by its `\\xNN` escape; tab, newline and carriage return are layout and
    survive; DEL (0x7F) is not C0 and is left alone -- `subprocess.run`
    accepts it, and the rule is stated as C0 so that a reader is not told
    more was sanitised than was. Ordinary text, including non-ASCII, passes
    through unchanged.
    """
    every_c0 = "".join(chr(code) for code in range(0x20))
    out = sanitised_for_composition(every_c0 + "\x7f" + "plain ’ text")
    for code in range(0x20):
        if chr(code) in "\t\n\r":
            assert chr(code) in out, f"layout character {code:#04x} was removed"
            assert f"\\x{code:02x}" not in out
        else:
            assert chr(code) not in out, f"control {code:#04x} survived"
            assert f"\\x{code:02x}" in out, f"control {code:#04x} was not escaped legibly"
    assert "\x7f" in out
    assert "plain ’ text" in out
    assert sanitised_for_composition("untouched") == "untouched"


def test_the_flows_repair_path_composes_the_goal_only_through_compose_repair_goal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """BEHAVIOURAL, not a source grep (round-3 test NEW-5: a grep is
    satisfiable by a comment). `acceptance()` is driven for real over a bare
    project directory -- its gate profile substituted with one failing gate,
    its worker with a stub that records what it was asked to run and fails,
    so the loop makes exactly one repair attempt -- and the module's
    `compose_repair_goal` is replaced by a spy. The flow must call the spy
    with the attempt number and the FAILING GATES, hand the worker exactly
    what the spy returned as the goal, and record `failing_gate_details` of
    those same gates in the ledger. A flow that composed the goal by hand
    would reach the worker without ever calling the spy.

    The source scan that remains is the one a grep can honestly answer: the
    goal's opening sentence is spelled exactly once across ALL of `src/`, in
    `compose_repair_goal`, so no other module composes a look-alike.
    """
    flow = DevelopmentFlow(tmp_path, worker_mode="claude-code")
    failing = GateResult("unit tests", False, "3 failed, 2 passed\nFAILED tests/test_x.py::t")
    monkeypatch.setattr(flow, "_acceptance_gates", lambda: [failing])
    monkeypatch.setenv("FORGE_MAX_REPAIR_ATTEMPTS", "1")

    composed: list[tuple[int, list[GateResult]]] = []

    def spy(attempt: int, gates: list[GateResult]) -> str:
        composed.append((attempt, list(gates)))
        return "SPY-COMPOSED GOAL"

    monkeypatch.setattr(development_flow, "compose_repair_goal", spy)

    asked: list[dict] = []

    class StubWorker:
        def run(self, **kwargs):
            asked.append(kwargs)
            return WorkerResult(kwargs["role"], kwargs["goal"], False, "stub: not repaired",
                                returncode=1)

    flow.worker = StubWorker()
    flow.acceptance()

    assert composed == [(1, [failing])], composed
    assert len(asked) == 1 and asked[0]["goal"] == "SPY-COMPOSED GOAL", asked
    assert asked[0]["role"] == "application-builder"
    events = [
        json.loads(line)
        for line in (tmp_path / ".nornyx/runs/build-events.jsonl").read_text(
            encoding="utf-8").splitlines()
        if line.strip()
    ]
    requested = [event for event in events if event.get("event_type") == "repair_requested"]
    assert len(requested) == 1, [event.get("event_type") for event in events]
    assert requested[0]["fields"]["failures"] == failing_gate_details([failing])
    assert requested[0]["fields"]["attempt"] == 1
    assert flow.data["repair_attempts"] == 1 and flow.data["accepted"] is False

    sentence = "Repair only these failing gates for attempt"
    spelled_in = [
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "src").rglob("*.py"))
        for _ in range(path.read_text(encoding="utf-8").count(sentence))
    ]
    assert spelled_in == ["src/nornyx_forge/development_flow.py"], spelled_in


def _windows_runtime_job(workflow: str) -> str:
    """The `windows-runtime` job's text, bounded at the NEXT job key, so a
    module list somewhere else in the workflow cannot satisfy a reader of it.
    A job key is a name at exactly two spaces; everything inside a job is
    indented further."""
    assert "\n  windows-runtime:\n" in workflow, "the windows-runtime job is gone"
    after = workflow.split("\n  windows-runtime:\n", 1)[1]
    return re.split(r"\n  [A-Za-z][\w-]*:", after, maxsplit=1)[0]


def _windows_job_pytest_commands(workflow: str) -> list[str]:
    """The job's `python -m pytest ...` INVOCATION lines -- what the job runs
    -- and nothing else in its YAML.

    Round-7 finding F-1: the round-7 assertion asked whether this module's
    path appeared anywhere in the job block, and the SAME COMMIT added a YAML
    comment inside that block naming it. Deleting the module from the pytest
    command therefore stayed green everywhere; only deleting the comment too
    went red. A comment is not a run. Comment lines are dropped here and only
    lines that invoke pytest survive, so what is read is the command."""
    return [line for line in _windows_runtime_job(workflow).splitlines()
            if "python -m pytest" in line and not line.lstrip().startswith("#")]


def _windows_job_code(workflow: str) -> str:
    """The job's non-comment lines, for reading the job's own guards. Same
    reason as above: `# if skipped:` inside a comment is not a guard."""
    return "\n".join(line for line in _windows_runtime_job(workflow).splitlines()
                     if not line.lstrip().startswith("#"))


#: A `windows-runtime` job that MENTIONS this module in a comment and does not
#: run it -- built here as text, so the negative control IS the specimen and
#: not a description of one. This is the shape round 7's assertion accepted.
_COMMENT_ONLY_JOB = (
    "jobs:\n"
    "  windows-runtime:\n"
    "    runs-on: windows-latest\n"
    "    steps:\n"
    "      # tests/test_provider_execution.py is here because the CHANGELOG said so\n"
    "      - name: Windows runtime tests\n"
    "        run: |\n"
    "          python -m pytest tests/test_windows_runtime.py -q -rs\n"
    "  a-later-job:\n"
    "    runs-on: ubuntu-latest\n"
)


def test_this_suite_is_named_by_the_windows_runtime_ci_job():
    """The claim that this suite runs on Windows CI, made checkable.

    `_provider_env()`'s stripping is a property of the environment a REAL
    child process inherits, and that is a platform property: asserting it only
    on the Linux matrix leaves the Windows behaviour asserted by nothing. The
    CHANGELOG said the windows-runtime job ran this module; it did not, and
    nothing was reading the workflow to notice (round-6 test T-P3-2). This
    reads it.

    A pin on the sentence would have been the smaller fix and the wrong one:
    what was false was not the wording but the module list, so what is pinned
    is the module list -- as it is SPELLED IN THE PYTEST COMMAND. Round 7
    pinned it as "appears anywhere in the job block", and the YAML comment
    that same commit added satisfied that, so removing this module from the
    command alone stayed green (round-7 finding F-1). What is asserted now is
    the invocation line; the comment-only specimen below is the job that must
    be REFUSED, and the same specimen with the module added to the command is
    the job that must be ACCEPTED, so the reader is falsified here rather than
    trusted."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    commands = _windows_job_pytest_commands(workflow)
    assert commands, "the windows-runtime job invokes pytest on no line"
    assert any("tests/test_provider_execution.py" in line for line in commands), (
        "the windows-runtime CI job's pytest command does not name this module, so "
        "`_provider_env()`'s stripping is asserted on Linux only -- which is what "
        f"round 6 claimed it was not: {commands}")
    # The job's own guards, which is what makes running there mean anything: a
    # skip fails it, so this module cannot arrive and quietly skip. Read from
    # the job's CODE, for the same reason the module list is.
    code = _windows_job_code(workflow)
    assert "if skipped:" in code and "sys.exit(1)" in code, (
        "the windows-runtime job no longer fails on a skip")

    # The reader's own controls. NEGATIVE: the comment-only job satisfies
    # round 7's assertion, and must not satisfy this one.
    assert "tests/test_provider_execution.py" in _windows_runtime_job(_COMMENT_ONLY_JOB), (
        "the specimen no longer reproduces the round-7 finding it exists to reproduce")
    assert not any("tests/test_provider_execution.py" in line
                   for line in _windows_job_pytest_commands(_COMMENT_ONLY_JOB)), (
        "a job that only MENTIONS this module in a comment satisfies the reader, which "
        "is exactly round-7 finding F-1")
    # POSITIVE: the same job with the module in its command is accepted, so
    # the negative above is not a reader that finds nothing at all.
    runs_it = _COMMENT_ONLY_JOB.replace(
        "python -m pytest tests/test_windows_runtime.py -q -rs",
        "python -m pytest tests/test_windows_runtime.py tests/test_provider_execution.py -q -rs")
    assert any("tests/test_provider_execution.py" in line
               for line in _windows_job_pytest_commands(runs_it)), (
        "the reader does not see a module that IS in the pytest command")
