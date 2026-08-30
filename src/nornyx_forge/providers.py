"""Provider adapters and the registry. The Claude path, wrapped — not moved.

BEHAVIOUR PRESERVATION, stated as the design rule it is: `claude_worker` is
untouched and stays at its import path — architecture guards pin it there, its
consumers (`development_flow`, `demo_app.agentic`) keep constructing it
directly, and its observable behaviour (inputs, outputs, failure semantics,
the 127/124 conventions, JSON session parsing) is the thing the contract was
shaped around. The adapter here DELEGATES to it and normalizes the result
verbatim through `result_from_worker`; a conformance test asserts field-level
equality between the raw worker result and the adapter's, so any drift between
the two paths is a red test, not a discovery.

BOTH DECLARED PROVIDERS ARE SERVED, each by delegation to its own worker, both
normalized through the same `result_from_worker` so the failure vocabulary
cannot fork per provider. The registry still refuses undeclared names, and
serving both names claims nothing about their equivalence — conformance is
per-adapter, and cross-adapter equivalence is a separate, pre-registered
proof that no line in this module asserts.

`layer.adapter`: this module touches the outside world only by delegating to
the declared worker adapter; it starts no process of its own.
"""

from __future__ import annotations

from pathlib import Path

from .claude_worker import ClaudeCodeWorker
from .codex_worker import CodexWorker
from .provider_contract import (
    ProviderError,
    ProviderResult,
    ProviderTask,
    result_from_worker,
    validate_adapter_identity,
)


class ClaudeProviderAdapter:
    """The existing Claude path behind the contract. Delegation, not logic."""

    name = "claude"

    def __init__(self, worker: ClaudeCodeWorker | None = None) -> None:
        # Injectable for conformance testing with a controlled executable;
        # the default is exactly the worker every current consumer constructs.
        self._worker = worker if worker is not None else ClaudeCodeWorker()

    def available(self) -> bool:
        return self._worker.available()

    def run_task(self, task: ProviderTask) -> ProviderResult:
        task.validate()
        worker_result = self._worker.run(
            role=task.role,
            goal=task.goal,
            workspace=Path(task.workspace),
            allowed_tools=task.allowed_tools,
            max_turns=task.max_turns,
            timeout_seconds=task.timeout_seconds,
        )
        return result_from_worker(self.name, worker_result)


class CodexProviderAdapter:
    """The Codex path behind the same contract. Delegation, not logic.

    Identical in shape to the Claude adapter on purpose: both delegate to a
    worker with the same surface and normalize through the same
    `result_from_worker`, so the contract vocabulary cannot fork per provider.
    Nothing here claims the two are EQUIVALENT — conformance is per-adapter,
    and cross-adapter equivalence is a separate, pre-registered proof.
    """

    name = "codex"

    def __init__(self, worker: CodexWorker | None = None) -> None:
        self._worker = worker if worker is not None else CodexWorker()

    def available(self) -> bool:
        return self._worker.available()

    def run_task(self, task: ProviderTask) -> ProviderResult:
        task.validate()
        worker_result = self._worker.run(
            role=task.role,
            goal=task.goal,
            workspace=Path(task.workspace),
            allowed_tools=task.allowed_tools,
            max_turns=task.max_turns,
            timeout_seconds=task.timeout_seconds,
        )
        return result_from_worker(self.name, worker_result)


def get_provider(name: str) -> ClaudeProviderAdapter | CodexProviderAdapter:
    """The one place a provider name becomes an adapter.

    Both declared names are served; an undeclared name is refused. Growing
    either set is a diff — to the capsule's vocabulary for names, to this
    dispatch for adapters. Serving a name is not claiming the adapters are
    equivalent: that proof is pre-registered work, not registry behaviour.
    """
    if name == "claude":
        adapter = ClaudeProviderAdapter()
        validate_adapter_identity(adapter)
        return adapter
    if name == "codex":
        adapter = CodexProviderAdapter()
        validate_adapter_identity(adapter)
        return adapter
    raise ProviderError(f"provider {name!r} is not a declared provider name")
