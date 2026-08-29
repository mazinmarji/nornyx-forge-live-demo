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

THE REGISTRY REFUSES WHAT IT CANNOT SERVE. `codex` is a declared provider name
— the capsule closed that vocabulary in PR-1 — but no Codex adapter exists in
this slice, and the registry says so with `unavailable` semantics rather than
handing back a stub that pretends. A name in the vocabulary is not a
capability, and nothing here converts one into the other quietly.

`layer.adapter`: this module touches the outside world only by delegating to
the declared worker adapter; it starts no process of its own.
"""

from __future__ import annotations

from pathlib import Path

from .claude_worker import ClaudeCodeWorker
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


def get_provider(name: str) -> ClaudeProviderAdapter:
    """The one place a provider name becomes an adapter.

    `codex` is refused honestly: it is a declared name with no adapter in this
    slice, and the refusal names the gap instead of stubbing over it. Any
    other name is refused as undeclared. Growing either set is a diff — to the
    capsule's vocabulary for names, to this dispatch for adapters.
    """
    if name == "claude":
        adapter = ClaudeProviderAdapter()
        validate_adapter_identity(adapter)
        return adapter
    if name == "codex":
        raise ProviderError(
            "codex is a declared provider name, but no Codex adapter exists in "
            "this slice; it arrives with the next slice and until then the "
            "honest answer is refusal, not a stub"
        )
    raise ProviderError(f"provider {name!r} is not a declared provider name")
