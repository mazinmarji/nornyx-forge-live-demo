"""The architect is told that any .nyx it writes must pass `nornyx check`.

A greenfield architect wrote `.nornyx/contracts/architecture.nyx` with no
`project:` block, which `nornyx check` refuses, and no stage said the file had
to validate. This does not make the file a gate: nothing here checks it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import nornyx_forge.development_flow as flow_module
from nornyx_forge.development_flow import DevelopmentFlow
from nornyx_forge.models import WorkerResult


class _RecordingWorker:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def run(self, **request: Any) -> WorkerResult:
        self.calls.append(dict(request))
        return WorkerResult(role=str(request["role"]), goal=str(request["goal"]),
                            success=True, output="ok", command=("recording-worker",))


def test_the_architect_goal_requires_nyx_files_to_pass_nornyx_check(tmp_path: Path, monkeypatch):
    (tmp_path / "BRD.md").write_text(
        "# BRD\n\n## BRD-001 Purpose\n\nAdd numbers.\n\n"
        "## BRD-002 Functional requirements\n\n### BRD-F-001 Add\n\nAdd two numbers.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(flow_module, "trusted_greenfield_gates", lambda _root, **_kw: ([], {}))
    flow = DevelopmentFlow(tmp_path, worker_mode="claude-code", repo_mode="greenfield")
    worker = _RecordingWorker()
    flow.worker = worker
    flow.run_sequential()
    architect = next(call for call in worker.calls if call["role"] == "solution-architect")
    assert "nornyx check" in architect["goal"]
    assert ".nyx" in architect["goal"]
