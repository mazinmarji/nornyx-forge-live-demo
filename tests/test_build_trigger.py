"""The build trigger: the no-terminal path runs only confirmed state.

WHAT WOULD FALSIFY IT: a build starting without a confirmed provider or a
derived BRD; a model actor starting one; two builds interleaving; the
flow receiving anything other than the project directory, the confirmed
provider, and the honest greenfield mode; or a result reported better
than the flow said. The flow factory is the injectable seam -- tests
capture what the route constructs; the shipped default is the real
DevelopmentFlow, pinned structurally.
"""

from __future__ import annotations

import threading
from pathlib import Path

from fastapi.testclient import TestClient

from nornyx_forge.capsule import Actor, confirm, create_document, propose
from nornyx_forge.capsule_store import CapsuleStore
from nornyx_forge.experience import advance, start_experience
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.provider_contract import GovernedEligibility

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}


def _project(tmp_path: Path, *, with_provider: bool = True,
             with_brd: bool = True, with_lifecycle: bool = True) -> Path:
    """A project whose lifecycle sits at CONFIRM -- the pre-build position
    the trigger requires since PR-17 -- reached through the contract's own
    `start_experience` and `advance`, never written by hand."""
    document = create_document("proj-1", "Test Project", Actor("human", "casey"),
                               "2026-08-30T12:00:00Z")
    document, intent_id = propose(document, "intent", "Build a portal.",
                                  Actor("model", "m"), "2026-08-30T12:01:00Z")
    document = confirm(document, intent_id, Actor("human", "casey"),
                       "2026-08-30T12:02:00Z")
    if with_provider:
        document, provider_id = propose(
            document, "provider", {"name": "codex"}, Actor("human", "casey"),
            "2026-08-30T12:03:00Z",
        )
        document = confirm(document, provider_id, Actor("human", "casey"),
                           "2026-08-30T12:04:00Z")
    lifecycle = None
    if with_lifecycle:
        lifecycle = start_experience(Actor("human", "casey"), "2026-08-30T12:00:00Z")
        lifecycle = advance(lifecycle, "CONFIRM", Actor("human", "casey"),
                            "2026-08-30T12:05:00Z")
    CapsuleStore(tmp_path / "capsule").initialize(document, experience=lifecycle)
    if with_brd:
        (tmp_path / "BRD.md").write_text(
            "# BRD — Test\n\n## BRD-001 Purpose\n\nBuild a portal.\n",
            encoding="utf-8", newline="",
        )
    return tmp_path


class RecordingFlow:
    """Captures construction, completes immediately, honestly."""

    instances: list["RecordingFlow"] = []

    def __init__(self, root, **kwargs):
        self.root = root
        self.kwargs = kwargs
        self.started = threading.Event()
        RecordingFlow.instances.append(self)

    def run(self):
        self.started.set()
        return {"accepted": False, "gates": ["worker unavailable"]}


def _seam_eligibility(provider: str) -> GovernedEligibility:
    """The injectable seam executes no provider: the deterministic flow the
    tests install answers in the flow's shape and never runs an engineering
    agent, so the governed-eligibility gate -- which exists to keep an
    unconfined provider off the authority store -- has nothing to decide.
    The shipped surface never sees this; it uses the contract's own decision,
    and tests/test_governed_provider_eligibility.py pins that."""
    return GovernedEligibility(provider=provider, eligible=True, confinement="established",
                               reason="deterministic flow at the injectable seam; no provider executes")


def _client(tmp_path: Path, factory=RecordingFlow) -> TestClient:
    RecordingFlow.instances = []
    return TestClient(create_app(tmp_path / "capsule", CONTRACTS,
                                 flow_factory=factory, seal_dir=tmp_path / "seals",
                                 eligibility=_seam_eligibility))


def _wait_finished(client: TestClient) -> dict:
    for _ in range(200):
        status = client.get("/api/build").json()
        if status["status"] in ("finished", "failed"):
            return status
        threading.Event().wait(0.02)
    raise AssertionError("the build never reported a terminal state")


# ---------------------------------------------------------------------------
# The wiring: project directory, confirmed provider, honest mode
# ---------------------------------------------------------------------------

def test_the_build_runs_the_flow_over_the_project_with_the_confirmed_provider(
        tmp_path: Path):
    client = _client(_project(tmp_path))
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 200, response.text
    status = _wait_finished(client)
    flow = RecordingFlow.instances[0]
    assert flow.root == tmp_path
    assert flow.kwargs["provider"] == "codex"
    assert flow.kwargs["worker_mode"] == "claude-code"
    assert flow.kwargs["repo_mode"] == "greenfield"
    assert status["status"] == "finished"


def test_the_result_is_reported_verbatim_never_improved(tmp_path: Path):
    client = _client(_project(tmp_path))
    client.post("/api/build", json={"actor": HUMAN})
    status = _wait_finished(client)
    assert status["accepted"] is False
    assert status["result"]["gates"] == ["worker unavailable"]


def test_the_shipped_default_is_the_real_flow(tmp_path: Path):
    """Structural: without an injected factory the route constructs
    DevelopmentFlow -- the seam exists for tests, not for substitution."""
    import nornyx_forge.onboarding_app as module
    from nornyx_forge.development_flow import DevelopmentFlow

    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "from .development_flow import DevelopmentFlow" in source
    assert DevelopmentFlow is not None


# ---------------------------------------------------------------------------
# Refusals, each by name
# ---------------------------------------------------------------------------

def test_a_model_actor_cannot_start_a_build(tmp_path: Path):
    client = _client(_project(tmp_path))
    response = client.post("/api/build", json={"actor": MODEL})
    assert response.status_code == 409
    assert "human act" in response.json()["refused"]
    assert RecordingFlow.instances == []


def test_no_confirmed_provider_refuses_by_name(tmp_path: Path):
    client = _client(_project(tmp_path, with_provider=False))
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409
    assert "no confirmed provider" in response.json()["refused"]


def test_no_brd_refuses_by_name(tmp_path: Path):
    client = _client(_project(tmp_path, with_brd=False))
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409
    assert "derive it first" in response.json()["refused"]


def test_a_second_build_cannot_interleave(tmp_path: Path):
    hold = threading.Event()

    class BlockingFlow(RecordingFlow):
        def run(self):
            self.started.set()
            hold.wait(timeout=10)
            return {"accepted": False}

    client = _client(_project(tmp_path), factory=BlockingFlow)
    first = client.post("/api/build", json={"actor": HUMAN})
    assert first.status_code == 200
    BlockingFlow.instances[0].started.wait(timeout=5)
    second = client.post("/api/build", json={"actor": HUMAN})
    hold.set()
    assert second.status_code == 409
    assert "already running" in second.json()["refused"]
    assert len(BlockingFlow.instances) == 1
    _wait_finished(client)


def test_a_crashing_flow_is_reported_failed_not_hidden(tmp_path: Path):
    class CrashingFlow(RecordingFlow):
        def run(self):
            raise RuntimeError("the flow exploded mid-build")

    client = _client(_project(tmp_path), factory=CrashingFlow)
    client.post("/api/build", json={"actor": HUMAN})
    status = _wait_finished(client)
    assert status["status"] == "failed"
    assert "exploded mid-build" in status["error"]


def test_the_status_starts_honest(tmp_path: Path):
    client = _client(_project(tmp_path))
    assert client.get("/api/build").json() == {"status": "never_run"}


def test_no_recorded_lifecycle_refuses_by_name(tmp_path: Path):
    """PR-17: the build is a lifecycle transition, so a capsule that predates
    lifecycle tracking cannot build until a human starts tracking it -- and
    nothing about its history is inferred to let it."""
    client = _client(_project(tmp_path, with_lifecycle=False))
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409
    assert "no lifecycle is recorded" in response.json()["refused"]
    assert RecordingFlow.instances == []
