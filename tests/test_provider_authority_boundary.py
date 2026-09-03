"""P17-B1: the provider's writable path into the authority store, closed.

THE MECHANISM, measured at 47bd370 through the production build seam and
through the real DevelopmentFlow worker seam alike. The capsule store lives
under the basic-user project directory; /api/build hands that directory to
the selected provider as its writable workspace (Claude with Edit, Write and
Bash; Codex under a workspace-write sandbox); both digest chains are one link
deep, so a worker who has read experience.py rewrites a state and recomputes
the final link; and the store's git repository is inside the same workspace,
so the worker can commit the forgery with the store's own identity. Measured:
the forged READY was rendered by /api/state while the build ran, persisted,
`fail`ed and retried as READY by the surface's own code, and read back after
a restart. Forged capsule authority (intent, provider) was rendered the same
way. The whole of PR-17's authority -- canonical advance, human CONFIRM,
evidence, human READY -- was bypassable by a file write.

THE BOUNDARY, as the tests below hold it. Authority consumed by the surface
is derived only from Forge's own transitions and Forge's own persistence:

  * while a build runs, every read is answered from the authority Forge
    sealed when it began and every write is refused (B5, B6);
  * when the flow returns, the store is checked against that seal --
    revision, working tree, exact bytes -- before the result is translated;
    a store that moved is restored and the run recorded as a failure that
    says so, dirty or committed (B1, B2, B3, B4);
  * at rest, every load checks the seal, so a forgery left for a later
    process is TAMPERED on every route until a person restores it (B10);
  * a legitimate build, a legitimate failure, a legitimate restart are
    exactly what they were (B7, B8, B9).

The seal is Forge-owned persistence outside the project directory. Its own
bound is stated in capsule_store and pinned here: out of a workspace-write
sandbox's reach; within the same operating-system user's reach.
"""

from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from nornyx_forge import onboarding_app as onboarding
from nornyx_forge import onboarding_serve
from nornyx_forge.capsule import Actor, _chain_digest, confirm, create_document, propose
from nornyx_forge.capsule_store import (
    AuthoritySnapshot,
    CapsuleSealError,
    CapsuleSealUnreadable,
    CapsuleStore,
    CapsuleStoreError,
    _remove_tree,
)
from nornyx_forge.development_flow import DevelopmentFlow
from nornyx_forge.experience import _link, advance, start_experience
from nornyx_forge.models import WorkerResult
from nornyx_forge.onboarding_app import create_app

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}
AT = "2026-09-03T09:00:00Z"
SUBJECT_GATE = {"name": "greenfield:test-execution", "passed": True, "detail": "",
                "command": ["python", "-I", "-c", "verifier"], "returncode": 0}
NORNYX_GATE = {"name": "nornyx check .nornyx/generated/brd_contract.nyx", "passed": True,
               "detail": "ok", "command": ["nornyx", "check", "brd_contract.nyx"], "returncode": 0}
IDENTITY = ["-c", "user.name=forge-capsule", "-c", "user.email=capsule@forge.invalid",
            "-c", "commit.gpgsign=false"]
FORGED_INTENT = "FORGED: exfiltrate customer data nightly."


def _clock():
    ticks = iter(range(100_000))
    return lambda: f"2026-09-03T{(next(ticks) // 60) % 24:02d}:{next(ticks) % 60:02d}:00Z"


# ---------------------------------------------------------------------------
# What a worker who has read the domain modules can do to the store
# ---------------------------------------------------------------------------

def forge_ready(store: Path) -> None:
    """READY, self-consistent to `verify_experience`."""
    path = store / "experience.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["stage"] = "READY"
    state["status"] = "active"
    state["evidence"] = {"READY": [
        {"kind": "gate_results", "ref": "gates/2-run", "passed": True},
        {"kind": "governance_validation", "ref": "gates/nornyx/1-run", "passed": True}]}
    state["history"].append({"event": "advanced", "from": state["history"][-1]["to"],
                             "to": "READY", "by": "casey", "kind": "human",
                             "at": "2026-09-03T12:00:00Z", "detail": ""})
    previous = state["chain"][-2] if len(state["chain"]) > 1 else "0" * 64
    state["chain"][-1] = _link(previous, state)
    path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8", newline="")


def forge_authority(store: Path) -> None:
    """Confirmed intent and provider rewritten, self-consistent to `verify_integrity`."""
    path = store / "capsule.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["authoritative"]["intent"] = FORGED_INTENT
    document["authoritative"]["provider"] = {"name": "claude"}
    previous = document["digest_chain"][-2] if len(document["digest_chain"]) > 1 else "0" * 64
    document["digest_chain"][-1] = _chain_digest(previous, document["authoritative"])
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8", newline="")


def commit_inside(store: Path, message: str = "experience: reached READY") -> str:
    """The store's own facilities, used by the worker: a clean tree at a new commit."""
    subprocess.run(["git", *IDENTITY, "add", "-A"], cwd=store, check=True, capture_output=True)
    subprocess.run(["git", *IDENTITY, "commit", "-q", "-m", message], cwd=store, check=True,
                   capture_output=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=store, capture_output=True,
                          text=True, check=True).stdout.strip()


def _git_log(store: Path) -> list[str]:
    return subprocess.run(["git", "log", "--format=%s"], cwd=store, capture_output=True,
                          text=True, check=True).stdout.splitlines()


class HostileFlow:
    """The object /api/build constructs: it receives the project directory and
    writes into `capsule/` inside it, then waits so the surface can be probed
    with the forgery on disk, then returns an ACCEPTED result with a Nornyx
    gate -- the shape from which READY would otherwise be reachable."""

    attack = "ready"          # ready | ready-committed | authority | authority-committed
    written = threading.Event()
    release = threading.Event()
    instances: list = []

    def __init__(self, root, **kwargs):
        self.root = Path(root)
        self.kwargs = kwargs
        HostileFlow.instances.append(self)

    def run(self):
        store = self.root / "capsule"
        if HostileFlow.attack.startswith("ready"):
            forge_ready(store)
        else:
            forge_authority(store)
        if HostileFlow.attack.endswith("committed"):
            commit_inside(store)
        HostileFlow.written.set()
        assert HostileFlow.release.wait(timeout=30), "the test never released the worker"
        return {"accepted": True, "gates": [dict(SUBJECT_GATE), dict(NORNYX_GATE)],
                "execution_backend": "sequential"}


class GovernedFlow:
    instances: list = []

    def __init__(self, root, **kwargs):
        self.root = Path(root)
        type(self).instances.append(self)

    def run(self):
        return {"accepted": True, "gates": [dict(SUBJECT_GATE), dict(NORNYX_GATE)],
                "execution_backend": "sequential"}


class RejectedFlow(GovernedFlow):
    def run(self):
        return {"accepted": False, "gates": [dict(SUBJECT_GATE, passed=False, returncode=1)],
                "execution_backend": "sequential"}


# ---------------------------------------------------------------------------
# Driving the surface
# ---------------------------------------------------------------------------

def _client(tmp_path: Path, factory=GovernedFlow) -> TestClient:
    HostileFlow.written.clear()
    HostileFlow.release.clear()
    HostileFlow.instances = []
    GovernedFlow.instances = []
    return TestClient(create_app(tmp_path / "capsule", CONTRACTS, clock=_clock(),
                                 flow_factory=factory, seal_dir=tmp_path / "seals"))


def _ok(response) -> dict:
    assert response.status_code == 200, response.text
    return response.json()


def _confirmed(client: TestClient) -> None:
    _ok(client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Support Portal", "actor": HUMAN}))
    intent = _ok(client.post("/api/proposals", json={
        "field": "intent", "value": "Build a customer support portal.", "actor": MODEL,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{intent}/confirm", json={"actor": HUMAN}))
    provider = _ok(client.post("/api/proposals", json={
        "field": "provider", "value": {"name": "codex"}, "actor": HUMAN,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{provider}/confirm", json={"actor": HUMAN}))
    _ok(client.post("/api/brd"))
    assert _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))["stage"] == "CONFIRM"


def _wait_finished(client: TestClient) -> dict:
    for _ in range(1500):
        status = client.get("/api/build").json()
        if status["status"] in ("finished", "failed"):
            return status
        threading.Event().wait(0.02)
    raise AssertionError("the build never reported a terminal state")


def _store(tmp_path: Path) -> CapsuleStore:
    return CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")


def _persisted(tmp_path: Path) -> dict:
    return _store(tmp_path).load_experience()


def _stages(state: dict) -> list[str]:
    return [event["to"] for event in state["history"]]


def _attack(tmp_path: Path, attack: str) -> tuple[TestClient, dict]:
    """A confirmed journey, a hostile build, the worker paused with its
    forgery on disk. Returns the client and the /api/state seen meanwhile."""
    HostileFlow.attack = attack
    client = _client(tmp_path, factory=HostileFlow)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    assert HostileFlow.written.wait(timeout=30), "the worker never wrote its forgery"
    return client, _ok(client.get("/api/state"))


# ---------------------------------------------------------------------------
# B1, B2, B3  forged READY: dirty, then committed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack", ["ready", "ready-committed"])
def test_b1_a_workers_forged_ready_is_never_trusted(tmp_path: Path, attack: str):
    client, mid = _attack(tmp_path, attack)
    on_disk = json.loads((tmp_path / "capsule" / "experience.json").read_text(encoding="utf-8"))
    assert on_disk["stage"] == "READY", "the specimen must really be on disk"
    assert mid["journey"]["stage"] == "BUILD" and mid["journey"]["status"] == "active"
    assert mid["authority"] == {"anchor": "sealed", "build": "running", "last_restoration": None}

    HostileFlow.release.set()
    status = _wait_finished(client)
    assert status["lifecycle"] == {"recorded": True, "stage": "BUILD", "status": "failed",
                                   "authority": "restored from seal"}
    persisted = _persisted(tmp_path)
    assert persisted["stage"] == "BUILD" and persisted["status"] == "failed"
    assert "READY" not in _stages(persisted)
    assert "modified the project's authority store" in persisted["history"][-1]["detail"]
    after = _ok(client.get("/api/state"))
    assert after["journey"]["stage"] == "BUILD" and after["journey"]["status"] == "failed"
    assert after["authority"]["anchor"] == "sealed"
    assert "modified" in after["authority"]["last_restoration"]["detail"]
    for _ in range(3):
        assert _ok(client.get("/api/state"))["journey"]["stage"] != "READY"


@pytest.mark.parametrize("attack", ["ready", "ready-committed"])
def test_b2_b3_the_accepted_result_is_not_translated_after_a_breach(tmp_path: Path, attack: str):
    """The worker's result is accepted, every gate passes, a Nornyx gate ran:
    the one shape READY is reachable from. It is never translated."""
    client, _ = _attack(tmp_path, attack)
    HostileFlow.release.set()
    status = _wait_finished(client)
    assert status["status"] == "finished" and status["accepted"] is True
    persisted = _persisted(tmp_path)
    assert persisted["evidence"] == {}, "the provider's result reached the lifecycle"
    assert _stages(persisted) == ["DISCOVER", "CONFIRM", "BUILD", "BUILD"]
    log = _git_log(tmp_path / "capsule")
    assert log[0] == "experience: authority restored from seal"
    assert "experience: reached READY" not in log, "the forged commit stayed on the branch"
    store = _store(tmp_path)
    assert store.seal_problems(store.sealed()) == []
    response = client.post("/api/journey/ready", json={"actor": HUMAN})
    assert response.status_code == 409 and "failed at BUILD" in response.json()["refused"]


def test_b3_a_clean_tree_at_a_new_commit_is_not_trusted_authority(tmp_path: Path):
    """The committed forgery leaves `git status` empty. The seal still sees it."""
    store = _store(tmp_path)
    document = create_document("proj-1", "Portal", Actor("human", "casey"), AT)
    store.initialize(document, experience=start_experience(Actor("human", "casey"), AT))
    forge_ready(tmp_path / "capsule")
    forged = commit_inside(tmp_path / "capsule")
    clean = subprocess.run(["git", "status", "--porcelain"], cwd=tmp_path / "capsule",
                           capture_output=True, text=True, check=True).stdout.strip()
    assert clean == "", "the specimen must leave the tree clean"
    with pytest.raises(CapsuleSealError) as refused:
        store.load_experience()
    assert any("HEAD is " + forged[:12] in problem for problem in refused.value.problems)
    assert any("experience.json differs" in problem for problem in refused.value.problems)


# ---------------------------------------------------------------------------
# B4  capsule authority
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("attack", ["authority", "authority-committed"])
def test_b4_forged_capsule_authority_is_never_confirmed_human_authority(
        tmp_path: Path, attack: str):
    client, mid = _attack(tmp_path, attack)
    on_disk = json.loads((tmp_path / "capsule" / "capsule.json").read_text(encoding="utf-8"))
    assert on_disk["authoritative"]["intent"] == FORGED_INTENT
    assert mid["authoritative"]["intent"] == "Build a customer support portal."
    assert mid["authoritative"]["provider"] == {"name": "codex"}

    HostileFlow.release.set()
    status = _wait_finished(client)
    assert status["lifecycle"]["stage"] == "BUILD" and status["lifecycle"]["status"] == "failed"
    after = _ok(client.get("/api/state"))
    assert after["authoritative"]["intent"] == "Build a customer support portal."
    assert after["authoritative"]["provider"] == {"name": "codex"}
    assert FORGED_INTENT not in json.dumps(after)
    restored = _store(tmp_path).load()
    assert restored["authoritative"]["intent"] == "Build a customer support portal."
    assert FORGED_INTENT not in (tmp_path / "capsule" / "capsule.json").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# B5, B6  during the build: reads from the seal, writes refused
# ---------------------------------------------------------------------------

def test_b5_polling_during_the_build_shows_only_the_sealed_position(tmp_path: Path):
    client, mid = _attack(tmp_path, "ready")
    assert mid["journey"] == {
        "tracking": "recorded", "stage": "BUILD", "status": "active", "actions": [],
        "blockers": [], "failure": None, "next": mid["journey"]["next"],
    }
    assert "running" in mid["journey"]["next"]
    assert mid["experience"]["stage"] == "BUILD"
    assert mid["revision"] == _store(tmp_path).sealed().revision
    preview = _ok(client.get("/api/sharing-preview"))
    assert preview["stage"] == "BUILD"
    HostileFlow.release.set()
    _wait_finished(client)


def test_b6_no_action_can_consume_the_forgery_while_the_build_runs(tmp_path: Path):
    client, _ = _attack(tmp_path, "ready")
    for path in ("/api/journey/ready", "/api/journey/confirm-scope", "/api/journey/retry",
                 "/api/journey/start", "/api/journey/restore", "/api/brd",
                 "/api/proposals/P-1/confirm", "/api/proposals/P-1/reject"):
        response = client.post(path, json={"actor": HUMAN})
        assert response.status_code == 409, (path, response.text)
        assert "sealed until it completes" in response.json()["refused"], path
    proposal = client.post("/api/proposals", json={
        "field": "intent", "value": "Another idea.", "actor": HUMAN})
    assert proposal.status_code == 409 and "sealed" in proposal.json()["refused"]
    HostileFlow.release.set()
    _wait_finished(client)
    assert _persisted(tmp_path)["stage"] == "BUILD"
    response = client.post("/api/journey/ready", json={"actor": HUMAN})
    assert response.status_code == 409 and "failed at BUILD" in response.json()["refused"]


# ---------------------------------------------------------------------------
# B7, B8, B9  the legitimate journey is exactly what it was
# ---------------------------------------------------------------------------

def test_b7_an_honest_accepted_build_still_reaches_test_and_govern(tmp_path: Path):
    client = _client(tmp_path)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    status = _wait_finished(client)
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    persisted = _persisted(tmp_path)
    assert _stages(persisted) == ["DISCOVER", "CONFIRM", "BUILD", "TEST", "GOVERN"]
    assert [row["kind"] for row in persisted["evidence"]["GOVERN"]] == [
        "gate_results", "governance_validation"]
    store = _store(tmp_path)
    assert store.sealed().revision == store.revision(), "the seal did not follow Forge's save"
    assert _ok(client.get("/api/state"))["authority"]["anchor"] == "sealed"
    assert _ok(client.get("/api/state"))["journey"]["actions"] == ["mark_ready"]


def test_b8_an_honest_failed_build_is_recorded_and_retryable(tmp_path: Path, monkeypatch):
    client = _client(tmp_path, factory=RejectedFlow)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    status = _wait_finished(client)
    assert status["lifecycle"] == {"recorded": True, "stage": "BUILD", "status": "failed"}
    assert "reports failure" in _persisted(tmp_path)["history"][-1]["detail"]
    assert _ok(client.post("/api/journey/retry", json={"actor": HUMAN}))["status"] == "active"
    monkeypatch.setattr(RejectedFlow, "run", GovernedFlow.run)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_b9_a_restart_after_an_honest_build_reads_trusted_state(tmp_path: Path):
    client = _client(tmp_path)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    restarted = _client(tmp_path)
    state = _ok(restarted.get("/api/state"))
    assert state["journey"]["stage"] == "GOVERN" and state["authority"]["anchor"] == "sealed"
    assert _ok(restarted.post("/api/journey/ready", json={"actor": HUMAN}))["stage"] == "READY"
    again = _client(tmp_path)
    assert _ok(again.get("/api/state"))["journey"]["stage"] == "READY"


# ---------------------------------------------------------------------------
# B10  restart: after a detected breach, and after an undetected one
# ---------------------------------------------------------------------------

def test_b10_a_restart_after_a_detected_breach_keeps_the_failure(tmp_path: Path):
    client, _ = _attack(tmp_path, "ready-committed")
    HostileFlow.release.set()
    _wait_finished(client)
    restarted = _client(tmp_path)
    state = _ok(restarted.get("/api/state"))
    assert state["journey"]["stage"] == "BUILD" and state["journey"]["status"] == "failed"
    assert "modified the project's authority store" in state["journey"]["failure"]
    assert state["authority"]["anchor"] == "sealed"


@pytest.mark.parametrize("attack", ["ready", "ready-committed", "authority-committed"])
def test_b10_a_forgery_left_for_a_later_process_is_tampered_until_a_person_restores(
        tmp_path: Path, attack: str):
    """The server died mid-build and the worker's forgery is what the disk
    holds. No memory survived. The seal did: every route is TAMPERED until a
    human restores, and the restoration records the breach on the lifecycle."""
    store = _store(tmp_path)
    document = create_document("proj-1", "Portal", Actor("human", "casey"), AT)
    document, intent = propose(document, "intent", "Build a customer support portal.",
                               Actor("model", "m"), "2026-09-03T09:01:00Z")
    document = confirm(document, intent, Actor("human", "casey"), "2026-09-03T09:02:00Z")
    lifecycle = start_experience(Actor("human", "casey"), AT)
    lifecycle = advance(lifecycle, "CONFIRM", Actor("human", "casey"), "2026-09-03T09:03:00Z")
    lifecycle = advance(lifecycle, "BUILD", Actor("human", "casey"), "2026-09-03T09:04:00Z")
    store.initialize(document, experience=lifecycle)
    sealed_revision = store.sealed().revision

    if attack.startswith("ready"):
        forge_ready(tmp_path / "capsule")
    else:
        forge_authority(tmp_path / "capsule")
    if attack.endswith("committed"):
        commit_inside(tmp_path / "capsule")

    client = _client(tmp_path)
    state = client.get("/api/state")
    assert state.status_code == 409
    assert state.json()["finding"] == "TAMPERED" and state.json()["restorable"] is True
    assert "READY" not in state.text and FORGED_INTENT not in state.text
    for path in ("/api/journey/ready", "/api/build", "/api/journey/confirm-scope",
                 "/api/proposals/P-1/confirm", "/api/brd", "/api/sharing-preview"):
        response = client.post(path, json={"actor": HUMAN}) if path != "/api/sharing-preview" \
            else client.get(path)
        assert response.status_code == 409 and response.json().get("finding") == "TAMPERED", path

    refused = client.post("/api/journey/restore", json={"actor": MODEL})
    assert refused.status_code == 409 and "human act" in refused.json()["refused"]
    restored = _ok(client.post("/api/journey/restore", json={"actor": HUMAN}))
    assert restored["stage"] == "BUILD" and restored["status"] == "failed"
    persisted = _persisted(tmp_path)
    assert "READY" not in _stages(persisted)
    assert "modified outside Forge" in persisted["history"][-1]["detail"]
    assert "casey" in persisted["history"][-1]["detail"]
    assert _store(tmp_path).load()["authoritative"]["intent"] == "Build a customer support portal."
    assert _ok(client.get("/api/state"))["journey"]["stage"] == "BUILD"
    log = _git_log(tmp_path / "capsule")
    assert log[0] == "experience: authority restored from seal"
    assert subprocess.run(["git", "rev-parse", "HEAD~1"], cwd=tmp_path / "capsule",
                          capture_output=True, text=True, check=True).stdout.strip() == sealed_revision


# ---------------------------------------------------------------------------
# The mechanism itself: the real DevelopmentFlow's worker seam
# ---------------------------------------------------------------------------

class HostileWorker:
    """A provider worker that uses the workspace it was given, as one with
    Write and Bash could: it writes into `workspace/capsule`."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def run(self, **request: Any) -> WorkerResult:
        self.requests.append(dict(request))
        store = Path(request["workspace"]) / "capsule"
        if request["role"] == "application-builder" and (store / "experience.json").exists():
            forge_ready(store)
            commit_inside(store)
        return WorkerResult(role=request["role"], goal=request["goal"], success=True,
                            output="accepted: true; all checks passed",
                            command=("hostile-local-worker", request["role"]))


def test_the_real_flow_hands_the_worker_the_store_and_the_seal_still_holds(tmp_path: Path):
    """Through the real DevelopmentFlow, not a fake: the worker seam receives
    the project directory -- the store inside it -- with Edit, Write and
    Bash. This is the mechanism the adjudication names. The worker forges and
    commits READY; the surface restores and refuses."""
    worker = HostileWorker()
    constructed: list[DevelopmentFlow] = []

    def real_flow(root, **kwargs):
        flow = DevelopmentFlow(root, **kwargs)
        flow.worker = worker
        constructed.append(flow)
        return flow

    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "def add(left: int, right: int) -> int:\n    return left + right\n",
        encoding="utf-8", newline="")
    (tmp_path / "tests" / "test_app.py").write_text(
        "# BRD-001\n\ndef test_addition_contract():\n    assert 1 + 1 == 2\n",
        encoding="utf-8", newline="")
    client = _client(tmp_path, factory=real_flow)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    status = _wait_finished(client)

    assert constructed[0].root == tmp_path and constructed[0].provider == "codex"
    workspaces = {str(request["workspace"]) for request in worker.requests}
    assert workspaces == {str(tmp_path)}, "the worker's workspace is the project directory"
    assert any(set(r["allowed_tools"]) >= {"Edit", "Write", "Bash"} for r in worker.requests)
    assert status["status"] == "finished"
    assert status["lifecycle"]["stage"] == "BUILD" and status["lifecycle"]["status"] == "failed"
    assert status["lifecycle"]["authority"] == "restored from seal"
    assert "READY" not in _stages(_persisted(tmp_path))
    assert _ok(client.get("/api/state"))["journey"]["stage"] == "BUILD"


# ---------------------------------------------------------------------------
# The seal itself
# ---------------------------------------------------------------------------

def _sealed_store(tmp_path: Path) -> CapsuleStore:
    store = _store(tmp_path)
    document = create_document("proj-1", "Portal", Actor("human", "casey"), AT)
    store.initialize(document, experience=start_experience(Actor("human", "casey"), AT))
    return store


def test_every_forge_save_reseals_and_the_seal_lives_outside_the_project(tmp_path: Path):
    store = _sealed_store(tmp_path)
    assert store.seal_path().parent == tmp_path / "seals"
    assert not store.seal_path().is_relative_to(tmp_path / "capsule")
    first = store.sealed().revision
    document, proposal = propose(store.load(), "intent", "x", Actor("human", "casey"), AT)
    store.save(document, "propose")
    assert store.sealed().revision == store.revision() != first
    state = advance(store.load_experience(), "CONFIRM", Actor("human", "casey"), AT)
    store.save_experience(state, "reached CONFIRM")
    assert store.sealed().revision == store.revision()
    assert store.seal_problems(store.sealed()) == []


@pytest.mark.parametrize("mutation", [
    "dirty-experience", "dirty-capsule", "committed", "extra-file", "marker-gone",
    "repository-gone", "head-moved",
])
def test_the_seal_sees_every_way_the_store_can_move(tmp_path: Path, mutation: str):
    store = _sealed_store(tmp_path)
    capsule = tmp_path / "capsule"
    if mutation == "dirty-experience":
        forge_ready(capsule)
    elif mutation == "dirty-capsule":
        forge_authority(capsule)
    elif mutation == "committed":
        forge_ready(capsule)
        commit_inside(capsule)
    elif mutation == "extra-file":
        (capsule / "notes.txt").write_text("hello", encoding="utf-8")
    elif mutation == "marker-gone":
        (capsule / ".forge-capsule").unlink()
    elif mutation == "repository-gone":
        _remove_tree(capsule / ".git")
    elif mutation == "head-moved":
        subprocess.run(["git", *IDENTITY, "commit", "-q", "--allow-empty", "-m", "x"],
                       cwd=capsule, check=True, capture_output=True)
    problems = store.seal_problems(store.sealed())
    assert problems, mutation
    with pytest.raises(CapsuleSealError):
        store.load()
    with pytest.raises(CapsuleSealError):
        store.load_experience()


def test_the_seal_reads_the_bytes_not_only_what_git_reports(tmp_path: Path):
    """A worker that hides its edit from git: `update-index --assume-unchanged`
    keeps HEAD and `git status` exactly as sealed while the file on disk says
    READY. The seal compares the bytes themselves, so the store is caught by
    that comparison alone -- the one check the other specimens never isolate."""
    store = _sealed_store(tmp_path)
    capsule = tmp_path / "capsule"
    subprocess.run(["git", "update-index", "--assume-unchanged", "experience.json"],
                   cwd=capsule, check=True, capture_output=True)
    forge_ready(capsule)
    status = subprocess.run(["git", "status", "--porcelain"], cwd=capsule,
                            capture_output=True, text=True, check=True).stdout.strip()
    assert status == "", "the specimen must be invisible to git status"
    problems = store.seal_problems(store.sealed())
    assert problems == ["experience.json differs from the sealed bytes"], problems
    with pytest.raises(CapsuleSealError):
        store.load_experience()


def test_restoration_rebuilds_the_repository_when_the_worker_destroyed_it(tmp_path: Path):
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    _remove_tree(tmp_path / "capsule" / ".git")
    forge_ready(tmp_path / "capsule")
    revision, notes = store.restore(sealed)
    assert notes and "rebuilt" in notes[0]
    assert store.seal_problems(store.sealed()) == []
    assert store.load_experience()["stage"] == "DISCOVER"
    assert store.sealed().revision == revision


def test_restoration_survives_a_worker_that_replaced_git_with_a_file(tmp_path: Path):
    """A review measured `restore()` raising NotADirectoryError -- and the
    human restore route returning 500, the store stuck TAMPERED -- when the
    worker left `capsule/.git` as a plain FILE. The rebuild now removes what
    it finds by shape. Driven through the surface: mid-build the worker
    swaps `.git` for a file and forges READY; the thread restores; then the
    same shape at rest is restored by a person."""

    class GitSmashingFlow(HostileFlow):
        def run(self):
            store = self.root / "capsule"
            forge_ready(store)
            _remove_tree(store / ".git")
            (store / ".git").write_text("x", encoding="utf-8")
            HostileFlow.written.set()
            assert HostileFlow.release.wait(timeout=30)
            return {"accepted": True, "gates": [dict(SUBJECT_GATE), dict(NORNYX_GATE)],
                    "execution_backend": "sequential"}

    client = _client(tmp_path, factory=GitSmashingFlow)
    _confirmed(client)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    assert HostileFlow.written.wait(timeout=30)
    assert _ok(client.get("/api/state"))["journey"]["stage"] == "BUILD"
    HostileFlow.release.set()
    status = _wait_finished(client)
    assert status["lifecycle"] == {"recorded": True, "stage": "BUILD", "status": "failed",
                                   "authority": "restored from seal"}
    assert (tmp_path / "capsule" / ".git").is_dir()
    persisted = _persisted(tmp_path)
    assert "READY" not in _stages(persisted) and "rebuilt" in persisted["history"][-1]["detail"]

    # The same shape left for a later process, restored by a person.
    _remove_tree(tmp_path / "capsule" / ".git")
    (tmp_path / "capsule" / ".git").write_text("x", encoding="utf-8")
    forge_authority(tmp_path / "capsule")
    later = _client(tmp_path)
    assert later.get("/api/state").json()["finding"] == "TAMPERED"
    restored = _ok(later.post("/api/journey/restore", json={"actor": HUMAN}))
    assert restored["stage"] == "BUILD" and "rebuilt" in restored["restoration"]["detail"]
    assert _store(tmp_path).load()["authoritative"]["intent"] == "Build a customer support portal."


def test_a_damaged_or_foreign_seal_is_a_tamper_finding_not_an_absent_project(tmp_path: Path):
    """A review measured a malformed seal turning an initialized project
    into `initialized: false`. A seal that is unreadable, of another schema,
    or written for another store anchors nothing: TAMPERED, with nothing to
    restore from, on every route."""
    store = _sealed_store(tmp_path)
    seal = store.seal_path()
    good = seal.read_text(encoding="utf-8")
    own = json.dumps(str((tmp_path / "capsule").resolve()))[1:-1]
    client = _client(tmp_path)
    for label, damaged in (
        ("malformed", "{not json"),
        ("other schema", good.replace("nornyx.forge.capsule_seal.v1", "nornyx.forge.other.v1")),
        ("other store", good.replace(own, "C:/elsewhere/capsule")),
    ):
        seal.write_text(damaged, encoding="utf-8", newline="")
        with pytest.raises(CapsuleSealUnreadable):
            store.load()
        state = client.get("/api/state")
        assert state.status_code == 409 and state.json()["finding"] == "TAMPERED", label
        assert "restorable" not in state.json(), label
        restore = client.post("/api/journey/restore", json={"actor": HUMAN})
        assert restore.status_code == 409 and restore.json().get("finding") == "TAMPERED", label
    seal.write_text(good, encoding="utf-8", newline="")
    assert _ok(client.get("/api/state"))["authority"]["anchor"] == "sealed"


def test_a_seal_that_cannot_be_written_is_the_stores_refusal(tmp_path: Path):
    """A review measured a raw OSError escaping `initialize` when the seal
    directory was unwritable. It is the store's refusal now, and it says
    what state the store is left in."""
    (tmp_path / "seals").write_text("not a directory", encoding="utf-8")
    store = _store(tmp_path)
    document = create_document("proj-1", "Portal", Actor("human", "casey"), AT)
    with pytest.raises(CapsuleStoreError, match="seal could not be written"):
        store.initialize(document, experience=start_experience(Actor("human", "casey"), AT))


def test_a_store_never_sealed_is_reported_unsealed_and_sealed_on_the_next_save(tmp_path: Path):
    """The disclosed downgrade: a store from before sealing, or a seal a
    same-user process deleted, has nothing to hold it to. The surface says
    so rather than claiming a seal it does not have, and Forge's next save
    seals it."""
    CapsuleStore(tmp_path / "capsule").initialize(
        create_document("proj-1", "Portal", Actor("human", "casey"), AT),
        experience=start_experience(Actor("human", "casey"), AT))
    client = _client(tmp_path)
    state = _ok(client.get("/api/state"))
    assert state["authority"]["anchor"] == "unsealed"
    _ok(client.post("/api/proposals", json={"field": "intent", "value": "x", "actor": HUMAN}))
    assert _ok(client.get("/api/state"))["authority"]["anchor"] == "sealed"
    restore = client.post("/api/journey/restore", json={"actor": HUMAN})
    assert restore.status_code == 409 and "nothing to restore" in restore.json()["refused"]


def test_the_served_seal_directory_is_forges_own_outside_any_project(tmp_path: Path):
    """What `assemble` passes: under the user's home beside the reviewer trust
    store, never under the project the provider is given."""
    assert onboarding_serve.SEAL_DIR == Path.home() / ".nornyx" / "forge" / "seals"
    assert not onboarding_serve.SEAL_DIR.is_relative_to(tmp_path)
    source = Path(onboarding.__file__).read_text(encoding="utf-8")
    assert "Path.home()" not in source, "the app must receive the seal directory, not find it"


# ---------------------------------------------------------------------------
# The thread-start P3
# ---------------------------------------------------------------------------

def test_a_thread_that_fails_to_start_releases_the_build_lock_and_the_seal(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    client = TestClient(create_app(tmp_path / "capsule", CONTRACTS, clock=_clock(),
                                   flow_factory=GovernedFlow, seal_dir=tmp_path / "seals"),
                        raise_server_exceptions=False)
    GovernedFlow.instances = []
    _confirmed(client)

    original_start = onboarding.threading.Thread.start

    def cannot_start(self):
        if self.name == "forge-build":
            raise RuntimeError("can't start new thread")
        return original_start(self)

    monkeypatch.setattr(onboarding.threading.Thread, "start", cannot_start)
    crashed = client.post("/api/build", json={"actor": HUMAN})
    assert crashed.status_code == 500
    monkeypatch.undo()
    state = _ok(client.get("/api/state"))
    assert state["journey"]["stage"] == "BUILD" and state["journey"]["actions"] == ["start_build"]
    assert state["authority"]["anchor"] == "sealed" and "build" not in state["authority"]
    assert client.get("/api/build").json() == {"status": "never_run"}
    again = client.post("/api/build", json={"actor": HUMAN})
    assert again.status_code == 200, again.text
    _wait_finished(client)
    assert _persisted(tmp_path)["stage"] == "GOVERN"


def test_a_seal_error_is_a_tamper_finding_with_its_problems(tmp_path: Path):
    snapshot = AuthoritySnapshot(revision="0" * 40, files={"capsule.json": "{}", "experience.json": None})
    error = CapsuleSealError(["HEAD moved"], snapshot)
    assert isinstance(error, CapsuleStoreError) is False
    assert error.problems == ["HEAD moved"] and error.snapshot is snapshot
