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
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from session_client import authed_client

from nornyx_forge import capsule_store as store_module
from nornyx_forge import onboarding_app as onboarding
from nornyx_forge import onboarding_serve
from nornyx_forge.capsule import Actor, _chain_digest, confirm, create_document, propose
from nornyx_forge.capsule_store import (
    MARKER_TRUST_BASIS,
    AuthoritySnapshot,
    CapsuleSealError,
    CapsuleSealMissing,
    CapsuleSealUnreadable,
    CapsuleStore,
    CapsuleStoreError,
    _remove_tree,
)
from nornyx_forge.development_flow import DevelopmentFlow
from nornyx_forge.experience import _link, advance, start_experience
from nornyx_forge.models import WorkerResult
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.provider_contract import (
    PROVIDER_CONFINEMENT,
    GovernedEligibility,
    governed_build_eligibility,
)

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


def _seam_eligibility(provider: str) -> GovernedEligibility:
    """The injectable seam executes no provider: the deterministic flow the
    tests install answers in the flow's shape and never runs an engineering
    agent, so the governed-eligibility gate -- which exists to keep an
    unconfined provider off the authority store -- has nothing to decide.
    The shipped surface never sees this; it uses the contract's own decision,
    and tests/test_governed_provider_eligibility.py pins that."""
    return GovernedEligibility(provider=provider, eligible=True, confinement="established",
                               reason="deterministic flow at the injectable seam; no provider executes")


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
    return authed_client(create_app(tmp_path / "capsule", CONTRACTS, clock=_clock(),
                                    flow_factory=factory, seal_dir=tmp_path / "seals",
                                    eligibility=_seam_eligibility))


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
    assert mid["authority"] == {"anchor": "sealed", "build": "running",
                                "currency": "not_independently_anchored", "last_restoration": None}

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
    # A review measured this one open: the worker deletes the store and a
    # client creates a new one, whose seal then overwrote the old.
    _remove_tree(tmp_path / "capsule")
    created = client.post("/api/project", json={
        "project_id": "proj-2", "project_name": "Impostor", "actor": HUMAN})
    assert created.status_code == 409 and "sealed" in created.json()["refused"]
    assert not (tmp_path / "capsule").exists()
    HostileFlow.release.set()
    status = _wait_finished(client)
    assert status["lifecycle"]["stage"] == "BUILD" and status["lifecycle"]["status"] == "failed"
    assert _persisted(tmp_path)["stage"] == "BUILD"
    assert _store(tmp_path).load()["project_id"] == "proj-1"
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
    # WHAT THE RECORD MAY SAY. This asserted "modified outside Forge" until
    # D-2 measured that the same finding is produced by a Forge process dying
    # between its own commit and its own seal, with no external actor in it.
    # The record names the measurement and the human who restored, and no
    # other actor -- pinned in full by
    # `test_a_seal_breach_reports_what_it_measured_and_no_author`.
    assert "no longer matched Forge's seal" in persisted["history"][-1]["detail"]
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
    assert status["accepted"] is True, "the specimen must be the shape READY is reachable from"
    gates = {gate["name"]: gate["passed"] for gate in status["result"]["gates"]}
    assert gates.get("greenfield:test-execution") is True, "the trusted verifier did not run"
    assert status["lifecycle"]["stage"] == "BUILD" and status["lifecycle"]["status"] == "failed"
    assert status["lifecycle"]["authority"] == "restored from seal"
    assert "READY" not in _stages(_persisted(tmp_path))
    assert "experience: reached READY" not in _git_log(tmp_path / "capsule")
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


def test_restoration_keeps_history_when_the_worker_left_an_extra_file(tmp_path: Path):
    """A review measured that skipping `git clean` in the restoration left
    the suite green: the rebuild fallback still restored the sealed bytes,
    at the price of the store's whole history. The honest route -- reset to
    the sealed revision, clean what the seal does not know -- must be the
    one taken when the worker left an untracked file beside its forgery."""
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    capsule = tmp_path / "capsule"
    forge_ready(capsule)
    (capsule / "notes.txt").write_text("left by the worker", encoding="utf-8")
    revision, notes = store.restore(sealed)
    assert notes == [], "the honest route was not taken; the repository was rebuilt"
    assert revision == sealed.revision, "the store's history was not preserved"
    assert not (capsule / "notes.txt").exists()
    assert _git_log(capsule) == ["capsule: initialize"]
    assert store.load_experience()["stage"] == "DISCOVER"


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


# ---------------------------------------------------------------------------
# D  the recovery path's own window, and the claim the refusal used to make
# ---------------------------------------------------------------------------

_AT_GIT_INIT = "at git init"
_BETWEEN_AUTHORITY_WRITES = "between the two authority-file writes"
_INSIDE_THE_MARKER_WRITE = "inside the seal marker's own write"


def _die_inside_the_marker_write(monkeypatch: pytest.MonkeyPatch, failure: BaseException):
    """Arm `failure` at the first byte-write the seal marker's own write makes.

    DELIMITED BY THE METHOD, NOT BY A FILENAME, and that is the whole point of
    the row: an implementation that clears the name and rewrites it, and one
    that writes a finished file and renames it, must be reached at the SAME
    instant -- otherwise the instrument measures the implementation instead of
    the property. Naming `.forge-seal` would have missed the second entirely
    and passed the row for the reason it exists to rule out.

    The kill is still on `Path.write_text`, like the other instants here. If a
    later implementation stops writing the marker through it the arming never
    fires, `restore()` does not raise, and the row goes RED at
    `pytest.raises` -- loud, rather than a silent pass.
    """
    survivor_write_text = Path.write_text
    survivor_marker = store_module.CapsuleStore._write_seal_marker
    armed: list[bool] = []

    def dies_at_the_first_write(self, *args, **kwargs):
        if armed:
            raise failure
        return survivor_write_text(self, *args, **kwargs)

    def arming_marker_write(self):
        armed.append(True)
        try:
            return survivor_marker(self)
        finally:
            armed.clear()

    monkeypatch.setattr(Path, "write_text", dies_at_the_first_write)
    monkeypatch.setattr(store_module.CapsuleStore, "_write_seal_marker", arming_marker_write)


def _assert_marker_stands_over_the_forgery(capsule: Path, store: CapsuleStore) -> None:
    """The property both marker-write rows assert, once."""
    seal_marker = capsule / ".forge-seal"
    assert seal_marker.exists(), (
        "the marker was absent while the worker's forged bytes were on disk: "
        f"{sorted(path.name for path in capsule.iterdir())}"
    )
    assert json.loads(seal_marker.read_text(encoding="utf-8")) == {
        "schema": "nornyx.forge.capsule_seal_marker.v1", "seal": store.seal_ident()}
    assert store.protected()
    forged = json.loads((capsule / "experience.json").read_text(encoding="utf-8"))
    assert forged["stage"] == "READY", (
        "this row exists to catch the rebuild BEFORE it corrects any authority "
        "byte, with the worker's forgery still on disk; if the forgery is "
        "already gone the failure landed somewhere else and the row proves nothing"
    )
    # One same-user deletion must still not be enough.
    store.seal_path().unlink()
    later = CapsuleStore(capsule, seal_dir=store.seal_dir)
    for call in (later.load_experience, later.load):
        with pytest.raises(CapsuleSealMissing):
            call()


def test_an_oserror_inside_the_marker_write_does_not_permanently_strip_the_marker(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The same instant as the crash row below, without the crash -- and this
    is the WORSE of the two, because it is permanent and it is reported clean.

    MEASURED at the parent of this commit. `_write_fresh` removed the entry and
    then wrote it, and `_rebuild` calls it on the seal marker FIRST, so an
    ordinary handled `OSError` in that gap -- a full disk, or a real-time
    scanner holding the create -- left `['.forge-capsule', 'capsule.json',
    'experience.json']` on disk: `protected()` False, the worker's forged
    `experience.json` intact, and a sealless `load_experience()` returning
    `READY`. Not a window. A durable state, reached without killing anything.

    And the surface said the opposite. `restore()` catches `OSError` and raises
    `CapsuleStoreError`, whose own docstring is asserted below because it is
    the promise that was false: a caller told "nothing was partially written"
    had in fact had the store's second authentication factor removed by the
    call it just made. The crash row could not see this: it kills the process,
    so it never reaches the handler that makes the claim.
    """
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    capsule = tmp_path / "capsule"
    forge_ready(capsule)
    _remove_tree(capsule / ".git")     # the honest reset route is unreachable

    _die_inside_the_marker_write(
        monkeypatch, OSError(28, "No space left on device"))
    with pytest.raises(CapsuleStoreError) as raised:
        store.restore(sealed)
    monkeypatch.undo()

    assert "Nothing was partially written." in (CapsuleStoreError.__doc__ or ""), (
        "the promise this row holds the store to has been edited away rather "
        "than kept; if the contract changed, this row must change with it"
    )
    assert "No space left on device" in str(raised.value)
    _assert_marker_stands_over_the_forgery(capsule, store)


@pytest.mark.parametrize(
    "marker, instant",
    [("intact", _AT_GIT_INIT),
     ("deleted", _AT_GIT_INIT),
     ("foreign", _AT_GIT_INIT),
     ("deleted", _BETWEEN_AUTHORITY_WRITES),
     ("intact", _INSIDE_THE_MARKER_WRITE)],
    ids=["intact-at-git-init", "deleted-at-git-init", "foreign-at-git-init",
         "deleted-between-the-authority-writes", "intact-inside-the-marker-write"],
)
def test_a_crash_inside_the_rebuild_never_leaves_the_store_readable_as_legacy(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, marker: str, instant: str):
    """Forge's own recovery used to be the cheapest way to strip the marker.

    MEASURED before the repair, with a `SystemExit` at the `git init` call
    inside `_rebuild`: the wipe had already removed `.forge-seal` while the
    worker's forged bytes were still on disk, so the directory held
    `['.forge-capsule', 'capsule.json', 'experience.json']`, `protected()` was
    False, and a load with the seal file also gone returned the forged
    `stage == "READY"`. Not a window -- a PERMANENT state. A-022 leans on
    "marker AND seal both gone" for the legacy reading; after this crash Forge
    itself had removed one of the two, leaving the attacker a single same-user
    deletion, which is exactly the capability that paragraph concedes an
    unconfined provider holds.

    Three marker states at the `git init` instant, because the first repair
    had two halves and each is invisible to the other. `intact` fails if the
    wipe is allowed to run before the marker is rewritten; `foreign` fails if
    the rewrite is made conditional on `protected()`, which only asks whether
    a file of that name exists and cannot see that it names another store's
    seal.

    AND A FOURTH ROW, WHICH VARIES THE INSTANT RATHER THAN THE MARKER. Round 2
    found that the three rows above all crash at exactly one moment, and that
    moment is after BOTH halves of the repair -- so the parametrisation could
    not see an ordering the repair itself got wrong. It did: the first fix
    wrote the sealed bytes and only THEN the marker, and `snapshot.files` is
    `capsule.json` then `experience.json`, so a death between the two left the
    worker's forged `experience.json` on disk with the marker still absent,
    `protected()` False, and a sealless load returning `READY` again. A
    two-statement window rather than a permanent state, but the same
    fall-open. `_rebuild` now writes the marker first, and this row is what
    demands it: reverting the hoist turns this id red and leaves the other
    three green.

    The bytes are deliberately NOT asserted equal at that instant -- mid-way
    through a rebuild `experience.json` is whatever it was or nothing at all,
    and asserting otherwise would pin the implementation rather than the
    property. What is asserted is the property: whatever is on disk, it is
    under a marker naming THIS store's seal, so with the seal gone the store
    refuses instead of reading as legacy.

    AND A FIFTH ROW, INSIDE THE MARKER'S OWN WRITE. Round 3 found that the
    four rows above vary the marker across one instant and the instant across
    one marker state, and that NONE of them lands inside the write of the
    marker itself -- so the set could not see a marker write that was not
    atomic. It was not. The repair that stopped the recovery path writing
    through a planted link removed the entry and then wrote it, and since the
    marker goes first, that removal reopened the very fall-open the hoist had
    just closed: measured, `['.forge-capsule', 'capsule.json',
    'experience.json']`, `protected()` False, and a sealless load returning
    the forged `READY`. `intact` is the marker state that shows it, because
    it is the one where Forge's own recovery is what MAKES the marker absent;
    with it deleted or foreign beforehand the store was already in that state
    and the row would prove nothing. Its non-crash twin, which is durable
    rather than a window, is the `OSError` test above.
    """
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    capsule = tmp_path / "capsule"
    forge_ready(capsule)
    _remove_tree(capsule / ".git")     # the honest reset route is unreachable
    if marker == "deleted":
        (capsule / ".forge-seal").unlink()
    elif marker == "foreign":
        (capsule / ".forge-seal").write_text(
            json.dumps({"schema": "nornyx.forge.capsule_seal_marker.v1", "seal": "0" * 24},
                       sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8", newline="")

    if instant == _AT_GIT_INIT:
        survivor = store_module._run_git

        def dies_at_init(root, *args):
            if args and args[0] == "init":
                raise SystemExit("the process died at git init inside _rebuild")
            return survivor(root, *args)

        monkeypatch.setattr(store_module, "_run_git", dies_at_init)
    elif instant == _BETWEEN_AUTHORITY_WRITES:
        # The second authority file, at the moment the rebuild reaches it and
        # before it has touched it: `capsule.json` is already sealed bytes and
        # `experience.json` is still whatever the worker left. Patched on the
        # Path method rather than on the store's write helper so the same
        # instrument reaches an implementation that writes either way.
        #
        # MATCHED BY FAMILY, NOT BY EQUALITY. Equality reached only an
        # implementation that writes the destination IN PLACE, and round 3
        # made the rebuild write a finished file and rename it -- at which
        # point the instrument stopped firing and the row failed at
        # `pytest.raises`, loudly, rather than passing for the wrong reason.
        # A sibling whose name extends the destination's is that destination's
        # write; anything further afield still fails the row rather than
        # quietly passing it.
        doomed = capsule / "experience.json"
        survivor_write_text = Path.write_text

        def dies_between_the_authority_writes(self, *args, **kwargs):
            if self.parent == doomed.parent and self.name.startswith(doomed.name):
                raise SystemExit("the process died between the two authority-file writes")
            return survivor_write_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", dies_between_the_authority_writes)
    else:
        _die_inside_the_marker_write(
            monkeypatch, SystemExit("the process died inside the marker's own write"))

    with pytest.raises(SystemExit):
        store.restore(sealed)
    monkeypatch.undo()

    if instant == _INSIDE_THE_MARKER_WRITE:
        # Nothing has been corrected yet -- the marker is written before any
        # authority byte -- so the assertions below about corrected files do
        # not apply, and the stronger one does: the forgery is still on disk
        # and the marker is standing over it.
        _assert_marker_stands_over_the_forgery(capsule, store)
        return

    seal_marker = capsule / ".forge-seal"
    assert seal_marker.exists(), (
        "the crash left the store with no seal marker while bytes were on "
        f"disk: {sorted(path.name for path in capsule.iterdir())}"
    )
    assert json.loads(seal_marker.read_text(encoding="utf-8")) == {
        "schema": "nornyx.forge.capsule_seal_marker.v1", "seal": store.seal_ident()}, (
        "the marker on disk does not name this store's seal, so a load would "
        "hold the store to an anchor that is not its own"
    )
    assert store.protected()
    if instant == _AT_GIT_INIT:
        for name in ("capsule.json", "experience.json"):
            assert (capsule / name).read_text(encoding="utf-8") == sealed.files[name], (
                f"{name} still holds the worker's bytes after the crash"
            )
    else:
        assert (capsule / "capsule.json").read_text(encoding="utf-8") == \
            sealed.files["capsule.json"]
        second = capsule / "experience.json"
        current = second.read_text(encoding="utf-8") if second.exists() else None
        assert current != sealed.files["experience.json"], (
            "this row exists to catch the rebuild MID-WAY, with the second "
            "authority file not yet corrected; if it already matches the seal "
            "the crash landed somewhere else and the row proves nothing"
        )

    # AND THE SECOND HALF. One same-user deletion is what the design concedes
    # an unconfined provider holds; it must not be enough. With the seal gone
    # too, the store is protected-but-unsealed -- a refusal -- rather than a
    # legacy store whose files are read.
    store.seal_path().unlink()
    later = CapsuleStore(capsule, seal_dir=tmp_path / "seals")
    for call in (later.load_experience, later.load):
        with pytest.raises(CapsuleSealMissing):
            call()


def _plant_at_the_marker(capsule: Path, shape: str, tmp_path: Path) -> None:
    """Put a directory or a junction at `.forge-seal`, and ASSERT it landed.

    Round 3 recorded an unasserted plant that never happened reading as a clean
    success and proving nothing; the assertions here are that finding applied.
    """
    marker = capsule / ".forge-seal"
    marker.unlink()
    if shape == "directory":
        marker.mkdir()
        (marker / "occupant.txt").write_text("x\n", encoding="utf-8", newline="")
        assert marker.is_dir() and not marker.is_symlink(), "the directory did not land"
    else:
        target = tmp_path / "junction-target"
        target.mkdir()
        (target / "outside.txt").write_text("the junction's target\n",
                                            encoding="utf-8", newline="")
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(marker), str(target)],
                              capture_output=True, text=True, check=False, timeout=60)
        assert done.returncode == 0, f"mklink: {done.stdout}{done.stderr}"
        assert store_module._is_junction(marker), "the plant is not a junction"


def _a_sealless_load_refuses(capsule: Path, store: CapsuleStore) -> None:
    """One same-user deletion of the seal is not enough to read the store.

    The seal is PUT BACK, so this may be asserted before the call as well as
    after it -- which is what lets the rows below measure a DEGRADATION rather
    than an absence.
    """
    seal = store.seal_path()
    kept = seal.read_bytes()
    seal.unlink()
    try:
        later = CapsuleStore(capsule, seal_dir=store.seal_dir)
        for call in (later.load_experience, later.load):
            with pytest.raises(CapsuleSealMissing):
                call()
    finally:
        seal.write_bytes(kept)


def _the_marker_write_fails_over(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str, form: str) -> None:
    """ROUND 3 CLOSED ONE SHAPE AND LEFT TWO OPEN, and nothing demanded them.

    The two rows above reach inside the marker's own write with an ordinary
    FILE at the destination, where `os.replace` does the whole job. When a
    DIRECTORY or a JUNCTION stands there instead, `_write_fresh` must remove it
    first -- a rename cannot replace either -- and round 3 removed it where the
    old code did: BEFORE the temp existed. So for those two shapes the marker
    was absent for the width of the write again, and `_write_seal_marker` is
    `_rebuild`'s first statement. Measured at that commit with nothing patched
    but `Path.write_text`, in both forms and both shapes:

        on disk  ['.forge-capsule', 'capsule.json', 'experience.json']
        protected() False   sealless load  RETURNED stage='READY'

    Durable in the `OSError` form -- no crash needed, a full disk is enough --
    and reported behind a refusal whose own docstring promises that nothing was
    partially written. And a DEGRADATION Forge itself causes, which is why the
    pre-call state is asserted below: the planted shape already made the store
    protected and already made a sealless load refuse, and the restoration is
    what took that away. A concurrent observer counting the marker's absence
    strictly inside `_write_fresh` measured file 0/2518, directory 1706/4204,
    junction 1475/2544.

    NO TEST ANYWHERE PLANTED EITHER SHAPE AT `.forge-seal` -- which is exactly
    why round 3's repair could reopen for two shapes what it closed for one.
    These four rows are what demand the removal happen INSIDE the `try`, after
    the finished temp exists; reverting that reorder turns all four red and
    leaves every other row in this module green.

    WHAT IS NOT CLAIMED. A crash-only micro-window survives for these two
    shapes and is disclosed rather than closed: the removal and the rename are
    two adjacent syscalls, and a death between them still leaves the name
    absent. `os.replace` cannot replace a directory, so no ordering of those
    two calls removes it. These rows kill at the FIRST write the marker's write
    makes, which is the instant that reaches both implementations; they do not
    reach that two-syscall gap and do not pretend to. A-022 records it.

    FOUR ROWS ACROSS THREE FUNCTIONS, and the split is bookkeeping rather than
    design: `check_test_coverage.EXPECTED_SKIPS` is keyed by node id and
    `test_every_declared_exemption_names_a_test_that_exists` resolves that key
    by looking for `def <name>(` in the module, so a PARAMETRISED row cannot be
    declared as a skip at all. The two junction rows need declaring, so they
    are whole functions; the directory rows need nothing and stay a
    parametrisation. A-022 records the census limitation rather than widening
    the guard to admit an entry of its author's own shape.
    """
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    capsule = tmp_path / "capsule"
    forge_ready(capsule)
    _remove_tree(capsule / ".git")     # the honest reset route is unreachable
    _plant_at_the_marker(capsule, shape, tmp_path)

    # BEFORE the call: the name is occupied, so the store is already protected
    # and a sealless load already refuses. Anything less afterwards is Forge
    # removing a factor it found in place.
    assert store.protected()
    _a_sealless_load_refuses(capsule, store)

    _die_inside_the_marker_write(
        monkeypatch,
        SystemExit("the process died inside the marker's own write") if form == "crash"
        else OSError(28, "No space left on device"))
    with pytest.raises(SystemExit if form == "crash" else CapsuleStoreError):
        store.restore(sealed)
    monkeypatch.undo()

    if form == "oserror":
        assert "Nothing was partially written." in (CapsuleStoreError.__doc__ or ""), (
            "the promise this row holds the store to has been edited away rather "
            "than kept; if the contract changed, this row must change with it"
        )
    forged = json.loads((capsule / "experience.json").read_text(encoding="utf-8"))
    assert forged["stage"] == "READY", (
        "this row exists to catch the rebuild BEFORE it corrects any authority "
        "byte, with the worker's forgery still on disk; if the forgery is "
        "already gone the failure landed somewhere else and the row proves nothing"
    )
    assert (capsule / ".forge-seal").exists(), (
        "the seal-marker name was left empty while the worker's forged bytes "
        f"were on disk: {sorted(path.name for path in capsule.iterdir())}"
    )
    assert store.protected(), (
        "the restoration removed the protection it found in place, leaving the "
        "forgery one same-user seal deletion away from reading as a legacy store"
    )
    _a_sealless_load_refuses(capsule, store)


@pytest.mark.parametrize("form", ["crash", "oserror"])
def test_a_failure_inside_the_marker_write_leaves_a_directory_marker_standing(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, form: str):
    """The directory shape, on every platform. See `_the_marker_write_fails_over`."""
    _the_marker_write_fails_over(tmp_path, monkeypatch, "directory", form)


@pytest.mark.skipif(
    os.name != "nt",
    reason="A junction is an NTFS directory-shaped reparse point that is_symlink() "
           "reports False for, and POSIX has no equivalent, so this row's plant "
           "cannot be built on a Linux job. The property is not weakened: the "
           "directory rows take the identical branch of _write_fresh and execute "
           "on every platform, and both junction rows execute on a Windows "
           "workstation.",
)
def test_a_crash_inside_the_marker_write_leaves_a_junction_marker_standing(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The junction shape, crashing. See `_the_marker_write_fails_over`."""
    _the_marker_write_fails_over(tmp_path, monkeypatch, "junction", "crash")


@pytest.mark.skipif(
    os.name != "nt",
    reason="A junction is an NTFS directory-shaped reparse point that is_symlink() "
           "reports False for, and POSIX has no equivalent, so this row's plant "
           "cannot be built on a Linux job. The property is not weakened: the "
           "directory rows take the identical branch of _write_fresh and execute "
           "on every platform, and both junction rows execute on a Windows "
           "workstation.",
)
def test_an_oserror_inside_the_marker_write_leaves_a_junction_marker_standing(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The junction shape, durable. See `_the_marker_write_fails_over`."""
    _the_marker_write_fails_over(tmp_path, monkeypatch, "junction", "oserror")


def test_a_stray_temp_from_forges_own_crash_is_not_a_tamper_finding(tmp_path: Path):
    """FORGE'S OWN CRASH MANUFACTURED A TAMPER FINDING AGAINST AN UNTOUCHED STORE.

    `_write_fresh` writes `<name>.<16 hex>.tmp` and renames it. A death between
    those two statements leaves the name behind -- no `finally` can take it,
    exactly as `seal()`'s own `.json.tmp` cannot be taken. The cleanliness
    check then saw an extra untracked file and every later load failed:

        seal_problems  ["the working tree is not clean: ?? .forge-seal.<hex>.tmp"]
        load()         REFUSED CapsuleSealError

    Fail-closed and repairable -- `git clean` on the honest restore route takes
    it, and `_rebuild`'s wipe takes it, since the temp name is in no keep set.
    But the product was reporting TAMPERED about a store nobody had touched,
    on account of its own crash, and the human restore it invites costs the
    lifecycle a transition. That is a false finding, and a finding that can be
    false for an innocent reason is worth less when it is true.

    THE EXEMPTION IS NARROW AND IS NOT A CLAIM OF OWNERSHIP. The name is the
    only evidence there is and any writer in the store can forge a name, so
    what the check now says is only that an UNTRACKED file bearing Forge's own
    temp suffix, in the store root, is not BY ITSELF a tamper finding. It can
    carry no authority: nothing in the module reads the store by pattern, and
    the authority files, the store marker and the seal marker are each read by
    exact name with their bytes compared to the seal regardless of what else
    is in the directory. The second half of this row is the load-bearing one:
    any OTHER untracked file is still a finding, so this is an exemption
    rather than the cleanliness check being switched off.
    """
    store = _sealed_store(tmp_path)
    capsule = tmp_path / "capsule"
    assert store.seal_problems(store.sealed()) == []

    stray = store_module._fresh_tmp_path(capsule / ".forge-seal")
    stray.write_text("a survivor of a death between the temp write and the rename\n",
                     encoding="utf-8", newline="")
    porcelain = subprocess.run(["git", "status", "--porcelain"], cwd=capsule,
                               capture_output=True, text=True, check=True).stdout
    assert porcelain.strip() == f"?? {stray.name}", (
        "the specimen must be an untracked file git actually reports"
    )

    # (i) Forge's own residue is not a finding, and both authority routes work.
    assert store.seal_problems(store.sealed()) == []
    assert store.load_experience()["stage"] == "DISCOVER"
    assert store.load()["project_id"] == "proj-1"

    # (ii) ANY other untracked file still is one, including one that only
    # resembles the temp name, and including one below the store root.
    for other, reported in ((capsule / "notes.txt", "?? notes.txt"),
                            (capsule / ".forge-seal.tmp", "?? .forge-seal.tmp"),
                            (capsule / ".forge-seal.00112233445566.tmp",
                             "?? .forge-seal.00112233445566.tmp")):
        other.write_text("x\n", encoding="utf-8", newline="")
        assert store.seal_problems(store.sealed()) == [
            "the working tree is not clean: " + reported], other.name
        with pytest.raises(CapsuleSealError):
            store.load()
        other.unlink()
    (capsule / "sub").mkdir()
    store_module._fresh_tmp_path(capsule / "sub" / ".forge-seal").write_text(
        "x\n", encoding="utf-8", newline="")
    assert store.seal_problems(store.sealed()) == [
        "the working tree is not clean: ?? sub/"], "the exemption reached below the root"


def test_the_cleanliness_exemption_matches_a_name_the_writer_really_produces(tmp_path: Path):
    """THE MATCHER AND THE NAME-BUILDER MUST NOT DRIFT APART IN SILENCE.

    `_tree_changes` recognises the names `_write_fresh` produces by a regular
    expression derived from `_FRESH_TMP_RANDOM_BYTES`, and two descriptions of
    one rule is the shape this repository keeps finding rot in. So the names
    are generated by the real builder and fed to the real matcher, rather than
    a literal being typed into both places.

    Drift would fail SAFE -- an unrecognised stray goes back to being a tamper
    finding, not to being ignored -- and it is pinned anyway, because a control
    that quietly stops applying is how the finding it prevents comes back.

    The near-misses are the other half: sixteen hex digits exactly, lower case,
    that suffix and nothing after it.
    """
    destination = tmp_path / ".forge-seal"
    produced = {store_module._fresh_tmp_path(destination).name for _ in range(64)}
    assert len(produced) == 64, "the temp name is not unpredictable"
    for name in produced:
        assert store_module._tree_changes(f"?? {name}") == [], name
    for near in (".forge-seal.tmp",
                 ".forge-seal.0011223344556677.TMP",
                 ".forge-seal.0011223344556677.tmp.bak",
                 ".forge-seal.001122334455667.tmp",      # fifteen
                 ".forge-seal.00112233445566778.tmp",    # seventeen
                 ".forge-seal.001122334455667g.tmp"):    # not hex
        assert store_module._tree_changes(f"?? {near}") == [f"?? {near}"], near
    # A TRACKED file of the exempt name that moved is still a finding: only the
    # untracked marker `??` is exempt.
    exempt = store_module._fresh_tmp_path(destination).name
    assert store_module._tree_changes(f" M {exempt}") == [f"M {exempt}"]
    assert store_module._tree_changes(f" D {exempt}") == [f"D {exempt}"]


@pytest.mark.parametrize("planted", ["capsule.json", "experience.json", ".forge-seal",
                                     ".forge-capsule"])
def test_the_rebuild_writes_no_bytes_outside_the_store_through_a_planted_link(
        tmp_path: Path, planted: str):
    """A restoration must not write THROUGH what the worker left behind.

    MEASURED under review at the parent: the rebuild wrote the authority files
    with a bare `write_text`, and the wipe preserves those names regardless of
    the SHAPE they have. A hardlink -- which needs no privilege on NTFS, and
    none on POSIX -- planted at an authority path made the restoration
    overwrite a file OUTSIDE the store with the sealed capsule bytes. The
    store's recovery from a hostile directory became a write primitive
    pointing anywhere the same user can reach.

    Identical at the parent and so not a regression of that commit; it is
    repaired here because the same commit hardened `.forge-seal` by shape two
    lines away and left these paths inconsistent. Every write `_rebuild` makes
    now goes through `_write_fresh`, which removes the entry first, so the
    link count drops and the bytes land in a new file no other name shares.

    NOT hardened, and stated rather than implied: `_write_document` and
    `_write_experience` on the ordinary save path still write through a
    planted link. That is unchanged from the parent and outside this slice;
    A-022 records it.
    """
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    capsule = tmp_path / "capsule"
    forge_ready(capsule)
    _remove_tree(capsule / ".git")     # force the rebuild rather than a reset

    outside = tmp_path / "outside.txt"
    outside.write_text("a file the store has no business touching\n", encoding="utf-8")
    target = capsule / planted
    target.unlink(missing_ok=True)
    os.link(outside, target)           # a hardlink: one inode, two names
    assert outside.stat().st_nlink == 2

    store.restore(sealed)

    assert outside.read_text(encoding="utf-8") == \
        "a file the store has no business touching\n", (
        f"restoring the store through a hardlink at {planted} wrote the "
        "store's bytes into a file outside it"
    )
    assert store.seal_problems(store.sealed()) == []


def _commit_landed_before_its_seal(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[CapsuleStore, list[str]]:
    """THE WRITE-ORDER GAP, driven rather than described.

    `save` writes, commits, and THEN seals, so a process that dies between the
    commit and the seal leaves Forge's own newest commit failing Forge's own
    seal: a clean tree at an unsealed revision. Returns the store and the
    problems the seal reports, so the callers assert against a measurement
    rather than a transcription of one.

    `monkeypatch.undo()` runs before returning because the restore route seals
    again, and a `seal` that is still raising would kill that instead.
    """
    store = _sealed_store(tmp_path)
    document, _ = propose(store.load(), "intent", "Build a customer support portal.",
                          Actor("model", "m"), "2026-09-03T10:00:00Z")

    def dies_before_sealing(self):
        raise SystemExit("the process died before sealing")

    monkeypatch.setattr(CapsuleStore, "seal", dies_before_sealing)
    with pytest.raises(SystemExit):
        store.save(document, "propose intent")
    monkeypatch.undo()
    return store, store.seal_problems(store.sealed())


def test_a_commit_that_landed_before_its_seal_fails_closed(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The write-order gap had no coverage at all; only the LEGACY never-sealed
    case did. It fails CLOSED, and that is the property pinned here.

    (ii) is the one that bites: reordering `save` to seal BEFORE committing
    would make these loads succeed, because the seal would then name the
    revision the commit was about to create -- a store sealed against a
    revision that does not exist yet, failing OPEN for the whole window
    instead of closed. The cost of failing closed is real and is asserted
    too: the transition is lost, and the lifecycle spends its
    one-failure-per-stage allowance on a Forge crash.
    """
    store, problems = _commit_landed_before_its_seal(tmp_path, monkeypatch)
    capsule = tmp_path / "capsule"
    sealed = store.sealed()
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=capsule, capture_output=True,
                          text=True, check=True).stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain"], cwd=capsule,
                            capture_output=True, text=True, check=True).stdout.strip()
    assert status == "", "the specimen is a CLEAN tree at an unsealed revision"
    # (i) the two measured problems, exactly.
    assert problems == [
        f"HEAD is {head[:12]}, sealed revision is {sealed.revision[:12]}",
        "capsule.json differs from the sealed bytes",
    ], problems
    # (ii) both authority routes refuse.
    for call in (store.load, store.load_experience):
        with pytest.raises(CapsuleSealError):
            call()
    # (iii) the surface says TAMPERED and offers the restoration.
    client = _client(tmp_path)
    state = client.get("/api/state")
    assert state.status_code == 409
    assert state.json()["finding"] == "TAMPERED" and state.json()["restorable"] is True
    # (iv) restoration costs the transition; the dropped commit is reflog-only.
    assert "capsule: propose intent" in _git_log(capsule)
    restored = _ok(client.post("/api/journey/restore", json={"actor": HUMAN}))
    assert "capsule: propose intent" not in _git_log(capsule)
    assert _store(tmp_path).load()["proposed"] == []
    assert restored["stage"] == "DISCOVER" and restored["status"] == "failed"
    # D-5. The revision reported is the one the store is AT, not the one it was
    # reset to: recording the lifecycle failure is itself a commit, and the
    # payload was measured naming a revision the store had already moved past.
    now_at = subprocess.run(["git", "rev-parse", "HEAD"], cwd=capsule, capture_output=True,
                            text=True, check=True).stdout.strip()
    assert restored["restoration"]["revision"] == now_at
    assert restored["restoration"]["revision"] != sealed.revision
    assert _store(tmp_path).seal_problems(_store(tmp_path).sealed()) == []


def test_a_seal_breach_reports_what_it_measured_and_no_author(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A label may not stand in for the thing measured -- least of all in a
    record that persists.

    The refusal used to say the store "was written outside this adapter" and
    the restoration wrote "modified outside Forge" into permanent lifecycle
    history. Both are claims about an ACTOR. What the seal measures is a
    revision, a working tree and file bytes; this specimen is a Forge crash
    with no external actor anywhere in it, and it produced both sentences.
    """
    store, problems = _commit_landed_before_its_seal(tmp_path, monkeypatch)
    with pytest.raises(CapsuleSealError) as breach:
        store.load()
    assert "outside" not in str(breach.value), str(breach.value)
    for problem in problems:
        assert problem in str(breach.value)

    client = _client(tmp_path)
    refused = client.get("/api/state").json()["refused"]
    assert "outside" not in refused, refused
    for problem in problems:
        assert problem in refused, (problem, refused)

    restored = _ok(client.post("/api/journey/restore", json={"actor": HUMAN}))
    detail = _persisted(tmp_path)["history"][-1]["detail"]
    assert detail == restored["restoration"]["detail"]
    for problem in problems:
        assert problem in detail, (problem, detail)
    # The only identity the record carries is the one SUPPLIED with the
    # request that asked for the restoration -- verbatim from the body, on a
    # surface that does not authenticate humans, so it is an assertion by the
    # caller and not an establishment by this route. Every word below claims a
    # DIFFERENT actor, and none of them is measured either: whoever moved the
    # store is unknown here, and git metadata cannot tell us -- `commit_inside`
    # above is the store's own identity.
    assert "casey" in detail
    for claimed in ("outside", "modified", "provider", "worker", "written by"):
        assert claimed not in detail, (claimed, detail)


def test_the_marker_trust_basis_cannot_survive_an_eligible_provider():
    """A-022 says a later slice making any provider eligible "must revisit
    this before it does so, or it silently reopens R2". A request that a human
    remember is not a control.

    Stated as a BICONDITIONAL over the eligibility decision, and round 2 is
    why it is one rather than an implication. As an implication guarded by
    `if eligible:` it could be SPENT IN ADVANCE: measured, with nothing
    eligible the constant was pinned by nothing, so any earlier commit that
    renamed or tidied it went unobjected, and the later commit that promoted a
    provider then found the implication ALREADY SATISFIED. The paragraph would
    have gone quietly false exactly as before, and the "record of a human
    decision" would have recorded an unrelated edit. So both directions are
    asserted: while nothing is eligible the constant must still read the
    literal, and once anything is eligible it must not.

    And the table it reads must not be EMPTY. `eligible` is derived by
    filtering `PROVIDER_CONFINEMENT`; measured, emptying that table made the
    guarded branch unreachable and this node green by vacuity. A refactor that
    moved the eligibility decision to another registry, leaving this table
    populated but unread, would do the same. So the rows are pinned by name.

    What this DOES NOT do, stated because the surrounding prose twice claimed
    more: it licenses nothing -- no code path consults `MARKER_TRUST_BASIS` to
    permit anything -- and editing the constant establishes nothing about the
    marker. It forces a promotion to state a new basis in the same commit, and
    that is the whole of it.
    """
    assert set(PROVIDER_CONFINEMENT) == {"claude", "codex"}, (
        "the confinement table is the population this interlock filters. "
        "Emptied, or moved to another registry, `eligible` is [] whatever the "
        "eligibility decision says and this node passes by vacuity rather "
        f"than by measurement: {sorted(PROVIDER_CONFINEMENT)}"
    )
    eligible = sorted(name for name in PROVIDER_CONFINEMENT
                      if governed_build_eligibility(name).eligible)
    if eligible:
        assert MARKER_TRUST_BASIS != "no_provider_executes_on_the_governed_path", (
            f"{eligible} may now execute on the governed path, and the seal "
            "marker's stated basis is still that none does. The marker sits "
            "inside the provider's workspace; A-022's marker paragraph reads "
            "a protected store as legacy only when the marker AND the seal are "
            "both gone, and R2 reopens the moment an unconfined provider can "
            "remove one of them. Revisit that paragraph and this constant "
            "together, in the commit that makes the provider eligible."
        )
    else:
        assert MARKER_TRUST_BASIS == "no_provider_executes_on_the_governed_path", (
            "no provider is eligible for the governed build, and that is "
            f"precisely the basis the marker is trusted on -- yet it now reads "
            f"{MARKER_TRUST_BASIS!r}. Changing it here spends the interlock in "
            "advance: the commit that later promotes a provider would find the "
            "implication above already satisfied and object to nothing."
        )
    assert MARKER_TRUST_BASIS in (store_module.__doc__ or ""), (
        "the module docstring states the basis in prose without carrying the "
        f"literal {MARKER_TRUST_BASIS!r}, so the prose and the constant can "
        "drift apart while a scan for the constant's NAME still passes"
    )


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
    client = authed_client(create_app(tmp_path / "capsule", CONTRACTS, clock=_clock(),
                                      flow_factory=GovernedFlow, seal_dir=tmp_path / "seals",
                                      eligibility=_seam_eligibility),
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
