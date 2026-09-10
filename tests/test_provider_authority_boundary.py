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

import contextlib
import errno
import hashlib
import json
import os
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from unittest import mock

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
    CapsuleSealReplaced,
    CapsuleSealUnreadable,
    CapsuleStore,
    CapsuleStoreError,
    ProcessWitness,
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
    # EXACT EQUALITY, so a new key or a changed word is a red test. `held_since`
    # is the one clock-derived value, so it is lifted out and asserted for what
    # it is rather than pinned to a tick count that every earlier request moves.
    held = dict(mid["authority"])
    since = held.pop("held_since")
    assert since is not None and since.endswith("Z")
    assert held == {"anchor": "sealed", "build": "running",
                    "currency": "not_independently_anchored",
                    "continuity": "process", "last_restoration": None}

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
    said = refused.json()["refused"]
    assert refused.status_code == 409, said
    # "restoring the authority store is a human act on this surface" was the
    # retired stop-route claim one synonym away; the refusal now claims only
    # the session holder (A-030).
    assert "holder of this run's session" in said, said
    assert "human act" not in said, said
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


def _readable_routes(capsule: Path, store: CapsuleStore) -> frozenset[str]:
    """Which authority routes a SEALLESS load can actually read.

    The fall-open is a CONJUNCTION -- the marker absent AND forged authority
    readable -- so what a row should measure is the conjunction itself, not
    the marker as a proxy for it. One same-user deletion of the seal is the
    capability A-015 concedes an unconfined provider holds; it is applied here
    and then PUT BACK, so this may be called before a call as well as after,
    which is what lets a row measure a DEGRADATION rather than an absence.
    """
    seal = store.seal_path()
    kept = seal.read_bytes() if seal.exists() else None
    if kept is not None:
        seal.unlink()
    try:
        later = CapsuleStore(capsule, seal_dir=store.seal_dir)
        readable = set()
        for name, call in (("capsule", later.load), ("experience", later.load_experience)):
            try:
                call()
            except Exception:                     # noqa: BLE001 -- any refusal will do
                continue
            readable.add(name)
        return frozenset(readable)
    finally:
        if kept is not None:
            seal.write_bytes(kept)


def _assert_the_marker_write_cannot_be_read_as_legacy(
        capsule: Path, store: CapsuleStore) -> None:
    """The property both marker-write rows assert, once -- restated for the
    ordering that replaced the one they were written against.

    They used to assert that the marker STOOD OVER the worker's forgery, which
    presumed the forgery was still on disk when the marker was written. It is
    not: `_rebuild` neutralises the untrusted authority BEFORE the marker, so
    at this instant there is nothing left to stand over. That is a stronger
    state, not a weaker one, and asserting the old sentence would now fail for
    the very reason the repair exists -- so the assertion moves to the property
    the old one was a proxy for: with the seal gone, NOTHING is readable.

    The specimen guard moves with it. "The forgery is still on disk, so the
    failure landed where the row thinks it did" becomes "the authority is
    already neutralised and the sealed bytes are not back yet", which is the
    same guarantee that the row is measuring the instant it names.
    """
    for name in ("capsule.json", "experience.json"):
        assert not (capsule / name).exists(), (
            f"{name} is still on disk at the marker write, so the neutralisation "
            "did not run before it and this row is measuring a different instant: "
            f"{sorted(path.name for path in capsule.iterdir())}"
        )
    assert _readable_routes(capsule, store) == frozenset(), (
        "one same-user deletion of the seal read the store as legacy: "
        f"{sorted(path.name for path in capsule.iterdir())}"
    )


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
    _assert_the_marker_write_cannot_be_read_as_legacy(capsule, store)


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
        _assert_the_marker_write_cannot_be_read_as_legacy(capsule, store)
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

    WHICH refusal is no longer pinned, and that is the design change rather
    than a loosening. This asserted `CapsuleSealMissing`, which is the refusal
    a store gives when the MARKER is present and the seal is not. `_rebuild`
    now removes the untrusted authority first, so a store caught mid-repair
    can refuse the other way -- `CapsuleStoreError`, on an absent authority
    file -- and both are the store failing closed. Pinning the exception type
    would have pinned the mechanism and called a stronger state a regression.
    What is asserted is the property: NEITHER route reads.
    """
    assert _readable_routes(capsule, store) == frozenset(), (
        "one same-user deletion of the seal read the store as legacy: "
        f"{sorted(path.name for path in capsule.iterdir())}"
    )


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

    WHAT THESE ROWS DO NOT REACH, AND WHAT DOES. The kill lands at the FIRST
    write the marker's write makes, which is before the removal, so these four
    never see the gap BETWEEN the removal and the rename. Round 4 disclosed
    that gap as a crash-only micro-window and both halves of that were wrong:
    an ordinary concurrent reader reaches it with no crash at all (95 of 400
    writes at a directory destination, durably absent in 95 of 95), and the
    window is 16.5% of the call at a directory and 29.1% at a junction rather
    than a micro-anything. `_the_rebuild_survives_every_shape_and_instant`
    below drives that instant deterministically, and
    `test_an_ordinary_concurrent_reader_cannot_open_the_store_to_a_legacy_read`
    drives it with no patching whatever.

    AND THE POST-CONDITION MOVED WITH THE REPAIR. These rows used to assert
    that the worker's forged `experience.json` was still on disk under the
    standing marker. It is not: `_rebuild` neutralises the untrusted authority
    before the marker write, so what they assert now is that it is GONE -- the
    same guarantee that the kill landed at the instant the row names, over a
    store that has nothing left to be read as legacy.

    FOUR ROWS ACROSS THREE FUNCTIONS, and the split is bookkeeping rather than
    design: `check_test_coverage.EXPECTED_SKIPS` is keyed by node id, so a
    declaration covers a whole identity and `EXPECTED_SKIP_CASES` bounds how
    many of its cases may skip. That is enough for a parametrised row -- the
    shape matrix below is declared exactly that way -- but it cannot single
    out ONE parameter of one, so a row that skips for a reason its siblings do
    not still has to be its own function. The two junction rows are that; the
    directory rows need nothing and stay a parametrisation.
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
    for name in ("capsule.json", "experience.json"):
        assert not (capsule / name).exists(), (
            f"{name} is still on disk, so the neutralisation did not run before "
            "the marker write and this row is measuring a different instant: "
            f"{sorted(path.name for path in capsule.iterdir())}"
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


# ---------------------------------------------------------------------------
# D5  the shape axis CROSSED with the failure axis, rather than enumerated apart
# ---------------------------------------------------------------------------
#
# THREE ROUNDS CLOSED THE SAME FALL-OPEN AND EACH LEFT A CELL OUT, and the
# pattern is only visible from here: rounds 3 and 4 enumerated SHAPES on one
# axis and FAILURE MODES on another, fixed the cells they had listed, and never
# multiplied the lists together. Round 4's own concurrent-observer measurement
# had already reached a cell it did not name -- it concluded "it fails CLOSED",
# which is true for a FILE destination and false for a directory or a junction,
# where the removal has already happened by the time the rename can fail.
#
# So the rows below are a product, and the EXPECTATION for each cell is derived
# from `_is_directory_entry` rather than written down per shape: a shape nobody
# anticipated gets an answer without anyone deciding one for it.

_SHAPES = ("non-existent", "regular file", "read-only file", "hardlink",
           "directory", "live junction", "dangling junction",
           "symlink-to-file", "symlink-to-dir", "dangling symlink")

_NO_JUNCTIONS = (
    "A junction is an NTFS directory-shaped reparse point with no POSIX "
    "equivalent, and `is_symlink()` reports False for it, so this plant cannot "
    "be built off Windows. The property is not weakened: `_is_directory_entry` "
    "sends the DIRECTORY rows down the identical branch and those execute on "
    "every platform, and the junction rows execute on a Windows workstation."
)

_NO_SYMLINKS = (
    "Creating a symlink on Windows needs SeCreateSymbolicLinkPrivilege, which "
    "an unelevated account without Developer Mode does not hold, so the three "
    "symlink shapes cannot be built on this host at all. They are NOT covered "
    "by the junction rows -- a junction carries a different reparse tag. What "
    "IS covered here is `_is_directory_entry`'s answer for them, against "
    "synthesised attributes, in "
    "test_the_directory_entry_predicate_answers_the_shapes_this_host_cannot_build: "
    "the predicate only, never os.replace's behaviour at such a destination, "
    "which stays unverified on this host and is declared so rather than assumed. "
    "Every CI test job runs Linux, where these three build and execute."
)


def _plant_shape(shape: str, path: Path, outside: Path) -> str | None:
    """Build `shape` at `path`. Returns None, or WHY it is impossible here.

    A shape this host cannot build is never silently dropped: the caller skips
    with the reason the operating system itself gave, so a row that stops
    running says which capability it stopped running for.
    """
    outside.mkdir(parents=True, exist_ok=True)
    if shape == "non-existent":
        return None
    if shape in ("live junction", "dangling junction"):
        if os.name != "nt":
            return _NO_JUNCTIONS
        target = outside / ("junction-target-" + os.urandom(3).hex())
        if shape == "live junction":
            target.mkdir()
            (target / "kept.txt").write_text("the target\n", encoding="utf-8", newline="")
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(path), str(target)],
                              capture_output=True, text=True, check=False, timeout=60)
        if done.returncode != 0:
            return f"mklink /J refused: {(done.stdout + done.stderr).strip()[:120]}"
        assert store_module._is_junction(path), f"{shape} did not land as a junction"
        assert os.path.exists(path) is (shape == "live junction"), (
            f"{shape} landed with the wrong liveness: a dangling junction must "
            "answer False to os.path.exists and a live one True, and the whole "
            "point of this shape is the difference between the two"
        )
        return None
    if shape in ("symlink-to-file", "symlink-to-dir", "dangling symlink"):
        target = outside / ("symlink-target-" + os.urandom(3).hex())
        if shape == "symlink-to-file":
            target.write_text("the target\n", encoding="utf-8", newline="")
        elif shape == "symlink-to-dir":
            target.mkdir()
        try:
            os.symlink(target, path, target_is_directory=(shape == "symlink-to-dir"))
        except OSError as exc:
            return f"os.symlink is refused on this host: {exc}. {_NO_SYMLINKS}"
        assert os.path.islink(path), f"{shape} did not land as a symlink"
        return None
    if shape == "regular file":
        path.write_text("occupant\n", encoding="utf-8", newline="")
        return None
    if shape == "read-only file":
        path.write_text("occupant\n", encoding="utf-8", newline="")
        os.chmod(path, stat.S_IREAD)
        return None
    if shape == "hardlink":
        other = outside / "hardlink-other.txt"
        other.write_text("a file the store has no business touching\n",
                         encoding="utf-8", newline="")
        os.link(other, path)
        assert other.stat().st_nlink == 2, "the hardlink did not land"
        return None
    if shape == "read-only hardlink":
        # THE SHAPE THAT SEPARATES A REMEDY FROM A LEAK. Both names reach one
        # file, so a chmod through the inside name clears the bit on the
        # OUTSIDE one; the plant is asserted through the outside name for
        # exactly that reason, and the rows read it back there afterwards.
        other = outside / "hardlink-other-readonly.txt"
        other.write_text("a file the store has no business touching\n",
                         encoding="utf-8", newline="")
        os.link(other, path)
        os.chmod(path, stat.S_IREAD)
        assert other.stat().st_nlink == 2, "the hardlink did not land"
        assert not (os.stat(other).st_mode & stat.S_IWRITE), (
            "the read-only bit did not reach the file through the link, so this "
            "plant cannot show a guard refusing to clear it")
        return None
    if shape == "directory":
        path.mkdir()
        (path / "occupant.txt").write_text("x\n", encoding="utf-8", newline="")
        assert path.is_dir() and not path.is_symlink(), "the directory did not land"
        return None
    raise AssertionError(f"unknown shape {shape!r}")


def _plant_at_authority(shape: str, path: Path, outside: Path,
                        stack: contextlib.ExitStack) -> str | None:
    """`_plant_shape`, at a name that ALREADY holds the store's authority file.

    TWO SHAPES ACT ON WHAT IS THERE RATHER THAN REPLACING IT, because that is
    what makes them the specimens they are: a read-only bit and a held handle
    are things done TO the worker's authority, not instead of it, and both are
    reached by a same-operating-system-user command A-015 concedes. Every
    other shape needs the name free first, and freeing it here is one plain
    unlink -- the entry is always a regular file the store itself just wrote,
    so the instrument never needs the shape dispatch it exists to falsify.

    The handle is entered on the caller's stack, so it closes when the row
    ends and no cell leaks a lock into the next one.
    """
    if shape == "read-only file":
        os.chmod(path, stat.S_IREAD)
        assert not (os.stat(path).st_mode & stat.S_IWRITE), "the +R did not land"
        return None
    if shape == "held handle":
        stack.enter_context(open(path, "rb"))
        return None
    if os.path.lexists(path):
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        os.unlink(path)
    return _plant_shape(shape, path, outside)


def _entry_state(path: Path) -> str:
    """What is at `path`, read WITHOUT following it.

    That is the whole point of the helper: `Path.is_dir()` stats THROUGH a
    reparse point and answers False for a dangling one, so an instrument built
    on it could not see the cell this slice exists to close.
    """
    if not os.path.lexists(path):
        return "absent"
    if store_module._is_junction(path):
        return "junction"
    if os.path.islink(path):
        return "symlink"
    if store_module._is_directory_entry(path):
        return "directory"
    try:
        return "file:" + path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"file:unreadable:{type(exc).__name__}"


_FRESH = "the marker Forge means to write\n"
_WRITE_FRESH_INSTANTS = ("clean", "before the temp write", "at the removal", "at the rename")
_FORMS = ("crash", "oserror")


@pytest.mark.parametrize(
    "shape", [pytest.param(shape, id=shape.replace(" ", "-")) for shape in _SHAPES])
def test_the_marker_write_is_shape_correct_at_every_interior_instant(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str):
    """`_write_fresh` at every shape a destination can have, crossed with every
    interior instant it can fail at, crossed with both forms of failure.

    THE EXPECTATION IS DERIVED, NOT LISTED. Whether a shape needs removing is
    `_is_directory_entry(destination)`, measured on the plant rather than read
    off a list of shape names, and that same answer decides what each instant
    leaves behind. This is the cell three rounds missed: a DANGLING junction is
    directory-attributed to `lstat` while `is_dir()` answers False, so the
    shipped guard skipped its removal and handed `os.replace` a destination
    Win32 forbids. One unprivileged `mklink /J .forge-seal <nonexistent>` and
    the marker was durably absent with the worker's forged authority beside it.

    THE FORM AXIS IS CROSSED INSIDE THE ROW rather than in the node id, and
    deliberately: a crash and a handled `OSError` at the same instant must
    leave the SAME destination state, and only a row that runs both can assert
    that. Split across two nodes, one could pass while the other failed
    somewhere else entirely. What the two forms MAY differ in is the temp
    sibling -- the `OSError` path runs the cleanup and a crash cannot -- and
    that is asserted too, because that survivor is what `_tree_changes` exempts.

    THE INSTRUMENT IS DELIMITED BY THE FUNCTION IT PATCHES, so an
    implementation that inlines `os.replace`, or removes by some third route,
    never fires the arming; the row then finds no exception where it demanded
    one and goes RED, rather than passing because nothing happened.
    """
    observed: list[str] = []
    for instant in _WRITE_FRESH_INSTANTS:
        for form in _FORMS:
            if instant == "clean" and form == "oserror":
                continue                      # one clean run, not two
            cell = tmp_path / f"cell-{len(observed)}"
            area, outside = cell / "store", cell / "outside"
            area.mkdir(parents=True)
            destination = area / ".forge-seal"
            reason = _plant_shape(shape, destination, outside)
            if reason is not None:
                pytest.skip(reason)
            directory_attributed = store_module._is_directory_entry(destination)
            before = _entry_state(destination)
            fired: list[str] = []
            failure: BaseException = (
                SystemExit("the process died inside _write_fresh") if form == "crash"
                else OSError(28, "No space left on device"))

            with monkeypatch.context() as patch:
                if instant == "before the temp write":
                    def dies_writing(self, *args, _f=failure, **kwargs):
                        fired.append("write_text")
                        raise _f

                    patch.setattr(Path, "write_text", dies_writing)
                elif instant == "at the removal":
                    def dies_removing(path, _f=failure):
                        fired.append("_remove_entry")
                        raise _f

                    patch.setattr(store_module, "_remove_entry", dies_removing)
                elif instant == "at the rename":
                    def dies_renaming(tmp, path, _f=failure):
                        fired.append("_replace_fresh")
                        raise _f

                    patch.setattr(store_module, "_replace_fresh", dies_renaming)
                raised: str | None = None
                try:
                    store_module._write_fresh(destination, _FRESH)
                except BaseException as exc:            # noqa: BLE001
                    raised = type(exc).__name__

            # WHAT THIS CELL SHOULD HAVE DONE, derived from the destination.
            # The removal instant is reachable ONLY where a rename cannot do
            # the job, so for every other shape this cell is a clean write and
            # the arming must not have fired at all.
            reached = instant != "clean" and (
                instant != "at the removal" or directory_attributed)
            if not reached:
                expected_state, expected_raised = "file:" + _FRESH, None
            elif instant == "at the rename" and directory_attributed:
                expected_state, expected_raised = "absent", type(failure).__name__
            else:
                expected_state, expected_raised = before, type(failure).__name__
            strays = sorted(entry.name for entry in area.iterdir()
                            if entry.name != destination.name)
            observed.append(
                f"{instant:<22} {form:<8} dir-attr={directory_attributed!s:<5} "
                f"fired={bool(fired)!s:<5} raised={raised!s:<16} "
                f"state={_entry_state(destination)!r} strays={strays}")
            assert (raised, _entry_state(destination)) == (expected_raised, expected_state), (
                f"{shape} / {instant} / {form}: the destination is not what this "
                f"cell requires.\n" + "\n".join(observed))
            assert bool(fired) == reached, (
                f"{shape} / {instant} / {form}: the arming "
                f"{'never fired' if reached else 'fired when it must not'}. An "
                "implementation this instrument cannot reach must fail the row "
                "loudly, not pass it quietly.\n" + "\n".join(observed))
            # The temp survives exactly when it EXISTED and nothing ran the
            # cleanup: a crash at an instant after the temp write. `before the
            # temp write` is the instant at which there is no temp yet, so
            # neither form leaves one -- which is why this is derived from the
            # instant as well as the form, and not from the form alone.
            survives = reached and instant != "before the temp write" and form == "crash"
            assert (strays != []) is survives, (
                f"{shape} / {instant} / {form}: the temp survivor is not what the "
                f"instant and the form together require: {strays}\n"
                + "\n".join(observed))
            if shape == "hardlink":
                assert (outside / "hardlink-other.txt").read_text(encoding="utf-8") == \
                    "a file the store has no business touching\n", (
                    f"{shape} / {instant} / {form}: the write reached a file "
                    "OUTSIDE the store through the planted link")


def test_the_directory_entry_predicate_answers_the_shapes_this_host_cannot_build():
    """The three symlink shapes could not be planted here, so the predicate is
    driven against SYNTHESISED attributes instead of an absent specimen.

    WHAT THIS ESTABLISHES AND WHAT IT DOES NOT. It establishes that a Windows
    DIRECTORY symlink -- which carries `FILE_ATTRIBUTE_DIRECTORY` on the link
    itself, dangling or not -- lands in `_write_fresh`'s removal branch, and
    that a FILE symlink does not. It does NOT establish that `os.replace`
    refuses a directory symlink on Windows; that is documented behaviour this
    host cannot exercise, and A-022 records it as unverified rather than
    measured. Saying so is the point: the shipped comment claimed `os.replace`
    "replaces a symlink rather than following it" flatly, on a machine where no
    symlink has ever been created.

    On POSIX `lstat` reports `S_IFLNK` for both, `S_ISDIR` is False, nothing is
    removed, and `os.rename` replaces the link -- which is the POSIX behaviour
    the flat claim was borrowed from.
    """
    directory_attribute = stat.FILE_ATTRIBUTE_DIRECTORY
    reparse_attribute = stat.FILE_ATTRIBUTE_REPARSE_POINT

    class _WindowsAttributes:
        def __init__(self, attributes: int) -> None:
            self.st_file_attributes = attributes
            self.st_mode = stat.S_IFLNK | 0o777

    answers = {}
    for label, attributes in (
        ("directory symlink", directory_attribute | reparse_attribute),
        ("dangling directory symlink", directory_attribute | reparse_attribute),
        ("file symlink", reparse_attribute),
        ("dangling file symlink", reparse_attribute),
    ):
        with mock.patch.object(os, "lstat", return_value=_WindowsAttributes(attributes)):
            answers[label] = store_module._is_directory_entry(Path("unread"))
    assert answers == {"directory symlink": True, "dangling directory symlink": True,
                       "file symlink": False, "dangling file symlink": False}, answers

    # The POSIX side of the same predicate, with no Windows attributes at all.
    class _PosixMode:
        def __init__(self, mode: int) -> None:
            self.st_mode = mode

    for mode, expected in ((stat.S_IFLNK | 0o777, False), (stat.S_IFDIR | 0o755, True),
                           (stat.S_IFREG | 0o644, False)):
        with mock.patch.object(os, "lstat", return_value=_PosixMode(mode)):
            assert store_module._is_directory_entry(Path("unread")) is expected, oct(mode)

    # A name that is not there answers False rather than raising, which is what
    # lets `_write_fresh` reach `os.replace` for a free destination.
    assert store_module._is_directory_entry(Path("no-such-name-anywhere")) is False


_REBUILD_INSTANTS = (
    "inside the neutralisation",
    "inside the marker's own write",
    "at the marker's rename, after the removal",
    "between the two authority writes",
    "at git init",
)


def _arm_rebuild(patch, capsule: Path, instant: str, failure: BaseException) -> list[str]:
    """Arm `failure` at one interior instant of `_rebuild`. Returns the list the
    arming appends to when it fires, so a row can fail loudly if it never did.

    Every arming is delimited by the METHOD or FUNCTION it patches rather than
    by a filename, for the reason round 3 recorded: a removal-then-write and a
    write-then-rename have to be reached at the same instant, or the instrument
    measures the implementation instead of the property.
    """
    fired: list[str] = []
    armed: list[int] = []
    if instant == "inside the neutralisation":
        # The SECOND authority file, so the first is already gone: the instant
        # at which a half-neutralised store must still be no more readable than
        # it was. Armed only while the neutralisation runs, so the wipe's own
        # removals later are not caught by it.
        survivor_remove = store_module._remove_entry
        survivor_neutralise = store_module.CapsuleStore._neutralise_untrusted_authority

        def counted_remove(path):
            if armed:
                armed.append(1)
                if len(armed) > 2:
                    fired.append("_remove_entry")
                    raise failure
            return survivor_remove(path)

        def arming_neutralise(self):
            armed.append(1)
            try:
                return survivor_neutralise(self)
            finally:
                armed.clear()

        patch.setattr(store_module, "_remove_entry", counted_remove)
        patch.setattr(store_module.CapsuleStore, "_neutralise_untrusted_authority",
                      arming_neutralise)
    elif instant == "inside the marker's own write":
        survivor_write_text = Path.write_text
        survivor_marker = store_module.CapsuleStore._write_seal_marker

        def dies_at_the_first_write(self, *args, **kwargs):
            if armed:
                fired.append("write_text")
                raise failure
            return survivor_write_text(self, *args, **kwargs)

        def arming_marker_write(self):
            armed.append(1)
            try:
                return survivor_marker(self)
            finally:
                armed.clear()

        patch.setattr(Path, "write_text", dies_at_the_first_write)
        patch.setattr(store_module.CapsuleStore, "_write_seal_marker", arming_marker_write)
    elif instant == "at the marker's rename, after the removal":
        # THE INSTANT ROUND 4 DISCLOSED AS CRASH-ONLY AND AN ORDINARY READER
        # REACHES. `_replace_fresh` runs after the removal, so at a
        # directory-attributed destination the marker name is already empty
        # when this raises -- the state the concurrent-reader row below reaches
        # with no patching at all, 95 times in 400.
        survivor_replace = store_module._replace_fresh
        survivor_marker = store_module.CapsuleStore._write_seal_marker

        def dies_renaming(tmp, path):
            if armed:
                fired.append("_replace_fresh")
                raise failure
            return survivor_replace(tmp, path)

        def arming_marker_write(self):
            armed.append(1)
            try:
                return survivor_marker(self)
            finally:
                armed.clear()

        patch.setattr(store_module, "_replace_fresh", dies_renaming)
        patch.setattr(store_module.CapsuleStore, "_write_seal_marker", arming_marker_write)
    elif instant == "between the two authority writes":
        doomed = capsule / "experience.json"
        survivor_write_text = Path.write_text

        def dies_between(self, *args, **kwargs):
            if self.parent == doomed.parent and self.name.startswith(doomed.name):
                fired.append("write_text")
                raise failure
            return survivor_write_text(self, *args, **kwargs)

        patch.setattr(Path, "write_text", dies_between)
    else:
        survivor_git = store_module._run_git

        def dies_at_init(root, *args):
            if args and args[0] == "init":
                fired.append("_run_git")
                raise failure
            return survivor_git(root, *args)

        patch.setattr(store_module, "_run_git", dies_at_init)
    return fired


def _the_rebuild_survives_every_shape_and_instant(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str) -> None:
    """THE INVARIANT, ONE SHAPE AT `.forge-seal`, EVERY INTERIOR INSTANT, BOTH
    FORMS -- stated over what a sealless load can READ rather than over the
    marker, because the marker was only ever a proxy for that.

    Three rounds patched the marker's write and each left a cell open, because
    `os.replace` cannot replace a directory and so a remove-then-create window
    is irreducible for a directory-shaped entry. `_rebuild` therefore breaks the
    OTHER half of the conjunction: it neutralises the untrusted authority before
    it touches the marker, so from that point on there is nothing a missing
    marker can expose. Measured, seal deleted and marker absent:

        authority              load_experience()   load()
        both gone              REFUSED             REFUSED
        capsule.json gone      RETURNED 'READY'    REFUSED
        experience.json gone   REFUSED             RETURNED
        neither gone           RETURNED 'READY'    RETURNED

    -- which is why BOTH files are neutralised, and why this row asserts the
    empty set rather than one route.

    ONE CLAUSE NOW, AND IT USED TO BE TWO. The instant INSIDE the
    neutralisation -- one file gone, one still there -- was the weak cell: the
    marker had not been written yet, so all this row could ask of it was that
    the restoration OPENED NOTHING, the readable set a subset of what the call
    found. That was honest and it was not enough, because the set it was a
    subset of could be everything: at that instant a store whose worker had
    deleted the marker was still readable, and one unprivileged `attrib +R` on
    an authority file made the failure PERMANENT there rather than transient.
    `_rebuild` now writes the marker best-effort on ANY failure of the
    neutralisation, so that instant closes like every other and this row
    asserts the same empty set at all five.

    THE STRENGTHENING IS A MEASUREMENT AND NOT A REWORDING, and the campaign
    says exactly how far it reaches: reverting the best-effort write reddens
    the `non-existent` and `dangling junction` rows of this parametrisation and
    no other row THAT RUNS HERE. That is not a gap. The plants it reddens are
    the ones `protected()` answers False for -- every other shape leaves an
    entry at `.forge-seal` that `protected()` counts, so those rows never
    rested on that write at all. A first draft said "every shape here", which
    the campaign falsified.

    THE HOST IS PART OF THAT SENTENCE, and leaving it out would restate a
    HOST-SCOPED observation as a property. `dangling symlink` is a THIRD plant
    `protected()` answers False for -- `Path.exists()` resolves the link and
    finds nothing, exactly as it does through a dangling junction -- and it
    merely SKIPS on this workstation, where `os.symlink` raises `[WinError
    1314]`. On a host that can build it the same mutation reddens three rows,
    so "and no other" would read as falsified on every Linux CI job. Two is
    what was counted where the count was taken; three is what the property
    predicts where all the plants build.

    THE ORDER IS NOT PROVEN HERE ANY MORE, and it never was proven WELL here.
    This row used to assert that the marker on disk still matched the plant at
    that instant, and read that as the neutralisation running first. It is a
    state, and a state is consistent with more than one ordering; it is also
    now false by design, since the failure path writes the marker on purpose.
    `test_the_rebuild_neutralises_the_authority_before_it_touches_the_marker`
    records the sequence of calls a clean rebuild makes and asserts it
    directly, which is the row that carries the ordering.

    A restoration that fails is a restoration that did not happen; it must
    never be a degradation Forge itself caused. That is the whole difference
    between this and the state round 3 measured, where Forge's own recovery
    removed the store's second authentication factor and then reported a clean
    refusal whose exception promised nothing had been partially written.
    """
    observed: list[str] = []
    for instant in _REBUILD_INSTANTS:
        for form in _FORMS:
            cell = tmp_path / f"cell-{len(observed)}"
            store = CapsuleStore(cell / "capsule", seal_dir=cell / "seals")
            store.initialize(create_document("proj-1", "Portal", Actor("human", "casey"), AT),
                             experience=start_experience(Actor("human", "casey"), AT))
            sealed = store.sealed()
            capsule = store.root
            forge_ready(capsule)
            _remove_tree(capsule / ".git")      # the honest reset route is unreachable
            (capsule / ".forge-seal").unlink()
            reason = _plant_shape(shape, capsule / ".forge-seal", cell / "outside")
            if reason is not None:
                pytest.skip(reason)
            planted = _entry_state(capsule / ".forge-seal")
            before = _readable_routes(capsule, store)

            failure: BaseException = (
                SystemExit("the process died inside _rebuild") if form == "crash"
                else OSError(28, "No space left on device"))
            with monkeypatch.context() as patch:
                fired = _arm_rebuild(patch, capsule, instant, failure)
                with pytest.raises(SystemExit if form == "crash" else CapsuleStoreError):
                    store.restore(sealed)

            after = _readable_routes(capsule, store)
            observed.append(
                f"{instant:<42} {form:<8} planted={planted:<12} "
                f"before={sorted(before)} after={sorted(after)} "
                f"marker={_entry_state(capsule / '.forge-seal')!r}")
            assert fired, (
                f"{shape} / {instant} / {form}: the arming never fired, so the row "
                "did not reach the instant it names and its verdict means nothing.\n"
                + "\n".join(observed))
            assert after <= before, (
                f"{shape} / {instant} / {form}: the restoration OPENED an "
                "authority route it found closed.\n" + "\n".join(observed))
            assert after == frozenset(), (
                f"{shape} / {instant} / {form}: one same-user deletion of the "
                "seal read the store as legacy. Entries: "
                f"{sorted(path.name for path in capsule.iterdir())}\n"
                + "\n".join(observed))


@pytest.mark.parametrize("shape", [
    pytest.param(shape, id=shape.replace(" ", "-"))
    for shape in _SHAPES if "junction" not in shape])
def test_the_rebuild_leaves_no_readable_instant_at_any_destination_shape(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str):
    """Every shape but the two junctions, which need their own skip reason.
    See `_the_rebuild_survives_every_shape_and_instant`."""
    _the_rebuild_survives_every_shape_and_instant(tmp_path, monkeypatch, shape)


@pytest.mark.skipif(os.name != "nt", reason=_NO_JUNCTIONS)
def test_the_rebuild_leaves_no_readable_instant_at_a_live_junction(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """See `_the_rebuild_survives_every_shape_and_instant`."""
    _the_rebuild_survives_every_shape_and_instant(tmp_path, monkeypatch, "live junction")


@pytest.mark.skipif(os.name != "nt", reason=_NO_JUNCTIONS)
def test_the_rebuild_leaves_no_readable_instant_at_a_dangling_junction(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """THE CELL THREE ROUNDS MISSED, driven through the real `restore()`.

    Measured at the parent of this commit, with one unprivileged
    `mklink /J .forge-seal <nonexistent>` and nothing else patched:

        .git INTACT : restore -> CapsuleStoreError: PermissionError [WinError 5]
                      protected=False   sealless load: RETURNED stage='READY'
        .git REMOVED: identical
        on disk       ['.forge-capsule', 'capsule.json', 'experience.json']

    Worse than either shape round 4 closed. No crash, no patched write, and the
    honest `git reset --hard` route cannot repair it either, so `_rebuild` runs
    and fails the same way on every later call: PERMANENT. The cause is one
    predicate. `Path.is_dir()` stats THROUGH a reparse point, so a junction
    whose target is gone answers False, the removal branch is skipped, and
    `os.replace` is handed a directory-attributed entry Win32 forbids it to
    replace. `_is_junction` was already in the module and was not consulted.

    See `_the_rebuild_survives_every_shape_and_instant`.
    """
    _the_rebuild_survives_every_shape_and_instant(tmp_path, monkeypatch, "dangling junction")


@pytest.mark.skipif(os.name != "nt", reason=_NO_JUNCTIONS)
def test_the_wipe_removes_a_dangling_junction_the_worker_left_behind(tmp_path: Path):
    """A STANDING PROPERTY OF THE WIPE, NOT A REPAIRED DEFECT -- and this row
    used to claim the second.

    It said `_rebuild`'s wipe read `entry.is_dir() and not entry.is_symlink()`
    and "sent everything else to `unlink`, which Win32 refuses for a
    directory-attributed entry", so one dangling junction at a non-kept name
    "stopped the rebuild before `git init`". THAT DID NOT HAPPEN. Measured at
    719c744, which carries that predicate, with a dangling AND a live junction
    planted and `.git` removed: `restore()` RETURNED, `git init` was reached,
    both entries were gone and the live target kept its bytes. `os.unlink`
    removes a junction -- CPython's `Py_DeleteFileW` sees a directory reparse
    point and calls `RemoveDirectoryW` -- and a live junction never reached
    that branch, because `is_dir()` is True through it. The refusal that is
    real is `os.replace`'s, at `_write_fresh`, which is P1-A.

    WHAT THIS ROW IS FOR, then: the wipe must take BOTH junction shapes and
    must take them AS LINKS. That is a property worth pinning whether or not
    it was ever broken, and it has teeth -- the mutation that removes both
    reparse-point guards, so a junction is walked rather than taken, reddens
    this row. The mutation that merely restores the old predicate does not,
    because on this host it removes every shape too; it is an equivalent
    mutant and is recorded as one in `_rebuild` and in A-022.

    The junction's TARGET must survive, and is asserted: removing a junction
    means removing the LINK. `_remove_entry` uses `os.rmdir` for exactly that,
    and a live junction is planted here beside the dangling one so both
    branches of the same predicate run in one row.
    """
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    capsule = tmp_path / "capsule"
    forge_ready(capsule)
    _remove_tree(capsule / ".git")          # force the rebuild rather than a reset

    outside = tmp_path / "outside"
    dangling = _plant_shape("dangling junction", capsule / "stray-dangling", outside)
    live = _plant_shape("live junction", capsule / "stray-live", outside)
    assert (dangling, live) == (None, None), (dangling, live)
    target = next(path for path in outside.iterdir() if path.is_dir())
    assert (target / "kept.txt").exists(), "the live junction's target did not land"

    revision, notes = store.restore(sealed)

    assert "rebuilt" in notes[0]
    assert not os.path.lexists(capsule / "stray-dangling"), (
        "the wipe left the dangling junction standing, so it either raised or "
        f"skipped it: {sorted(path.name for path in capsule.iterdir())}")
    assert not os.path.lexists(capsule / "stray-live")
    assert (target / "kept.txt").read_text(encoding="utf-8") == "the target\n", (
        "removing the junction reached THROUGH it and destroyed the target's "
        "contents; a junction is removed as a link, not walked"
    )
    assert (capsule / ".git").is_dir(), "the rebuild never reached git init"
    assert store.seal_problems(store.sealed()) == []
    assert _store(tmp_path).load_experience()["stage"] == "DISCOVER"


def test_the_rebuild_neutralises_the_authority_before_it_touches_the_marker(tmp_path: Path):
    """THE ORDER IS THE PROPERTY, so the order is what this row reads.

    Every other row here observes a state after a failure, and a state is
    consistent with more than one ordering. This one records the sequence of
    calls a CLEAN rebuild makes and asserts it: the untrusted authority is
    neutralised, THEN the seal marker, THEN the sealed bytes, THEN the store
    marker. Reordering `_rebuild` to write the marker first -- which is what
    shipped for two rounds -- reddens this row directly rather than by
    consequence, and so does dropping the neutralisation altogether.
    """
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    capsule = tmp_path / "capsule"
    forge_ready(capsule)
    _remove_tree(capsule / ".git")

    trace: list[str] = []
    survivor_neutralise = CapsuleStore._neutralise_untrusted_authority
    survivor_marker = CapsuleStore._write_seal_marker
    survivor_write_fresh = store_module._write_fresh

    def traced_neutralise(self):
        trace.append("neutralise")
        return survivor_neutralise(self)

    def traced_marker(self):
        trace.append("seal marker")
        return survivor_marker(self)

    def traced_write_fresh(path, text):
        # The marker's own `_write_fresh` is the "seal marker" entry above; it
        # is not recorded twice.
        if path.name != ".forge-seal":
            trace.append(f"write {path.name}")
        return survivor_write_fresh(path, text)

    with mock.patch.object(CapsuleStore, "_neutralise_untrusted_authority",
                           traced_neutralise), \
         mock.patch.object(CapsuleStore, "_write_seal_marker", traced_marker), \
         mock.patch.object(store_module, "_write_fresh", traced_write_fresh):
        store.restore(sealed)

    assert trace == ["neutralise", "seal marker", "write capsule.json",
                     "write experience.json", "write .forge-capsule"], trace
    assert store.seal_problems(store.sealed()) == []


def test_an_ordinary_concurrent_reader_cannot_open_the_store_to_a_legacy_read(tmp_path: Path):
    """NO PRIVILEGE, NO PATCHING, NO CRASH -- one reader doing what an indexer,
    a backup agent or Defender does, and the shipped `restore()`.

    A-022 said the durable form of this "disappears entirely (no `OSError`, no
    full disk, no scanner can reach it)". A scanner is precisely what reached
    it. `_write_fresh` writes its temp sibling, removes the directory at the
    destination and then renames; a reader holding the SOURCE denies the rename
    with a sharing violation, and the removal has already happened. Measured at
    the parent, one observer thread, 400 rounds per destination shape:

        destination   succeeded   raised            durably ABSENT after
        regular file  390         10                 0 / 10
        directory     305         95 (WinError 32)  95 / 95
        junction      399          1 (WinError 32)   1 / 1

    The file column is why round 4 concluded it fails closed: at a file
    destination there is no removal, so the old marker is still standing. End to
    end through `restore()` at the parent, 25 attempts with one reader thread:
    the marker was left absent once, and that once the store fell open --
    `['.forge-capsule', 'capsule.json', 'experience.json']`, a sealless load
    RETURNING the forged `READY`. On this tree, same instrument, same 25
    attempts: the marker was still left absent once, and NOTHING fell open.

    THIS ROW ASSERTS THE PROPERTY, NOT THE RATE. Whether the denial happens in
    a given run is timing; that it cannot open the store is not. It is bounded
    by attempts AND by a wall clock, and it asserts the observer really ran, so
    a reader thread that died at once cannot make it pass by doing nothing.
    """
    attempts, deadline = 6, time.monotonic() + 120
    opens, denials = 0, 0
    for attempt in range(attempts):
        if time.monotonic() > deadline:
            break
        cell = tmp_path / f"attempt-{attempt}"
        store = CapsuleStore(cell / "capsule", seal_dir=cell / "seals")
        store.initialize(create_document("proj-1", "Portal", Actor("human", "casey"), AT),
                         experience=start_experience(Actor("human", "casey"), AT))
        sealed = store.sealed()
        capsule = store.root
        forge_ready(capsule)
        _remove_tree(capsule / ".git")
        marker = capsule / ".forge-seal"
        marker.unlink()
        marker.mkdir()
        (marker / "occupant.txt").write_text("x\n", encoding="utf-8", newline="")

        stop = threading.Event()
        seen = [0]

        def read_everything(area=capsule, seen=seen):
            while not stop.is_set():
                try:
                    for entry in os.scandir(area):
                        try:
                            with open(entry.path, "rb") as handle:
                                handle.read(1)
                            seen[0] += 1
                        except OSError:
                            pass
                except OSError:
                    pass

        reader = threading.Thread(target=read_everything, daemon=True, name="ordinary-reader")
        reader.start()
        try:
            try:
                store.restore(sealed)
            except CapsuleStoreError:
                denials += 1
        finally:
            stop.set()
            reader.join(timeout=30)
        opens += seen[0]

        assert _readable_routes(capsule, store) == frozenset(), (
            f"attempt {attempt}: an ordinary reader opened the store to a legacy "
            f"read. Entries: {sorted(path.name for path in capsule.iterdir())}; "
            f"marker: {_entry_state(marker)!r}; denials so far: {denials}"
        )
    assert opens > 0, (
        "the observer never opened anything, so this row measured a restoration "
        "with no concurrent reader at all and proves nothing"
    )


# ---------------------------------------------------------------------------
# D6  the cross product FOLLOWS THE REMOVAL to the site round 5 created
# ---------------------------------------------------------------------------
#
# ROUND 5 MADE THE AUTHORITY PATHS A REMOVAL SITE FOR THE FIRST TIME and the
# shape axis did not follow it there. Every plant in D5 goes to `.forge-seal`;
# `os.chmod(..., S_IREAD)` appeared exactly once in this file, inside
# `_plant_shape`, and nothing planted anything at `capsule.json` or
# `experience.json` as a SHAPE. So `_remove_entry`'s plain-file branch -- a
# bare `os.unlink`, the one primitive in the module that did not clear the
# read-only bit while both its siblings did -- became the first removal that
# runs while `protected()` is still False, and its refusal became a fall-open.
# Measured through the shipped `restore()`, `.git` destroyed and the marker
# deleted, one `attrib +R experience.json` and nothing else:
#
#     BEFORE   ['.forge-capsule', 'capsule.json', 'experience.json']
#     restore  CapsuleStoreError: PermissionError [WinError 5]
#     AFTER    ['.forge-capsule', 'experience.json']
#     marker absent   protected() False   sealless load RETURNED 'READY'
#     attempts 2 and 3: identical. PERMANENT.
#
# TWO PROPERTIES, AND THEY ARE NOT THE SAME PROPERTY. Clearing the bit makes
# the remedy WORK again -- recoverability. But a held handle raises WinError 32
# and no chmod reaches it, so no list of shapes can be the whole answer, and
# four rounds of extending such a list is what this one stops. `_rebuild`
# therefore writes the seal marker, best effort, on ANY failure of the
# neutralisation: whatever defeated the removal, the store ends PROTECTED and
# the residue is a refusal instead of a legacy read -- fail-closed. The rows
# below assert the second for every cell and the first where it is reachable,
# and the two are killed by different mutations: reverting the read-only retry
# reddens the recoverability rows only, and removing the best-effort write
# reddens the fail-closed rows only. Measured both ways.

_AUTHORITY_SHAPES = _SHAPES + ("read-only hardlink", "held handle")
_AUTHORITY_FORMS = ("clean", "oserror", "crash")


def _arm_the_removal_of(target: str, failure: BaseException,
                        fired: list[str]):
    """Make `_remove_entry` raise `failure` at ONE authority name and pass
    every other path through to the real one.

    Keyed on the NAME rather than on a call count, so the row reaches the
    instant it names whichever position that file holds in `_AUTHORITY_FILES`:
    at `capsule.json` the FIRST removal fails and nothing has been touched, at
    `experience.json` the SECOND fails with the first already gone. That
    second cell is the one a shipped sentence denied could exist.
    """
    survivor = store_module._remove_entry

    def armed(path: Path):
        if path.name == target:
            fired.append(path.name)
            raise failure
        return survivor(path)

    return armed


def _the_neutralisation_fails_closed_at_every_shape(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str) -> None:
    """One shape at BOTH authority names, crossed with a clean run, a handled
    `OSError` and a process death, driven through the shipped `restore()`.

    THE INVARIANT IS ONE SENTENCE AND IT DOES NOT NAME A SHAPE: however the
    neutralisation ends, the store is left PROTECTED and a sealless load can
    read nothing. `protected()` True with the seal gone is `CapsuleSealMissing`
    on both routes, so the two halves of the assertion are the conjunction the
    fall-open needs, measured rather than proxied.

    EVERY CELL ASSERTS ITS PRECONDITION IS REALLY A FALL-OPEN before the call.
    A row whose plant destroyed both authority routes would pass by having
    nothing left to open, which proves nothing at all; `before` is asserted
    non-empty, and an armed cell asserts its arming fired.

    WHAT THE `clean` FORM IS FOR. It runs the real removal against the real
    shape with nothing patched, so the row measures what the operating system
    does rather than what the test supposes it does -- which is how the
    read-only cell was found in the first place. Its extra assertion is
    two-sided and DERIVED rather than listed per shape: a restoration that
    RETURNED must leave the store matching its seal, and one that was REFUSED
    must leave the plant exactly as it stood. The second half is what stops a
    partial removal being reported as a clean refusal. Neither half decides
    which shapes may refuse -- that is read off the disk, and the two that do
    reach it here are disclosed in A-022 rather than encoded in a list.

    RECOVERABILITY IS A DIFFERENT PROPERTY AND HAS ITS OWN ROW. A permanent
    refusal is a defeated remedy even while it is fail-closed, and `restore()`
    is the only remedy this surface has, so the read-only shape is asserted to
    RECOVER by
    `test_a_read_only_authority_file_no_longer_permanently_defeats_the_restoration`.
    Keeping the two apart is deliberate, and the campaign measured the split:
    reverting the read-only retry reddens that ONE row and leaves every row
    here green, which is what tells a later reader that this matrix proves
    fail-closed and not repair.

    A HARDLINK IS NEVER REACHED THROUGH, and the two link rows read the
    outside file back: its bytes, and for the read-only one its bit. An
    unguarded chmod through the inside name clears the bit on the file
    outside -- measured directly, `True` before and `False` after, which is
    why `_solely_owned_file` exists and why this row would catch its removal.
    """
    observed: list[str] = []
    for target in store_module._AUTHORITY_FILES:
        for form in _AUTHORITY_FORMS:
            cell = tmp_path / f"cell-{len(observed)}"
            store = CapsuleStore(cell / "capsule", seal_dir=cell / "seals")
            store.initialize(create_document("proj-1", "Portal", Actor("human", "casey"), AT),
                             experience=start_experience(Actor("human", "casey"), AT))
            sealed = store.sealed()
            capsule, outside = store.root, cell / "outside"
            forge_ready(capsule)
            _remove_tree(capsule / ".git")     # the honest reset route is unreachable
            (capsule / ".forge-seal").unlink()  # one same-user deletion; A-015 concedes it

            with contextlib.ExitStack() as stack:
                reason = _plant_at_authority(shape, capsule / target, outside, stack)
                if reason is not None:
                    pytest.skip(reason)
                planted = _entry_state(capsule / target)
                before = _readable_routes(capsule, store)
                assert before, (
                    f"{shape} / {target} / {form}: the plant left NO authority route "
                    "readable, so this cell has no fall-open to close and would pass "
                    "for the wrong reason.\n" + "\n".join(observed))

                fired: list[str] = []
                failure: BaseException = (
                    SystemExit("the process died inside the neutralisation")
                    if form == "crash" else OSError(28, "No space left on device"))
                with monkeypatch.context() as patch:
                    if form != "clean":
                        patch.setattr(store_module, "_remove_entry",
                                      _arm_the_removal_of(target, failure, fired))
                    outcome = "returned"
                    try:
                        store.restore(sealed)
                    except (CapsuleStoreError, SystemExit) as exc:
                        outcome = type(exc).__name__

                after = _readable_routes(capsule, store)
                protected = store.protected()
                observed.append(
                    f"{target:<16} {form:<8} planted={planted[:24]:<24} "
                    f"{outcome:<18} protected={protected!s:<5} "
                    f"before={sorted(before)} after={sorted(after)}")

                assert (form == "clean") or fired, (
                    f"{shape} / {target} / {form}: the arming never fired, so the row "
                    "did not reach the removal it names and its verdict means "
                    "nothing.\n" + "\n".join(observed))
                assert protected, (
                    f"{shape} / {target} / {form}: the neutralisation ended with the "
                    "store NOT protected, so a residue Forge could not clean is a "
                    "legacy read rather than a refusal. Entries: "
                    f"{sorted(path.name for path in capsule.iterdir())}\n"
                    + "\n".join(observed))
                assert after == frozenset(), (
                    f"{shape} / {target} / {form}: one same-user deletion of the seal "
                    "read the store as legacy. Entries: "
                    f"{sorted(path.name for path in capsule.iterdir())}\n"
                    + "\n".join(observed))

                if form == "clean" and outcome == "returned":
                    assert store.seal_problems(store.sealed()) == [], (
                        f"{shape} / {target} / clean: the restoration RETURNED but "
                        "the store does not match its seal, so it reported a repair "
                        "it did not make.\n" + "\n".join(observed))
                elif form == "clean":
                    # A REFUSAL MUST BE THE OPERATING SYSTEM'S, NOT FORGE'S. The
                    # plant is still exactly what it was, so the removal really
                    # could not take it -- rather than Forge dropping the file and
                    # giving up. Which shapes reach here is not listed: it is read
                    # off the disk, and A-022 discloses the two that do.
                    assert _entry_state(capsule / target) == planted, (
                        f"{shape} / {target} / clean: the restoration was refused "
                        "and the plant is GONE, so the refusal is not the shape "
                        "standing its ground -- it is a partial removal reported "
                        "as a failure.\n" + "\n".join(observed))

                if shape in ("hardlink", "read-only hardlink"):
                    victim = outside / ("hardlink-other-readonly.txt"
                                        if shape == "read-only hardlink"
                                        else "hardlink-other.txt")
                    assert victim.read_text(encoding="utf-8") == \
                        "a file the store has no business touching\n", (
                        f"{shape} / {target} / {form}: the removal reached a file "
                        "OUTSIDE the store through the planted link.\n"
                        + "\n".join(observed))
                    if shape == "read-only hardlink":
                        assert not (os.stat(victim).st_mode & stat.S_IWRITE), (
                            f"{shape} / {target} / {form}: the read-only bit was "
                            "cleared on a file OUTSIDE the store. `os.chmod` acts on "
                            "the file and not the name, so a retry that does not "
                            "check `st_nlink` frees whatever the worker linked in.\n"
                            + "\n".join(observed))


@pytest.mark.parametrize("shape", [
    pytest.param(shape, id=shape.replace(" ", "-"))
    for shape in _AUTHORITY_SHAPES if "junction" not in shape])
def test_the_neutralisation_fails_closed_at_every_authority_shape(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str):
    """Every shape but the two junctions, which need their own skip reason.
    See `_the_neutralisation_fails_closed_at_every_shape`."""
    _the_neutralisation_fails_closed_at_every_shape(tmp_path, monkeypatch, shape)


@pytest.mark.skipif(os.name != "nt", reason=_NO_JUNCTIONS)
def test_the_neutralisation_fails_closed_at_a_live_junction_authority(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """See `_the_neutralisation_fails_closed_at_every_shape`."""
    _the_neutralisation_fails_closed_at_every_shape(tmp_path, monkeypatch, "live junction")


@pytest.mark.skipif(os.name != "nt", reason=_NO_JUNCTIONS)
def test_the_neutralisation_fails_closed_at_a_dangling_junction_authority(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """See `_the_neutralisation_fails_closed_at_every_shape`."""
    _the_neutralisation_fails_closed_at_every_shape(tmp_path, monkeypatch, "dangling junction")


def test_a_read_only_authority_file_no_longer_permanently_defeats_the_restoration(
        tmp_path: Path):
    """THE P1 OF ROUND 6, DRIVEN THROUGH THE SHIPPED `restore()` WITH NOTHING
    PATCHED -- and driven three times, because permanence is the finding.

    One `attrib +R experience.json` is a same-operating-system-user command
    A-015 concedes, and `_replace_fresh`'s own docstring names it as the
    capability that "would otherwise disable the product's human recovery
    route permanently". It named it for the RENAME. The removal had no such
    retry, and round 5 put the removal in front of the marker write. Measured
    at the parent of this commit:

        BEFORE   ['.forge-capsule', 'capsule.json', 'experience.json']
        restore  CapsuleStoreError: PermissionError [WinError 5]
        AFTER    ['.forge-capsule', 'experience.json']
        marker absent   protected() False   sealless load RETURNED 'READY'
        restore #2, #3: raised identically; the forged stage stayed readable

    So a shipped sentence -- "re-running `restore()` with the same seal repairs
    it. That is fail-closed and recoverable, not unrecoverable" -- was false
    for this shape: the bit does not clear itself, so every later call fails
    the same way. THIS ROW IS THE RECOVERABILITY HALF and it is the one the
    read-only retry kills; the fail-closed half is asserted by the matrix
    above and survives this mutation, which is why the two are separate rows.

    The precondition is pinned to the state `_rebuild` exists for. `.git` is
    destroyed, so the honest `git reset --hard` route cannot run; with `.git`
    intact the honest route repairs the store and the defect is unreachable,
    and that is asserted here too rather than left as a claim.
    """
    for git_intact in (True, False):
        cell = tmp_path / ("git-intact" if git_intact else "git-destroyed")
        store = CapsuleStore(cell / "capsule", seal_dir=cell / "seals")
        store.initialize(create_document("proj-1", "Portal", Actor("human", "casey"), AT),
                         experience=start_experience(Actor("human", "casey"), AT))
        sealed = store.sealed()
        capsule = store.root
        forge_ready(capsule)
        if not git_intact:
            _remove_tree(capsule / ".git")
        (capsule / ".forge-seal").unlink()
        os.chmod(capsule / "experience.json", stat.S_IREAD)
        assert not (os.stat(capsule / "experience.json").st_mode & stat.S_IWRITE), (
            "the read-only plant did not land, so this row proves nothing")
        assert _readable_routes(capsule, store) == frozenset({"capsule", "experience"}), (
            "the precondition is not the fall-open this row exists to close")

        for attempt in (1, 2, 3):
            revision, notes = store.restore(sealed)
            assert revision, f"{cell.name} attempt {attempt}: no revision"
            assert store.protected(), f"{cell.name} attempt {attempt}: not protected"
            assert store.seal_problems(store.sealed()) == [], (
                f"{cell.name} attempt {attempt}: the store does not match its seal")
            assert _readable_routes(capsule, store) == frozenset(), (
                f"{cell.name} attempt {attempt}: a sealless load can still read "
                f"{sorted(path.name for path in capsule.iterdir())}")
            assert _store_experience_stage(capsule, store) == "DISCOVER", (
                f"{cell.name} attempt {attempt}: the forged stage survived")
            if not git_intact:
                assert any("rebuilt" in note for note in notes), (
                    f"{cell.name} attempt {attempt}: the rebuild route was not the "
                    f"one taken, so this row did not reach `_rebuild`: {notes}")
            # The next attempt must find the same specimen, not a repaired store.
            forge_ready(capsule)
            if not git_intact:
                _remove_tree(capsule / ".git")
            (capsule / ".forge-seal").unlink()
            os.chmod(capsule / "experience.json", stat.S_IREAD)


def _store_experience_stage(capsule: Path, store: CapsuleStore) -> str:
    """The stage a FRESH, SEAL-CHECKING load reads off the store as it stands,
    or the refusal it raises instead.

    Deliberately NOT the sealless read `_readable_routes` makes. That one asks
    whether a store falls open when its seal is deleted; this one asks whether
    the restoration actually put the sealed authority back, which is the
    question a permanent refusal hides. An earlier spelling of this helper
    deleted the seal first and then asserted `DISCOVER`, which a correctly
    protected store answers `CapsuleSealMissing` to -- the assertion was
    unsatisfiable and the instrument, not the store, was wrong.
    """
    try:
        return CapsuleStore(capsule, seal_dir=store.seal_dir).load_experience()["stage"]
    except Exception as exc:                       # noqa: BLE001 -- any refusal will do
        return f"REFUSED {type(exc).__name__}"


def test_the_second_authority_removal_can_raise_with_the_first_already_gone(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A SHIPPED SENTENCE SAID THIS STATE COULD NOT EXIST, and it can.

    `_rebuild` read: "If the neutralisation itself raises, it raises BEFORE
    anything else has been touched -- so the store is left exactly as the
    worker left it, which is a restoration that did not happen rather than a
    degradation Forge caused." `_AUTHORITY_FILES` is ordered `(capsule.json,
    experience.json)`, so a failure at the SECOND name happens with the first
    already removed. The sentence counted the function as one statement.

    THE STATE IS REAL AND IT IS SURVIVABLE, and this row asserts both halves
    rather than only the comfortable one: `capsule.json` really is gone, the
    seal marker really was written on the way out, and the store therefore
    refuses on BOTH routes rather than answering the worker's forged
    `experience.json` -- which is exactly what it did before the best-effort
    write existed. Reached with nothing patched but the removal itself, so the
    row cannot pass because the neutralisation never ran.
    """
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    capsule = tmp_path / "capsule"
    forge_ready(capsule)
    _remove_tree(capsule / ".git")
    (capsule / ".forge-seal").unlink()
    assert _readable_routes(capsule, store) == frozenset({"capsule", "experience"})

    fired: list[str] = []
    monkeypatch.setattr(store_module, "_remove_entry", _arm_the_removal_of(
        "experience.json", OSError(28, "No space left on device"), fired))
    with pytest.raises(CapsuleStoreError):
        store.restore(sealed)

    assert fired == ["experience.json"], f"the arming never reached the second name: {fired}"
    assert not os.path.lexists(capsule / "capsule.json"), (
        "the first removal did not land, so this row did not reach the state it "
        f"names: {sorted(path.name for path in capsule.iterdir())}")
    assert os.path.lexists(capsule / "experience.json"), (
        "the second name was removed after all, so the arming did not stop it")
    assert store.protected(), (
        "the neutralisation raised part-done and the store was left with NO seal "
        "marker, so the worker's forged experience.json is readable as legacy")
    assert _readable_routes(capsule, store) == frozenset(), (
        f"{sorted(path.name for path in capsule.iterdir())} still reads as legacy")


_MARKER_OCCUPANTS = ("absent", "regular file", "directory",
                     "live junction", "dangling junction")


def test_the_best_effort_marker_write_never_spends_the_protection_it_defends(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """THE FAIL-CLOSED STEP MUST NOT ITSELF OPEN THE STORE, and the first
    version of it did -- which an ordinary concurrent reader found before any
    row here did.

    `_write_seal_marker` writes THROUGH whatever occupies the name: at a
    directory-attributed occupant it removes first and renames second, and a
    denied rename leaves the name EMPTY. Run on the FAILURE path that was
    exactly backwards -- a store that already demanded a seal stopped
    demanding one because Forge tried to improve the marker it already had.
    Measured, the neutralisation failing and the marker's rename denied by an
    ordinary sharing violation, before the repair:

        occupant            rename denied   marker after   protected()
        absent              YES             absent         False
        directory           YES             absent         False  <-- was True
        live junction       YES             absent         False  <-- was True
        dangling junction   YES             absent         False

    Not a theoretical cell. The ordinary-reader row --
    `test_an_ordinary_concurrent_reader_cannot_open_the_store_to_a_legacy_read`
    -- plants a directory at the marker and runs one reader thread; it failed
    once in eight observations against the first version, and the assertion it
    failed was the store reading as legacy.

    THE REPAIR IS TWO RULES AND THIS ROW HOLDS BOTH. Do nothing when the store
    is already protected -- on this path the marker's CONTENT buys nothing,
    since one naming another store's seal is a refusal too -- and where the
    name really is free, fall back to a single `O_CREAT | O_EXCL` write with
    no removal and no rename, so the last resort has no window of its own.
    Every occupant is crossed with a denied rename and an allowed one, and the
    row asserts the occupant SURVIVED as well as that the store is closed:
    protection preserved is not the same fact as protection restored.
    """
    observed: list[str] = []
    for occupant in _MARKER_OCCUPANTS:
        for denied in (False, True):
            if "junction" in occupant and os.name != "nt":
                continue                                    # see _NO_JUNCTIONS
            cell = tmp_path / f"cell-{len(observed)}"
            store = CapsuleStore(cell / "capsule", seal_dir=cell / "seals")
            store.initialize(create_document("proj-1", "Portal", Actor("human", "casey"), AT),
                             experience=start_experience(Actor("human", "casey"), AT))
            sealed = store.sealed()
            capsule, marker = store.root, store.root / ".forge-seal"
            forge_ready(capsule)
            _remove_tree(capsule / ".git")
            marker.unlink()
            if occupant != "absent":
                reason = _plant_shape(occupant, marker, cell / "outside")
                assert reason is None, reason
            planted = _entry_state(marker)
            was_protected = store.protected()

            survivor_replace = store_module._replace_fresh

            def denies_the_marker_rename(tmp, path, _s=survivor_replace, _d=denied):
                if _d and path.name == ".forge-seal":
                    raise PermissionError(13, "the marker's rename is denied", None, 32)
                return _s(tmp, path)

            with monkeypatch.context() as patch:
                patch.setattr(store_module, "_remove_entry", _arm_the_removal_of(
                    "capsule.json", OSError(28, "No space left on device"), []))
                patch.setattr(store_module, "_replace_fresh", denies_the_marker_rename)
                with pytest.raises(CapsuleStoreError):
                    store.restore(sealed)

            after, now = _readable_routes(capsule, store), _entry_state(marker)
            observed.append(
                f"{occupant:<20} denied={denied!s:<6} before={planted[:20]:<20} "
                f"after={now[:20]:<20} was_protected={was_protected!s:<5} "
                f"protected={store.protected()!s:<5} readable={sorted(after)}")

            assert store.protected(), (
                f"{occupant} / denied={denied}: the fail-closed step left the store "
                "NOT protected, so Forge spent the very property it was defending.\n"
                + "\n".join(observed))
            assert after == frozenset(), (
                f"{occupant} / denied={denied}: the store reads as legacy. Entries: "
                f"{sorted(path.name for path in capsule.iterdir())}\n"
                + "\n".join(observed))
            if was_protected:
                assert now == planted, (
                    f"{occupant} / denied={denied}: an occupant the store was ALREADY "
                    "protected by was replaced on a path that had nothing to gain by "
                    f"replacing it -- {planted!r} became {now!r}.\n"
                    + "\n".join(observed))


def test_the_exclusive_create_fallback_writes_the_markers_exact_bytes(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """THE ONE WRITE IN THIS MODULE NO ROW WAS WATCHING.

    Every other write here is byte-exact on purpose -- `_write_fresh` and
    `seal` both pass `newline=""` to stop the text layer translating, and
    `canonical_json` fixes the ordering and the separators -- and the reason
    is that the seal compares BYTES. The exclusive-create fallback was written
    with `os.open` + `os.write` instead, and `os.open` defaults to TEXT mode on
    Windows, so it silently translated the trailing newline. Measured on this
    host before the repair, the flags exactly as they shipped:

        os.write(fd, b'{"a": 1}\\n')  ->  on disk b'{"a": 1}\\r\\n'   CR 1
        the same with os.O_BINARY    ->  on disk b'{"a": 1}\\n'     CR 0

    NOTHING WAS BROKEN BY IT, and saying otherwise would be the overclaim this
    module keeps correcting: `json.loads` tolerates the extra byte, and the
    marker's job is to exist rather than to parse -- `seal_problems` refuses a
    marker of any content that does not name this store's seal. What was wrong
    is narrower and worth a row anyway: the module's idiom is byte-exactness,
    one write escaped it, and no assertion would have noticed if it had
    escaped further.

    THE REFERENCE IS THE SHIPPED WRITE, NOT A LITERAL. The row drives the
    fallback, keeps its bytes, then removes the marker and calls
    `_write_seal_marker` on the SAME store with nothing patched. Same root, so
    `seal_ident()` is the same string, so the two writes have no licence to
    differ. A literal here would pin the schema instead of the property, and
    would go stale the next time the marker's content changes.

    THE FALLBACK REALLY IS WHAT RAN. `_replace_fresh` is denied at the
    marker's name, so `_write_fresh` raises with its temp cleaned up and never
    puts a file at `.forge-seal`; the denial is asserted to have fired, so a
    marker standing afterwards can only be the exclusive create's. Without
    that assertion this row would pass on the careful write and prove nothing
    about the fallback at all.

    THE LOOP IS THE SECOND CELL, AND IT NEEDED AN INSTRUMENT TO BE REACHABLE.
    `os.write` is permitted to write fewer bytes than it is handed, and a
    single unlooped call would then leave a TORN marker where a whole one was
    available. Sixty bytes to a local file never write short here, so a normal
    run cannot tell a looped write from an unlooped one and the second cell
    supplies the case: `store_module.os` -- the module's OWN reference, not the
    global module, so nothing else in the session is affected -- is replaced by
    a proxy that delegates everything and truncates `write` to one byte per
    call. That is `os` behaving legally at its worst. The bytes must still come
    out whole, and the proxy is asserted to have been called more than once, so
    the cell cannot pass by never reaching the write it names.
    """
    class _WritesShort:
        """`os`, delegating everything, with `write` truncated to one byte."""

        def __init__(self, real, short: bool):
            self._real, self._short, self.calls = real, short, 0

        def __getattr__(self, name):
            return getattr(self._real, name)

        def write(self, fd, data):
            self.calls += 1
            return self._real.write(fd, data[:1] if self._short else data)

    observed: list[str] = []
    for short in (False, True):
        cell = tmp_path / ("short-write" if short else "whole-write")
        store = CapsuleStore(cell / "capsule", seal_dir=cell / "seals")
        store.initialize(create_document("proj-1", "Portal", Actor("human", "casey"), AT),
                         experience=start_experience(Actor("human", "casey"), AT))
        sealed = store.sealed()
        capsule = store.root
        marker = capsule / store_module._SEAL_MARKER_FILE
        forge_ready(capsule)
        _remove_tree(capsule / ".git")
        marker.unlink()

        survivor = store_module._replace_fresh
        denied: list[str] = []

        def denies_the_marker_rename(tmp, path, _s=survivor, _d=denied):
            if path.name == store_module._SEAL_MARKER_FILE:
                _d.append(path.name)
                raise PermissionError(13, "the marker's rename is denied", None, 32)
            return _s(tmp, path)

        writer = _WritesShort(os, short)
        with monkeypatch.context() as patch:
            patch.setattr(store_module, "_remove_entry", _arm_the_removal_of(
                "capsule.json", OSError(28, "No space left on device"), []))
            patch.setattr(store_module, "_replace_fresh", denies_the_marker_rename)
            patch.setattr(store_module, "os", writer)
            with pytest.raises(CapsuleStoreError):
                store.restore(sealed)

        assert denied, (
            f"short={short}: the careful write was never denied, so the fallback "
            "did not run and this cell would be measuring `_write_fresh`.\n"
            + "\n".join(observed))
        assert marker.is_file(), (
            f"short={short}: the fallback left no marker, so there are no bytes "
            "to check and the fail-closed step did not happen. Entries: "
            f"{sorted(path.name for path in capsule.iterdir())}\n"
            + "\n".join(observed))
        fallback = marker.read_bytes()

        # The REFERENCE, taken from the shipped success-path write on the same
        # store, with nothing patched: same root, so the same `seal_ident()`.
        marker.unlink()
        store._write_seal_marker()
        careful = marker.read_bytes()
        observed.append(f"short={short!s:<6} os.write calls={writer.calls:<3} "
                        f"fallback={fallback!r} careful={careful!r}")

        assert writer.calls >= 1, (
            f"short={short}: the fallback's `os.write` was never reached.\n"
            + "\n".join(observed))
        if short:
            assert writer.calls > 1, (
                "short=True: one call wrote the whole payload, so the truncating "
                "proxy did not take effect and the loop is not what was measured.\n"
                + "\n".join(observed))
        assert fallback == careful, (
            f"short={short}: the exclusive-create fallback and "
            "`_write_seal_marker` disagree about the marker's bytes.\n"
            + "\n".join(observed))
        assert b"\r" not in fallback, (
            f"short={short}: the fallback's bytes carry a carriage return the "
            "careful write does not put there -- `os.open` translated them.\n"
            + "\n".join(observed))
        assert fallback.endswith(b"}\n"), (
            f"short={short}: the fallback wrote a torn or padded marker.\n"
            + "\n".join(observed))


def test_the_best_effort_marker_write_never_becomes_the_error_the_caller_sees(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A SECONDARY FAILURE MUST NOT REPLACE THE DIAGNOSIS.

    The best-effort write runs on a path that is already failing, so it must
    neither raise nor mask. This row makes BOTH fail -- the neutralisation with
    one error and the marker write with a different one -- and asserts the
    caller is told about the first. `_write_fresh`'s own temp cleanup already
    holds this property; the marker write is the second place in the module
    that needed it, and a `raise` inside a handler is exactly how it would be
    lost.

    IT ALSO PINS THAT THE ATTEMPT IS MADE AT ALL. The marker write is asserted
    to have fired, so a future `_rebuild` that simply drops the call reddens
    here rather than passing quietly on a store that happened to be protected.
    """
    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    capsule = tmp_path / "capsule"
    forge_ready(capsule)
    _remove_tree(capsule / ".git")
    (capsule / ".forge-seal").unlink()

    attempted: list[str] = []

    def refuses(self):
        attempted.append("marker")
        raise OSError(13, "the marker's own destination is denied too")

    monkeypatch.setattr(store_module, "_remove_entry", _arm_the_removal_of(
        "capsule.json", OSError(28, "No space left on device"), []))
    monkeypatch.setattr(store_module.CapsuleStore, "_write_seal_marker", refuses)

    with pytest.raises(CapsuleStoreError) as raised:
        store.restore(sealed)

    assert attempted == ["marker"], (
        "the best-effort marker write was never attempted, so a failing "
        "neutralisation leaves the store exactly as open as it found it")
    assert "No space left on device" in str(raised.value), (
        f"the caller was told about the CLEANUP failure instead of the real one: "
        f"{raised.value}")
    assert "denied too" not in str(raised.value)


def test_a_stray_temp_from_forges_own_crash_is_not_a_tamper_finding(tmp_path: Path):
    """FORGE'S OWN CRASH MANUFACTURED A TAMPER FINDING AGAINST AN UNTOUCHED STORE.

    `_write_fresh` writes `<name>.<16 hex>.tmp` and renames it. A death between
    those two statements leaves the name behind -- no `finally` can take it,
    exactly as `seal()`'s own `.json.tmp` cannot be taken. The cleanliness
    check then saw an extra untracked file and every later load failed:

        seal_problems  ["the working tree is not clean: ?? .forge-seal.<hex>.tmp"]
        load()         REFUSED CapsuleSealError

    Fail-closed and repairable WHILE IT IS UNTRACKED -- `git clean` on the
    honest restore route takes it, and `_rebuild`'s wipe takes it, since the
    temp name is in no keep set. That sentence stood without the qualifier and
    is not true after the next save; the row below measures what happens then.
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


def test_an_exempt_named_stray_that_survives_a_save_becomes_tracked_and_invisible(
        tmp_path: Path):
    """THE EXEMPTION'S DISPOSAL ROUTES STOP APPLYING ONCE A SAVE HAS RUN.

    A-022 and the row above say the stray is "fail-closed and repairable --
    `git clean` on the honest restore route takes it, and `_rebuild`'s wipe
    takes it". True while it is UNTRACKED. `save` runs `git add -A` and
    commits, so a stray still on disk at the next save is absorbed into the
    store's own history. Measured, after one ordinary save:

        git status --porcelain    ''            (nothing at all)
        git ls-files              ['.forge-seal.<hex>.tmp']
        seal_problems             []
        git clean -fdxq           leaves it standing
        restore()                 leaves it standing -- the honest route is a
                                  reset and a clean, and neither takes a
                                  tracked, unmodified file
        a FORCED _rebuild         takes it, because the wipe enumerates the
                                  root and the name is in no keep set

    So it stops being EXEMPT and becomes INVISIBLE: not reported because there
    is nothing to report, and removed only by the route that runs when the
    honest one has already failed. It still carries no authority, for the
    reason the row above gives -- nothing reads the store by pattern -- and it
    is one inert file. What is corrected is the disposal claim, not the
    authority claim.
    """
    store = _sealed_store(tmp_path)
    capsule = tmp_path / "capsule"
    stray = store_module._fresh_tmp_path(capsule / ".forge-seal")
    stray.write_text("a survivor of a death between the temp write and the rename\n",
                     encoding="utf-8", newline="")

    def porcelain() -> str:
        return subprocess.run(["git", "status", "--porcelain"], cwd=capsule,
                              capture_output=True, text=True, check=True).stdout.strip()

    def tracked() -> list[str]:
        listed = subprocess.run(["git", "ls-files"], cwd=capsule, capture_output=True,
                                text=True, check=True).stdout.split()
        return [name for name in listed if name.endswith(".tmp")]

    # (i) untracked: reported by git, exempted by Forge, and `git clean` takes it.
    assert porcelain() == f"?? {stray.name}" and tracked() == []
    assert store.seal_problems(store.sealed()) == []
    subprocess.run(["git", "clean", "-fdxq"], cwd=capsule, check=True, capture_output=True)
    assert not stray.exists(), "git clean did not take the untracked stray"

    # (ii) survive one ordinary save, and it is TRACKED and CLEAN thereafter.
    stray.write_text("a survivor of a death between the temp write and the rename\n",
                     encoding="utf-8", newline="")
    document, _ = propose(store.load(), "intent", "Build a customer support portal.",
                          Actor("human", "casey"), "2026-09-03T10:00:00Z")
    store.save(document, "propose intent")
    assert porcelain() == "", "the stray must be absorbed, not left untracked"
    assert tracked() == [stray.name], "the save did not commit the stray"
    assert store.seal_problems(store.sealed()) == []

    # (iii) neither route the exemption named still takes it.
    subprocess.run(["git", "clean", "-fdxq"], cwd=capsule, check=True, capture_output=True)
    assert stray.exists(), "git clean took a tracked file"
    store.restore(store.sealed())
    assert stray.exists(), (
        "the honest restore route took a tracked, unmodified file; if it now "
        "does, this correction is stale and the sentence above must move back"
    )

    # (iv) and the one route that does: the wipe, reached only when the honest
    # route cannot run at all.
    _remove_tree(capsule / ".git")
    revision, notes = store.restore(store.sealed())
    assert "rebuilt" in notes[0]
    assert not stray.exists(), "the rebuild's wipe left a name outside its keep set"
    assert store.seal_problems(store.sealed()) == []


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

    # AND EVERY LINE IS TRIMMED, NOT ONLY THE FIRST. `"\n".join(kept).strip()`
    # stripped the leading status padding off the joined BLOCK, which is the
    # first line and nothing else, so one finding read `M capsule.json` while
    # the same status one line lower read ` D experience.json`. Two spellings
    # of one status, decided by where it landed in the list -- and these
    # strings go verbatim into `seal_problems`, into the refusal a user reads
    # and into permanent lifecycle history.
    assert store_module._tree_changes(" M capsule.json\n D experience.json") == [
        "M capsule.json", "D experience.json"]
    assert store_module._tree_changes(
        " M capsule.json\n?? notes.txt\n D experience.json") == [
        "M capsule.json", "?? notes.txt", "D experience.json"]
    # An empty line contributes nothing rather than an empty finding.
    assert store_module._tree_changes(" M capsule.json\n\n") == ["M capsule.json"]


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


# ---------------------------------------------------------------------------
# Tranche E  the process witness: a rollback of the whole set, while Forge runs
#
# WHAT THIS SECTION IS AND IS NOT ABOUT. The seal catches a store that moved
# away from it and a seal that moved away from its store; both are pinned
# above. What none of it catches is the actor who moves BOTH -- who copies the
# store, its committed marker and its seal back to an earlier consistent set.
# Measured at this module's parent commit, through the shipped surface: after
# such a rollback `GET /api/state` returned `200 / CONFIRM`, the restore route
# answered "the store matches its seal; there is nothing to restore", and a
# fresh build ran the project to GOVERN a second time at a new revision, with
# the previous GOVERN unreachable and unrecorded anywhere Forge can read.
#
# EVERY DURABLE WITNESS WAS BUILT AND EVERY ONE WAS ROLLED BACK WITH THE SET:
# a counter beside the seal, a mirror in a second Forge-owned directory, an
# append-only log in a third place, and a DENY ACE on the seal file. Two of
# them detect a FORGETFUL actor and none detects a thorough one; NTFS has no
# append-only attribute, so `open(log, "w")` truncates the last line; and the
# DENY ACE does not even prevent replacement, because the parent directory
# grants the owner FILE_DELETE_CHILD and the owner's implicit WRITE_DAC then
# removes the ACE. A-029 states each result per candidate. What resists the
# restoration of a whole filesystem set is a second operating-system principal
# or hardware, and both are external authority this repository does not
# synthesize.
#
# SO THE WORD DOES NOT MOVE. `currency` is still `not_independently_anchored`,
# pinned by exact equality above and by the vocabulary test below. What the
# witness earns is a SEPARATE, SMALLER field -- `continuity == "process"` with
# `held_since` -- and the fourth test here pins its limit in the affirmative,
# so the cross-restart case cannot be closed without rewriting the disclosure
# it names.
# ---------------------------------------------------------------------------

def _content_manifest(root: Path) -> dict[str, str]:
    """Every path under `root` with the SHA-256 of its bytes.

    Content, never `git status`: a rollback that also COMMITS reads clean, so
    a copy verified by the store's own history is a copy verified by something
    the actor controls.
    """
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        name = str(path.relative_to(root)).replace("\\", "/")
        manifest[name] = "<dir>" if path.is_dir() else hashlib.sha256(
            path.read_bytes()).hexdigest()
    return manifest


def _capture(tmp_path: Path, into: str) -> tuple[Path, dict, dict]:
    """Copy the store directory AND the seal directory aside: the two
    user-writable locations an actor must replace, and nothing else. The store
    holds `.forge-capsule`, `.forge-seal`, `.git`, `capsule.json` and
    `experience.json`; the seal directory holds one `<ident>.json`, and the
    ident derives from the resolved store path alone."""
    held = tmp_path / into
    shutil.copytree(tmp_path / "capsule", held / "capsule")
    shutil.copytree(tmp_path / "seals", held / "seals")
    return held, _content_manifest(tmp_path / "capsule"), _content_manifest(tmp_path / "seals")


def _rolled_back_to(tmp_path: Path, held: Path, manifests: tuple[dict, dict]) -> None:
    """Put both locations back exactly as they were, as the same OS user, and
    assert byte for byte that the earlier set is what is now on disk."""
    for name in ("capsule", "seals"):
        _remove_tree(tmp_path / name)
        shutil.copytree(held / name, tmp_path / name)
    assert _content_manifest(tmp_path / "capsule") == manifests[0], (
        "the rollback did not reproduce the earlier store byte for byte")
    assert _content_manifest(tmp_path / "seals") == manifests[1], (
        "the rollback did not reproduce the earlier seal byte for byte")


class _Listed:
    """What `os.scandir` hands back: a closeable ITERATOR of the entries as
    they were AT THE LISTING. Real `os.DirEntry` objects, so every later
    `stat` or `open` still goes to the filesystem.

    A plain iterable is not enough: 3.12's `rmtree` walks Windows trees
    through `os.walk`, which calls `next()` on this directly.

    ONE SPELLING, TWO SITES. It was defined inside the vanishing-entry pin
    below until the appearing-entry pin needed exactly the same stale listing
    from the other direction. Two copies of a fake this load-bearing drift
    apart, and a drifted one stops reproducing the failure it was written for
    while still passing.
    """

    def __init__(self, entries):
        self._entries = iter(entries)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._entries)

    def close(self):
        self._entries = iter(())


def _git_shaped_capsule(tmp_path: Path) -> Path:
    """A capsule directory whose `.git` carries loose objects left exactly as
    git leaves them: read-only. Both listing-window pins remove one of these,
    so the case `_remove_tree`s handler exists for is live in both."""
    capsule = tmp_path / "capsule"
    objects = capsule / ".git" / "objects"
    objects.mkdir(parents=True)
    for name in ("7e", "7f", "80"):
        fanout = objects / name
        fanout.mkdir()
        blob = fanout / ("a" * 38)
        blob.write_bytes(b"an object")
        os.chmod(blob, stat.S_IRUSR)  # exactly how git leaves a loose object
    return capsule


def _is_directory(target, path: Path) -> bool:
    """Is the `os.scandir` argument THIS directory?

    `rmtree` passes a PATH on Windows and an open DIRECTORY FD on the POSIX
    walk. `os.stat` accepts both, so identity by `(st_dev, st_ino)` answers on
    either platform. Recognising by the names that came back instead -- which
    is all the vanishing-entry pin below needs, because it fires once on a
    tree nobody is changing -- stops working the moment a retry re-lists a
    directory whose contents have moved on.
    """
    try:
        seen, want = os.stat(target), os.stat(path)
    except OSError:
        return False
    return (seen.st_dev, seen.st_ino) == (want.st_dev, want.st_ino)


def test_a_removal_survives_an_entry_that_appears_between_listing_and_removing(
    tmp_path: Path,
):
    """THE SIBLING OF THE PIN BELOW, AND THE OPPOSITE DIRECTION.

    CI, Python 3.12, this module's rollback helper -- the same helper, the same
    store, one run of `test_a_rollback_across_a_restart_is_the_disclosed_limit`:
    `OSError: [Errno 39] Directory not empty:
    '/tmp/pytest-of-runner/pytest-0/test_a_rollback_across_a_resta0/capsule/.git'`.
    It passed on the retry, so the run's conclusion read success; that is a
    property of retries, not evidence about the code.

    `rmtree` LISTS a directory and then removes what it listed. An entry that
    VANISHES in that window is the pin below. An entry that APPEARS in that
    window is this one: the listing is already stale, the appeared name is
    never visited, and the closing `os.rmdir` refuses the directory it was
    told to remove. The handler chmods and retries the same `os.rmdir`, gets
    `ENOTEMPTY` a second time, and that one escapes the handler and `rmtree`
    both -- which is why the failure surfaces at `.git` itself rather than at
    any name under it.

    WHY THIS IS NOT ABSORBED THE WAY `FileNotFoundError` IS, pinned as
    behaviour by `test_a_removal_still_refuses_a_tree_it_cannot_empty`: not
    found means the goal is already reached, not empty means it is NOT, and
    returning on it would report a store removed while it was still on disk.

    The condition is injected rather than raced, so this pin is deterministic;
    a real second thread would make the suite depend on scheduling. Measured
    with a real one anyway, before trusting the injection: a writer planting
    files inside `.git` while the removal ran failed 60 of 60 trials before the
    repair and 0 of 300 after, on 3.12. The injection fires ONCE, which is what
    a transient writer does -- git's own auto-maintenance finishes -- and it is
    asserted to have HAPPENED, because an instrument that quietly stops firing
    proves nothing.
    """
    capsule = _git_shaped_capsule(tmp_path)
    gitdir = capsule / ".git"
    real_scandir = os.scandir
    appeared: list[str] = []

    def scandir_then_appear(target):
        entries = list(real_scandir(target))
        if not appeared and _is_directory(target, gitdir):
            planted = gitdir / "maintenance.lock"
            planted.write_bytes(b"held")
            appeared.append(planted.name)
        return _Listed(entries)

    with mock.patch("os.scandir", scandir_then_appear):
        _remove_tree(capsule)

    assert appeared == ["maintenance.lock"], (
        "the entry was never made to appear, so this pins nothing")
    assert not capsule.exists(), (
        "the removal must finish the tree it was given; returning with the "
        "store still on disk is the fail-open this refuses to become")


def test_a_removal_still_refuses_a_tree_it_cannot_empty(tmp_path: Path):
    """THE RETRY ABOVE MUST NOT BECOME A WAY OF REPORTING SUCCESS.

    A writer that never stops is not a transient one, and no bound outlasts
    it. When the attempts are spent the removal RAISES -- the real `ENOTEMPTY`
    at the real path -- and leaves the tree it could not empty visibly on
    disk. This is the assertion that separates a bounded retry from absorbing
    the error: with `ENOTEMPTY` absorbed both pins above pass and this one
    fails, which is exactly the fail-open a partially removed store would be.
    """
    capsule = _git_shaped_capsule(tmp_path)
    gitdir = capsule / ".git"
    real_scandir = os.scandir
    plants: list[str] = []

    def scandir_then_appear_forever(target):
        entries = list(real_scandir(target))
        if _is_directory(target, gitdir):
            planted = gitdir / f"forever-{len(plants)}.lock"
            planted.write_bytes(b"held")
            plants.append(planted.name)
        return _Listed(entries)

    with mock.patch("os.scandir", scandir_then_appear_forever):
        with pytest.raises(OSError) as caught:
            _remove_tree(capsule)

    assert caught.value.errno == errno.ENOTEMPTY, (
        "the refusal must be the real filesystem error, not a substitute")
    assert Path(caught.value.filename) == gitdir, (
        "and it must name the directory that could not be emptied")
    assert len(plants) == store_module._APPEARED_ATTEMPTS, (
        "every attempt in the bound must have been spent -- one listing of "
        "`.git` per attempt -- so this pins the bound and not a single try")
    assert capsule.exists(), (
        "a removal that refused must leave the tree it refused, not a "
        "half-removed one reported as gone")


def test_the_removal_handler_leaves_a_directory_a_mode_it_can_be_entered_through(
    tmp_path: Path,
):
    """THE PLATFORM DEFECT THAT MADE THE TWO PINS ABOVE RED ON LINUX.

    `rmtree` hands a failed `rmdir` to the handler exactly as it hands it a
    failed `unlink`, so the handler's `target` is a DIRECTORY as often as it
    is a file. `os.chmod(target, 0o600)` was written for the Windows
    read-only attribute, where traversal is not a permission; on POSIX it
    STRIPS THE SEARCH BIT off a directory and makes every entry inside it
    unreachable. The retry the two pins above added then re-lists the
    directory the handler just sealed and gets `EACCES` on the first name it
    tries to remove -- which is not `ENOTEMPTY`, so `_remove_tree` re-raises
    on the first attempt at an error the handler manufactured. Measured on
    all four Linux jobs at the previous head:
    `PermissionError: [Errno 13] Permission denied:
    '.../capsule/.git/maintenance.lock'` in the appearing-entry pin, and that
    same `EACCES` reaching the refusal pin where it demanded the real
    `ENOTEMPTY`. Windows passed 300 trials of the same mechanism, because
    there the two modes differ in no bit that Win32 reads.

    WHAT THIS PIN PROVES AND WHERE. It asserts the MODE THE HANDLER CHOOSES,
    which is a fact about the argument and is therefore checkable on either
    platform and skips on neither. It does NOT prove the traversal effect:
    that a directory at `0o600` is unenterable, and that `stat.S_IRWXU`
    restores it, is POSIX semantics this Windows host cannot exhibit, and the
    two pins above are what measure it -- on Linux, in CI, which is the
    instrument for this repair because Linux is where the defect lives.

    BOTH DIRECTIONS, because "make it traversable" is as easy to overdo as to
    omit: a builder who chmods everything `0o700` would hand every git loose
    object an execute bit it never had. The directory keeps its search bit,
    the file keeps `0o600`, and each injection is asserted to have HAPPENED.
    """
    real_chmod = os.chmod
    real_scandir = os.scandir
    real_unlink = os.unlink

    capsule = _git_shaped_capsule(tmp_path / "appearing")
    gitdir = capsule / ".git"
    appeared: list[str] = []
    modes: list[tuple[str, int]] = []

    def recording_chmod(target, mode, *args, **kwargs):
        modes.append((os.fspath(target), mode))
        return real_chmod(target, mode, *args, **kwargs)

    def scandir_then_appear(target):
        entries = list(real_scandir(target))
        if not appeared and _is_directory(target, gitdir):
            planted = gitdir / "maintenance.lock"
            planted.write_bytes(b"held")
            appeared.append(planted.name)
        return _Listed(entries)

    with mock.patch("os.scandir", scandir_then_appear), \
            mock.patch("os.chmod", recording_chmod):
        _remove_tree(capsule)

    assert appeared == ["maintenance.lock"], (
        "the entry was never made to appear, so no `rmdir` refused and this "
        "pins nothing")
    on_the_directory = [mode for name, mode in modes if Path(name) == gitdir]
    assert on_the_directory, (
        "the handler never chmod'd the directory whose `rmdir` refused, so "
        "the mode this pins was never chosen")
    assert set(on_the_directory) == {stat.S_IRWXU}, (
        "a directory the handler is about to re-`rmdir` must keep the search "
        "bit it is entered through -- `0o600` strips it on POSIX and every "
        "entry inside becomes unreachable, which is the `EACCES` CI reported: "
        f"{sorted(oct(mode) for mode in set(on_the_directory))}")

    plain = _git_shaped_capsule(tmp_path / "plain")
    refused: list[str] = []
    file_modes: list[tuple[str, int]] = []

    def unlink_refusing_the_first_entry(target, *args, **kwargs):
        if not refused:
            refused.append(os.fspath(target))
            raise PermissionError(errno.EACCES, "refused once", os.fspath(target))
        return real_unlink(target, *args, **kwargs)

    def recording_file_chmod(target, mode, *args, **kwargs):
        file_modes.append((os.fspath(target), mode))
        return real_chmod(target, mode, *args, **kwargs)

    with mock.patch("os.unlink", unlink_refusing_the_first_entry), \
            mock.patch("os.chmod", recording_file_chmod):
        _remove_tree(plain)

    assert refused, (
        "no `unlink` was made to refuse, so the file branch of the handler "
        "never ran and this half pins nothing")
    assert not plain.exists(), (
        "clearing the bit must still finish the removal, on the file branch "
        "as on the directory one")
    assert file_modes, "the handler never chmod'd the entry whose `unlink` refused"
    assert {mode for _, mode in file_modes} == {0o600}, (
        "a plain file keeps `0o600`: it has no search bit to lose, and "
        "granting one to every git loose object is the opposite mistake to "
        f"the one repaired above: {sorted(oct(mode) for _, mode in file_modes)}")


def test_a_removal_that_is_not_being_written_into_takes_no_retry(tmp_path: Path):
    """AND THE ORDINARY REMOVAL PAYS NOTHING FOR THE BOUND ABOVE.

    The first attempt wins whenever nothing is writing, so no pause is taken
    and `.git` is listed exactly once. A builder who moves the `time.sleep`
    ahead of the attempt, or who retries unconditionally, turns this red --
    which matters because the sleep is otherwise invisible until a suite gets
    slow for reasons nobody attributes.
    """
    capsule = _git_shaped_capsule(tmp_path)
    gitdir = capsule / ".git"
    real_scandir = os.scandir
    listings: list[str] = []

    def counted(target):
        entries = list(real_scandir(target))
        if _is_directory(target, gitdir):
            listings.append("git")
        return _Listed(entries)

    slept: list[float] = []
    with mock.patch("os.scandir", counted), \
            mock.patch.object(store_module.time, "sleep", slept.append):
        _remove_tree(capsule)

    assert not capsule.exists()
    assert listings == ["git"], "the tree must be listed once, not retried"
    assert slept == [], "no pause may be taken when the first attempt succeeds"


def test_a_removal_survives_an_entry_that_vanishes_between_listing_and_visiting(
    tmp_path: Path,
):
    """THE REMOVAL ABOVE ONCE DIED ON A DIRECTORY THAT WAS ALREADY GONE.

    CI, Python 3.11, this module's rollback helper:
    `FileNotFoundError: .../capsule/.git/objects/7f` raised at the `os.chmod`
    in `_remove_tree`'s handler, chained to shutil's own `entry.stat()`
    reporting the bare name `7f`. `rmtree` LISTS a directory and then VISITS
    its entries one at a time; an entry that disappears in that window is
    handed to the handler, which chmod'd a path that no longer existed and
    raised a second `FileNotFoundError` -- from the handler, so it escaped
    `rmtree` and failed the test. Intermittent because the window is small,
    not because the code was ever safe: measured with a concurrent remover,
    40 of 40 trials failed on 3.12 and 20 of 20 on 3.11, and after the repair
    0 of 200 and 0 of 100. Run against the unrepaired handler this pin fails at
    that `os.chmod`, on `.git/objects/7f`, with the same exception -- the CI
    report's own file, statement and path, which is what makes it this failure
    rather than one that merely resembles it.

    The condition is injected rather than raced, so this pin is deterministic:
    a real second thread would make the suite depend on scheduling. The
    injection is asserted to have HAPPENED -- an instrument that quietly stops
    firing proves nothing -- and the read-only bit git puts on loose objects is
    present throughout, so the case the handler exists for is live at the same
    time.
    """
    capsule = _git_shaped_capsule(tmp_path)
    objects = capsule / ".git" / "objects"

    real_scandir = os.scandir
    vanished: list[str] = []

    def scandir_then_vanish(target):
        # `target` is a path on Windows and a DIRECTORY FD on the POSIX
        # `rmtree`, so the fanout is recognised by what was listed rather than
        # by the argument.
        entries = list(real_scandir(target))
        if not vanished and any(entry.name == "7f" for entry in entries):
            vanished.append("7f")
            doomed = objects / "7f"
            for path in doomed.iterdir():
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            shutil.rmtree(doomed)
        return _Listed(entries)

    with mock.patch("os.scandir", scandir_then_vanish):
        _remove_tree(capsule)

    assert vanished == ["7f"], (
        "the entry was never made to vanish, so this pins nothing")
    assert not capsule.exists(), (
        "the removal must finish the tree it was given, not stop at the hole")


def test_a_rollback_of_store_and_seal_together_is_caught_while_forge_runs(tmp_path: Path):
    """The adapter, without the surface. A store carrying a witness refuses a
    seal that is not the one this process last wrote, and hands back the
    snapshot to restore from; the SAME rolled-back set, opened by a store with
    no witness, loads and reports the earlier stage -- which is what every
    process did before this change and what a restart still does."""
    at = _clock()
    witness = ProcessWitness(at)
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals", witness=witness)
    casey = Actor("human", "casey")
    store.initialize(create_document("proj-1", "Portal", casey, AT),
                     experience=start_experience(casey, AT))
    held_since = witness.held_since(store.seal_ident())
    assert held_since is not None and witness.continuity(store.seal_ident()) == "process"

    at_b = advance(store.load_experience(), "CONFIRM", casey, at())
    revision_b = store.save_experience(at_b, "reached CONFIRM")
    earlier, *manifests = _capture(tmp_path, "B")

    at_c = advance(store.load_experience(), "ARCHITECT", casey, at())
    revision_c = store.save_experience(at_c, "reached ARCHITECT")
    assert store.load_experience()["stage"] == "ARCHITECT"
    assert witness.held_since(store.seal_ident()) == held_since, (
        "an ordinary Forge write must not restart the interval it is held over")

    _rolled_back_to(tmp_path, earlier, tuple(manifests))
    # NOTHING ON DISK CAN TELL THIS APART from an honest state: the store, its
    # committed marker and its seal all agree, at a revision that really is an
    # ancestor of the one Forge last wrote. This is the control.
    assert CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals"
                        ).load_experience()["stage"] == "CONFIRM"
    assert store.sealed().revision == revision_b

    with pytest.raises(CapsuleSealReplaced) as caught:
        store.load_experience()
    assert caught.value.snapshot.revision == revision_c
    assert "while Forge was running" in str(caught.value)
    assert any(revision_b[:12] in problem and revision_c[:12] in problem
               for problem in caught.value.problems), caught.value.problems
    assert isinstance(caught.value, CapsuleSealError)
    with pytest.raises(CapsuleSealReplaced):
        store.load()          # both authority routes, not one
    assert witness.continuity(store.seal_ident()) is None, (
        "nothing may claim continuity across a replacement it has just found")

    revision, notes = store.restore(caught.value.snapshot)
    assert any("rebuilt" in note for note in notes), notes
    assert store.load_experience()["stage"] == "ARCHITECT"
    assert store.revision() == revision
    assert witness.continuity(store.seal_ident()) == "process"
    assert witness.held_since(store.seal_ident()) != held_since, (
        "the interval after a restoration is a NEW one; it did not span the "
        "replacement")


def test_the_authority_store_cannot_be_rolled_back_under_a_running_forge(tmp_path: Path):
    """The same attack through the shipped surface, end to end: refused on
    every authority route while the process lives, and restorable by a person
    to what that process last wrote -- not to what the actor put on disk."""
    client = _client(tmp_path)
    _confirmed(client)
    earlier, *manifests = _capture(tmp_path, "B")
    before = _ok(client.get("/api/state"))
    assert before["journey"]["stage"] == "CONFIRM"
    held_since = before["authority"]["held_since"]
    assert before["authority"]["continuity"] == "process" and held_since is not None

    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    at_c = _ok(client.get("/api/state"))
    assert at_c["journey"]["stage"] == "GOVERN"
    assert at_c["authority"]["held_since"] == held_since

    _rolled_back_to(tmp_path, earlier, tuple(manifests))

    refused = client.get("/api/state")
    assert refused.status_code == 409, refused.text
    finding = refused.json()
    assert finding["finding"] == "TAMPERED" and finding["restorable"] is True
    assert "while Forge was running" in finding["refused"]
    assert any("this process last sealed" in problem for problem in finding["problems"]), finding
    for route in ("/api/build", "/api/journey/ready", "/api/proposals/P-1/confirm"):
        blocked = client.post(route, json={"actor": HUMAN})
        assert blocked.status_code == 409 and blocked.json().get("finding") == "TAMPERED", route

    restoration = _ok(client.post("/api/journey/restore", json={"actor": HUMAN}))
    assert restoration["stage"] == "GOVERN" and restoration["status"] == "failed"
    detail = restoration["restoration"]["detail"]
    assert "replaced while Forge was running" in detail and "casey" in detail
    after = _ok(client.get("/api/state"))
    assert after["journey"]["stage"] == "GOVERN" and after["journey"]["status"] == "failed"
    assert after["authority"]["currency"] == "not_independently_anchored"
    assert after["authority"]["continuity"] == "process"
    assert after["authority"]["held_since"] != held_since
    assert "replaced while Forge was running" in after["authority"]["last_restoration"]["detail"]


def test_every_forge_write_moves_the_witness_with_it(tmp_path: Path):
    """No false positive on anything Forge itself does. Every writing route
    ends in `seal()` and so moves the witness with it, and the interval it is
    held over does not restart, because an interval that restarted on every
    save would say nothing at all."""
    casey = Actor("human", "casey")
    legacy = CapsuleStore(tmp_path / "capsule")
    legacy.initialize(create_document("proj-1", "Portal", casey, AT))
    client = _client(tmp_path)
    unsealed = _ok(client.get("/api/state"))["authority"]
    assert unsealed["anchor"] == "unsealed" and unsealed["currency"] is None
    assert unsealed["continuity"] is None and unsealed["held_since"] is None, (
        "a store that was never sealed has no interval to hold anything over")

    def writes(path: str, **body: Any) -> dict:
        return _ok(client.post(path, json=body))

    writes("/api/journey/start", actor=HUMAN)     # the store's first seal
    first = _ok(client.get("/api/state"))["authority"]
    assert first["anchor"] == "sealed" and first["continuity"] == "process"
    held_since = first["held_since"]
    assert held_since is not None

    intent = writes("/api/proposals", field="intent",
                    value="Build a customer support portal.", actor=MODEL)["proposal_id"]
    writes(f"/api/proposals/{intent}/confirm", actor=HUMAN)
    provider = writes("/api/proposals", field="provider",
                      value={"name": "codex"}, actor=HUMAN)["proposal_id"]
    writes(f"/api/proposals/{provider}/confirm", actor=HUMAN)
    spare = writes("/api/proposals", field="intent", value="Something else.",
                   actor=MODEL)["proposal_id"]
    writes(f"/api/proposals/{spare}/reject", actor=HUMAN)
    _ok(client.post("/api/brd"))
    writes("/api/journey/confirm-scope", actor=HUMAN)
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    writes("/api/journey/ready", actor=HUMAN)

    state = _ok(client.get("/api/state"))
    assert state["journey"]["stage"] == "READY"
    assert state["authority"]["continuity"] == "process"
    assert state["authority"]["held_since"] == held_since, (
        "an ordinary sequence of Forge writes must hold ONE interval")

    # An ordinary breach -- the store moved, the seal did not -- is the finding
    # it always was, and its restoration does not end the interval: the seal
    # this process holds is the seal that is still on disk.
    (tmp_path / "capsule" / "experience.json").write_text("{}", encoding="utf-8")
    breached = client.get("/api/state")
    assert breached.status_code == 409 and breached.json()["finding"] == "TAMPERED"
    assert "while Forge was running" not in breached.json()["refused"]
    _ok(client.post("/api/journey/restore", json={"actor": HUMAN}))
    recovered = _ok(client.get("/api/state"))["authority"]
    assert recovered["continuity"] == "process" and recovered["held_since"] == held_since


def test_a_rollback_across_a_restart_is_the_disclosed_limit(tmp_path: Path):
    """THE LIMIT, PINNED IN THE AFFIRMATIVE. The witness is memory, restarting
    Forge is a same-user act, and a new process adopts whatever consistent set
    it finds. This asserts that this is what HAPPENS and that the assumptions
    record says so, so the cross-restart case cannot be closed -- nor the word
    moved without the mechanism -- while the disclosure still stands.

    The pattern is the ledger's `test_a_whole_directory_restore_is_the_disclosed_limit`:
    state the residue as behaviour, not as a comment nobody reads.
    """
    client = _client(tmp_path)
    _confirmed(client)
    earlier, *manifests = _capture(tmp_path, "B")
    first_run_held_since = _ok(client.get("/api/state"))["authority"]["held_since"]
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    _wait_finished(client)
    assert _ok(client.get("/api/state"))["journey"]["stage"] == "GOVERN"

    _rolled_back_to(tmp_path, earlier, tuple(manifests))
    assert client.get("/api/state").status_code == 409, "the running process holds the interval"

    # Forge is restarted over the same two directories. Nothing else changes.
    restarted = _client(tmp_path)
    state = _ok(restarted.get("/api/state"))
    assert state["journey"]["stage"] == "CONFIRM" and state["journey"]["status"] == "active"
    assert state["experience"]["history"][-1]["to"] == "CONFIRM"
    assert state["authority"]["currency"] == "not_independently_anchored", (
        "the currency word does not move: nothing here anchors the seal as the "
        "newest thing Forge ever wrote")
    assert state["authority"]["continuity"] == "process"
    assert state["authority"]["held_since"] != first_run_held_since, (
        "the new process holds its OWN interval, beginning at its first read")
    nothing = restarted.post("/api/journey/restore", json={"actor": HUMAN})
    assert nothing.status_code == 409
    assert nothing.json()["refused"] == (
        "the store matches its seal; there is nothing to restore")
    _ok(restarted.post("/api/build", json={"actor": HUMAN}))
    assert _wait_finished(restarted)["lifecycle"]["stage"] == "GOVERN", (
        "the restarted process builds the project a second time and nothing it "
        "can read knows about the first")

    disclosed = (ROOT / "docs/requirements/ASSUMPTIONS.md").read_text(encoding="utf-8")
    assert "A ROLLBACK ACROSS A RESTART OF FORGE IS THE LIMIT" in disclosed, (
        "the behaviour above is the disclosed limit; a slice closing it has to "
        "rewrite the disclosure in the same commit")
    assert "raises the cost" in disclosed


def test_the_currency_word_and_continuity_vocabulary_are_closed(tmp_path: Path):
    """The word, and everything beside it. `currency` reads exactly
    `not_independently_anchored`; `continuity` is `"process"` or absent and
    nothing else; and no value in the authority payload -- on a legacy store,
    at rest, during a build, or after a restoration -- claims an anchored,
    monotonic or latest authority. A builder who renames the word, or promotes
    it because a witness now exists, turns this red."""
    forbidden = ("anchored", "monotonic", "latest")

    def values(payload: Any) -> list[str]:
        """EVERY string anywhere under the payload, sequences included.

        This walker handled `str` and `dict` only, so a forbidden phrase
        inside a LIST was invisible to the gate this slice's central risk
        rests on. Demonstrated on this baseline with no edit to this test: a
        phrase placed in a list under `last_restoration` -- a free-shaped dict
        a later slice may well grow notes in -- left this test and both claim
        pins green. No list is in the payload today; descending into one costs
        nothing and closes the gap before it opens.
        """
        if isinstance(payload, str):
            return [payload]
        found: list[str] = []
        if isinstance(payload, dict):
            for value in payload.values():
                found.extend(values(value))
        elif isinstance(payload, (list, tuple)):
            for item in payload:
                found.extend(values(item))
        return found

    # The walker itself, against the shape it used to miss: a list value, and
    # a dict and a tuple nested inside it, all yield their strings. The
    # pre-fix walker returned `[]` for this payload.
    nested = {"last_restoration": {"notes": ["a monotonic anchor",
                                             {"why": ("the latest write",)}]}}
    assert values(nested) == ["a monotonic anchor", "the latest write"], values(nested)

    def check(payload: dict, sealed: bool) -> None:
        assert payload["currency"] == (
            "not_independently_anchored" if sealed else None), payload
        assert payload["continuity"] in {"process", None}, payload
        for value in values(payload):
            if value == "not_independently_anchored":
                continue
            for word in forbidden:
                assert word not in value.lower(), (word, value, payload)

    casey = Actor("human", "casey")
    CapsuleStore(tmp_path / "capsule").initialize(
        create_document("proj-1", "Portal", casey, AT),
        experience=start_experience(casey, AT))
    check(_ok(_client(tmp_path).get("/api/state"))["authority"], sealed=False)

    HostileFlow.attack = "ready"
    hostile = _client(tmp_path / "hostile", factory=HostileFlow)
    _confirmed(hostile)
    check(_ok(hostile.get("/api/state"))["authority"], sealed=True)
    _ok(hostile.post("/api/build", json={"actor": HUMAN}))
    assert HostileFlow.written.wait(timeout=30), "the worker never wrote its forgery"
    running = _ok(hostile.get("/api/state"))["authority"]
    assert running["build"] == "running"
    check(running, sealed=True)
    HostileFlow.release.set()
    _wait_finished(hostile)
    restored_state = _ok(hostile.get("/api/state"))["authority"]
    assert restored_state["last_restoration"] is not None
    check(restored_state, sealed=True)


def test_the_page_reports_the_interval_and_never_a_latest_authority(tmp_path: Path):
    """The page is where a basic user meets this, so it is where a promotion
    would be cheapest and least visible. It names the interval and the
    unchanged currency, and the words `latest` and `monotonic` appear nowhere
    in it at all."""
    page = onboarding._PAGE
    assert "currency not independently anchored" in page
    assert 'held.continuity === "process"' in page
    assert "unchanged since " in page and "in this run" in page
    for word in ("latest", "monotonic"):
        assert word not in page.lower(), word
    # And what the page renders is what the route serves: the two keys it
    # reads are on a sealed store's payload rather than rendering `undefined`.
    client = _client(tmp_path)
    _confirmed(client)
    authority = _ok(client.get("/api/state"))["authority"]
    assert set(authority) == {"anchor", "currency", "continuity", "held_since",
                              "last_restoration"}
