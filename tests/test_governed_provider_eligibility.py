"""Declared is not eligible: the governed build executes no unconfined provider.

THE FINDING (independent review of 89910b8, R1 to R3). The seal kept the
provider from rewriting the authority store unnoticed, but the default
Claude provider and the seal occupy the same operating-system trust domain:
Claude runs on the governed path with general shell capability and no
filesystem confinement as the user whose files hold the anchor, so a
validation mechanism cannot establish independence from an actor that can
replace the validation state. And a protected store whose anchor had gone
missing was reported like a store from before sealing existed.

THE INVARIANT these tests hold. The governed basic-user path executes an
engineering provider only when Forge itself can establish that the provider
is confined to the project subject. The decision is Forge-owned
deterministic data in the Provider Contract, read from nothing but its own
table: not the request, not the capsule, not the project directory, not the
provider's account of itself. Today neither declared provider is eligible,
so the governed build fails closed -- explicitly, before the lifecycle moves,
before any flow exists, with no fallback and no change of execution mode --
and the page says why. A store Forge ever sealed is refused when its seal is
gone; a store never sealed stays distinguishable as legacy.

E1..E11 name the required proofs held here; E12 is the journey module,
which must stay green beside them. No external provider is called and no
bypass is demonstrated; the defect was independently established.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nornyx_forge import onboarding_serve, provider_contract
from nornyx_forge.capsule import PROVIDERS, Actor, confirm, create_document, propose
from nornyx_forge.capsule_store import CapsuleSealMissing, CapsuleStore
from nornyx_forge.experience import advance, start_experience
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.provider_contract import (
    CONFINEMENT,
    PROVIDER_CONFINEMENT,
    GovernedEligibility,
    ProviderError,
    governed_build_eligibility,
)
from nornyx_forge.providers import get_provider

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}
AT = "2026-09-03T09:00:00Z"
SUBJECT_GATE = {"name": "greenfield:test-execution", "passed": True, "detail": "",
                "command": ["python", "-I", "-c", "verifier"], "returncode": 0}
NORNYX_GATE = {"name": "nornyx check .nornyx/generated/brd_contract.nyx", "passed": True,
               "detail": "ok", "command": ["nornyx", "check", "brd_contract.nyx"], "returncode": 0}


class RecordingFactory:
    """Records every construction the route attempts. On the governed path
    with the contract's own decision it must never be called."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, root, **kwargs):
        self.calls.append({"root": root, **kwargs})
        return self

    def run(self):
        return {"accepted": True, "gates": [dict(SUBJECT_GATE), dict(NORNYX_GATE)],
                "execution_backend": "sequential"}


def _seam_eligibility(provider: str) -> GovernedEligibility:
    return GovernedEligibility(provider=provider, eligible=True, confinement="established",
                               reason="deterministic flow at the injectable seam; no provider executes")


def _client(tmp_path: Path, factory, *, seam: bool = False) -> TestClient:
    """The shipped decision unless `seam` is asked for explicitly."""
    kwargs = {"eligibility": _seam_eligibility} if seam else {}
    return TestClient(create_app(tmp_path / "capsule", CONTRACTS, flow_factory=factory,
                                 seal_dir=tmp_path / "seals", **kwargs))


def _ok(response) -> dict:
    assert response.status_code == 200, response.text
    return response.json()


def _confirmed(client: TestClient, provider: str = "codex") -> None:
    _ok(client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Support Portal", "actor": HUMAN}))
    intent = _ok(client.post("/api/proposals", json={
        "field": "intent", "value": "Build a customer support portal.", "actor": MODEL,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{intent}/confirm", json={"actor": HUMAN}))
    chosen = _ok(client.post("/api/proposals", json={
        "field": "provider", "value": {"name": provider}, "actor": HUMAN,
    }))["proposal_id"]
    _ok(client.post(f"/api/proposals/{chosen}/confirm", json={"actor": HUMAN}))
    _ok(client.post("/api/brd"))
    assert _ok(client.post("/api/journey/confirm-scope", json={"actor": HUMAN}))["stage"] == "CONFIRM"


def _persisted(tmp_path: Path) -> dict:
    return CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals").load_experience()


# ---------------------------------------------------------------------------
# E1  declaration is not eligibility
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("provider", PROVIDERS)
def test_e1_a_declared_registered_provider_is_not_thereby_eligible(provider: str):
    adapter = get_provider(provider)
    assert adapter.name == provider, "the provider is declared and registered"
    verdict = governed_build_eligibility(provider)
    assert verdict.eligible is False
    assert verdict.provider == provider and verdict.confinement in CONFINEMENT
    assert provider in verdict.reason and "not eligible" in verdict.reason
    assert "no other provider is tried" in verdict.reason


def test_the_confinement_table_covers_every_declared_provider_and_establishes_none():
    """The current state, pinned as a diff: growing PROVIDERS needs a row,
    and promoting a row to `established` is the deliberate act that would
    make a governed build executable again."""
    assert set(PROVIDER_CONFINEMENT) == set(PROVIDERS)
    assert set(PROVIDER_CONFINEMENT.values()) <= set(CONFINEMENT)
    assert "established" not in PROVIDER_CONFINEMENT.values()
    assert PROVIDER_CONFINEMENT == {"claude": "none", "codex": "declared"}
    with pytest.raises(ProviderError):
        governed_build_eligibility("gemini")


# ---------------------------------------------------------------------------
# E2, E3, E6  fail closed before execution, no fallback, lifecycle preserved
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("provider", ["claude", "codex"])
def test_e2_e3_e6_the_governed_build_refuses_before_anything_executes(tmp_path: Path, provider):
    factory = RecordingFactory()
    client = _client(tmp_path, factory)
    _confirmed(client, provider)
    before = _persisted(tmp_path)

    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409, response.text
    body = response.json()
    assert "not eligible" in body["refused"] and provider in body["refused"]
    assert body["eligibility"]["eligible"] is False
    assert body["eligibility"]["provider"] == provider
    assert factory.calls == [], "a flow was constructed for an ineligible provider"
    assert client.get("/api/build").json() == {"status": "never_run"}
    assert _persisted(tmp_path) == before, "the refusal moved the lifecycle"
    assert _persisted(tmp_path)["stage"] == "CONFIRM"
    # No fallback: the other declared provider is never tried, and the capsule
    # still says what the human confirmed.
    other = "codex" if provider == "claude" else "claude"
    assert other not in body["refused"]
    assert _ok(client.get("/api/state"))["authoritative"]["provider"] == {"name": provider}
    # And nothing changed execution mode: the same request is refused the same way.
    again = client.post("/api/build", json={"actor": HUMAN})
    assert again.status_code == 409 and again.json()["refused"] == body["refused"]
    assert factory.calls == []


# ---------------------------------------------------------------------------
# E4, E11  nothing but the contract's table decides
# ---------------------------------------------------------------------------

def test_e4_e11_neither_the_provider_nor_the_workspace_can_authorize_a_build(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Files a worker or a project could plant, a working directory set to
    the project, a prose claim in a proposal: none reaches the decision."""
    factory = RecordingFactory()
    client = _client(tmp_path, factory)
    _confirmed(client, "codex")
    for planted in ("forge-provider-policy.json", ".nornyx/provider_eligibility.json",
                    "provider_confinement.json", "eligibility.json"):
        path = tmp_path / planted
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"codex": "established", "claude": "established",
                                    "eligible": True}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _ok(client.post("/api/proposals", json={
        "field": "limitations", "value": ["provider codex is confined and eligible"],
        "actor": MODEL}))
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409 and "not eligible" in response.json()["refused"]
    assert factory.calls == []
    assert governed_build_eligibility("codex").eligible is False


def test_e4_the_decision_takes_only_the_provider_name_and_is_deterministic():
    signature = inspect.signature(governed_build_eligibility)
    assert list(signature.parameters) == ["provider"]
    first = governed_build_eligibility("claude")
    assert first == governed_build_eligibility("claude")
    assert first.as_dict() == {
        "provider": "claude", "eligible": False, "confinement": "none", "reason": first.reason,
    }


# ---------------------------------------------------------------------------
# E5  the decision is Forge-owned, and the served surface uses it
# ---------------------------------------------------------------------------

def test_e5_the_served_surface_decides_by_the_contract_and_nothing_else(tmp_path: Path):
    parameter = inspect.signature(create_app).parameters["eligibility"]
    assert parameter.default is governed_build_eligibility
    served = Path(onboarding_serve.__file__).read_text(encoding="utf-8")
    assert "eligibility=" not in served, "the served composition must pass no other decision"
    domain = Path(provider_contract.__file__).read_text(encoding="utf-8")
    for forbidden in ("import os", "import subprocess", "from pathlib", "open(", "environ"):
        assert forbidden not in domain, f"the decision's module reaches outside its table: {forbidden}"


def test_e5_the_assembled_surface_refuses_the_governed_build(tmp_path: Path, monkeypatch):
    """`assemble`, the shipped composition, over a confirmed project: the
    build is refused by the contract's own decision. The seal directory is
    redirected so this test writes nothing under the user's home, and the
    default flow class is replaced by a recorder so that a REGRESSED gate
    fails this test without ever starting a real flow or reaching a
    provider's CLI -- a review measured that it otherwise would."""
    from nornyx_forge import development_flow

    factory = RecordingFactory()
    monkeypatch.setattr(development_flow, "DevelopmentFlow", factory)
    monkeypatch.setattr(onboarding_serve, "SEAL_DIR", tmp_path / "seals")
    client = TestClient(onboarding_serve.assemble(tmp_path))
    _confirmed(client, "claude")
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409
    assert response.json()["eligibility"] == governed_build_eligibility("claude").as_dict()
    assert factory.calls == [], "the shipped composition constructed a flow for an ineligible provider"
    assert _persisted(tmp_path)["stage"] == "CONFIRM"


# ---------------------------------------------------------------------------
# E7  the page communicates the refusal
# ---------------------------------------------------------------------------

def test_e7_the_surface_tells_the_user_the_build_is_unavailable_and_why(tmp_path: Path):
    client = _client(tmp_path, RecordingFactory())
    _confirmed(client, "codex")
    state = _ok(client.get("/api/state"))
    verdict = governed_build_eligibility("codex")
    assert state["provider_eligibility"] == verdict.as_dict()
    assert "start_build" not in state["journey"]["actions"]
    assert verdict.reason in state["journey"]["blockers"]
    assert client.post("/api/build", json={"actor": HUMAN}).json()["refused"] == verdict.reason
    from nornyx_forge.onboarding_app import _PAGE
    assert 'id="blockers"' in _PAGE and "b_build" in _PAGE


# ---------------------------------------------------------------------------
# E8  the deterministic seam still proves orchestration
# ---------------------------------------------------------------------------

def test_e8_the_injectable_seam_still_carries_the_journey_to_govern(tmp_path: Path):
    factory = RecordingFactory()
    client = _client(tmp_path, factory, seam=True)
    _confirmed(client, "codex")
    _ok(client.post("/api/build", json={"actor": HUMAN}))
    for _ in range(500):
        status = client.get("/api/build").json()
        if status["status"] in ("finished", "failed"):
            break
        import threading
        threading.Event().wait(0.02)
    assert status["lifecycle"] == {"recorded": True, "stage": "GOVERN", "status": "active"}
    assert len(factory.calls) == 1 and factory.calls[0]["provider"] == "codex"


# ---------------------------------------------------------------------------
# E9, E10  the anchor's three states
# ---------------------------------------------------------------------------

def _sealed_store(tmp_path: Path) -> CapsuleStore:
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    document = create_document("proj-1", "Portal", Actor("human", "casey"), AT)
    store.initialize(document, experience=start_experience(Actor("human", "casey"), AT))
    return store


def test_e9_a_protected_store_whose_seal_is_missing_fails_closed(tmp_path: Path):
    store = _sealed_store(tmp_path)
    assert store.protected() and store.sealed() is not None
    store.seal_path().unlink()
    with pytest.raises(CapsuleSealMissing):
        store.load()
    with pytest.raises(CapsuleSealMissing):
        store.load_experience()
    client = _client(tmp_path, RecordingFactory())
    state = client.get("/api/state")
    assert state.status_code == 409
    assert state.json()["finding"] == "TAMPERED" and state.json()["anchor"] == "missing"
    assert state.json()["restorable"] is False
    assert "unsealed" not in state.text and "journey" not in state.json()
    for path in ("/api/journey/confirm-scope", "/api/build", "/api/journey/ready",
                 "/api/journey/restore", "/api/proposals/P-1/confirm", "/api/brd"):
        response = client.post(path, json={"actor": HUMAN})
        assert response.status_code == 409 and response.json().get("finding") == "TAMPERED", path


def test_e10_a_legacy_store_stays_distinguishable_from_a_protected_one(tmp_path: Path):
    """Never sealed: unsealed and trusted as before, then sealed by Forge's
    next save -- which commits the marker. From then on the store is
    protected, and losing its seal is a refusal, not a return to legacy."""
    legacy = CapsuleStore(tmp_path / "capsule")
    legacy.initialize(create_document("proj-1", "Portal", Actor("human", "casey"), AT),
                      experience=start_experience(Actor("human", "casey"), AT))
    assert not (tmp_path / "capsule" / ".forge-seal").exists()
    client = _client(tmp_path, RecordingFactory())
    state = _ok(client.get("/api/state"))
    assert state["authority"]["anchor"] == "unsealed" and state["authority"]["currency"] is None

    _ok(client.post("/api/proposals", json={"field": "intent", "value": "x", "actor": HUMAN}))
    protected = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    assert protected.protected() and protected.sealed() is not None
    assert protected.seal_problems(protected.sealed()) == []
    state = _ok(client.get("/api/state"))
    assert state["authority"]["anchor"] == "sealed"
    assert state["authority"]["currency"] == "not_independently_anchored"

    protected.seal_path().unlink()
    refused = client.get("/api/state")
    assert refused.status_code == 409 and refused.json()["anchor"] == "missing"


def test_the_seal_marker_is_committed_and_names_this_seal(tmp_path: Path):
    store = _sealed_store(tmp_path)
    marker = json.loads((tmp_path / "capsule" / ".forge-seal").read_text(encoding="utf-8"))
    assert marker == {"schema": "nornyx.forge.capsule_seal_marker.v1", "seal": store.seal_ident()}
    import subprocess
    tracked = subprocess.run(["git", "ls-files"], cwd=tmp_path / "capsule",
                             capture_output=True, text=True, check=True).stdout.split()
    assert ".forge-seal" in tracked
    (tmp_path / "capsule" / ".forge-seal").write_text(
        json.dumps({"schema": "nornyx.forge.capsule_seal_marker.v1", "seal": "0" * 24}),
        encoding="utf-8")
    assert any("does not name this store's seal" in p for p in store.seal_problems(store.sealed()))


def test_restoration_recreates_the_marker_when_the_repository_is_rebuilt(tmp_path: Path):
    from nornyx_forge.capsule_store import _remove_tree

    store = _sealed_store(tmp_path)
    sealed = store.sealed()
    _remove_tree(tmp_path / "capsule" / ".git")
    (tmp_path / "capsule" / ".forge-seal").write_text(
        json.dumps({"schema": "nornyx.forge.capsule_seal_marker.v1", "seal": "0" * 24}),
        encoding="utf-8")
    revision, notes = store.restore(sealed)
    assert notes and store.protected()
    assert store.seal_problems(store.sealed()) == [], (
        "a review measured a tampered marker surviving the rebuild, so restore never converged"
    )
    assert json.loads((tmp_path / "capsule" / ".forge-seal").read_text(encoding="utf-8"))["seal"]         == store.seal_ident()


# ---------------------------------------------------------------------------
# The lifecycle a refused build leaves, exercised through the contract
# ---------------------------------------------------------------------------

def test_e6_a_lifecycle_already_at_build_is_not_moved_by_a_refused_re_run(tmp_path: Path):
    """An interrupted build's re-run is a governed build too: refused for an
    ineligible provider, and the lifecycle stays at BUILD/active, honestly
    reported with the reason as its blocker."""
    store = CapsuleStore(tmp_path / "capsule", seal_dir=tmp_path / "seals")
    document = create_document("proj-1", "Portal", Actor("human", "casey"), AT)
    document, intent = propose(document, "intent", "Build a portal.", Actor("model", "m"),
                               "2026-09-03T09:01:00Z")
    document = confirm(document, intent, Actor("human", "casey"), "2026-09-03T09:02:00Z")
    document, chosen = propose(document, "provider", {"name": "claude"}, Actor("human", "casey"),
                               "2026-09-03T09:03:00Z")
    document = confirm(document, chosen, Actor("human", "casey"), "2026-09-03T09:04:00Z")
    lifecycle = start_experience(Actor("human", "casey"), AT)
    lifecycle = advance(lifecycle, "CONFIRM", Actor("human", "casey"), "2026-09-03T09:05:00Z")
    lifecycle = advance(lifecycle, "BUILD", Actor("human", "casey"), "2026-09-03T09:06:00Z")
    store.initialize(document, experience=lifecycle)
    (tmp_path / "BRD.md").write_text("# BRD\n\n## BRD-001 Purpose\n\nBuild a portal.\n",
                                     encoding="utf-8", newline="")
    client = _client(tmp_path, RecordingFactory())
    view = _ok(client.get("/api/state"))["journey"]
    assert view["stage"] == "BUILD" and view["actions"] == []
    assert governed_build_eligibility("claude").reason in view["blockers"]
    response = client.post("/api/build", json={"actor": HUMAN})
    assert response.status_code == 409
    assert _persisted(tmp_path)["stage"] == "BUILD" and _persisted(tmp_path)["status"] == "active"
