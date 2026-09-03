"""The onboarding surface serves the capsule's authority rules unchanged.

WHAT WOULD FALSIFY THIS MODULE: a route that upgrades an actor, confirms
without a human, invents lifecycle state, serves prose instead of the
guarded rendering, or dresses a tamper finding up as an empty page. Each
has a specimen here, and each specimen exercises the REAL app over a real
git-backed store — the surface under test is the shipping composition, not
a mock of it.

The actor on a request is judged by the capsule's KIND rule, so the
hostile requests here claim kind "model" outright. That is the honest
version of the threat on a local single-user surface: the module's
docstring discloses that humans are not authenticated yet, and these tests
pin that the surface at least never REFUSES less than the capsule does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nornyx_forge.capsule import PROVIDERS
from nornyx_forge.governance_rendering import parse_business
from nornyx_forge.onboarding_app import create_app

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / ".nornyx" / "contracts"

HUMAN = {"kind": "human", "ident": "casey"}
MODEL = {"kind": "model", "ident": "builder-model"}


def _clock():
    ticks = iter(range(10_000))
    return lambda: (
        f"2026-08-30T{(next(ticks) // 60) % 24:02d}:{next(ticks) % 60:02d}:00Z"
    )


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    app = create_app(tmp_path / "capsule", CONTRACTS_DIR, clock=_clock())
    return TestClient(app)


def _created(client: TestClient) -> None:
    response = client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Test Project", "actor": HUMAN,
    })
    assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# The page and the uninitialized state
# ---------------------------------------------------------------------------

def test_the_page_serves_and_says_who_holds_authority(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert "the contracts, not\nthis page, are the authority" in response.text


def test_an_uninitialized_store_is_reported_not_invented(client: TestClient):
    state = client.get("/api/state").json()
    assert state == {"initialized": False, "providers": list(PROVIDERS)}


# ---------------------------------------------------------------------------
# Creation and the authority line
# ---------------------------------------------------------------------------

def test_a_human_creates_a_project_and_it_persists(client: TestClient):
    _created(client)
    state = client.get("/api/state").json()
    assert state["initialized"] is True
    assert state["authoritative"] == {"project_name": "Test Project"}
    # PR-17: creation starts the lifecycle through the contract. This line
    # read `== "absent"` before, and pinned the gap it now closes.
    assert state["experience"]["stage"] == "DISCOVER"
    assert state["experience"]["status"] == "active"
    assert state["revision"]


def test_a_model_actor_cannot_create_a_project(client: TestClient):
    response = client.post("/api/project", json={
        "project_id": "proj-1", "project_name": "Test Project", "actor": MODEL,
    })
    assert response.status_code == 409
    assert "created by a human actor" in response.json()["refused"]
    assert client.get("/api/state").json()["initialized"] is False


def test_a_need_enters_only_as_a_proposal(client: TestClient):
    """C2 on the wire: a model's plain-language need is stored, validated,
    and NOT authoritative."""
    _created(client)
    response = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a customer support portal.",
        "actor": MODEL,
    })
    assert response.status_code == 200
    proposal_id = response.json()["proposal_id"]
    state = client.get("/api/state").json()
    assert "intent" not in state["authoritative"]
    row = next(p for p in state["proposals"] if p["proposal_id"] == proposal_id)
    assert row["status"] == "open" and row["kind"] == "model"


def test_a_human_confirmation_moves_the_need_into_authority(client: TestClient):
    _created(client)
    proposal_id = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": MODEL,
    }).json()["proposal_id"]
    before = client.get("/api/state").json()["digest_chain_length"]
    response = client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": HUMAN})
    assert response.status_code == 200
    state = client.get("/api/state").json()
    assert state["authoritative"]["intent"] == "Build a portal."
    assert state["digest_chain_length"] == before + 1


def test_a_model_actor_cannot_confirm(client: TestClient):
    """The authority line itself, exercised through the route."""
    _created(client)
    proposal_id = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": MODEL,
    }).json()["proposal_id"]
    response = client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": MODEL})
    assert response.status_code == 409
    assert "only a human actor may confirm" in response.json()["refused"]
    state = client.get("/api/state").json()
    assert "intent" not in state["authoritative"]


def test_a_forged_or_double_confirmation_is_refused(client: TestClient):
    _created(client)
    missing = client.post("/api/proposals/P-99/confirm", json={"actor": HUMAN})
    assert missing.status_code == 409 and "no proposal" in missing.json()["refused"]

    proposal_id = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": HUMAN,
    }).json()["proposal_id"]
    assert client.post(
        f"/api/proposals/{proposal_id}/confirm", json={"actor": HUMAN}
    ).status_code == 200
    again = client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": HUMAN})
    assert again.status_code == 409 and "not open" in again.json()["refused"]


def test_rejection_closes_without_touching_authority(client: TestClient):
    _created(client)
    proposal_id = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": MODEL,
    }).json()["proposal_id"]
    assert client.post(
        f"/api/proposals/{proposal_id}/reject", json={"actor": MODEL}
    ).status_code == 200
    state = client.get("/api/state").json()
    assert "intent" not in state["authoritative"]


# ---------------------------------------------------------------------------
# Provider selection through the same gate
# ---------------------------------------------------------------------------

def test_provider_selection_is_capsule_gated(client: TestClient):
    _created(client)
    proposal_id = client.post("/api/proposals", json={
        "field": "provider", "value": {"name": "codex"}, "actor": HUMAN,
    }).json()["proposal_id"]
    client.post(f"/api/proposals/{proposal_id}/confirm", json={"actor": HUMAN})
    state = client.get("/api/state").json()
    assert state["authoritative"]["provider"] == {"name": "codex"}

    undeclared = client.post("/api/proposals", json={
        "field": "provider", "value": {"name": "gemini"}, "actor": HUMAN,
    })
    assert undeclared.status_code == 422
    assert "not one of" in undeclared.json()["refused"]


def test_an_undeclared_field_is_refused_at_the_door(client: TestClient):
    _created(client)
    response = client.post("/api/proposals", json={
        "field": "telemetry_endpoint", "value": "https://x", "actor": HUMAN,
    })
    assert response.status_code == 422
    assert "undeclared field" in response.json()["refused"]


# ---------------------------------------------------------------------------
# The governance view and honest failure states
# ---------------------------------------------------------------------------

def test_the_governance_view_is_the_guarded_renderers_output(client: TestClient):
    first = client.get("/api/governance").json()
    assert [c["file"] for c in first["contracts"]] == [
        "architecture_governance.nyx", "forge_control.nyx", "runtime_network.nyx",
    ]
    for contract in first["contracts"]:
        assert "the contract is the authority" in contract["view"]
        parse_business(contract["view"])  # strict grammar: prose cannot hide here
    second = client.get("/api/governance").json()
    assert second == first, "the governance view must be deterministic"


def test_an_unrenderable_contract_is_a_reported_failure(tmp_path: Path):
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "broken.nyx").write_text("project: [not, a, mapping]\n",
                                          encoding="utf-8", newline="")
    app = create_app(tmp_path / "capsule", contracts, clock=_clock())
    response = TestClient(app).get("/api/governance")
    assert response.status_code == 502
    assert "broken.nyx" in response.json()["refused"]


def test_a_tampered_capsule_is_named_tampered(client: TestClient, tmp_path: Path):
    _created(client)
    capsule_file = tmp_path / "capsule" / "capsule.json"
    document = json.loads(capsule_file.read_text(encoding="utf-8"))
    document["authoritative"]["project_name"] = "Renamed Behind The Chain"
    capsule_file.write_text(json.dumps(document), encoding="utf-8", newline="")
    response = client.get("/api/state")
    assert response.status_code == 409
    assert response.json()["finding"] == "TAMPERED"
