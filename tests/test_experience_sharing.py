"""The sharing preview: minimized by registry, displayed, never transmitted.

WHAT WOULD FALSIFY C5's implementation here: the user's own words leaking
into the payload; a field outside the closed registry appearing; the
transmission state claiming or implying authorization; or the module
acquiring any path to a network. Each has a specimen. The route tests run
the real onboarding app over a real store, so the displayed payload is
the shipped derivation, not a reconstruction.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nornyx_forge.capsule import Actor, confirm, create_document, propose
from nornyx_forge.experience_sharing import (
    SHARED_FIELDS,
    SHARING_SCHEMA,
    SharingError,
    assert_minimized,
    sharing_preview,
)
from nornyx_forge.onboarding_app import create_app

ROOT = Path(__file__).resolve().parents[1]
HUMAN = Actor(kind="human", ident="casey")
MODEL = Actor(kind="model", ident="builder-model")

MARKER = "ZEBRA-CONFIDENTIAL-BUSINESS-PLAN"


def _document() -> dict:
    document = create_document(
        "proj-1", f"Project {MARKER}", HUMAN, "2026-08-30T12:00:00Z"
    )
    document, intent_id = propose(
        document, "intent", f"Build the {MARKER} portal for our customers.",
        MODEL, "2026-08-30T12:01:00Z",
    )
    document = confirm(document, intent_id, HUMAN, "2026-08-30T12:02:00Z")
    document, provider_id = propose(
        document, "provider", {"name": "codex"}, HUMAN, "2026-08-30T12:03:00Z",
    )
    document = confirm(document, provider_id, HUMAN, "2026-08-30T12:04:00Z")
    document, _ = propose(
        document, "intent", f"Second idea about {MARKER}.", MODEL,
        "2026-08-30T12:05:00Z",
    )
    return document


# ---------------------------------------------------------------------------
# Minimization: the user's words never leave, the registry is exact
# ---------------------------------------------------------------------------

def test_the_users_words_never_reach_the_payload():
    payload = sharing_preview(_document(), None)
    serialized = json.dumps(payload)
    assert MARKER not in serialized
    assert "proj-1" not in serialized, "the raw project identity leaked"
    assert "casey" not in serialized, "an actor identity leaked"


def test_the_payload_carries_exactly_the_registered_fields():
    payload = sharing_preview(_document(), None)
    assert set(payload) == set(SHARED_FIELDS)
    assert payload["schema"] == SHARING_SCHEMA


def test_the_counts_and_names_are_derived_not_worded():
    payload = sharing_preview(_document(), {"stage": "CONFIRM"})
    assert payload["provider"] == "codex"
    assert payload["stage"] == "CONFIRM"
    assert payload["proposals_opened"] == 3
    assert payload["proposals_confirmed"] == 2
    assert payload["authority_confirmations"] == 2
    assert payload["lifecycle_recorded"] is True
    assert len(payload["project_fingerprint"]) == 16


def test_absent_lifecycle_is_recorded_absent():
    payload = sharing_preview(_document(), None)
    assert payload["stage"] is None
    assert payload["lifecycle_recorded"] is False


# ---------------------------------------------------------------------------
# Transmission: never, and said in the payload itself
# ---------------------------------------------------------------------------

def test_transmission_is_denied_as_data_in_every_payload():
    payload = sharing_preview(_document(), None)
    assert payload["transmission"]["authorized"] is False
    assert "never sent" in payload["transmission"]["reason"]


def test_the_sharing_module_has_no_path_to_a_network():
    """Structural: the module's import surface contains nothing that can
    open a connection. A transmit capability arriving would show up here
    as a new import before it could show up anywhere else."""
    import nornyx_forge.experience_sharing as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    for spelling in ("socket", "http", "urllib", "requests", "httpx", "websocket"):
        assert spelling not in source, (
            f"the TRANSMIT-NEVER module mentions {spelling!r}"
        )


# ---------------------------------------------------------------------------
# The guard itself must be falsifiable
# ---------------------------------------------------------------------------

def test_a_leaking_payload_is_caught_by_the_guard():
    document = _document()
    leaking = dict(sharing_preview(document, None))
    leaking["stage"] = f"reached CONFIRM for {MARKER}"
    with pytest.raises(SharingError, match="minimization failed"):
        assert_minimized(leaking, document)


def test_an_unregistered_field_is_caught_by_the_guard():
    document = _document()
    widened = dict(sharing_preview(document, None))
    widened["project_notes"] = "harmless-looking"
    with pytest.raises(SharingError, match="outside the shared registry"):
        assert_minimized(widened, document)


# ---------------------------------------------------------------------------
# The route: the shipped derivation, displayed
# ---------------------------------------------------------------------------

def test_the_route_serves_the_minimized_preview(tmp_path: Path):
    from nornyx_forge.capsule_store import CapsuleStore

    CapsuleStore(tmp_path / "capsule").initialize(_document())
    contracts = ROOT / ".nornyx" / "contracts"
    client = TestClient(create_app(tmp_path / "capsule", contracts,
                                   seal_dir=tmp_path / "seals"))
    response = client.get("/api/sharing-preview")
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == set(SHARED_FIELDS)
    assert MARKER not in response.text
    assert payload["transmission"]["authorized"] is False


def test_the_route_refuses_when_no_project_exists(tmp_path: Path):
    client = TestClient(create_app(tmp_path / "capsule", ROOT / ".nornyx" / "contracts",
                                   seal_dir=tmp_path / "seals"))
    response = client.get("/api/sharing-preview")
    assert response.status_code == 409
    assert "no project exists" in response.json()["refused"]
