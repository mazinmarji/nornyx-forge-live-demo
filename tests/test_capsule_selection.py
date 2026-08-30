"""The confirmed capsule provider drives the build; proposals never do.

THE AUTHORITY LINE, extended to execution: onboarding records a provider
selection in the capsule, and only the CONFIRMED — human-gated —
selection may feed the development flow. A proposed-but-unconfirmed
selection driving a build would be model output steering execution
without a human confirmation, which is exactly what the capsule's split
exists to prevent. Every test here goes through the real CLI command over
a real git-backed store, and the flow is captured rather than run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nornyx_forge import cli
from nornyx_forge.capsule import Actor, confirm, create_document, propose
from nornyx_forge.capsule_store import CapsuleStore

HUMAN = Actor(kind="human", ident="casey")
MODEL = Actor(kind="model", ident="builder-model")


def _project(tmp_path: Path, *, confirm_provider: str | None,
             propose_only: str | None = None) -> Path:
    project = tmp_path / "proj"
    document = create_document("proj-1", "Test Project", HUMAN,
                               "2026-08-30T12:00:00Z")
    if confirm_provider is not None:
        document, proposal_id = propose(
            document, "provider", {"name": confirm_provider}, MODEL,
            "2026-08-30T12:01:00Z",
        )
        document = confirm(document, proposal_id, HUMAN, "2026-08-30T12:02:00Z")
    if propose_only is not None:
        document, _ = propose(
            document, "provider", {"name": propose_only}, MODEL,
            "2026-08-30T12:03:00Z",
        )
    CapsuleStore(project / "capsule").initialize(document)
    return project


@pytest.fixture()
def captured(monkeypatch: pytest.MonkeyPatch) -> dict:
    observed: dict = {}

    class FakeFlow:
        def __init__(self, root, **kwargs):
            observed.update(kwargs, root=root)

        def run(self):
            return {"accepted": True}

    monkeypatch.setattr(cli, "DevelopmentFlow", FakeFlow)
    return observed


def test_the_confirmed_provider_feeds_the_build(tmp_path: Path, captured: dict):
    project = _project(tmp_path, confirm_provider="codex")
    result = CliRunner().invoke(cli.app, [
        "build", "--worker-mode", "claude-code", "--project-dir", str(project),
    ])
    assert result.exit_code == 0, result.output
    assert captured["provider"] == "codex"


def test_a_proposed_but_unconfirmed_selection_never_drives_a_build(
        tmp_path: Path, captured: dict):
    """THE LINE ITSELF: the proposal sits in the capsule, visible and open,
    and the build refuses to treat it as a decision."""
    project = _project(tmp_path, confirm_provider=None, propose_only="codex")
    result = CliRunner().invoke(cli.app, [
        "build", "--worker-mode", "claude-code", "--project-dir", str(project),
    ])
    assert result.exit_code == 2
    assert "no CONFIRMED provider" in result.output
    assert captured == {}, "the flow was constructed despite the refusal"


def test_a_missing_capsule_is_a_refusal_not_a_default(tmp_path: Path, captured: dict):
    result = CliRunner().invoke(cli.app, [
        "build", "--worker-mode", "claude-code",
        "--project-dir", str(tmp_path / "nowhere"),
    ])
    assert result.exit_code != 0
    assert captured == {}


def test_contradicting_selections_are_refused_not_ranked(
        tmp_path: Path, captured: dict):
    project = _project(tmp_path, confirm_provider="codex")
    result = CliRunner().invoke(cli.app, [
        "build", "--worker-mode", "claude-code", "--project-dir", str(project),
        "--provider", "claude",
    ])
    assert result.exit_code == 2
    assert "contradicts" in result.output
    assert captured == {}


def test_an_agreeing_explicit_provider_is_accepted(tmp_path: Path, captured: dict):
    project = _project(tmp_path, confirm_provider="claude")
    result = CliRunner().invoke(cli.app, [
        "build", "--worker-mode", "claude-code", "--project-dir", str(project),
        "--provider", "claude",
    ])
    assert result.exit_code == 0, result.output
    assert captured["provider"] == "claude"


def test_a_tampered_capsule_refuses_before_anything_runs(
        tmp_path: Path, captured: dict):
    project = _project(tmp_path, confirm_provider="codex")
    capsule_file = project / "capsule" / "capsule.json"
    document = json.loads(capsule_file.read_text(encoding="utf-8"))
    document["authoritative"]["provider"] = {"name": "claude"}
    capsule_file.write_text(json.dumps(document), encoding="utf-8", newline="")
    result = CliRunner().invoke(cli.app, [
        "build", "--worker-mode", "claude-code", "--project-dir", str(project),
    ])
    assert result.exit_code != 0
    assert captured == {}, "a tampered capsule reached the flow"


def test_without_a_project_dir_the_provider_path_is_unchanged(
        tmp_path: Path, captured: dict, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli.app, ["build"])
    assert result.exit_code in (0, 2)
    assert captured["provider"] is None