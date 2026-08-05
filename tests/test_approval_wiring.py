"""Inserting a human approval must be mechanical, reversible and fail closed.

Drives the documented commands against a throwaway git repository, so nothing
here depends on hand-edited YAML. The approvals used are labelled synthetic
fixtures; the tooling only ever reads and hashes them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REFRESH = "scripts/refresh_governance_evidence.py"
BASELINE = "scripts/check_pre_approval_baseline.py"
CONTRACTS = Path(".nornyx/contracts")

FIXTURE_STATEMENT = (
    "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL. It grants nothing and "
    "represents no human decision."
)

needs_nornyx = pytest.mark.skipif(
    shutil.which("nornyx") is None, reason="nornyx CLI is not installed"
)


def _git(workspace: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=workspace, capture_output=True, text=True, check=True
    )


def _repo(tmp_path: Path) -> Path:
    """A throwaway repository carrying the contracts and the tooling."""
    workspace = tmp_path / "repo"
    (workspace / "scripts").mkdir(parents=True)
    for script in (REFRESH, BASELINE, "scripts/check_architecture.py"):
        shutil.copy2(ROOT / script, workspace / script)
    shutil.copytree(ROOT / CONTRACTS, workspace / CONTRACTS)
    shutil.copytree(ROOT / "src", workspace / "src")
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.email", "fixture@example.invalid")
    _git(workspace, "config", "user.name", "fixture")
    _git(workspace, "add", "-A")
    _git(workspace, "commit", "-qm", "fixture baseline")
    return workspace


def _run(workspace: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(workspace / "src")}
    return subprocess.run(
        [sys.executable, *args], cwd=workspace, capture_output=True, text=True, env=env
    )


def _head(workspace: Path) -> str:
    return "git:" + _git(workspace, "rev-parse", "HEAD").stdout.strip()


def _write_approvals(workspace: Path, revision: str, *, expires: str) -> None:
    """Author both synthetic approvals, exactly as a human would drop them in."""
    evidence = workspace / CONTRACTS / "evidence"
    for filename, role in (
        ("runtime_human_approval.json", "network_governance_owner"),
        ("architecture_human_approval.json", "architecture_reviewer"),
    ):
        payload = {
            "schema": "nornyx.forge.human_approval_record.v1",
            "approval": "granted",
            "producer": {"id": f"human.test_fixture:{role}", "type": "human"},
            "status": "pass",
            "subject_revision": revision,
            "generated_at": "2026-08-02T00:00:00Z",
            "expires_at": expires,
            "statement": FIXTURE_STATEMENT,
        }
        (evidence / filename).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


def _prepare(workspace: Path, *, as_of: str) -> None:
    """The documented sequence, as one atomic operation.

    It used to be four separate invocations. Each step rewrites the contracts,
    so once the governed-tree gate existed the second invocation correctly saw
    the first one's output as drift. Adoption is therefore gated once, up front,
    and then runs to completion — rather than exempting `.nyx` files from the
    check that exists to protect them.
    """
    completed = _run(workspace, REFRESH, "--adopt-approval", "--as-of", as_of)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def _check(workspace: Path, contract: str, as_of: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [shutil.which("nornyx") or "nornyx", "check", str(CONTRACTS / contract),
         "--as-of", as_of],
        cwd=workspace,
        capture_output=True,
        text=True,
    )


@needs_nornyx
def test_approvals_wire_in_without_hand_editing_yaml(tmp_path: Path):
    """Both contracts must validate after the documented commands alone."""
    workspace = _repo(tmp_path)
    _write_approvals(workspace, _head(workspace), expires="2026-08-05T00:00:00Z")
    _prepare(workspace, as_of="2026-08-02T00:00:00Z")

    for contract in ("runtime_network.nyx", "architecture_governance.nyx"):
        completed = _check(workspace, contract, "2026-08-03T00:00:00Z")
        assert completed.returncode == 0, (
            f"{contract} did not validate:\n{completed.stdout}{completed.stderr}"
        )


@needs_nornyx
def test_removing_the_approvals_restores_the_pre_approval_state(tmp_path: Path):
    """Deleting the human artifacts must put the contracts back, mechanically."""
    workspace = _repo(tmp_path)
    _write_approvals(workspace, _head(workspace), expires="2026-08-05T00:00:00Z")
    _prepare(workspace, as_of="2026-08-02T00:00:00Z")
    assert _check(workspace, "runtime_network.nyx", "2026-08-03T00:00:00Z").returncode == 0

    evidence = workspace / CONTRACTS / "evidence"
    for name in ("runtime_human_approval.json", "architecture_human_approval.json"):
        (evidence / name).unlink()
    _prepare(workspace, as_of="2026-08-02T00:00:00Z")

    # Pinned well past the withdrawn approval's window: withdrawing must
    # restore the non-expiring placeholder, not leave a short expiry to rot
    # later. Regenerating refreshes machine evidence, which genuinely expires;
    # if the withdrawn window had been left behind, no amount of regeneration
    # would make this pass.
    report = json.loads(
        _run(workspace, BASELINE, "--regenerate", "--as-of", "2030-01-01T00:00:00Z").stdout
    )
    assert report["status"] == "pass", report
    assert report["human_approval_present"] is False
    for contract in report["contracts"]:
        assert contract["approval_blocked"] is True, contract
        assert contract["unexpected_diagnostics"] == [], contract


@needs_nornyx
def test_wiring_is_idempotent(tmp_path: Path):
    workspace = _repo(tmp_path)
    _write_approvals(workspace, _head(workspace), expires="2026-08-05T00:00:00Z")
    _prepare(workspace, as_of="2026-08-02T00:00:00Z")
    first = {
        name: (workspace / CONTRACTS / name).read_bytes()
        for name in ("runtime_network.nyx", "architecture_governance.nyx")
    }
    _run(workspace, REFRESH, "--wire-approvals")
    _run(workspace, REFRESH, "--wire-approvals")
    for name, before in first.items():
        assert (workspace / CONTRACTS / name).read_bytes() == before, name


@needs_nornyx
def test_advancing_head_after_approval_fails_closed(tmp_path: Path):
    """A moved HEAD must stop the workflow and change nothing.

    Otherwise evidence built from the new tree would be stamped with the old
    approved revision, describing code nobody approved.
    """
    workspace = _repo(tmp_path)
    approved = _head(workspace)
    _write_approvals(workspace, approved, expires="2026-08-05T00:00:00Z")
    _prepare(workspace, as_of="2026-08-02T00:00:00Z")

    (workspace / "NOTES.md").write_text("moved on\n", encoding="utf-8")
    _git(workspace, "add", "-A")
    _git(workspace, "commit", "-qm", "advance head")
    assert _head(workspace) != approved

    before = {
        path: path.read_bytes()
        for path in sorted((workspace / CONTRACTS).rglob("*"))
        if path.is_file()
    }

    for args in (
        (REFRESH,),
        (REFRESH, "--wire-approvals"),
        (REFRESH, "--materialize-approval-window"),
        (REFRESH, "--sync-contracts"),
    ):
        completed = _run(workspace, *args)
        assert completed.returncode != 0, f"{args} did not fail closed"
        assert "mismatch" in (completed.stdout + completed.stderr).lower()

    after = {
        path: path.read_bytes()
        for path in sorted((workspace / CONTRACTS).rglob("*"))
        if path.is_file()
    }
    assert after == before, "a failed run modified contracts or evidence"


@needs_nornyx
def test_tooling_never_authors_or_edits_an_approval(tmp_path: Path):
    """The human files must come back byte-identical after a full run."""
    workspace = _repo(tmp_path)
    _write_approvals(workspace, _head(workspace), expires="2026-08-05T00:00:00Z")
    evidence = workspace / CONTRACTS / "evidence"
    originals = {
        name: (evidence / name).read_bytes()
        for name in ("runtime_human_approval.json", "architecture_human_approval.json")
    }
    _prepare(workspace, as_of="2026-08-02T00:00:00Z")
    for name, raw in originals.items():
        assert (evidence / name).read_bytes() == raw, f"{name} was modified"


@needs_nornyx
def test_a_non_human_producer_is_refused(tmp_path: Path):
    """A machine cannot be laundered into an approval by renaming the file."""
    workspace = _repo(tmp_path)
    payload = {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": {"id": "tool:forge", "type": "tool"},
        "status": "pass",
        "subject_revision": _head(workspace),
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "statement": FIXTURE_STATEMENT,
    }
    (workspace / CONTRACTS / "evidence" / "runtime_human_approval.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    completed = _run(workspace, REFRESH, "--as-of", "2026-08-02T00:00:00Z")
    assert completed.returncode != 0
    assert "not a human approval record" in (completed.stdout + completed.stderr)


@needs_nornyx
def test_withdrawing_an_approval_restores_the_authority_placeholder(tmp_path: Path):
    """Materialization must have an inverse.

    Leaving the short reviewer window behind after an approval is withdrawn
    re-rots the baseline the moment that date passes.
    """
    workspace = _repo(tmp_path)
    _write_approvals(workspace, _head(workspace), expires="2026-08-05T00:00:00Z")
    _prepare(workspace, as_of="2026-08-02T00:00:00Z")
    contract = workspace / CONTRACTS / "runtime_network.nyx"
    assert "2026-08-05T00:00:00Z" in contract.read_text(encoding="utf-8")

    evidence = workspace / CONTRACTS / "evidence"
    for name in ("runtime_human_approval.json", "architecture_human_approval.json"):
        (evidence / name).unlink()
    _prepare(workspace, as_of="2026-08-02T00:00:00Z")

    text = contract.read_text(encoding="utf-8")
    assert "2026-08-05T00:00:00Z" not in text, "a stale reviewer window was left behind"
    # Back to the non-expiring representation, not a distant date pretending to
    # be one. A declaration of who may approve has no reason to decay.
    for declaration in yaml.safe_load(text)["approvals"]:
        assert declaration["expires_at"] is None, declaration

    # And the baseline is healthy long after the withdrawn window would have
    # ended. The far-future case needs the documented regeneration, because
    # machine evidence has a real finite window; see EVIDENCE_FRESHNESS.md.
    report = json.loads(_run(workspace, BASELINE, "--as-of", "2026-08-06T00:00:00Z").stdout)
    assert report["status"] == "pass", report
    report = json.loads(
        _run(workspace, BASELINE, "--regenerate", "--as-of", "2030-01-01T00:00:00Z").stdout
    )
    assert report["status"] == "pass", report


@needs_nornyx
def test_review_binding_refuses_on_a_revision_mismatch(tmp_path: Path):
    """It is the document a human reads before approving, so it must not lie."""
    workspace = _repo(tmp_path)
    _write_approvals(workspace, _head(workspace), expires="2026-08-05T00:00:00Z")
    _prepare(workspace, as_of="2026-08-02T00:00:00Z")
    _run(workspace, REFRESH, "--review-binding")
    binding = workspace / CONTRACTS / "evidence" / "review_binding.json"
    before = binding.read_bytes() if binding.exists() else None

    (workspace / "NOTES.md").write_text("moved on\n", encoding="utf-8")
    _git(workspace, "add", "-A")
    _git(workspace, "commit", "-qm", "advance head")

    completed = _run(workspace, REFRESH, "--review-binding")
    assert completed.returncode != 0, "review binding was written during a mismatch"
    assert "mismatch" in (completed.stdout + completed.stderr).lower()
    if before is not None:
        assert binding.read_bytes() == before, "review binding changed on a refused run"
