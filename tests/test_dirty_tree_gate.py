"""An approval covers content, not a commit label.

`require_approval_matches_head()` used to prove only that the approved revision
equalled `git rev-parse HEAD`. That says which commit is checked out; it says
nothing about the files on disk, and every governed operation reads the files.
So an uncommitted edit to a contract or to governed source would be inspected,
bound into evidence, and reported as approved content.

Each case installs a synthetic approval for HEAD, dirties the tree one way, then
drives every approval-bound write path and proves two things: the path refuses,
and the contracts and evidence tree are byte-identical afterwards.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = Path(".nornyx/contracts")
REFRESH = "scripts/refresh_governance_evidence.py"

# Every documented write path that may act on a human approval.
APPROVAL_BOUND_PATHS = [
    pytest.param([REFRESH, "--as-of", "2026-08-03T00:00:00Z"], id="evidence-build"),
    pytest.param([REFRESH, "--sync-contracts"], id="sync"),
    pytest.param([REFRESH, "--wire-approvals"], id="wiring"),
    pytest.param([REFRESH, "--materialize-approval-window"], id="materialization"),
    pytest.param([REFRESH, "--review-binding"], id="review-binding"),
    pytest.param(["scripts/prepare_runtime.py"], id="lock"),
]


def _git(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=work, capture_output=True, text=True, check=True)


def _workspace(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    work.mkdir()
    for item in ("scripts", "src", "tests", "docs", ".nornyx", ".github"):
        shutil.copytree(
            ROOT / item,
            work / item,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
        )
    # The repository scope declares these; a fixture missing them now gets
    # SUBJECT_SCOPE_INCOMPLETE rather than a quietly smaller subject.
    for item in ("pyproject.toml", ".gitignore", "BRD.md", "Dockerfile", "docker-compose.yml"):
        shutil.copy2(ROOT / item, work / item)
    _git(work, "init", "-q")
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "fixture")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "fixture")
    return work


def _head(work: Path) -> str:
    return "git:" + _git(work, "rev-parse", "HEAD").stdout.strip()


def _install_approval(work: Path) -> None:
    """A synthetic approval pinned to HEAD. Labelled, and never a real one."""
    payload = {
        "schema": "nornyx.forge.human_approval_record.v1",
        "approval": "granted",
        "producer": {"id": "human.test_fixture:network_governance_owner", "type": "human"},
        "status": "pass",
        "subject_revision": _head(work),
        "generated_at": "2026-08-02T00:00:00Z",
        "expires_at": "2026-08-05T00:00:00Z",
        "statement": "SYNTHETIC TEST FIXTURE - NOT A REAL APPROVAL.",
    }
    (work / CONTRACTS / "evidence" / "runtime_human_approval.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _run(work: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    return subprocess.run(
        [sys.executable, *args], cwd=work, capture_output=True, text=True, env=env
    )


def _tree_digest(work: Path) -> dict[str, str]:
    """Content of the whole contracts and evidence tree, file by file."""
    return {
        str(path.relative_to(work)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((work / CONTRACTS).rglob("*"))
        if path.is_file()
    }


def _dirty(work: Path, how: str) -> None:
    if how == "governed source":
        target = work / "src/nornyx_forge/nornyx_runtime.py"
        target.write_bytes(target.read_bytes() + b"\n# uncommitted\n")
    elif how == "contract":
        target = work / CONTRACTS / "runtime_network.nyx"
        target.write_bytes(target.read_bytes() + b"\n# uncommitted\n")
    elif how == "staged governed change":
        target = work / "scripts/check_architecture.py"
        target.write_bytes(target.read_bytes() + b"\n# staged\n")
        _git(work, "add", "scripts/check_architecture.py")
    elif how == "untracked governed input":
        (work / "src/nornyx_forge/injected_module.py").write_bytes(b"SECRET = 'not in the approved commit'\n")
    else:  # pragma: no cover - guards the parametrization
        raise AssertionError(how)


DIRT = ["governed source", "contract", "staged governed change", "untracked governed input"]


@pytest.mark.parametrize("how", DIRT)
@pytest.mark.parametrize("args", APPROVAL_BOUND_PATHS)
def test_every_approval_bound_path_refuses_a_dirty_tree(
    how: str, args: list[str], tmp_path: Path
):
    work = _workspace(tmp_path)
    _install_approval(work)
    _dirty(work, how)
    # Snapshot after dirtying: the claim under test is that the refused run
    # changes nothing further, not that the dirt itself is invisible.
    before = _tree_digest(work)

    completed = _run(work, args)
    output = completed.stdout + completed.stderr

    assert completed.returncode != 0, f"{args} accepted a tree dirtied by {how}:\n{output}"
    assert "governed tree is dirty" in output, output
    assert _tree_digest(work) == before, (
        f"{args} modified the contracts/evidence tree after refusing ({how})"
    )


@pytest.mark.parametrize("args", APPROVAL_BOUND_PATHS)
def test_a_clean_tree_is_not_blocked(args: list[str], tmp_path: Path):
    """The gate must not break the flow it guards.

    Only the tool's own regenerated outputs differ between these steps, and
    those are the documented exceptions, so a legitimate sequence runs through.
    """
    work = _workspace(tmp_path)
    _install_approval(work)

    completed = _run(work, args)
    output = completed.stdout + completed.stderr
    assert "governed tree is dirty" not in output, output


def test_the_untracked_check_ignores_gitignored_files(tmp_path: Path):
    """A gitignored build artifact is not evidence of a drifted subject.

    The human approval artifacts themselves are gitignored, so treating every
    unknown file as drift would make the gate refuse its own legitimate input.
    """
    work = _workspace(tmp_path)
    _install_approval(work)
    (work / ".pytest_cache").mkdir(exist_ok=True)
    (work / ".pytest_cache/CACHEDIR.TAG").write_bytes(b"ignored\n")

    completed = _run(work, [REFRESH, "--materialize-approval-window"])
    assert "governed tree is dirty" not in (completed.stdout + completed.stderr)


def test_the_gate_is_inert_without_an_approval(tmp_path: Path):
    """No approval, nothing to protect: the ordinary pipeline still runs.

    The gate exists to stop an approval being honored against content it does
    not cover. With no approval there is no such claim to protect, and blocking
    here would only break the pre-approval baseline everything else rests on.
    """
    work = _workspace(tmp_path)
    _dirty(work, "governed source")

    completed = _run(work, [REFRESH, "--as-of", "2026-08-03T00:00:00Z"])
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_the_refusal_names_what_drifted(tmp_path: Path):
    """A refusal a human cannot act on is only half a control."""
    work = _workspace(tmp_path)
    _install_approval(work)
    _dirty(work, "contract")
    _dirty(work, "untracked governed input")

    output = _run(work, [REFRESH, "--wire-approvals"]).stdout + ""
    combined = output + _run(work, [REFRESH, "--wire-approvals"]).stderr
    assert "runtime_network.nyx" in combined, combined
    assert "injected_module.py" in combined, combined
