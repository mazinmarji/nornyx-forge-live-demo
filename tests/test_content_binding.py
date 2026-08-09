"""Evidence must describe the content that exists, not a commit related to it.

Freshness used to be checked by asking whether the bound revision was an
*ancestor* of HEAD. Ancestry is a fact about history: every commit is an
ancestor of infinitely many futures, so the check passed identically for a
binding one commit stale and one twenty commits stale. Evidence at HEAD claimed
to describe `git:75c32e33` while `src/`, `tests/` and `.github/` had all changed
since, and no gate could see it.

The seventh case below is the direct killer for that logic:

    reviewed commit A
    commit B is a descendant of A
    git ancestry says:  related
    content digest says: different
    expected:            FAIL

No `is-ancestor` result should ever be sufficient to claim evidence is current.
"""

from __future__ import annotations

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

sys.path.insert(0, str(ROOT / "scripts"))

from governed_content import (  # noqa: E402
    GOVERNED_CONTENT_PATHS,
    GovernedContentError,
    control_pack_digest,
    digest_of,
    governed_content_manifest,
)


def _git(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(work), *args], capture_output=True, text=True, check=True
    )


def _workspace(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    work.mkdir()
    for item in ("scripts", "src", "docs", ".nornyx", "tests"):
        shutil.copytree(ROOT / item, work / item)
    for item in ("pyproject.toml", ".gitignore", "Dockerfile", "docker-compose.yml", "BRD.md"):
        shutil.copy2(ROOT / item, work / item)
    shutil.copytree(ROOT / ".github", work / ".github")
    _git(work, "init", "-q")
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "fixture")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "fixture")
    return work


def _run(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    return subprocess.run(
        [sys.executable, *args], cwd=work, capture_output=True, text=True, env=env
    )


def _generate(work: Path) -> None:
    assert _run(work, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    assert _run(work, REFRESH, "--sync-contracts").returncode == 0


def _verify(work: Path) -> subprocess.CompletedProcess[str]:
    return _run(work, REFRESH, "--verify")


# --------------------------------------------------------------------------
# The mutation table
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        (
            "edit governed python source",
            lambda w: (w / "src/nornyx_forge/util.py").write_text(
                (w / "src/nornyx_forge/util.py").read_text(encoding="utf-8") + "\n# edit\n",
                encoding="utf-8",
            ),
        ),
        (
            "edit a .nyx contract",
            lambda w: (w / CONTRACTS / "forge_control.nyx").write_text(
                (w / CONTRACTS / "forge_control.nyx").read_text(encoding="utf-8") + "\n# edit\n",
                encoding="utf-8",
            ),
        ),
        (
            "edit governed configuration",
            lambda w: (w / "pyproject.toml").write_text(
                (w / "pyproject.toml").read_text(encoding="utf-8") + "\n# edit\n",
                encoding="utf-8",
            ),
        ),
        (
            "add a governed source file",
            lambda w: (w / "src/nornyx_forge/added.py").write_text("X = 1\n", encoding="utf-8"),
        ),
        (
            "remove a governed file",
            lambda w: (w / "src/nornyx_forge/util.py").unlink(),
        ),
    ],
)
def test_mutating_governed_content_invalidates_the_evidence(
    label: str, mutate, tmp_path: Path
):
    """Any change to what the evidence describes must invalidate it."""
    work = _workspace(tmp_path)
    _generate(work)
    assert _verify(work).returncode == 0, f"{label}: baseline was not clean"

    mutate(work)
    if label == "add a governed source file":
        # Untracked until added; the digest describes tracked governed content,
        # and the dirty-tree gate is what refuses untracked files by name.
        _git(work, "add", "src/nornyx_forge/added.py")

    completed = _verify(work)
    assert completed.returncode != 0, f"{label} did not invalidate the evidence"
    assert "governed content" in completed.stdout, completed.stdout


def test_a_staged_but_uncommitted_change_invalidates_the_binding(tmp_path: Path):
    """The digest is over content on disk, not over what has been committed."""
    work = _workspace(tmp_path)
    _generate(work)

    target = work / "src/nornyx_forge/util.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# staged\n", encoding="utf-8")
    _git(work, "add", "src/nornyx_forge/util.py")

    completed = _verify(work)
    assert completed.returncode != 0
    assert "governed content" in completed.stdout


def test_a_committed_descendant_does_not_make_stale_evidence_current(tmp_path: Path):
    """The ancestry killer.

    Git says the reviewed commit is an ancestor of HEAD, which the old check
    accepted as sufficient. The content says otherwise, and the content is what
    the evidence claimed to describe.
    """
    work = _workspace(tmp_path)
    _generate(work)
    reviewed = _git(work, "rev-parse", "HEAD").stdout.strip()

    target = work / "src/nornyx_forge/util.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# descendant\n", encoding="utf-8")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "descendant commit")

    # Git ancestry is satisfied — precisely the condition the old check trusted.
    ancestry = subprocess.run(
        ["git", "-C", str(work), "merge-base", "--is-ancestor", reviewed, "HEAD"],
        capture_output=True,
    )
    assert ancestry.returncode == 0, "the fixture must exercise the ancestor case"

    completed = _verify(work)
    assert completed.returncode != 0, "ancestry alone was accepted as freshness"
    assert "governed content" in completed.stdout


def test_identical_content_at_a_different_commit_still_verifies(tmp_path: Path):
    """Content is the integrity primitive; the commit id is provenance.

    An empty commit changes the SHA and nothing else. Evidence about the content
    is still true, and must not be invalidated by a fact about history.
    """
    work = _workspace(tmp_path)
    _generate(work)
    before = _git(work, "rev-parse", "HEAD").stdout.strip()

    _git(work, "commit", "-q", "--allow-empty", "-m", "provenance only")
    assert _git(work, "rev-parse", "HEAD").stdout.strip() != before

    completed = _verify(work)
    assert completed.returncode == 0, completed.stdout


def test_generated_evidence_is_not_part_of_the_content_digest(tmp_path: Path):
    """Otherwise the digest would depend on artifacts derived from itself."""
    work = _workspace(tmp_path)
    _generate(work)
    index = json.loads(
        (work / CONTRACTS / "evidence/INDEX.json").read_text(encoding="utf-8")
    )
    recorded = index["governed_content_digest"]

    assert not any(
        entry["path"].startswith(".nornyx/contracts/evidence/")
        for entry in governed_content_manifest()["entries"]
    )
    assert recorded.startswith("sha256:")


def test_changing_an_evidence_file_does_not_move_the_content_digest(tmp_path: Path):
    """The two layers are separate, and must move independently."""
    work = _workspace(tmp_path)
    _generate(work)
    index_path = work / CONTRACTS / "evidence/INDEX.json"
    recorded = json.loads(index_path.read_text(encoding="utf-8"))["governed_content_digest"]

    manifest = work / CONTRACTS / "evidence/architecture_evidence_manifest.json"
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    completed = _verify(work)
    # Content is unchanged, so the content assertion holds...
    assert "governed content" not in completed.stdout
    # ...but the artifact's own hash binding does not.
    assert completed.returncode != 0
    assert json.loads(index_path.read_text(encoding="utf-8"))[
        "governed_content_digest"
    ] == recorded


# --------------------------------------------------------------------------
# Manifest rules
# --------------------------------------------------------------------------


def test_the_manifest_is_canonical_and_deterministic():
    first = governed_content_manifest()
    second = governed_content_manifest()
    assert first == second
    assert digest_of(first) == digest_of(second)

    paths = [entry["path"] for entry in first["entries"]]
    assert paths == sorted(paths), "entries must be deterministically ordered"
    assert len(paths) == len(set(paths)), "a path must appear once"


def test_manifest_entries_use_normalised_relative_paths():
    for entry in governed_content_manifest()["entries"]:
        path = entry["path"]
        assert not path.startswith("/"), path
        assert ".." not in path.split("/"), path
        assert "\\" not in path, path
        assert set(entry) == {"path", "sha256", "size"}


@pytest.mark.parametrize(
    "bad", ["/etc/passwd", "C:/Windows/system32", "../outside.py", "src/../../escape.py", ""]
)
def test_unsafe_paths_are_refused(bad: str):
    from governed_content import _normalise  # noqa: PLC0415

    with pytest.raises(GovernedContentError):
        _normalise(bad)


def test_a_manifest_digest_is_not_a_naive_concatenation():
    """`A`+`BC` and `AB`+`C` must not digest identically.

    A concatenation-based digest cannot see content moving across a file
    boundary. A structure with explicit paths and sizes cannot collapse that way.
    """
    left = {
        "schema": "x",
        "entries": [
            {"path": "a", "sha256": "aa", "size": 1},
            {"path": "b", "sha256": "bc", "size": 2},
        ],
    }
    right = {
        "schema": "x",
        "entries": [
            {"path": "a", "sha256": "ab", "size": 2},
            {"path": "b", "sha256": "c", "size": 1},
        ],
    }
    assert digest_of(left) != digest_of(right)


def test_the_control_pack_digest_is_not_self_referential():
    """A binding that named its own containing commit was always wrong.

    Writing the file produced a new commit, so the recorded value was stale the
    instant it was recorded. A digest over inputs can be committed afterwards
    without invalidating what it says it reviewed.
    """
    binding = json.loads(
        (ROOT / CONTRACTS / "evidence/review_binding.json").read_text(encoding="utf-8")
    )
    assert "control_pack_commit" not in binding
    assert binding["control_pack_digest"].startswith("sha256:")
    assert binding["governed_content_digest"].startswith("sha256:")
    assert binding["evidence_manifest_digest"].startswith("sha256:")
    assert binding["source_commit"].startswith("git:")

    # Recomputable from its stated inputs, by anyone holding them.
    assert control_pack_digest(
        content_digest=binding["governed_content_digest"],
        evidence_digest=binding["evidence_manifest_digest"],
        contract_digests={
            path.name: "sha256:" + __import__("hashlib").sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT / CONTRACTS).glob("*.nyx"))
        },
    ) == binding["control_pack_digest"]


def test_the_review_binding_does_not_digest_itself():
    """A document cannot honestly digest itself: writing the digest changes it."""
    source = (ROOT / "scripts/refresh_governance_evidence.py").read_text(encoding="utf-8")
    assert 'exclude=("review_binding.json",)' in source


def test_governed_content_covers_source_contracts_and_configuration():
    """The declared set, asserted rather than assumed."""
    for expected in ("src", "scripts", ".nornyx/contracts", "pyproject.toml"):
        assert expected in GOVERNED_CONTENT_PATHS

    paths = [entry["path"] for entry in governed_content_manifest()["entries"]]
    assert any(p.startswith("src/") for p in paths)
    assert any(p.endswith(".nyx") for p in paths)
    assert any(p == "pyproject.toml" for p in paths)
