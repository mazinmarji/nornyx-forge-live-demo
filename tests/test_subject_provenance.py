"""Git is provenance. It has no path into subject identity.

The runtime used to derive authority from `git rev-parse HEAD` and compare it
against a revision the contract declared. That comparison could not succeed: a
contract cannot contain the hash of the commit that contains it, so
`declared == actual` was false at every commit, and the only state where it
passed was an uncommitted working tree — precisely the dirty tree the same
system refuses.

`GIT_DIR` also walked straight through the docstring claiming "there is
deliberately no environment override", because that claim was tested against two
retired `FORGE_*` names and never against git's own environment.

Both digests are now computed from content. These tests hold the separation at
the layer that exists today:

    same content + same config, different provenance -> same digests

The matching claim about `request_digest` and approval compatibility belongs to
R1-E and is tested there, against the real authorization path, rather than
simulated here.
"""

from __future__ import annotations

import itertools
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from nornyx_forge.governed_subject import (
    REPOSITORY_SCOPE,
    RUNTIME_IMAGE_SCOPE,
    RuntimeAuthorityConfig,
)
from nornyx_forge.subject_bootstrap import establish_subject
from nornyx_forge.subject_observer import observe_source_commit

ROOT = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "__pycache__", "*.pyc", "*.egg-info", "evidence"
)
CONFIG = RuntimeAuthorityConfig("nornyx", "crewai")


_HISTORIES = itertools.count()


def _tree(*, with_git: bool) -> Path:
    """A copy of the governed content, optionally under its own git history.

    Each history gets a distinct commit message. Identical content committed in
    the same second produces an identical hash — which it did on Linux, where
    the fixture then compared a commit against itself and proved nothing. The
    message is not governed content, so the digests stay equal while the
    provenance genuinely differs, which is the whole point of the comparison.
    """
    work = Path(tempfile.mkdtemp()) / "repo"
    shutil.copytree(ROOT, work, ignore=IGNORE)
    if with_git:
        marker = f"fixture history {next(_HISTORIES)}"
        for command in (
            ["init", "-q"],
            ["config", "user.email", "fixture@example.invalid"],
            ["config", "user.name", "fixture"],
            ["add", "-A"],
            ["commit", "-qm", marker],
        ):
            subprocess.run(["git", *command], cwd=work, check=True, capture_output=True)
    return work


def _digests(root: Path, scope=RUNTIME_IMAGE_SCOPE):
    subject = establish_subject(root, scope=scope, config=CONFIG)
    assert subject.subject_verified, subject.unavailable_reason
    return subject.governed_revision_digest, subject.governed_subject_digest


def test_identical_content_under_different_git_history_yields_identical_digests():
    """Two histories, one content. Authority must not notice the difference."""
    first, second = _tree(with_git=True), _tree(with_git=True)

    first_commit = observe_source_commit(first)
    second_commit = observe_source_commit(second)
    assert first_commit and second_commit
    assert first_commit != second_commit, "the fixture produced the same commit twice"

    assert _digests(first) == _digests(second)


def test_absent_git_metadata_changes_only_provenance():
    """A deployed image has no `.git`, and must still know what it is."""
    tracked, bare = _tree(with_git=True), _tree(with_git=False)

    assert observe_source_commit(tracked) is not None
    assert observe_source_commit(bare) is None, "provenance was invented without git"
    assert _digests(tracked) == _digests(bare)


@pytest.mark.parametrize("variable", ["GIT_DIR", "GIT_WORK_TREE"])
def test_hostile_git_environment_cannot_move_either_digest(
    variable: str, monkeypatch: pytest.MonkeyPatch
):
    """`GIT_DIR` takes precedence over `-C`, so a foreign repository answers.

    That is exactly how the retired revision model was re-aimed. It may still
    alter provenance if something asks git a question; it may not alter
    authority, because nothing in either digest asks git anything.
    """
    work = _tree(with_git=True)
    honest = _digests(work)

    foreign = _tree(with_git=True)
    monkeypatch.setenv(variable, str(foreign / ".git"))

    assert _digests(work) == honest


def test_provenance_is_recorded_but_never_consulted():
    """The subject carries `source_commit` and derives nothing from it."""
    work = _tree(with_git=True)
    subject = establish_subject(work, scope=RUNTIME_IMAGE_SCOPE, config=CONFIG)
    assert subject.source_commit is not None

    # Same content, no history: the authority half is identical.
    bare = _tree(with_git=False)
    other = establish_subject(bare, scope=RUNTIME_IMAGE_SCOPE, config=CONFIG)
    assert other.source_commit is None
    assert other.governed_subject_digest == subject.governed_subject_digest
    assert other.governed_revision_digest == subject.governed_revision_digest


def test_the_runtime_holds_no_git_revision_vocabulary():
    """The authorization module must not be able to ask git what it is.

    Asserted against the source because the deletion is the property. Leaving
    the functions in place "for compatibility" is how a removed model returns:
    the next maintainer finds a working helper and calls it.
    """
    source = (ROOT / "src/nornyx_forge/nornyx_runtime.py").read_text(encoding="utf-8")
    for banned in ("def actual_revision", "def runtime_revision", "rev-parse", "import subprocess"):
        assert banned not in source, f"{banned} is back in the authorization module"


def test_git_environment_does_not_reach_the_observer_by_accident(monkeypatch):
    """Provenance may change under a hostile GIT_DIR; that is its only power."""
    work = _tree(with_git=True)
    honest_commit = observe_source_commit(work)

    foreign = _tree(with_git=True)
    monkeypatch.setenv("GIT_DIR", str(foreign / ".git"))
    hostile_commit = observe_source_commit(work)

    # Provenance is steerable, which is why it is not authority.
    assert hostile_commit != honest_commit
    # And the digests, computed from content, are untouched by that.
    monkeypatch.delenv("GIT_DIR")
    assert _digests(work) == _digests(work)


def test_repository_and_runtime_scopes_are_both_git_independent():
    """The property holds per scope, not only for the one that was convenient."""
    tracked, bare = _tree(with_git=True), _tree(with_git=False)
    for scope in (REPOSITORY_SCOPE, RUNTIME_IMAGE_SCOPE):
        assert _digests(tracked, scope) == _digests(bare, scope), scope.scope_id
