"""Symlinks and special files under a governed root fail closed.

A symlink could point outside the tree entirely, so a digest that quietly
followed one would describe content the repository does not contain. A FIFO or
device is worse: reading it is not reproducible and may not terminate, so the
subject cannot be described at all.

These are mandatory on Linux. A Windows workstation cannot create the fixtures
without elevation, and the honest response to that is to skip *there* while
still requiring the proof somewhere — never to weaken the property because one
host cannot construct the adversarial case. CI runs Linux, so CI runs these.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from nornyx_forge.governed_subject import RUNTIME_IMAGE_SCOPE, RuntimeAuthorityConfig
from nornyx_forge.subject_bootstrap import establish_subject

ROOT = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "__pycache__", "*.pyc", "*.egg-info", "evidence"
)
CONFIG = RuntimeAuthorityConfig("nornyx", "crewai")

#: `os.mkfifo` does not exist on Windows, and symlink creation needs elevation
#: there. The property is proved on the platform that can express it.
posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="requires POSIX symlink and FIFO creation; proved on Linux in CI",
)


def _tree() -> Path:
    work = Path(tempfile.mkdtemp()) / "repo"
    shutil.copytree(ROOT, work, ignore=IGNORE)
    return work


def _subject(root: Path):
    return establish_subject(root, scope=RUNTIME_IMAGE_SCOPE, config=CONFIG)


@posix_only
def test_a_symlink_under_a_governed_root_is_refused():
    """Never silently followed: the target may not even be inside the tree."""
    work = _tree()
    (work / "src/nornyx_forge/linked.py").symlink_to(work / "BRD.md")

    subject = _subject(work)
    assert subject.subject_verified is False
    reason = subject.unavailable_reason or ""
    assert "symlink" in reason
    assert "src/nornyx_forge/linked.py" in reason
    assert subject.governed_subject_digest == ""


@posix_only
def test_a_symlink_pointing_outside_the_tree_is_refused():
    """The case the refusal exists for: a digest describing somewhere else."""
    work = _tree()
    outside = Path(tempfile.mkdtemp()) / "elsewhere.py"
    outside.write_bytes(b"SECRET = 'not in this repository'\n")
    (work / "src/nornyx_forge/escape.py").symlink_to(outside)

    subject = _subject(work)
    assert subject.subject_verified is False
    assert "symlink" in (subject.unavailable_reason or "")


@posix_only
def test_a_fifo_under_a_governed_root_is_refused():
    """Reading one is not reproducible and may block forever."""
    work = _tree()
    os.mkfifo(work / "src/nornyx_forge/pipe.py")

    subject = _subject(work)
    assert subject.subject_verified is False
    reason = subject.unavailable_reason or ""
    assert "not a regular file" in reason
    assert "src/nornyx_forge/pipe.py" in reason


@posix_only
def test_a_device_node_is_refused_if_one_can_be_referenced():
    """A character device under a governed root is not describable content."""
    work = _tree()
    link = work / "src/nornyx_forge/null_device.py"
    try:
        link.symlink_to("/dev/null")
    except OSError:  # pragma: no cover - unusual sandbox
        pytest.skip("cannot reference a device node here")

    subject = _subject(work)
    assert subject.subject_verified is False
    # A symlink is caught as a symlink before its target is ever read, which is
    # the stricter of the two refusals and the one that must fire first.
    assert "symlink" in (subject.unavailable_reason or "")


def test_the_refusals_are_reachable_on_every_platform():
    """Guards the skip: the code path must exist even where the fixture cannot.

    A file of skipped tests proves nothing, so this asserts on every platform
    that the observer still contains both refusals — a deletion would otherwise
    go unnoticed on the host that cannot run the cases.
    """
    source = (ROOT / "src/nornyx_forge/subject_observer.py").read_text(encoding="utf-8")
    assert "is_symlink()" in source
    assert "is not a regular file" in source
