"""Session-wide containment for scratch directories.

WHY THIS EXISTS. Nineteen call sites across this suite build their workspaces
with `tempfile.mkdtemp()`, and `mkdtemp` never cleans up -- that is its
contract. Many of those workspaces are whole repository copies: `faithful_copy`
alone writes every tracked file plus a real `.git`.

Nothing removed them. A single full run left thousands of directories behind,
they accumulated across runs, and the disk reached zero bytes mid-suite. Three
consecutive full-suite runs died that way, each reporting a success exit code
because the failure was in `tail` and `git`, not in pytest. 8,379 abandoned
workspaces were removed by hand afterwards, holding 7.5 GB.

The fix is one place rather than nineteen: `tempfile.tempdir` is repointed at a
per-session directory, so every `mkdtemp` in the suite -- including call sites
nobody has written yet -- lands inside it, and the whole thing is removed when
the session ends.

Not left to pytest's own retention. `tmp_path_factory` keeps the last three
runs, which for a suite that copies the repository thousands of times is still
tens of gigabytes. It is deleted outright.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def _contained_scratch(tmp_path_factory: pytest.TempPathFactory):
    """Point `tempfile` at a directory this session owns, and remove it after.

    `autouse` and session-scoped because the leak is a property of the suite,
    not of any test that has to remember to opt in. A test that must keep a
    workspace beyond the session should say so explicitly rather than rely on
    the absence of cleanup.
    """
    original = tempfile.tempdir
    scratch = Path(tmp_path_factory.mktemp("scratch"))
    tempfile.tempdir = str(scratch)
    try:
        yield scratch
    finally:
        tempfile.tempdir = original
        # `ignore_errors` because a workspace holding a still-open handle must
        # not fail the run: the point is to reclaim space, and a directory that
        # survives one session is a leak, not a broken test.
        shutil.rmtree(scratch, ignore_errors=True)
