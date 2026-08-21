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
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def introduced_paths(before: str, after: str) -> list:
    """Paths present in `after` and not in `before`.

    Module-level and public so `tests/test_probe_containment.py` can drive THIS
    function rather than a copy of it. See the note at the call site.
    """
    return sorted(set(after.splitlines()) - set(before.splitlines()))


#: Returned when git could not answer at all. NOT the same value as a clean
#: tree, which is `""`. A review measured the two being indistinguishable while
#: the call site's comment said "absence of an answer is not a pass here" -- and
#: the line it annotated returned without asserting anything, which is a pass.
UNANSWERED = None


def _worktree_state() -> "str | None":
    """What git says about the working tree, or `UNANSWERED` when it cannot say.

    A clean tree is `""`. git being unavailable is `None`. Collapsing them made
    a suite that dirties the tree pass silently whenever git could not run,
    which is precisely the environment where nobody would notice.
    """
    try:
        completed = subprocess.run(  # noqa: S603
            ["git", "status", "--porcelain"],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120, check=False,
        )
    except OSError:
        return UNANSWERED
    return completed.stdout if completed.returncode == 0 else UNANSWERED


@pytest.fixture(scope="session", autouse=True)
def _contained_scratch(tmp_path_factory: pytest.TempPathFactory):
    """Point `tempfile` at a directory this session owns, and remove it after.

    `autouse` and session-scoped because the leak is a property of the suite,
    not of any test that has to remember to opt in. A test that must keep a
    workspace beyond the session should say so explicitly rather than rely on
    the absence of cleanup.

    NOT inside `tmp_path_factory`'s numbered basetemp -- see the comment at the
    creation site. Putting it there meant a concurrently starting pytest
    session deleted this session's scratch mid-run, and 557 tests errored with
    a path that no longer existed.
    """
    # OUTSIDE THE NUMBERED BASETEMP, which is the repair.
    #
    # This was `tmp_path_factory.mktemp("scratch")`, putting the session
    # scratch inside `pytest-of-<user>/pytest-<n>/` -- the directory pytest's
    # own retention deletes when a LATER session starts. `tmp_path_retention_count`
    # is unset, so the default keep-3 applies.
    #
    # A review measured the consequence: a census run reported `GATE: FAIL`
    # with 557 errored setups, every one a FileNotFoundError on this scratch,
    # because other pytest sessions started while it was running and collected
    # the basetemp out from under it. The verdict was a property of the
    # machine, not of the tree.
    #
    # `tmp_path_factory.getbasetemp().parent` is the `pytest-of-<user>` root,
    # which retention walks but never deletes; a unique name under it belongs
    # to this session alone and is removed below.
    original = tempfile.tempdir
    scratch = Path(tempfile.mkdtemp(
        prefix="forge-session-",
        dir=str(tmp_path_factory.getbasetemp().parent),
    ))
    tempfile.tempdir = str(scratch)
    try:
        yield scratch
    finally:
        tempfile.tempdir = original
        # `ignore_errors` because a workspace holding a still-open handle must
        # not fail the run: the point is to reclaim space, and a directory that
        # survives one session is a leak, not a broken test.
        shutil.rmtree(scratch, ignore_errors=True)


@pytest.fixture(scope="module", autouse=True)
def _reclaim_scratch_between_modules(_contained_scratch: Path):
    """Delete each module's workspaces as it finishes, not at session end.

    SESSION-END CLEANUP BOUNDS THE LEAK BUT NOT THE PEAK, and the peak is what
    exhausts a disk. Measured: a full run on this machine consumed more than
    26 GB of workspaces before the session ended, hit `No space left on device`,
    and took the suite down with `database or disk is full` and a git
    `index.lock` write error. The session scratch was then removed correctly on
    teardown -- leaving 471 MB behind and no evidence of what had happened.

    Every workspace here is a whole repository copy. Holding one module's worth
    is cheap; holding the entire suite's is not, and nothing needs them to
    outlive the module that created them.

    MODULE scope, deliberately, not function scope: several suites build a
    workspace in a module- or class-scoped fixture and share it across tests.
    Reclaiming between tests would delete a tree still in use, so this runs
    after the module's own fixtures have torn down.
    """
    before = {entry.name for entry in _contained_scratch.iterdir()}
    yield
    for entry in _contained_scratch.iterdir():
        if entry.name in before:
            continue
        # `ignore_errors`: a workspace holding an open handle must not fail the
        # run. Space is the goal; a survivor is retried at session end.
        shutil.rmtree(entry, ignore_errors=True) if entry.is_dir() else entry.unlink(
            missing_ok=True
        )


@pytest.fixture(scope="session", autouse=True)
def _governed_tree_is_left_as_found():
    """The suite must not leave the governed tree modified.

    Several tests mutate real tracked files and restore them in `finally` --
    which holds right up until a run does not reach the restore. One did not:
    forged `authenticated_inspections` records survived an interrupted run in
    `test_artifact_authority.py` and were committed, so a governed artifact in
    this repository asserted three authenticated inspections that never
    happened, and `observe_governance_integrity` reported COMPROMISED because
    of it. Nobody noticed until the file was regenerated by accident.

    Those particular tests now work in copies. This catches the next one --
    including modules not yet written, and including the semantic-binding suite,
    which still mutates the contracts in place under a restoring fixture.

    A loud failure at session end is the point. Silent corruption of a governed
    artifact is the failure mode that actually happened, and it is the one a
    `finally` cannot prevent.
    """
    before = _worktree_state()
    yield
    after = _worktree_state()
    if before is UNANSWERED or after is UNANSWERED:
        # ABSENCE OF AN ANSWER IS NOT A PASS -- which is what the comment here
        # always said, above a line that returned without asserting anything.
        # Both states were `""`, so a clean tree and an unusable git were the
        # same value and the guard was silent in exactly the environment where
        # a dirtied tree would go unnoticed.
        raise AssertionError(
            "git could not report the working tree, so this run cannot show "
            "that the suite left the governed tree as it found it. That is an "
            "unanswered question, not a clean result."
        )

    # ONE implementation, shared with the owner. The comparison used to live
    # here and be RE-IMPLEMENTED in `test_probe_containment._introduced`, so a
    # review replaced this line with `introduced = []` and FG26's named owner
    # stayed green at 14 passed. A guard whose owner tests a copy of it is a
    # guard nobody has fired -- the defect this file already repaired for FG29.
    introduced = introduced_paths(before, after)
    assert introduced == [], (
        "the test suite left the governed tree modified:\n  "
        + "\n  ".join(introduced)
        + "\n\nA test mutated a tracked file and did not restore it. Restore it "
        "with `git checkout --` after checking the diff, and move that test's "
        "workspace into a copy: a `finally` does not run when a process dies, "
        "and this exact failure has already put forged attestation records into "
        "a commit."
    )
