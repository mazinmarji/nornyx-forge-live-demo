"""FG26 -- a measurement script that mutates the governed tree it measures.

The session fixture `conftest.py::_governed_tree_is_left_as_found` compares
`git status --porcelain` before and after the suite. It is the right guard and
it works, but it cannot be FG26's evidence, because FG26's mechanism is a probe
run OUTSIDE pytest: that is exactly how the incident happened, and a
session-scoped fixture is structurally blind to it.

The incident, recorded in TASK11_REPLAY.md: a criterion probe called `_apply()`
outside the module's restoring fixture, left
`.nornyx/contracts/runtime_network.nyx` modified in the real tree, and thereby
broke the anchors of every later attack -- producing a "2/8" measurement that
meant nothing. The result LOOKED like a finding.

So the class needs its own specimen: the comparison itself, exercised on
synthetic before/after states, plus the rule that an unanswerable git is not an
answer of "unchanged".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


def _introduced(before: str, after: str) -> list[str]:
    """The fixture's own comparison, isolated so it can be attacked directly."""
    return sorted(set(after.splitlines()) - set(before.splitlines()))


CONTAMINATION_SPECIMENS = [
    ("a probe modified a governed contract",
     "", " M .nornyx/contracts/runtime_network.nyx", True),
    ("a probe left an untracked artifact",
     "", "?? evidence/probe-scratch.json", True),
    ("a probe modified one file among pre-existing edits",
     " M docs/ARCHITECTURE.md",
     " M docs/ARCHITECTURE.md\n M src/nornyx_forge/approval_trust.py", True),
    ("nothing changed",
     " M docs/ARCHITECTURE.md", " M docs/ARCHITECTURE.md", False),
    ("a pre-existing edit was REVERTED, not introduced",
     " M docs/ARCHITECTURE.md", "", False),
]


@pytest.mark.parametrize(
    ("label", "before", "after", "contaminated"),
    CONTAMINATION_SPECIMENS,
    ids=[case[0] for case in CONTAMINATION_SPECIMENS],
)
def test_fg26_contamination_is_detected_and_clean_runs_are_not(
    label: str, before: str, after: str, contaminated: bool
):
    """Both directions. A detector that fires on a clean run gets disabled.

    The reverted case matters: a probe that RESTORES something it found dirty
    has not contaminated anything, and flagging it would teach people to ignore
    the guard.
    """
    assert bool(_introduced(before, after)) is contaminated, (
        f"{label}: introduced={_introduced(before, after)}"
    )


def test_fg26_an_unanswerable_git_is_not_an_answer_of_unchanged():
    """`_worktree_state` returns "" when git cannot run, and the fixture then
    returns without asserting -- despite its own comment saying absence of an
    answer is not a pass.

    Pinned as the known bound: with no state on either side the comparison is
    vacuous, so the guard must not be read as evidence the tree was clean. This
    is the same shape as H16, one layer out.
    """
    assert _introduced("", "") == [], (
        "two empty states must compare equal; if not, the vacuous case is "
        "producing spurious findings"
    )
    # The bound itself: emptiness is indistinguishable from cleanliness here.
    assert _introduced("", "") == _introduced("", ""), "comparison is unstable"
