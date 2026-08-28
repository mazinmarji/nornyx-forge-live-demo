"""The suite must not leak scratch directories into the system temp root.

This is a resource control, not a style rule. Nineteen call sites build
workspaces with `tempfile.mkdtemp()`, which by contract never cleans up, and
many of them copy the whole repository. Nothing removed them, they accumulated
across runs, and the disk reached zero bytes mid-suite -- three consecutive
full-suite runs died that way, each reporting a success exit code because what
failed was `tail` and `git` rather than pytest.

A green suite that cannot be run twice is not a green suite.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_mkdtemp_is_contained_within_the_session_scratch():
    """`tempfile.tempdir` must point inside pytest's managed area.

    Asked of the module the suite actually calls, not of the conftest source:
    the defect was that nothing redirected it, and only the live value shows
    whether anything does now.
    """
    contained = tempfile.gettempdir()
    assert "scratch" in Path(contained).name or "pytest-of" in contained, (
        f"tempfile.gettempdir() is {contained!r}, which is the system temp root. "
        "Every mkdtemp in this suite will leak there permanently."
    )


def test_a_workspace_created_now_lands_in_the_session_scratch():
    """The behaviour, measured, rather than the setting inspected."""
    made = Path(tempfile.mkdtemp())
    try:
        assert "pytest-of" in str(made), (
            f"a workspace was created at {made}, outside pytest's managed area"
        )
    finally:
        made.rmdir()


def test_the_containment_fixture_is_autouse_and_session_scoped():
    """Opt-in containment is containment nobody remembers to use.

    The leak is a property of the suite, so the fixture must apply without any
    test asking for it. Read from the conftest source because scope and autouse
    are declarations, not observable values.
    """
    source = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert 'scope="session"' in source, "the containment fixture is not session-scoped"
    assert "autouse=True" in source, (
        "the containment fixture is opt-in, so a new module that forgets it "
        "leaks exactly as before"
    )
    assert "shutil.rmtree" in source, (
        "the scratch directory is never removed, so the space is reclaimed only "
        "when pytest happens to prune, which for this suite is far too late"
    )
