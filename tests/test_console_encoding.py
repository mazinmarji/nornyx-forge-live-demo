"""A terminal's encoding must not be able to abort a governed run.

Reproduced on a Windows workstation: `sys.stdout.encoding` is `cp1252`, and
writing `✓` raises `UnicodeEncodeError: 'charmap' codec can't encode
character '✓'`. CrewAI's event bus prints progress marks like that one, so
selecting the CrewAI backend on a legacy console could abort partway through —
after side effects, with a traceback naming a checkmark rather than anything
that actually went wrong.

The characters here are built from code points rather than written literally,
because a source file full of the exact bytes under test is one careless
re-encoding away from testing nothing.
"""

from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Characters CrewAI and rich actually emit, and cp1252 cannot encode.
UNENCODABLE = "".join(chr(point) for point in (0x2713, 0x2500, 0x256D, 0x1F680))


def test_the_failure_is_real_on_a_legacy_console():
    """Anchor the defect, so the fix below is not solving an imagined problem."""
    legacy = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    try:
        legacy.write(UNENCODABLE)
        legacy.flush()
    except UnicodeEncodeError:
        return
    raise AssertionError("cp1252 encoded these characters, so the premise is wrong")


def test_importing_the_cli_makes_output_survivable():
    """Process-wide and at import, because the writer is a third-party library.

    Run in a subprocess with a legacy console encoding forced, so this asserts
    what happens on the affected machine rather than on whatever encoding the
    test runner happens to have.
    """
    program = (
        "import sys;"
        "import nornyx_forge.cli;"
        "sys.stdout.write(''.join(chr(p) for p in (0x2713, 0x2500, 0x1F680)));"
        'sys.stdout.write(chr(10) + chr(69) + chr(78) + chr(67) + str(sys.stdout.encoding))'
    )
    completed = subprocess.run(
        [sys.executable, "-c", program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_legacy_console_env(),
    )
    assert completed.returncode == 0, completed.stderr
    assert "UnicodeEncodeError" not in completed.stderr
    assert "ENCutf-8" in completed.stdout


def test_a_stream_that_cannot_be_retuned_does_not_raise():
    """Redirected and wrapped streams exist; refusing to start over one is worse."""
    from nornyx_forge.cli import _make_output_encoding_safe

    original_out, original_err = sys.stdout, sys.stderr
    try:
        sys.stdout = io.StringIO()  # no reconfigure attribute
        sys.stderr = io.StringIO()
        _make_output_encoding_safe()
    finally:
        sys.stdout, sys.stderr = original_out, original_err


def _legacy_console_env() -> dict:
    """The real environment, with only the console encoding forced.

    A hand-picked subset looked tidier and broke the subprocess on a missing
    HOME — a test failing for a reason unrelated to what it asserts is worse
    than one that inherits more than it strictly needs.
    """
    import os

    return {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "PYTHONIOENCODING": "cp1252",
    }
