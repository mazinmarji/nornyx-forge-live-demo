"""The entry the Windows launcher runs: guard the import, then hand over.

Nothing here decides anything. Its one job is failure visibility for the
case the runtime module cannot see: a folder whose code does not import --
a partial copy without `pylib`, a missing dependency, an interpreter that is
not what the bundle needs. Under `pythonw` a traceback goes nowhere, so a
person who double-clicked Forge would see a window flash and nothing else.
This module therefore imports only the standard library; if loading the
runtime fails it says so in the one place a basic user can see, appends the
traceback to the launch-failure trail, and exits 2.

The notification rule is the runtime module's, duplicated here in eight
lines on purpose: this module must not import anything that could be the
thing that failed.
"""

from __future__ import annotations

import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

#: Where a launch that never reached the runtime leaves its trace. The same
#: operational place the runtime uses; created on demand.
FAILURE_TRAIL = Path.home() / ".nornyx" / "forge" / "runtime" / "launch-failures.log"


def notify(title: str, text: str) -> None:
    """A message box when there is no console; the console otherwise."""
    if sys.platform == "win32" and sys.__stdout__ is None:
        import ctypes  # noqa: PLC0415 - Windows-only presentation

        ctypes.windll.user32.MessageBoxW(None, text, title, 0x10 | 0x10000)
        return
    print(f"{title}: {text}", file=sys.stderr, flush=True)


def _trail(text: str) -> None:
    try:
        FAILURE_TRAIL.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        with FAILURE_TRAIL.open("a", encoding="utf-8", newline="") as trail:
            trail.write(f"{stamp} {text}\n")
    except OSError:
        pass


def main(argv: list[str] | None = None) -> None:
    try:
        from .windows_runtime import launch
    except Exception as exc:  # noqa: BLE001 - whatever failed must reach the person
        detail = "".join(traceback.format_exception(exc))
        _trail("the runtime could not be loaded:\n" + detail)
        notify(
            "Forge could not start",
            "The Forge in this folder could not be loaded, so nothing was started. "
            f"{type(exc).__name__}: {exc}\n\nThis usually means the folder is an "
            "incomplete copy (its pylib or python directory is missing) or was "
            f"started on the wrong interpreter. Details: {FAILURE_TRAIL}",
        )
        sys.exit(2)
    try:
        code = launch(sys.argv[1:] if argv is None else argv)
    except Exception as exc:  # noqa: BLE001 - a crash under pythonw is otherwise invisible
        _trail("the runtime raised before it could refuse:\n"
               + "".join(traceback.format_exception(exc)))
        notify(
            "Forge could not start",
            f"Forge stopped with an error it could not explain: {type(exc).__name__}: "
            f"{exc}\n\nDetails: {FAILURE_TRAIL}",
        )
        sys.exit(2)
    sys.exit(code)


if __name__ == "__main__":  # pragma: no cover - the process entry
    main()
