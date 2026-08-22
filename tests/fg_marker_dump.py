"""A pytest plugin that reports which COLLECTED node declares which FG class.

Used by `tests/test_false_green_audit.py` to establish the class-to-guard link
by collection rather than by reading source. The distinction is the whole point:
a marker is metadata on a node pytest actually collected, so it cannot be
satisfied by a comment and cannot be carried by a function pytest never sees.

Writes `ident<TAB>nodeid` lines to the path in `FG_MARKER_DUMP`.
"""

from __future__ import annotations

import os
from pathlib import Path


def pytest_collection_modifyitems(items) -> None:
    destination = os.environ.get("FG_MARKER_DUMP")
    if not destination:
        return
    rows = []
    for item in items:
        for marker in item.iter_markers(name="false_green"):
            if marker.args:
                rows.append(f"{marker.args[0]}\t{item.nodeid}")
    Path(destination).write_text("\n".join(sorted(set(rows))), encoding="utf-8")
