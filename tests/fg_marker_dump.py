"""A pytest plugin that reports which COLLECTED node declares which FG class.

Used by `tests/test_false_green_audit.py` to establish the class-to-guard link
by collection rather than by reading source. The distinction is the whole point:
a marker is metadata on a node pytest actually collected, so it cannot be
satisfied by a comment and cannot be carried by a function pytest never sees.

Writes `ident<TAB>nodeid<TAB>blocking` lines to the path in
`FG_MARKER_DUMP`, where `blocking` names any `skip`, `skipif` or `xfail`
marker on the node -- a node can be collected and still never run.
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
        # COLLECTED IS NOT RUN. `skip`, `skipif` and `xfail` are evaluated at
        # SETUP, not at collection, so `iter_markers` sees the node either way
        # and a collection census cannot tell the difference. A review added
        # `@pytest.mark.skip` to a declared guard and the audit reported 5
        # passed, exit 0, with the collection count identical.
        #
        # Recorded here rather than inferred later, because this is the only
        # place that sees the real marker set of the real collected item.
        blocking = sorted(
            marker.name for marker in item.iter_markers()
            if marker.name in {"skip", "skipif", "xfail"}
        )
        for marker in item.iter_markers(name="false_green"):
            if marker.args:
                rows.append(
                    f"{marker.args[0]}\t{item.nodeid}\t{','.join(blocking)}"
                )
    Path(destination).write_text("\n".join(sorted(set(rows))), encoding="utf-8")
