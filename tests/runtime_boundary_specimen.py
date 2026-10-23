"""Forge's own reference specimen for the runtime operation contract (A-053).

A small application that Forge's tests write into a temporary project and hand
to the real trusted greenfield verifier, whose existing test executor runs the
specimen's own tests. It is Forge-authored, test-only and never shipped: no
module here is collected (the name does not start with `test_`), and nothing
under `src/` imports it. It is not a provider build and not a runnable
Forge-generated application; it is the mechanism's specimen.

THE APPLICATION. A notebook of short team notes. Every state-changing request
goes through `app/boundary.py`, its embedded boundary, which decides it
against the closed operation table in `app/runtime_contract.json` -- the bytes
Forge's `render_runtime_contract` produced for this BRD and these declarations.
The boundary refuses an operation the table does not list, refuses every
operation the table does not permit, and refuses the two consequences no
approval mechanism can release whatever the table says. Its one outbound
adapter, `app/adapters/outbound.py`, opens a socket; it lives under
`adapters/`, the only place the verifier lets network capability live.

THE REFUSAL ROWS are Forge's own words: BRD-F-002 asks to remove every note at
once and BRD-F-003 asks to forward a note to an outside address. Each declares
its operation by the registry's exact spelling (`OPERATION_REGISTRY` is the
demonstration's, so its spellings are what a declaration can name); nothing
classifies a row from its words.
"""

from __future__ import annotations

from pathlib import Path

BRD = """# BRD - Runtime boundary reference

## BRD-001 Purpose

A small local notebook keeps short team notes and refuses every act that no approval can release.

## BRD-002 Functional requirements

### BRD-F-001 Record a note

A team member records a short note in the notebook.

### BRD-F-002 Remove every note at once

A team member asks to remove every note in one step, and the notebook refuses and keeps every note.

### BRD-F-003 Forward a note outside

A team member asks to forward a note to an outside address, and the notebook refuses before anything is sent.
"""

#: Each declared operation, by its exact registered spelling, and the
#: requirement it serves. The registry decides everything else about it.
DECLARATIONS = {
    "send guidance": "BRD-F-001",
    "delete all service requests": "BRD-F-002",
    "send external email": "BRD-F-003",
}

#: A documentation address (RFC 5737): never routed, so even an unguarded
#: attempt reaches no one.
UNROUTED = "192.0.2.1"

APP_INIT = '''"""A notebook of short team notes: Forge's runtime-boundary reference specimen."""
'''

APP_BOUNDARY = '''"""The embedded boundary: every state-changing request is decided here.

It reads the closed operation table Forge rendered (runtime_contract.json),
accepts only that exact shape, and decides each operation against it. Standard
library only; it imports no Forge module.
"""

from __future__ import annotations

import json
from pathlib import Path

CONTRACT_SCHEMA = "nornyx.forge.runtime_contract.v1"
CONTRACT = Path(__file__).with_name("runtime_contract.json")
#: No approval mechanism exists, so these are refused whatever the table says.
ALWAYS_REFUSED = frozenset({"destructive_bulk_deletion", "external_transmission"})
TOP_KEYS = frozenset({
    "always_refused_consequences", "brd", "operation_registry", "operations",
    "schema", "unlisted_operation",
})
ENTRY_KEYS = frozenset({
    "capability", "consequence", "disposition", "operation", "requirement", "risk",
})


class Refused(Exception):
    """A request the boundary refused, with its code and the reason named."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


def load_table(path: Path = CONTRACT) -> dict[str, dict[str, str]]:
    """The closed operation table, or ValueError: a malformed contract permits nothing."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or set(data) != TOP_KEYS
        or data["schema"] != CONTRACT_SCHEMA
        or data["unlisted_operation"] != "refused"
        or not ALWAYS_REFUSED <= set(data["always_refused_consequences"])
        or not isinstance(data["operations"], list)
    ):
        raise ValueError("the runtime contract is not the shape this boundary accepts")
    table: dict[str, dict[str, str]] = {}
    for entry in data["operations"]:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise ValueError("a runtime contract entry is not the shape this boundary accepts")
        if not all(type(value) is str for value in entry.values()):
            raise ValueError("a runtime contract entry holds a value that is not text")
        if entry["operation"] in table:
            raise ValueError("the runtime contract lists an operation twice")
        table[entry["operation"]] = dict(entry)
    return table


class Boundary:
    """Decides an operation against the table; it never runs anything itself."""

    def __init__(self, table: dict[str, dict[str, str]]) -> None:
        self._table = {name: dict(entry) for name, entry in table.items()}

    def decide(self, operation: object) -> dict[str, str]:
        entry = self._table.get(operation) if type(operation) is str else None
        if entry is None:
            raise Refused(
                "OPERATION_UNREGISTERED",
                f"operation {operation!r} is not in the runtime contract's closed table",
            )
        consequence = entry["consequence"]
        if consequence in ALWAYS_REFUSED or entry["disposition"] != "permitted":
            raise Refused(
                "NO_APPROVAL_MECHANISM",
                f"operation {operation!r} is {consequence}, which needs an approval "
                "this application has no way to obtain, so it is always refused",
            )
        return dict(entry)
'''

APP_NOTEBOOK = '''"""The notebook: its acts exist, and the boundary decides whether any runs."""

from __future__ import annotations

from collections.abc import Callable

from app.boundary import Boundary, Refused


class Notebook:
    def __init__(self, boundary: Boundary, send: Callable[[str, int, bytes], None]) -> None:
        self._boundary = boundary
        self._send = send
        self._notes: list[str] = []

    def notes(self) -> tuple[str, ...]:
        return tuple(self._notes)

    def request(self, operation: object, **fields: object) -> None:
        self._boundary.decide(operation)
        acts = {
            "send guidance": self._record,
            "delete all service requests": self._remove_all,
            "send external email": self._forward,
        }
        act = acts.get(operation) if type(operation) is str else None
        if act is None:
            raise Refused("NO_HANDLER", f"operation {operation!r} has no act here")
        act(**fields)

    def _record(self, text: str) -> None:
        self._notes.append(text)

    def _remove_all(self) -> None:
        self._notes.clear()

    def _forward(self, text: str, host: str, port: int) -> None:
        self._send(host, port, text.encode("utf-8"))
'''

APP_ADAPTERS_INIT = '''"""The application's only outbound adapters."""
'''

APP_OUTBOUND = '''"""The one adapter that opens a socket. Only the boundary's permission reaches it."""

from __future__ import annotations

import socket


def send(host: str, port: int, payload: bytes) -> None:
    with socket.create_connection((host, port), timeout=1) as connection:
        connection.sendall(payload)
'''

TESTS = f'''"""The specimen's own tests: BRD-001, BRD-F-001, BRD-F-002, BRD-F-003."""

import pytest

from app.adapters import outbound
from app.boundary import Boundary, Refused, load_table
from app.notebook import Notebook


def notebook(send=outbound.send):
    return Notebook(Boundary(load_table()), send)


def test_brd_f_001_a_permitted_operation_records_a_note():
    book = notebook()
    book.request("send guidance", text="Water the plants on Friday.")
    assert book.notes() == ("Water the plants on Friday.",)


def test_brd_f_002_removing_every_note_is_refused_and_every_note_is_kept():
    book = notebook()
    book.request("send guidance", text="Keep this note.")
    with pytest.raises(Refused) as refused:
        book.request("delete all service requests")
    assert refused.value.code == "NO_APPROVAL_MECHANISM"
    assert "destructive_bulk_deletion" in refused.value.reason
    assert book.notes() == ("Keep this note.",)


def test_brd_f_003_forwarding_is_refused_before_anything_is_sent():
    sent = []
    book = notebook(send=lambda *arguments: sent.append(arguments))
    with pytest.raises(Refused) as refused:
        book.request("send external email", text="x", host="{UNROUTED}", port=25)
    assert refused.value.code == "NO_APPROVAL_MECHANISM"
    assert "external_transmission" in refused.value.reason
    assert sent == []


def test_brd_001_an_operation_the_table_does_not_list_is_refused():
    book = notebook()
    for operation in ("archive every note", "Send guidance", " send guidance", None):
        with pytest.raises(Refused) as refused:
            book.request(operation)
        assert refused.value.code == "OPERATION_UNREGISTERED"
    assert book.notes() == ()


def test_brd_001_the_two_consequences_stay_refused_if_the_table_permits_them():
    table = load_table()
    for operation in ("delete all service requests", "send external email"):
        table[operation] = dict(table[operation], disposition="permitted")
    sent = []
    book = Notebook(Boundary(table), lambda *arguments: sent.append(arguments))
    book.request("send guidance", text="Still here.")
    for operation, fields in (
        ("delete all service requests", {{}}),
        ("send external email", {{"text": "x", "host": "{UNROUTED}", "port": 25}}),
    ):
        with pytest.raises(Refused) as refused:
            book.request(operation, **fields)
        assert refused.value.code == "NO_APPROVAL_MECHANISM"
    assert book.notes() == ("Still here.",) and sent == []


def test_brd_f_003_a_send_that_skips_the_boundary_meets_the_test_guard():
    # Run by Forge's test executor, whose audit hook refuses and counts a
    # network attempt; Forge reads the count from the executor's record.
    with pytest.raises(PermissionError):
        outbound.send("{UNROUTED}", 25, b"never sent")
'''


def files(contract_text: str | None) -> dict[str, str]:
    """The specimen's files; `contract_text` is the Forge-rendered contract, if any."""
    written = {
        "BRD.md": BRD,
        "app/__init__.py": APP_INIT,
        "app/boundary.py": APP_BOUNDARY,
        "app/notebook.py": APP_NOTEBOOK,
        "app/adapters/__init__.py": APP_ADAPTERS_INIT,
        "app/adapters/outbound.py": APP_OUTBOUND,
        "tests/test_notebook.py": TESTS,
    }
    if contract_text is not None:
        written["app/runtime_contract.json"] = contract_text
    return written


def write(project: Path, written: dict[str, str]) -> Path:
    for relative, text in written.items():
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="")
    return project
