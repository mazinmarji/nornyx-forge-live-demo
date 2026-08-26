"""The v1 boundary of `architecture-check`, pinned from both sides.

THESE ARE DISCLOSED LIMITATIONS, NOT FAILING CONTROLS. `check_architecture.py`
is a static, side-effect-free reader: it decides the declared, statically
visible dependency structure and refuses the dynamic module-acquisition
constructs it can name. A module object reached through an expression whose
value is known only at runtime is outside its scope, and outside what
`docs/ASSURANCE_BOUNDARY.md` claims.

Three attempts were made to close that gap by static analysis, and each was
reopened by a spelling nobody had used yet -- the third by five at once. The
decision recorded in `docs/governance/MODULE_ACQUISITION.md` is to narrow the
claim rather than to keep enumerating, and NOT to add a parser heuristic for any
route below: each heuristic is one more member of a set that cannot be closed.

So each route is measured here as it behaves TODAY, and the test fails if that
changes IN EITHER DIRECTION:

  - it stops passing  -> someone closed the route, and the disclosure in
                         ASSURANCE_BOUNDARY.md and the contract's `scope` now
                         claim LESS than the code delivers. Update them.
  - the paired control stops refusing -> the gate has regressed on a spelling
                         it does decide, which is a real defect.

The second half matters as much as the first. A file that only asserted "these
are not refused" would still pass if `check_architecture` refused nothing at
all, which is the shape this repository exists to catch.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

RUNTIME = "nornyx_forge.nornyx_runtime"

#: (label, file, payload that ACQUIRES a module, why the parser cannot see it).
#:
#: Every payload was verified at the head that recorded them to hand back the
#: live module object, not merely to parse.
UNDECIDED_ROUTES = [
    (
        "a function's __globals__",
        "src/demo_app/agentic.py",
        "\n_SP = ClaudeCodeWorker.run.__globals__['subprocess']\n",
        "the module dict under an attribute name the refusal does not read",
    ),
    (
        "the modules map bound by from-import, then one hop",
        "src/demo_app/main.py",
        "\nfrom sys import modules as _m\n_H = _m\n_R = _H.pop('" + RUNTIME + "')\n",
        "`from sys import modules` writes no `.modules` attribute to key on",
    ),
    (
        "a Subscript callee",
        "src/demo_app/store.py",
        "\n_SP = __builtins__['__import__']('subprocess')\n",
        "the callee is neither a Name nor an Attribute",
    ),
    (
        "pkgutil.resolve_name",
        "src/demo_app/agentic.py",
        "\nimport pkgutil\n_SP = pkgutil.resolve_name('subprocess')\n",
        "a module-acquisition API outside the declared importer list",
    ),
    (
        "runpy.run_module",
        "src/demo_app/agentic.py",
        "\nimport runpy\n_SP = runpy.run_module('subprocess')\n",
        "as above, by a different stdlib entry point",
    ),
]

#: (label, file, payload) the gate DOES decide. The contrast that keeps the
#: table above from being satisfied by a gate that refuses nothing.
DECIDED_CONTROLS = [
    ("the spelled import", "src/demo_app/main.py",
     "\nimport nornyx_forge.nornyx_runtime as _rt\n"),
    ("the modules map by attribute", "src/demo_app/main.py",
     "\nimport sys\n_R = sys.modules.pop('" + RUNTIME + "')\n"),
    ("the modules map through vars", "src/demo_app/main.py",
     "\nimport sys\n_R = vars(sys)['modules']['" + RUNTIME + "']\n"),
]


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> Path:
    work = tmp_path_factory.mktemp("acquisition") / "repo"
    work.mkdir()
    for item in ("src", "scripts", ".nornyx"):
        shutil.copytree(
            ROOT / item,
            work / item,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
        )
    for item in ("pyproject.toml", "README.md", "BRD.md", "Dockerfile"):
        shutil.copy2(ROOT / item, work / item)
    return work


def _gate(work: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "scripts/check_architecture.py"],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _with(work: Path, relative: str, payload: str):
    target = work / relative
    original = target.read_bytes()
    target.write_bytes(original + payload.encode("utf-8"))
    try:
        return _gate(work)
    finally:
        target.write_bytes(original)


def test_the_baseline_is_clean(workspace: Path):
    """Or nothing below means anything."""
    completed = _gate(workspace)
    assert completed.returncode == 0, completed.stdout[-800:]


@pytest.mark.parametrize(
    ("label", "relative", "payload", "why"), UNDECIDED_ROUTES,
    ids=[case[0] for case in UNDECIDED_ROUTES],
)
def test_a_disclosed_route_is_still_outside_the_static_claim(
    workspace: Path, label: str, relative: str, payload: str, why: str,
):
    """Measured, not asserted: this route is NOT refused, and that is disclosed.

    If this fails, the route has been closed. That is good news and a
    documentation defect at the same time: `docs/ASSURANCE_BOUNDARY.md` and the
    `scope` on `architecture-check` both say the gate does not establish this,
    and they would now be claiming less than the code delivers. Update the
    disclosure, then delete the row.
    """
    completed = _with(workspace, relative, payload)
    assert completed.returncode == 0, (
        label + ": this route is now REFUSED. " + why + ". The claim in "
        "docs/ASSURANCE_BOUNDARY.md and the `scope` on architecture-check are "
        "now narrower than the gate; update them and remove this row:\n"
        + completed.stdout[-800:]
    )


@pytest.mark.parametrize(
    ("label", "relative", "payload"), DECIDED_CONTROLS,
    ids=[case[0] for case in DECIDED_CONTROLS],
)
def test_what_the_gate_does_decide_is_still_decided(
    workspace: Path, label: str, relative: str, payload: str,
):
    """The other half, without which the table above proves nothing.

    A gate that refused NOTHING would satisfy every row of
    `UNDECIDED_ROUTES`. These three are inside the v1 claim and must stay
    refused, so the disclosure above describes a boundary rather than an
    absence.
    """
    completed = _with(workspace, relative, payload)
    assert completed.returncode != 0, (
        label + ": a spelling inside the v1 claim was accepted, so the "
        "disclosed limits above are not a boundary -- the gate is not deciding"
    )
