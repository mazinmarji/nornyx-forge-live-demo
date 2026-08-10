"""A forbidden layer cannot ACQUIRE process-execution capability.

Two independent reviews defeated the previous control, and the second defeated
the fix for the first. Both times the control recognised *invocation syntax* — a
list of dangerous call spellings — so each round closed the demonstrated
spelling and left the adjacent one open:

    review 1:  from os import system
    fix:       add from-import and alias tracking
    review 2:  import os as _o  →  _o.system(cmd)
               getattr(os, "system"), os.__dict__["system"], import posix,
               _RUN = os.system, functools.partial(os.system)

A list of spellings can always be extended by one more. So the question changed
from "is this call dangerous?" to "does this module obtain the means to start a
process at all?", which is a property rather than an enumeration:

    EXEC-ONLY MODULES   importing subprocess/pty/posix/nt/multiprocessing IS
                        the capability — no call site need be found
    DUAL-USE MODULES    importing os/asyncio is ordinary; BINDING one of their
                        exec-family names is the capability
    OPAQUE ACCESS       getattr / __dict__ / computed targets cannot be
                        resolved, so inside a forbidden layer they are refused

The attack table below is a test of the property, not the design of it. The
benign table matters equally: a control that flags `os.getenv` gets switched
off, and then it protects nothing.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: An application-layer module with no compensating path rule of its own, so
#: what is measured is the layer constraint rather than a file-specific ban.
TARGET = "src/demo_app/agentic.py"


def _source(*lines: str) -> str:
    return "\n".join(lines) + "\n"


ACQUISITIONS = [
    ("module alias then exec attr", _source("import os as _o", "def p(c):", "    _o.system(c)")),
    ("from-import exec name", _source("from os import system", "def p(c):", "    system(c)")),
    ("from-import aliased", _source("from os import system as _s", "def p(c):", "    _s(c)")),
    ("attribute call", _source("import os", "def p(c):", "    os.system(c)")),
    ("getattr literal member", _source("import os", "def p(c):", "    getattr(os, 'system')(c)")),
    ("getattr computed member", _source("import os as _o", "def p(c, n):", "    getattr(_o, n)(c)")),
    ("__dict__ member access", _source("import os", "def p(c):", "    os.__dict__['system'](c)")),
    ("posix directly", _source("import posix", "def p(c):", "    posix.system(c)")),
    ("from posix import", _source("from posix import system", "def p(c):", "    system(c)")),
    ("bound, never called", _source("import os", "_RUN = os.system")),
    ("bound through an alias chain", _source("import os", "_o = os", "_RUN = _o.popen")),
    ("subprocess aliased", _source("import subprocess as sp", "def p(c):", "    sp.run(c)")),
    ("subprocess star-import", _source("from subprocess import *", "def p(c):", "    run(c)")),
    ("multiprocessing", _source("import multiprocessing as mp", "def p(f):", "    mp.Process(target=f).start()")),
    ("asyncio subprocess", _source("import asyncio", "async def p(c):", "    await asyncio.create_subprocess_shell(c)")),
    ("pty", _source("import pty", "def p(c):", "    pty.spawn(c)")),
]

BENIGN = [
    ("os.getenv", _source("import os", "def p():", "    return os.getenv('HOME')")),
    ("os.path.join", _source("import os", "def p(a, b):", "    return os.path.join(a, b)")),
    ("aliased os, ordinary members", _source("import os as _o", "def p(a):", "    return _o.path.dirname(_o.getenv('X', a))")),
    ("os.environ mapping", _source("import os", "def p():", "    return dict(os.environ)")),
    ("unrelated stdlib", _source("import json", "from pathlib import Path", "def p(x):", "    return json.loads(Path(x).read_text())")),
    ("shutil.which is a PATH lookup", _source("import shutil", "def p(n):", "    return shutil.which(n)")),
]


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> Path:
    work = tmp_path_factory.mktemp("capability") / "repo"
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
    return subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _with_appended(work: Path, snippet: str):
    target = work / TARGET
    original = target.read_bytes()
    target.write_bytes(original + b"\n\n" + snippet.encode("utf-8"))
    try:
        return _gate(work)
    finally:
        target.write_bytes(original)


def test_the_gate_is_clean_before_any_probe(workspace: Path):
    """Baseline, or every case below would 'pass' for free."""
    completed = _gate(workspace)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert '"violations": []' in completed.stdout


@pytest.mark.parametrize(
    ("label", "snippet"), ACQUISITIONS, ids=[case[0] for case in ACQUISITIONS]
)
def test_acquiring_process_capability_is_refused(workspace: Path, label: str, snippet: str):
    completed = _with_appended(workspace, snippet)
    assert completed.returncode == 2, f"{label}: not detected\n{completed.stdout}"
    assert "performs process execution" in completed.stdout, (
        f"{label}: refused for some other reason\n{completed.stdout}"
    )
    assert TARGET in completed.stdout, f"{label}: wrong file named"
    assert "Traceback" not in completed.stderr, completed.stderr


@pytest.mark.parametrize(("label", "snippet"), BENIGN, ids=[case[0] for case in BENIGN])
def test_ordinary_module_use_is_not_refused(workspace: Path, label: str, snippet: str):
    """The false-positive side is part of the property.

    A gate that refuses `os.getenv` or `shutil.which` is switched off within a
    day, and then protects nothing. `shutil` is deliberately not a dual-use
    module: it has no exec family, and `which` only resolves a name against
    PATH.
    """
    completed = _with_appended(workspace, snippet)
    assert completed.returncode == 0, (
        f"{label}: ordinary code was refused\n{completed.stdout}"
    )


def test_an_adapter_may_still_execute_processes(workspace: Path):
    """The rule is about layer, not about the whole repository.

    `nornyx_cli_adapter` is a declared adapter and imports subprocess; if the
    capability model refused that, the system could not run its own gates.
    """
    completed = _gate(workspace)
    assert completed.returncode == 0
    source = (workspace / "src/nornyx_forge/nornyx_cli_adapter.py").read_text(
        encoding="utf-8"
    )
    assert "import subprocess" in source, (
        "the adapter no longer executes processes; this test needs a new subject"
    )


def test_the_vocabulary_separates_exec_only_from_dual_use():
    """Stated, so a future widening has to confront the distinction.

    Folding `os` into EXEC_ONLY_MODULES would flag every `os.getenv` in the
    repository; folding `subprocess` into DUAL_USE would require finding a call
    site, which is exactly the recognition-of-syntax the model replaced.
    """
    import ast

    source = (ROOT / "scripts/check_architecture.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    values: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in {"EXEC_ONLY_MODULES", "DUAL_USE_MODULES", "EXEC_FUNCTIONS"}:
                values[name] = {
                    element.value
                    for element in ast.walk(node.value)
                    if isinstance(element, ast.Constant) and isinstance(element.value, str)
                }

    assert "subprocess" in values["EXEC_ONLY_MODULES"]
    assert "posix" in values["EXEC_ONLY_MODULES"]
    assert "os" in values["DUAL_USE_MODULES"]
    assert "os" not in values["EXEC_ONLY_MODULES"], (
        "os is ordinary to import; treating it as exec-only would flag os.getenv "
        "everywhere and the gate would be switched off"
    )
    assert "shutil" not in values["DUAL_USE_MODULES"]
    assert {"system", "popen", "run", "Popen"} <= values["EXEC_FUNCTIONS"]
