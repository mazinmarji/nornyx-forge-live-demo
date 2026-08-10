"""One spelling proved is not the constraint proved.

An independent exact-head review put this into an unauthenticated endpoint in
the interface layer:

    from os import popen as _p, system as _s

    @app.get("/exec")
    def _exec(cmd: str) -> dict:
        _s(cmd)
        return {"out": _p(cmd).read()}

`check_architecture.py` returned `violations: []` and `check_security.py`
returned `findings: []`, both exit 0. Arbitrary process execution from an
unauthenticated query parameter, never crossing the action boundary, and the
generated `architecture_conformance_report.json` would have carried
`status: pass` over it.

Two tests already asserted this constraint was guarded "against `os.system` as
well as `subprocess`". Both passed throughout, because both exercised only the
attribute-call spelling. The import filter consulted `PROCESS_MODULES`, which
does not contain `os`; the call filter matched only `ast.Attribute`, so a
bare-name call was invisible.

So this file enumerates spellings rather than sampling one. Each case is real
source text run through the real gate, and the gate must name the execution it
found — a non-zero exit alone proves nothing, since a syntax error would also
produce one.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: (label, source appended to a governed non-adapter module). Every one of these
#: starts a process. The gate must produce a marker for each.
SPELLINGS = [
    ("attribute call", "import os\ndef _probe(cmd):\n    os.system(cmd)\n"),
    ("from-import bare name", "from os import system\ndef _probe(cmd):\n    system(cmd)\n"),
    ("from-import aliased", "from os import system as _s\ndef _probe(cmd):\n    _s(cmd)\n"),
    ("popen aliased", "from os import popen as _p\ndef _probe(cmd):\n    return _p(cmd).read()\n"),
    ("subprocess module", "import subprocess\ndef _probe(cmd):\n    subprocess.run(cmd)\n"),
    ("subprocess from-import", "from subprocess import run\ndef _probe(cmd):\n    run(cmd)\n"),
    ("os.startfile", "import os\ndef _probe(p):\n    os.startfile(p)\n"),
    ("os.execvp", "from os import execvp\ndef _probe(a, b):\n    execvp(a, b)\n"),
    ("multiprocessing", "import multiprocessing\ndef _probe(f):\n    multiprocessing.Process(target=f).start()\n"),
    ("imported, not visibly called", "from os import system\n_HANDLE = system\n"),
]

#: A governed module in a delegating layer — process execution here is exactly
#: what the constraint forbids.
TARGET = "src/demo_app/main.py"


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> Path:
    """A copy of the governed tree the architecture gate can run against."""
    work = tmp_path_factory.mktemp("spellings") / "repo"
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


def _run_gate(work: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_the_gate_is_clean_before_any_probe(workspace: Path):
    """The baseline must pass, or every case below would 'fail' for free."""
    completed = _run_gate(workspace)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert '"violations": []' in completed.stdout


@pytest.mark.parametrize(
    ("label", "snippet"), SPELLINGS, ids=[case[0] for case in SPELLINGS]
)
def test_every_spelling_of_process_execution_is_detected(
    workspace: Path, label: str, snippet: str
):
    target = workspace / TARGET
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\n\n" + snippet.encode("utf-8"))
        completed = _run_gate(workspace)

        # A refusal, named. `returncode != 0` alone would also be produced by a
        # syntax error in the probe, which would prove nothing about the gate.
        assert completed.returncode == 2, (
            f"{label}: gate exited {completed.returncode}\n{completed.stdout}"
        )
        assert "performs process execution" in completed.stdout, (
            f"{label}: gate failed for some other reason\n{completed.stdout}"
        )
        assert TARGET in completed.stdout, f"{label}: wrong file named"
        assert "Traceback" not in completed.stderr, completed.stderr
    finally:
        target.write_bytes(original)


def test_an_ordinary_os_import_is_not_flagged(workspace: Path):
    """The rule is about starting processes, not about importing `os`.

    Widening the detector to treat `os` as a process module outright would flag
    `os.getenv` and `os.path.join` everywhere, and a gate that cries wolf gets
    switched off. Named explicitly so a future widening has to confront it.
    """
    target = workspace / TARGET
    original = target.read_bytes()
    try:
        target.write_bytes(
            original + b"\n\nimport os\ndef _probe():\n    return os.getenv('HOME')\n"
        )
        completed = _run_gate(workspace)
        assert completed.returncode == 0, (
            "an ordinary os call was flagged as process execution\n" + completed.stdout
        )
    finally:
        target.write_bytes(original)
