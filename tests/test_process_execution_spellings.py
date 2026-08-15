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
    # ACQUISITION WITHOUT AN IMPORT STATEMENT, and without the word.
    #
    # Every case above spells `os` or `subprocess` as a literal, so all of them
    # were also caught by a substring test over the source text -- which meant
    # this file could not tell whether the AST analysis was working. Two
    # spellings walked through both gates at exit 0 with `violations: []`:
    # `sys.modules.get` (the subscript form was covered, the method form was
    # not) and an importer fetched by a computed `getattr`. The split literal is
    # what made them invisible: it defeated the substring test, and nothing else
    # was looking.
    #
    # The invocation is spelled through a computed attribute on purpose. A probe
    # that also writes `.run(` proves only that `.run(` is recognised, which is
    # how these stayed hidden behind a check that was answering for a different
    # one. Holding the module IS the capability.
    ("sys.modules subscript, split literal",
     "import sys\n_R = sys.modules['sub' + 'process']\n"
     "def _probe(c):\n    return getattr(_R, 'r' + 'un')(c)\n"),
    ("sys.modules.get, split literal",
     "import sys\n_R = sys.modules.get('sub' + 'process')\n"
     "def _probe(c):\n    return getattr(_R, 'r' + 'un')(c)\n"),
    ("sys.modules.pop, split literal",
     "import sys\n_R = sys.modules.pop('sub' + 'process')\n"
     "def _probe(c):\n    return getattr(_R, 'r' + 'un')(c)\n"),
    ("builtins.__import__, split literal",
     "import builtins\n_R = builtins.__import__('sub' + 'process')\n"
     "def _probe(c):\n    return getattr(_R, 'r' + 'un')(c)\n"),
    ("importer via computed getattr",
     "import builtins\n_I = getattr(builtins, '__imp' + 'ort__')\n"
     "_R = _I('sub' + 'process')\n"
     "def _probe(c):\n    return getattr(_R, 'r' + 'un')(c)\n"),
    ("aliased sys, modules.get",
     "import sys as _y\n_R = _y.modules.get('sub' + 'process')\n"
     "def _probe(c):\n    return getattr(_R, 'r' + 'un')(c)\n"),
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


# --------------------------------------------------------------------------
# A declared dependency graph the code can step around describes nothing
# --------------------------------------------------------------------------

#: Snippets are assembled from `chr(10)` joins rather than written with escape
#: sequences. Every previous attempt to add source-text fixtures to this repo
#: through a shell heredoc silently turned the escapes into real newlines and
#: broke the file; building them this way removes the class of mistake instead
#: of getting the quoting right one more time.
DYNAMIC_IMPORTS = [
    (
        "importlib into a purity-constrained domain module",
        "src/nornyx_forge/governed_subject.py",
        chr(10).join(["import importlib", "def _probe():", "    return importlib.import_module('subprocess')"]) + chr(10),
        "forbidden dependency subprocess",
    ),
    (
        "importlib across a layer boundary from a declared leaf",
        "src/nornyx_forge/models.py",
        chr(10).join(["import importlib", "def _probe():", "    return importlib.import_module('demo_app.store')"]) + chr(10),
        "demo_app.store",
    ),
    (
        "__import__ builtin",
        "src/nornyx_forge/governed_subject.py",
        chr(10).join(["def _probe():", "    return __import__('subprocess')"]) + chr(10),
        "forbidden dependency subprocess",
    ),
]


@pytest.mark.parametrize(
    ("label", "target", "snippet", "expected"),
    DYNAMIC_IMPORTS,
    ids=[case[0] for case in DYNAMIC_IMPORTS],
)
def test_a_dynamic_import_is_a_dependency(
    workspace: Path, label: str, target: str, snippet: str, expected: str
):
    """`importlib.import_module` was invisible to the dependency graph.

    An independent review reached `subprocess` from the module held to a purity
    constraint whose own comment says the gate fails if it ever gains a
    dependency, and reached infrastructure from a domain leaf declared
    `depends_on: []`. The gate reported `violations: []` both times, because it
    read only `ast.Import` and `ast.ImportFrom`.

    A literal dynamic import is now an ordinary dependency, checked like one.
    """
    path = workspace / target
    original = path.read_bytes()
    try:
        path.write_bytes(original + chr(10).encode() * 2 + snippet.encode("utf-8"))
        completed = _run_gate(workspace)
        assert completed.returncode == 2, f"{label}: not detected{chr(10)}{completed.stdout}"
        assert expected in completed.stdout, f"{label}: wrong diagnostic"
        assert "Traceback" not in completed.stderr, completed.stderr
    finally:
        path.write_bytes(original)


def test_a_module_name_assembled_at_runtime_is_refused(workspace: Path):
    """What cannot be read must not pass silently.

    Modelling a literal dynamic import is possible; modelling a computed one is
    not. Ignoring it would leave the hole the literal case just closed, reachable
    by concatenating two strings. Refusing is the honest option, and passing a
    literal is the supported form -- visible, and something the graph can hold.
    """
    path = workspace / "src/nornyx_forge/models.py"
    original = path.read_bytes()
    snippet = chr(10).join(["import importlib", "_P = ['demo', 'app']", "def _probe():", "    return importlib.import_module('_'.join(_P) + '.store')"]) + chr(10)
    try:
        path.write_bytes(original + chr(10).encode() * 2 + snippet.encode("utf-8"))
        completed = _run_gate(workspace)
        assert completed.returncode == 2
        assert "named at runtime" in completed.stdout, completed.stdout
    finally:
        path.write_bytes(original)


def test_an_ordinary_declared_import_is_still_accepted(workspace: Path):
    """The gate must not start refusing the imports the contract permits."""
    completed = _run_gate(workspace)
    assert completed.returncode == 0, completed.stdout


def test_the_constraint_is_structural_not_textual(workspace: Path):
    """The other direction, and the one that proves the substring test is gone.

    `api_no_commands` was `if "subprocess" in main_text`. Wrong both ways: a
    split literal passed it, and the word in a comment failed it. It also masked
    the acquisition gate -- every probe above spells the module name somewhere,
    so this fired and answered for a check that had never seen the payload,
    which is why two real bypasses sat behind a green gate.

    Mentioning process execution is not performing it.
    """
    target = workspace / TARGET
    original = target.read_bytes()
    prose = (
        "# This layer must never hold subprocess, or call os.system directly;\n"
        "# consequential work goes through the governed action boundary.\n"
        "_NOTE = 'subprocess and os.system are forbidden in this layer'\n"
    )
    try:
        target.write_bytes(original + b"\n\n" + prose.encode("utf-8"))
        completed = _run_gate(workspace)
        assert completed.returncode == 0, (
            "the gate refused a module that only NAMES process execution, so it "
            "is still reading text rather than structure:\n" + completed.stdout
        )
    finally:
        target.write_bytes(original)
