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
import yaml

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
    # DYNAMIC ACQUISITION. Seven of these were accepted by the gate while the
    # static `import subprocess` two lines away was refused, so the control was
    # not "process capability must be declared" but "must be declared if you
    # spell it the way the analyser expects". Only the computed name refused,
    # and for the unrelated reason that unreadable names are refused wholesale.
    ("importlib literal", _source(
        "import importlib", "def p(c):",
        "    return importlib.import_module('subprocess').run(c)")),
    ("importlib from-import", _source(
        "from importlib import import_module", "def p(c):",
        "    return import_module('subprocess').run(c)")),
    ("importlib from-import aliased", _source(
        "from importlib import import_module as _im", "def p(c):",
        "    return _im('subprocess').run(c)")),
    ("importlib module aliased", _source(
        "import importlib as _il", "def p(c):",
        "    return _il.import_module('subprocess').run(c)")),
    ("__import__ literal", _source(
        "def p(c):", "    return __import__('subprocess').run(c)")),
    ("__import__ rebound", _source(
        "_imp = __import__", "def p(c):", "    return _imp('subprocess').run(c)")),
    ("sys.modules lookup", _source(
        "import sys", "def p(c):", "    return sys.modules['subprocess'].run(c)")),
    ("computed module name", _source(
        "import importlib", "def p(c):",
        "    return importlib.import_module('sub' + 'process').run(c)")),
    # Dual-use reached dynamically, then used for exec. The module object is
    # the same object however it was obtained.
    ("dynamic os bound then exec", _source(
        "import importlib", "_o = importlib.import_module('os')", "def p(c):",
        "    return _o.system(c)")),
]

BENIGN = [
    ("os.getenv", _source("import os", "def p():", "    return os.getenv('HOME')")),
    ("os.path.join", _source("import os", "def p(a, b):", "    return os.path.join(a, b)")),
    ("aliased os, ordinary members", _source("import os as _o", "def p(a):", "    return _o.path.dirname(_o.getenv('X', a))")),
    ("os.environ mapping", _source("import os", "def p():", "    return dict(os.environ)")),
    ("unrelated stdlib", _source("import json", "from pathlib import Path", "def p(x):", "    return json.loads(Path(x).read_text())")),
    ("shutil.which is a PATH lookup", _source("import shutil", "def p(n):", "    return shutil.which(n)")),
    # The other half of the dynamic rule. Importing a module dynamically is
    # ordinary; a gate that refused every `import_module` would be refusing
    # plugin loading rather than process capability, and would be turned off.
    ("dynamic import of json", _source(
        "import importlib", "def p():",
        "    return importlib.import_module('json').dumps({})")),
    ("dynamic import aliased, benign module", _source(
        "from importlib import import_module as _im", "def p():",
        "    return _im('pathlib').Path('.')")),
    ("sys.modules for a benign module", _source(
        "import sys", "def p():", "    return sys.modules.get('json')")),
    ("dynamic os, ordinary member", _source(
        "import importlib", "def p():",
        "    return importlib.import_module('os').getenv('HOME')")),
    ("dynamic os bound, ordinary member", _source(
        "import importlib", "_o = importlib.import_module('os')", "def p():",
        "    return _o.getenv('HOME')")),
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


# --------------------------------------------------------------------------
# Cross-module propagation: capability arriving through a first-party name
# --------------------------------------------------------------------------
#
# The scan above asks what a module takes from the STANDARD LIBRARY. It cannot
# see capability that arrives through a first-party module, because `helper` is
# not `subprocess` and never will be:
#
#     helper.py:   runner = subprocess.run
#     agentic.py:  from .helper import runner
#                  runner(["curl", url])
#
# That acquires exactly what the layer forbids, through a name the per-file scan
# had no reason to distrust. Adding `helper` to a list would be the enumeration
# mistake again, one module at a time -- so the gate computes what each module
# EXPORTS, transitively, and asks of an importer "is this name capability?"

#: (label, {relative path: source}, snippet appended to the delegating module)
PROPAGATIONS = [
    (
        "re-export through a helper module",
        {"src/nornyx_forge/_helper.py": _source("import subprocess", "runner = subprocess.run")},
        _source("from nornyx_forge._helper import runner", "def p(c):", "    runner(c)"),
    ),
    (
        "re-export of a dual-use exec name",
        {"src/nornyx_forge/_helper.py": _source("import os", "runner = os.system")},
        _source("from nornyx_forge._helper import runner", "def p(c):", "    runner(c)"),
    ),
    (
        "from-import of the module object itself",
        {"src/nornyx_forge/_helper.py": _source("import subprocess")},
        _source(
            "from nornyx_forge._helper import subprocess",
            "def p(c):",
            "    subprocess.run(c)",
        ),
    ),
    (
        "two-hop alias chain",
        {
            "src/nornyx_forge/_deep.py": _source("import subprocess", "runner = subprocess.run"),
            "src/nornyx_forge/_helper.py": _source("from nornyx_forge._deep import runner"),
        },
        _source("from nornyx_forge._helper import runner", "def p(c):", "    runner(c)"),
    ),
    (
        "three-hop chain with renames at each step",
        {
            "src/nornyx_forge/_a.py": _source("from subprocess import run"),
            "src/nornyx_forge/_b.py": _source("from nornyx_forge._a import run as go"),
            "src/nornyx_forge/_helper.py": _source("from nornyx_forge._b import go as launch"),
        },
        _source("from nornyx_forge._helper import launch", "def p(c):", "    launch(c)"),
    ),
    (
        "star-import of a capable helper",
        {"src/nornyx_forge/_helper.py": _source("import subprocess", "runner = subprocess.run")},
        _source("from nornyx_forge._helper import *", "def p(c):", "    runner(c)"),
    ),
    (
        # Relative, as a package __init__ is actually written. A package is
        # anchored to ITSELF, not to its parent, so `from .inner import runner`
        # inside `relay/__init__.py` means `relay.inner` -- and a mutation that
        # anchored it one level too high survived while this case spelled the
        # import absolutely.
        "package __init__ re-export",
        {
            "src/relay/__init__.py": _source("from .inner import runner"),
            "src/relay/inner.py": _source("import subprocess", "runner = subprocess.run"),
        },
        _source("from relay import runner", "def p(c):", "    runner(c)"),
    ),
    (
        "attribute access on an imported capable module",
        {"src/nornyx_forge/_helper.py": _source("import subprocess", "runner = subprocess.run")},
        _source(
            "from nornyx_forge import _helper",
            "def p(c):",
            "    _helper.runner(c)",
        ),
    ),
    (
        "imported outright and reached by attribute",
        {"src/nornyx_forge/_helper.py": _source("from subprocess import Popen")},
        _source("import nornyx_forge._helper as h", "def p(c):", "    h.Popen(c)"),
    ),
    (
        "bound but never called",
        {"src/nornyx_forge/_helper.py": _source("import subprocess", "runner = subprocess.Popen")},
        _source("from nornyx_forge._helper import runner", "_HELD = runner"),
    ),
    (
        # The middle module star-imports. Distinct from "star-import of a
        # capable helper" above, which star-imports at the point of USE: this
        # exercises propagation THROUGH a star-import, and a mutation that
        # dropped it survived until this case existed.
        "star-import in the middle of the chain",
        {
            "src/nornyx_forge/_deep.py": _source("import subprocess", "runner = subprocess.run"),
            "src/nornyx_forge/_helper.py": _source("from nornyx_forge._deep import *"),
        },
        _source("from nornyx_forge._helper import runner", "def p(c):", "    runner(c)"),
    ),
    (
        # The chain hop is written relatively, as first-party code actually
        # writes it. Absolute spellings alone would leave the relative
        # resolution untested.
        "relative import in the middle of the chain",
        {
            "src/nornyx_forge/_deep.py": _source("import subprocess", "runner = subprocess.run"),
            "src/nornyx_forge/_helper.py": _source("from ._deep import runner"),
        },
        _source("from nornyx_forge._helper import runner", "def p(c):", "    runner(c)"),
    ),
]

BENIGN_CROSS_MODULE = [
    (
        "ordinary name from a module that also holds capability",
        {
            "src/nornyx_forge/_helper.py": _source(
                "import subprocess",
                "runner = subprocess.run",
                "TIMEOUT = 30",
            )
        },
        _source("from nornyx_forge._helper import TIMEOUT", "def p():", "    return TIMEOUT"),
    ),
    (
        "a helper that wraps capability behind an interface",
        {
            "src/nornyx_forge/_helper.py": _source(
                "import subprocess",
                "",
                "",
                "def tool_version(name):",
                "    return subprocess.run([name], capture_output=True)",
            )
        },
        _source(
            "from nornyx_forge._helper import tool_version",
            "def p(n):",
            "    return tool_version(n)",
        ),
    ),
    (
        "importing a capable module without taking a capable name",
        {"src/nornyx_forge/_helper.py": _source("import subprocess", "runner = subprocess.run")},
        _source("from nornyx_forge import _helper", "def p():", "    return _helper.__name__"),
    ),
    (
        "existing declared adapter, reached for its safe interface",
        {},
        _source(
            "from nornyx_forge.claude_worker import ClaudeCodeWorker",
            "def p():",
            "    return ClaudeCodeWorker()",
        ),
    ),
    (
        # A name is an export because of what the MODULE binds it to, not
        # because some function body once bound that name to something
        # dangerous. Widening the scan to every node made a local shadow
        # poison the module-level name of the same spelling, and no test
        # noticed until this one.
        "a local shadow does not make the module-level name capability",
        {
            "src/nornyx_forge/_helper.py": _source(
                "import subprocess",
                "",
                "runner = None",
                "",
                "",
                "def configure():",
                "    runner = subprocess.run",
                "    return runner",
            )
        },
        _source("from nornyx_forge._helper import runner", "def p():", "    return runner"),
    ),
]


CONTRACT = ".nornyx/contracts/architecture_governance.nyx"


def _declare(work: Path, dotted_names: list[str]) -> bytes:
    """Register planted modules as declared adapters. Returns the original bytes.

    Without this the gate refuses them as undeclared first-party modules, which
    is a different rule -- and a benign case failing on it would say nothing
    about whether the capability model over-refuses. Declared as ADAPTERS
    because an adapter is exactly where capability is allowed to live; the
    question under test is what a delegating layer may take FROM one.
    """
    contract = work / CONTRACT
    original = contract.read_bytes()
    document = yaml.safe_load(original.decode("utf-8"))
    modules = document["architecture"]["modules"]
    planted_ids = []
    for dotted in dotted_names:
        identifier = "module.planted_" + dotted.replace(".", "_")
        planted_ids.append(identifier)
        modules.append(
            {
                "id": identifier,
                "name": dotted,
                "component": "component.nornyx_cli",
                "layer": "layer.adapter",
                "depends_on": [],
            }
        )
    # The importer must also DECLARE the edge, or the gate refuses it as an
    # undeclared dependency -- again a different rule from the one under test.
    target_name = TARGET.removeprefix("src/").removesuffix(".py").replace("/", ".")
    for module in modules:
        if module["name"] == target_name:
            module.setdefault("depends_on", []).extend(planted_ids)
    contract.write_bytes(yaml.safe_dump(document, sort_keys=False).encode("utf-8"))
    return original


def _with_modules(work: Path, planted: dict[str, str], snippet: str):
    """Plant helper modules, append the snippet, run the gate, restore."""
    target = work / TARGET
    original = target.read_bytes()
    contract_original = _declare(
        work,
        [
            relative.removeprefix("src/").removesuffix(".py").replace("/", ".").removesuffix(".__init__")
            for relative in planted
        ],
    )
    created: list[Path] = []
    try:
        for relative, source in planted.items():
            path = work / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8", newline="")
            created.append(path)
        target.write_bytes(original + b"\n\n" + snippet.encode("utf-8"))
        return _gate(work)
    finally:
        target.write_bytes(original)
        (work / CONTRACT).write_bytes(contract_original)
        for path in created:
            path.unlink(missing_ok=True)
        for path in created:
            if path.parent.exists() and not any(path.parent.iterdir()):
                path.parent.rmdir()


@pytest.mark.parametrize(
    ("label", "planted", "snippet"),
    PROPAGATIONS,
    ids=[case[0] for case in PROPAGATIONS],
)
def test_capability_through_a_first_party_module_is_refused(
    workspace: Path, label: str, planted: dict[str, str], snippet: str
):
    completed = _with_modules(workspace, planted, snippet)
    assert completed.returncode == 2, f"{label}: not detected\n{completed.stdout}"
    assert "re-exported by a first-party module" in completed.stdout, (
        f"{label}: refused, but not for acquiring capability\n{completed.stdout}"
    )
    assert TARGET in completed.stdout, f"{label}: wrong file named"
    assert "Traceback" not in completed.stderr, completed.stderr


@pytest.mark.parametrize(
    ("label", "planted", "snippet"),
    BENIGN_CROSS_MODULE,
    ids=[case[0] for case in BENIGN_CROSS_MODULE],
)
def test_ordinary_cross_module_use_is_not_refused(
    workspace: Path, label: str, planted: dict[str, str], snippet: str
):
    """Delegating to an adapter is the ARCHITECTURE, not a violation.

    If importing anything from a module that touches subprocess were refused,
    the correct design -- capability held in an adapter behind a named
    interface -- would be unbuildable, and the gate would be switched off.
    """
    completed = _with_modules(workspace, planted, snippet)
    assert completed.returncode == 0, (
        f"{label}: ordinary delegation was refused\n{completed.stdout}"
    )


def test_the_planting_harness_restores_the_workspace(workspace: Path):
    """The cases above are only independent if nothing leaks between them."""
    assert not (workspace / "src/nornyx_forge/_helper.py").exists()
    assert not (workspace / "src/relay").exists()
    completed = _gate(workspace)
    assert completed.returncode == 0, completed.stdout
