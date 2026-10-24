"""Network capability, refused twice: statically by the verifier, and measured while tests run (A-053).

TWO LAYERS, NEITHER OF THEM CONFINEMENT.

1. STATIC. The trusted greenfield verifier refuses network capability -- a
   socket, an SMTP or other mail session, an HTTP or XML-RPC client or
   server, TLS, `asyncio`'s stream helpers -- in any module outside the
   explicit side-effect directories (`adapters/`, `services/`, `tools/`,
   `workers/`), exactly as it already refuses process capability there. It
   is a refusal of named spellings: an event loop's own connection methods,
   a native extension or a module the table does not name are outside it.
2. MEASURED. The test executor's audit hook refuses every socket connect,
   bind, send-to and name lookup while the subject's tests run, and COUNTS
   each refusal into the executor's trusted completion record, so an
   attempted send is measured refused rather than asserted by the code that
   attempted it. An audit hook is a test mechanism, not OS confinement:
   ctypes, a native extension or another process can evade it. It never
   stands in for confining a provider or a produced application.

Forge's own reference specimen (`runtime_boundary_specimen.py`) is run through
the real verifier, and the executor's count shows its one unguarded send
refused. That is the mechanism on a Forge-authored specimen: not a provider
build, and not a runnable Forge-generated application.
"""

from __future__ import annotations

import ast
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from nornyx_forge import gates as gate_module
from nornyx_forge import greenfield_verifier as verifier_module
from nornyx_forge.gates import trusted_greenfield_gates
from nornyx_forge.requirements import parse_brd

sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_boundary_specimen as specimen  # noqa: E402

BRD = (
    "# BRD - Capability guard specimen\n\n"
    "## BRD-F-001 Application behavior\n\n"
    "The application adds two whole numbers.\n"
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def _project(root: Path, app: str = "def add(left, right):\n    return left + right\n") -> Path:
    _write(root / "BRD.md", BRD)
    _write(root / "src/app.py", app)
    _write(root / "tests/test_app.py",
           "# BRD-F-001\nfrom src.app import add\n\n"
           "def test_addition():\n    assert add(1, 1) == 2\n")
    return root


def _gate(gates: list, suffix: str):
    return next(gate for gate in gates if gate.name.endswith(suffix))


# ---------------------------------------------------------------------------
# The measured layer: the executor's guard, run directly
# ---------------------------------------------------------------------------

def _run_executor(tmp_path: Path, test_source: str) -> tuple[subprocess.CompletedProcess, dict]:
    subject = _project(tmp_path / "subject")
    _write(subject / "tests/test_app.py", test_source)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    executor = scratch / "greenfield_pytest_executor.py"
    result = scratch / "greenfield_pytest_inner.json"
    config = scratch / "greenfield_pytest.ini"
    _write(executor, gate_module.GREENFIELD_TEST_EXECUTOR_SOURCE)
    _write(config, "[pytest]\n")
    completed = subprocess.run(
        [
            os.fspath(Path(sys.executable)), "-I", "-c",
            gate_module.GREENFIELD_IN_MEMORY_BOOTSTRAP, os.fspath(executor),
            gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST, os.fspath(subject),
            os.fspath(result), os.fspath(config), gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
        ],
        cwd=subject, text=True, capture_output=True, check=False, timeout=60,
    )
    assert completed.returncode == 73, completed.stdout + completed.stderr
    return completed, json.loads(result.read_text(encoding="utf-8"))


#: Each attempt the guard refuses, as a subject test makes it. A loopback
#: address is refused like any other: the guard has no exemption.
_ATTEMPTS = {
    "connect": "socket.socket().connect(('192.0.2.1', 25))",
    "connect_ex": "socket.socket().connect_ex(('127.0.0.1', 9))",
    "loopback bind": "socket.socket().bind(('127.0.0.1', 0))",
    "sendto": "socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('192.0.2.1', 9))",
    "getaddrinfo": "socket.getaddrinfo('localhost', 80)",
    "gethostbyname": "socket.gethostbyname('localhost')",
    "gethostbyname_ex": "socket.gethostbyname_ex('localhost')",
    "gethostbyaddr": "socket.gethostbyaddr('127.0.0.1')",
    "getnameinfo": "socket.getnameinfo(('127.0.0.1', 80), 0)",
    "create_connection": "socket.create_connection(('192.0.2.1', 25), timeout=1)",
}
#: Windows has no `sendmsg`. Folded into the one test rather than skipped,
#: so this module collects the same tests on every platform and adds no skip
#: to the Windows job, which refuses any.
if hasattr(socket.socket, "sendmsg"):
    _ATTEMPTS["sendmsg"] = (
        "socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
        ".sendmsg([b'x'], [], 0, ('192.0.2.1', 9))"
    )


def test_every_guarded_attempt_is_refused_and_counted_by_the_executor(tmp_path: Path) -> None:
    body = "".join(
        f"    with pytest.raises(PermissionError, match='cannot use the network'):\n"
        f"        {attempt}\n"
        for attempt in _ATTEMPTS.values()
    )
    source = (
        "# BRD-F-001\nimport socket\n\nimport pytest\n\n\n"
        f"def test_each_attempt_meets_the_guard():\n{body}"
    )

    _completed, payload = _run_executor(tmp_path, source)

    assert payload["schema"] == "nornyx.greenfield.pytest_result.v2"
    assert payload["returncode"] == 0 and payload["failed"] == 0, payload
    assert payload["network_refused"] == len(_ATTEMPTS)


def test_a_swallowed_refusal_is_still_counted(tmp_path: Path) -> None:
    # The subject cannot hide an attempt by catching what the guard raised:
    # the count is the executor's, written by the executor.
    source = (
        "# BRD-F-001\nimport socket\n\n\n"
        "def test_hides_the_attempt():\n"
        "    try:\n"
        "        socket.create_connection(('192.0.2.1', 25), timeout=1)\n"
        "    except OSError:\n"
        "        pass\n"
        "    assert True\n"
    )

    _completed, payload = _run_executor(tmp_path, source)

    assert payload["returncode"] == 0 and payload["network_refused"] == 1


def test_a_subject_that_attempts_nothing_records_zero(tmp_path: Path) -> None:
    _completed, payload = _run_executor(
        tmp_path, "# BRD-F-001\n\ndef test_quiet():\n    assert 1 + 1 == 2\n")

    assert payload["network_refused"] == 0
    assert set(payload) == {
        "schema", "returncode", "collected", "executed", "failed", "skipped",
        "network_refused", "executor_digest",
    }


def test_the_guard_is_named_the_same_by_the_parent_and_the_verifier() -> None:
    assert gate_module.GREENFIELD_NETWORK_GUARD == verifier_module.NETWORK_GUARD
    assert "not-os-confinement" in gate_module.GREENFIELD_NETWORK_GUARD
    assert gate_module.GREENFIELD_TEST_EXECUTOR_SOURCE == verifier_module.TEST_EXECUTOR_SOURCE
    assert gate_module.GREENFIELD_TEST_RUNNER_SOURCE == verifier_module.TEST_RUNNER_SOURCE
    assert gate_module.GREENFIELD_PROFILE_DEFINITION == verifier_module.PROFILE_DEFINITION
    # 5, not 4: A-049 (the governance entry) and A-053 (this guard) each moved
    # the profile 3 -> 4 on their own branches. Merged, the profile is neither
    # parent's version 4, so its version is 5 and no version names two profiles.
    assert gate_module.GREENFIELD_PROFILE_DEFINITION["version"] == 5


# ---------------------------------------------------------------------------
# The measured layer, through the real verifier and the parent's check
# ---------------------------------------------------------------------------

def test_a_completion_without_a_well_formed_count_is_not_trusted(tmp_path: Path) -> None:
    interpreter = Path(os.path.abspath(sys.executable))
    command = [
        str(interpreter), "-I", "-c", gate_module.GREENFIELD_IN_MEMORY_BOOTSTRAP,
        str(tmp_path / "executor.py"), gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
        str(tmp_path / "subject"), str(tmp_path / "inner.json"), str(tmp_path / "pytest.ini"),
        gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
    ]
    good = {
        "schema": "nornyx.greenfield.pytest_result.v2", "returncode": 1, "collected": 1,
        "executed": 1, "failed": 1, "skipped": 0, "network_refused": 0,
        "executor_digest": gate_module.GREENFIELD_TEST_EXECUTOR_DIGEST,
        "executor_command": command, "executor_cwd": command[6], "executor_returncode": 73,
    }
    trusted = gate_module._greenfield_completion_from_trusted_executor

    assert trusted(good, interpreter)
    for value in (-1, True, 1.0, "1", None):
        assert not trusted({**good, "network_refused": value}, interpreter), value
    assert not trusted({k: v for k, v in good.items() if k != "network_refused"}, interpreter)
    assert not trusted({**good, "schema": "nornyx.greenfield.pytest_result.v1"}, interpreter)


def _specimen_project(root: Path, files: dict[str, str] | None = None) -> Path:
    from nornyx_forge.contract_generator import render_runtime_contract

    root.mkdir(parents=True)
    _write(root / "BRD.md", specimen.BRD)
    contract = render_runtime_contract(parse_brd(root / "BRD.md"), specimen.DECLARATIONS)
    return specimen.write(root, files if files is not None else specimen.files(contract))


def test_the_reference_specimen_passes_and_its_one_unguarded_send_is_measured_refused(
    tmp_path: Path,
) -> None:
    project = _specimen_project(tmp_path / "project")

    gates, provenance = trusted_greenfield_gates(project)

    assert all(gate.passed for gate in gates), [(g.name, g.detail) for g in gates if not g.passed]
    execution = provenance["test_execution"]
    completion = execution["completion"]
    assert execution["network_guard"] == gate_module.GREENFIELD_NETWORK_GUARD
    assert completion["collected"] == completion["executed"] == 6
    assert completion["failed"] == completion["skipped"] == 0
    # Exactly one attempt reached the guard: the test that skips the boundary
    # and calls the adapter. The refused bulk deletion and external send never
    # got as far as a socket, because the boundary refused them first.
    assert completion["network_refused"] == 1
    assert "refused 1 network attempt(s)" in _gate(gates, "test-execution").detail
    assert "not OS confinement" in _gate(gates, "test-execution").detail


def test_the_specimens_contract_is_forges_rendering_and_its_app_imports_no_forge(
    tmp_path: Path,
) -> None:
    from nornyx_forge.contract_generator import validate_runtime_contract

    project = _specimen_project(tmp_path / "project")
    model = parse_brd(project / "BRD.md")
    contract = (project / "app/runtime_contract.json").read_text(encoding="utf-8")

    data = validate_runtime_contract(contract, model)

    assert {entry["operation"]: entry["requirement"] for entry in data["operations"]} == (
        specimen.DECLARATIONS)
    for relative in sorted(project.rglob("*.py")):
        for node in ast.walk(ast.parse(relative.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                assert all(not item.name.startswith("nornyx") for item in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("nornyx")


def test_a_boundary_that_lets_the_bulk_deletion_through_fails_the_specimens_tests(
    tmp_path: Path,
) -> None:
    # The specimen's tests are what its boundary is held to: weaken the
    # boundary and the executor records a subject failure.
    files = specimen.files(None)
    files["app/boundary.py"] = files["app/boundary.py"].replace(
        'if consequence in ALWAYS_REFUSED or entry["disposition"] != "permitted":',
        "if False:",
    )
    project = _specimen_project(tmp_path / "project", files)
    from nornyx_forge.contract_generator import render_runtime_contract
    _write(project / "app/runtime_contract.json",
           render_runtime_contract(parse_brd(project / "BRD.md"), specimen.DECLARATIONS))

    gates, provenance = trusted_greenfield_gates(project)

    test_gate = _gate(gates, "test-execution")
    assert test_gate.passed is False
    assert "isolated project tests failed" in test_gate.detail
    assert provenance["test_execution"]["completion"]["failed"] >= 1


# ---------------------------------------------------------------------------
# The static layer
# ---------------------------------------------------------------------------

_NETWORK_SPELLINGS = {
    "import socket": "import socket\nHANDLE = socket.socket\n",
    "aliased socket": "import socket as wire\nHANDLE = wire\n",
    "member of socket": "from socket import create_connection\n",
    "raw _socket": "import _socket\n",
    "ssl": "import ssl\n",
    "smtplib": "import smtplib\n",
    "ftplib": "from ftplib import FTP\n",
    "http.client": "import http.client\n",
    "client from http": "from http import client\n",
    "aliased client": "from http import client as c\n",
    "http attribute chain": "import http\nHANDLE = http.client\n",
    "http.server": "import http.server\n",
    "urllib.request": "import urllib.request\n",
    "request from urllib": "from urllib import request\n",
    "urllib attribute chain": "import urllib\nHANDLE = urllib.request.urlopen\n",
    "xmlrpc client": "import xmlrpc.client\n",
    "socketserver": "import socketserver\n",
    "wsgiref server": "from wsgiref.simple_server import make_server\n",
    "requests": "import requests\n",
    "httpx": "import httpx\n",
    "asyncio stream member": "import asyncio\nHANDLE = asyncio.open_connection\n",
    "asyncio from-import": "from asyncio import start_server\n",
    "asyncio star": "from asyncio import *\n",
    "asyncio aliased": "import asyncio as loop\nHANDLE = loop.start_server\n",
    "asyncio assigned": "import asyncio\nmod = asyncio\nHANDLE = mod.open_connection\n",
    "getattr constant": "import asyncio\nHANDLE = getattr(asyncio, 'open_' + 'connection')\n",
    "modules subscript": "import sys\nHANDLE = sys.modules['soc' + 'ket']\n",
    "modules get": "import sys as s\nHANDLE = s.modules.get('ssl')\n",
}

_NOT_NETWORK = {
    "urllib.parse": "import urllib.parse\nHANDLE = urllib.parse.quote\n",
    "http status": "from http import HTTPStatus\n",
    "a list called requests": "requests = []\nrequests.append(1)\n",
    "a parameter called socket": "def f(socket):\n    return socket.connect\n",
    "asyncio.run": "import asyncio\nHANDLE = asyncio.run\n",
    "email message": "from email.message import EmailMessage\n",
    "relative module named socket": "from . import socket\nfrom .ssl import thing\n",
    "a module named like one": "import requests_cache_free_name\n",
}


@pytest.mark.parametrize("label", sorted(_NETWORK_SPELLINGS))
def test_each_network_spelling_is_a_marker(label: str) -> None:
    tree = ast.parse(_NETWORK_SPELLINGS[label])

    assert verifier_module._network_capability_markers(tree), label


@pytest.mark.parametrize("label", sorted(_NOT_NETWORK))
def test_what_is_not_network_capability_is_not_a_marker(label: str) -> None:
    tree = ast.parse(_NOT_NETWORK[label])

    assert verifier_module._network_capability_markers(tree) == set(), label


@pytest.mark.parametrize("label", ["import socket", "urllib attribute chain", "asyncio stream member"])
def test_network_capability_outside_an_adapter_fails_the_architecture_gate(
    tmp_path: Path, label: str
) -> None:
    project = _project(tmp_path, _NETWORK_SPELLINGS[label] + "\n\ndef add(left, right):\n"
                       "    return left + right\n")

    gates, _provenance = trusted_greenfield_gates(project)

    architecture = _gate(gates, "architecture-boundary")
    assert architecture.passed is False
    assert "network capability is not behind an explicit service/tool/adapter/worker" in (
        architecture.detail)
    assert "src/app.py" in architecture.detail
    assert _gate(gates, "test-execution").passed is False   # nothing was run


def test_the_same_capability_inside_an_adapter_passes(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _write(project / "src/adapters/outbound.py",
           "import socket\n\n\ndef send(host, port, payload):\n"
           "    with socket.create_connection((host, port), timeout=1) as c:\n"
           "        c.sendall(payload)\n")

    gates, _provenance = trusted_greenfield_gates(project)

    assert all(gate.passed for gate in gates), [(g.name, g.detail) for g in gates if not g.passed]


@pytest.mark.parametrize(("capability", "source", "words"), [
    ("network", "import socket\n", "network capability"),
    ("process", "import subprocess\n", "process capability"),
])
def test_a_test_module_holding_network_or_process_capability_is_refused(
    tmp_path: Path, capability: str, source: str, words: str
) -> None:
    # Tests are subject code too: the specimen's unguarded send lives in an
    # adapter, and a test may call it, but may not hold the capability itself.
    project = _project(tmp_path)
    _write(project / "tests/test_app.py",
           "# BRD-F-001\n" + source + "from src.app import add\n\n"
           "def test_addition():\n    assert add(1, 1) == 2\n")

    gates, _provenance = trusted_greenfield_gates(project)

    architecture = _gate(gates, "architecture-boundary")
    assert architecture.passed is False, capability
    assert words in architecture.detail and "tests/test_app.py" in architecture.detail


def test_the_specimen_with_its_socket_moved_out_of_the_adapter_is_refused(
    tmp_path: Path,
) -> None:
    files = specimen.files(None)
    files["app/notebook.py"] = files["app/notebook.py"].replace(
        "from __future__ import annotations\n",
        "from __future__ import annotations\n\nimport socket\n",
    )
    assert "import socket" in files["app/notebook.py"]
    project = _specimen_project(tmp_path / "project", files)

    gates, _provenance = trusted_greenfield_gates(project)

    architecture = _gate(gates, "architecture-boundary")
    assert architecture.passed is False
    assert "app/notebook.py (socket)" in architecture.detail


# ---------------------------------------------------------------------------
# The fail-closed reference rule (A-053, review round 1)
#
# Outside an adapter, the verifier does not try to follow every alias of a
# reflective accessor. It refuses the REFERENCE: any use of `getattr`,
# `__import__`, `importlib` or `builtins` other than a direct call
# `getattr(obj, "literal")`, so no alias of them can be bound; any attribute
# named like one of asyncio's network helpers, on anything; and a literal
# `getattr` naming one. Imports of network modules were already refused at
# the import.
# ---------------------------------------------------------------------------

_REFERENCE_REFUSALS = {
    "getattr alias": "import asyncio\nfetch = getattr\nHANDLE = fetch(asyncio, 'open_connection')\n",
    "annotated alias": "from typing import Any\nfetch: Any = getattr\n",
    "walrus alias": "if (fetch := getattr):\n    HANDLE = fetch\n",
    "tuple alias": "fetch, size = getattr, len\n",
    "getattr passed on": "HANDLE = list(map(getattr, [], []))\n",
    "getattr default": "def pick(obj, accessor=getattr):\n    return accessor(obj, 'x')\n",
    "getattr rebound": "getattr = print\n",
    "getattr with keywords": "def pick(obj):\n    return getattr(obj, name='x')\n",
    "dunder import reference": "loader = __import__\n",
    "importlib import": "import importlib\n",
    "importlib member": "from importlib import import_module as load\n",
    "builtins import": "from builtins import getattr as fetch\n",
    "helper by attribute": "def go(loop):\n    return loop.create_connection\n",
    "sock helper by attribute": "def go(loop):\n    return loop.sock_connect\n",
    "server helper by attribute": "def go(anything):\n    return anything.start_server\n",
    "helper by literal getattr": "def go(loop):\n    return getattr(loop, 'create_server')\n",
    "helper from-import": "from asyncio.base_events import create_connection\n",
}

_REFERENCE_CONTROLS = {
    "direct literal getattr": "def name_of(obj):\n    return getattr(obj, '__name__')\n",
    "direct literal getattr with default": "def name_of(obj):\n    return getattr(obj, 'label', '')\n",
    "asyncio for non-network work": (
        "import asyncio\n\nTIMEOUT = asyncio.TimeoutError\n\n"
        "def queue():\n    return asyncio.Queue()\n"
    ),
}


@pytest.mark.parametrize("label", sorted(_REFERENCE_REFUSALS))
def test_each_reflective_or_helper_reference_is_a_marker(label: str) -> None:
    tree = ast.parse(_REFERENCE_REFUSALS[label])

    assert verifier_module._capability_reference_markers(tree), label


@pytest.mark.parametrize("label", sorted(_REFERENCE_CONTROLS))
def test_a_direct_literal_getattr_and_non_network_asyncio_are_not_markers(label: str) -> None:
    tree = ast.parse(_REFERENCE_CONTROLS[label])

    assert verifier_module._capability_reference_markers(tree) == set(), label


@pytest.mark.parametrize("label", [
    "getattr alias", "annotated alias", "walrus alias", "tuple alias",
    "helper by attribute", "helper by literal getattr",
])
def test_a_reference_outside_an_adapter_fails_the_architecture_gate(
    tmp_path: Path, label: str
) -> None:
    project = _project(tmp_path, _REFERENCE_REFUSALS[label]
                       + "\n\ndef add(left, right):\n    return left + right\n")

    gates, _provenance = trusted_greenfield_gates(project)

    architecture = _gate(gates, "architecture-boundary")
    assert architecture.passed is False, label
    assert "reference is not behind an explicit service/tool/adapter/worker" in (
        architecture.detail)
    assert "src/app.py" in architecture.detail
    assert _gate(gates, "test-execution").passed is False   # nothing was run


def test_an_imported_alias_of_a_network_module_fails_the_architecture_gate(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path, "from urllib import request as fetch_url\n\n\n"
                       "def add(left, right):\n    return left + right\n")

    gates, _provenance = trusted_greenfield_gates(project)

    architecture = _gate(gates, "architecture-boundary")
    assert architecture.passed is False
    assert "network capability" in architecture.detail and "urllib.request" in architecture.detail


def test_the_same_references_inside_an_adapter_pass(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _write(project / "src/adapters/outbound.py",
           "import asyncio\n\nfetch = getattr\n\n\n"
           "def opener():\n    return fetch(asyncio, 'open_connection')\n")

    gates, _provenance = trusted_greenfield_gates(project)

    assert all(gate.passed for gate in gates), [(g.name, g.detail) for g in gates if not g.passed]


def test_non_network_asyncio_and_a_literal_getattr_outside_an_adapter_pass(
    tmp_path: Path,
) -> None:
    project = _project(
        tmp_path,
        "import asyncio\n\nTIMEOUT = asyncio.TimeoutError\n\n\n"
        "def add(left, right):\n    return getattr(left, '__add__')(right)\n",
    )

    gates, _provenance = trusted_greenfield_gates(project)

    assert all(gate.passed for gate in gates), [(g.name, g.detail) for g in gates if not g.passed]


# ---------------------------------------------------------------------------
# The whole class, challenged (A-053, review round 1)
# ---------------------------------------------------------------------------

import network_class_challenge as challenge  # noqa: E402


def _static_refusals(source: str) -> set[str]:
    """Everything the verifier's static layer refuses in a non-adapter module."""
    tree = ast.parse(source)
    return (
        verifier_module._network_capability_markers(tree)
        | verifier_module._capability_reference_markers(tree)
        | set(verifier_module._execution_control_findings(
            tree, relative="src/app.py", is_test=False))
    )


@pytest.mark.parametrize("label", sorted(challenge.CHALLENGE))
def test_every_variant_of_the_class_is_refused_outside_an_adapter(label: str) -> None:
    assert _static_refusals(challenge.CHALLENGE[label]), label


@pytest.mark.parametrize("label", sorted(challenge.CONTROLS))
def test_the_class_controls_stay_accepted(label: str) -> None:
    assert _static_refusals(challenge.CONTROLS[label]) == set(), label


# ---------------------------------------------------------------------------
# One name check at every name position (A-053, review round 2)
#
# The exact-head review found two positions checked against a narrower set
# than the rest: a literal `getattr` member (only network helpers) and a
# class pattern's keyword attribute (no reflective names). Every position now
# calls `_forbidden_name`, the one combined set. Each position below is tried
# with a name from each part of that set.
# ---------------------------------------------------------------------------

_NAME_POSITIONS = {
    "plain name": "HANDLE = {n}\n",
    "stored name": "{n} = 1\n",
    "attribute": "def go(thing):\n    return thing.{n}\n",
    "import": "import {n}\n",
    "dotted import part": "import package.{n}\n",
    "import alias": "import json as {n}\n",
    "from-import module part": "from {n} import thing\n",
    "from-import name": "from package import {n}\n",
    "from-import alias": "from package import thing as {n}\n",
    "getattr literal": "def go(o):\n    return getattr(o, '{n}')\n",
    "hasattr literal": "def go(o):\n    return hasattr(o, '{n}')\n",
    "setattr literal": "def go(o):\n    setattr(o, '{n}', 1)\n",
    "delattr literal": "def go(o):\n    delattr(o, '{n}')\n",
    "class pattern keyword attribute": (
        "def go(o):\n    match o:\n        case object({n}=grab):\n            return grab\n"),
    "keyword argument": "HANDLE = dict({n}=1)\n",
    "capture": "def go(o):\n    match o:\n        case {n}:\n            return 1\n",
    "star capture": "def go(o):\n    match o:\n        case [*{n}]:\n            return 1\n",
    "mapping rest": "def go(o):\n    match o:\n        case {{**{n}}}:\n            return 1\n",
    "parameter": "def go({n}):\n    return 1\n",
    "function definition": "def {n}():\n    return 1\n",
    "class definition": "class {n}:\n    pass\n",
    "except name": "try:\n    pass\nexcept Exception as {n}:\n    pass\n",
    "global": "def go():\n    global {n}\n",
}
#: One name from each part of the combined set.
_FORBIDDEN_SAMPLES = {
    "reflective": "attrgetter",
    "network attribute": "socket",
    "network helper": "open_connection",
    "sock helper": "sock_sendall",
    "code loading": "pickle",
}


@pytest.mark.parametrize("position", sorted(_NAME_POSITIONS))
@pytest.mark.parametrize("part", sorted(_FORBIDDEN_SAMPLES))
def test_every_name_position_checks_the_whole_forbidden_set(position: str, part: str) -> None:
    source = _NAME_POSITIONS[position].format(n=_FORBIDDEN_SAMPLES[part])

    assert verifier_module._capability_reference_markers(ast.parse(source)), (position, part)


@pytest.mark.parametrize("position", sorted(_NAME_POSITIONS))
def test_every_name_position_accepts_an_ordinary_name(position: str) -> None:
    source = _NAME_POSITIONS[position].format(n="label")

    assert verifier_module._capability_reference_markers(ast.parse(source)) == set(), position


def test_the_one_name_check_is_the_union_of_the_four_tables() -> None:
    for name in (*verifier_module._REFLECTIVE_NAMES, *verifier_module._NETWORK_ATTRIBUTE_NAMES,
                 *verifier_module._CODE_LOADING_MODULES, *verifier_module._ASYNC_NETWORK_HELPERS,
                 "sock_anything"):
        assert verifier_module._forbidden_name(name), name
    for name in ("label", "parse", "quote", "asyncio", "Queue", None, 7):
        assert not verifier_module._forbidden_name(name), name


@pytest.mark.parametrize(("label", "source"), [
    ("literal getattr naming an accessor",
     "import asyncio\nimport operator\n\n"
     "HANDLE = getattr(operator, 'attrgetter')('open_connection')(asyncio)\n"),
    ("class pattern naming an accessor",
     "def go(thing):\n    match thing:\n        case object(attrgetter=grab):\n"
     "            return grab\n"),
])
def test_both_review_findings_fail_the_architecture_gate(
    tmp_path: Path, label: str, source: str
) -> None:
    project = _project(tmp_path, source + "\n\ndef add(left, right):\n    return left + right\n")

    gates, _provenance = trusted_greenfield_gates(project)

    architecture = _gate(gates, "architecture-boundary")
    assert architecture.passed is False, label
    assert "attrgetter" in architecture.detail and "src/app.py" in architecture.detail


def test_ordinary_literal_getattr_class_pattern_and_asyncio_pass_the_gates(
    tmp_path: Path,
) -> None:
    project = _project(
        tmp_path,
        "import asyncio\n\nTIMEOUT = asyncio.TimeoutError\n\n\n"
        "def kind(point):\n    match point:\n        case object(x=0, y=across):\n"
        "            return across\n    return getattr(point, 'label', None)\n\n\n"
        "def add(left, right):\n    return left + right\n",
    )

    gates, _provenance = trusted_greenfield_gates(project)

    assert all(gate.passed for gate in gates), [(g.name, g.detail) for g in gates if not g.passed]
