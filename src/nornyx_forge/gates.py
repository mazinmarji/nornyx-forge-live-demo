from __future__ import annotations

import hashlib
import importlib.metadata
import json
import locale
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .models import GateResult

GREENFIELD_PROFILE_ID = "nornyx.greenfield.python.v1"
GREENFIELD_VERIFIER_ID = "nornyx_forge.greenfield_verifier"
GREENFIELD_PROFILE_DEFINITION = {
    "id": GREENFIELD_PROFILE_ID,
    # 5: A-049's governance entry and A-053's network guard each moved the
    # profile 3 -> 4 on its own branch; merged, it is neither of those, so no
    # version number names two different profiles.
    "version": 5,
    "checks": [
        "project-structure",
        "requirements-traceability",
        "source-compilation",
        "test-semantics",
        "architecture-boundary",
        "security-static",
        "test-execution",
    ],
    "execution": "bounded-static-inspection-and-isolated-tests",
    # A-049. Run by the trusted parent after the verifier, not by the
    # verifier: the real Nornyx CLI on a private snapshot of the contract this
    # build generated, only when its bytes still have the digest the flow
    # recorded at generation. Declared here so the profile's digest names a
    # profile that runs it.
    "governance": {
        "checks": ["nornyx-contract-check"],
        "subject": ".nornyx/generated/brd_contract.nyx",
        "binding": "sha256-recorded-at-generation",
        "execution": "trusted-parent-isolated-nornyx-cli-on-private-snapshot",
    },
}
GREENFIELD_GATE_IDS = tuple(GREENFIELD_PROFILE_DEFINITION["checks"])
GREENFIELD_GOVERNANCE_CHECK = GREENFIELD_PROFILE_DEFINITION["governance"]["checks"][0]
GENERATED_CONTRACT_PATH = GREENFIELD_PROFILE_DEFINITION["governance"]["subject"]
GOVERNANCE_CHECK_SCHEMA = "nornyx.forge.governance_check.v1"
#: The Nornyx CLI's own entry point, as its console script calls it, run by
#: the trusted interpreter with `-I`: no PATH lookup decides which `nornyx`
#: runs, and no project directory is on the import path. Exactly this string
#: is what `experience_build` recognises as a Nornyx gate (A-049).
NORNYX_CHECK_BOOTSTRAP = (
    "import sys;from nornyx.cli import main;"
    "sys.argv=['nornyx']+sys.argv[1:];sys.exit(main())"
)
#: A generated contract is a few kilobytes per requirement; a file this large
#: is not one Forge generated, and is not read into memory to find that out.
GOVERNANCE_CONTRACT_MAX_BYTES = 16 * 1024 * 1024
#: The private snapshot's directory prefix and file name. `experience_build`
#: holds a copy of both, and recognises a check only over a snapshot of this
#: shape (Codex P2 4353133125 on `8ae32b3`).
GOVERNANCE_SNAPSHOT_PREFIX = "nornyx-forge-governance-"
GOVERNANCE_SNAPSHOT_NAME = "brd_contract.nyx"
GOVERNANCE_CHECK_TIMEOUT_SECONDS = 120
#: What Nornyx prints after its diagnostics when a contract passes.
_NORNYX_PASSED_LINE = "Nornyx check passed"
#: Nornyx's exit statuses for a contract it refused: 1 for validation errors,
#: 2 for a document it could not parse. Measured on nornyx 1.11.0.
_NORNYX_REFUSAL_STATUSES = frozenset({1, 2})
GREENFIELD_IN_MEMORY_BOOTSTRAP = (
    "import builtins,hashlib,sys;"
    "p=sys.argv[1];expected=sys.argv[2];data=open(p,'rb').read();"
    "actual='sha256:'+hashlib.sha256(data).hexdigest();"
    "actual==expected or (_ for _ in ()).throw(SystemExit('snapshot digest mismatch'));"
    "sys.argv=[p]+sys.argv[3:];"
    "getattr(builtins,'ex'+'ec')(compile(data,p,'exec'),"
    "{'__name__':'__main__','__file__':p})"
)

GREENFIELD_TEST_EXECUTOR_SOURCE = """from __future__ import annotations
def _entry():
    import json as _json
    import os as _os
    import sys as _sys
    from pathlib import Path as _Path
    import pytest as _pytest

    _subject = _Path(_sys.argv[1]).resolve(strict=True)
    _result_path = _Path(_sys.argv[2]).resolve()
    _config_path = _Path(_sys.argv[3]).resolve(strict=True)
    _executor_digest = _sys.argv[4]
    _test_tmp = (_subject / ".nornyx-test-tmp").resolve()
    _test_tmp.mkdir(parents=True, exist_ok=True)
    _dumps = _json.dumps
    _open = _os.open
    _write = _os.write
    _close = _os.close
    _pytest_main = _pytest.main
    _int = int
    _len = len
    _system_exit = SystemExit
    _permission_error = PermissionError
    _get_ident = __import__("_thread").get_ident
    _trusted_result_writer = [None]
    _write_flags = (
        _os.O_WRONLY | _os.O_RDWR | _os.O_CREAT | _os.O_TRUNC | _os.O_APPEND
    )
    _network_refused = [0]
    _network_events = frozenset({
        "socket.bind", "socket.connect", "socket.getaddrinfo",
        "socket.gethostbyaddr", "socket.gethostbyname", "socket.getnameinfo",
        "socket.sendmsg", "socket.sendto",
    })

    def _inside(_path, _root):
        try:
            _path.relative_to(_root)
        except ValueError:
            return False
        return True

    def _resolved(_raw):
        try:
            _path = _Path(_os.fspath(_raw))
        except (TypeError, ValueError):
            return None
        if not _path.is_absolute():
            _path = _subject / _path
        try:
            return _path.resolve(strict=False)
        except OSError:
            return None

    def _write_is_allowed(_raw):
        _path = _resolved(_raw)
        if _path is None:
            return False
        if _trusted_result_writer[0] == _get_ident() and _path == _result_path:
            return True
        return _inside(_path, _test_tmp)

    def _audit(_event, _args):
        if _event in _network_events:
            _network_refused[0] += 1
            raise PermissionError(
                "test process cannot use the network (a test guard, not OS confinement)"
            )
        if _event == "open":
            _mode = _args[1] if _len(_args) > 1 else None
            _flags = _args[2] if _len(_args) > 2 else 0
            _writes = (
                isinstance(_mode, str) and any(_mark in _mode for _mark in "wax+")
            ) or (isinstance(_flags, int) and bool(_flags & _write_flags))
            if _writes and not _write_is_allowed(_args[0]):
                raise PermissionError("test process cannot write outside its private temp root")
        elif _event in {
            "os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown",
            "os.truncate", "os.utime",
        }:
            if _args and not _write_is_allowed(_args[0]):
                raise PermissionError("test process cannot mutate outside its private temp root")
        elif _event == "os.link":
            if _len(_args) < 2 or not all(
                _write_is_allowed(_item) for _item in _args[:2]
            ):
                raise PermissionError("test process cannot link outside its private temp root")
        elif _event == "os.symlink":
            if _len(_args) < 2 or not _write_is_allowed(_args[1]):
                raise PermissionError("test process cannot link outside its private temp root")
        elif _event == "os.rename":
            if _len(_args) < 2 or not all(_write_is_allowed(_item) for _item in _args[:2]):
                raise PermissionError("test process cannot rename outside its private temp root")
        elif _event == "os.chdir":
            _target = _resolved(_args[0]) if _args else None
            if _target != _subject and not (
                _target is not None and _inside(_target, _test_tmp)
            ):
                raise PermissionError("test process cannot leave the private subject roots")
        elif _event in {
            "os.system", "os.fork", "os.forkpty", "os.posix_spawn", "subprocess.Popen",
        }:
            raise PermissionError("test process cannot change execution authority")

    def _refuse_interpreter_callback(*_args, **_kwargs):
        raise _permission_error("test process cannot register interpreter callbacks")

    class _Recorder:
        def __init__(self):
            self.collected = 0
            self.executed = 0
            self.failed = 0
            self.skipped = 0

        def pytest_collection_finish(self, session):
            self.collected = _len(session.items)

        def pytest_runtest_logreport(self, report):
            if report.when == "call":
                self.executed += 1
                self.failed += _int(report.failed)
                self.skipped += _int(report.skipped)
            elif report.when == "setup" and (report.failed or report.skipped):
                self.executed += 1
                self.failed += _int(report.failed)
                self.skipped += _int(report.skipped)
            elif report.when == "teardown" and report.failed:
                self.failed += 1

    _recorder = _Recorder()
    _sys.argv[:] = [str(_subject)]
    if hasattr(_sys, "orig_argv"):
        _sys.orig_argv[:] = [str(_subject)]
    _module = _sys.modules.get("__main__")
    if _module is not None:
        for _name in tuple(vars(_module)):
            if _name not in {"__builtins__", "__name__", "__package__", "__spec__"}:
                vars(_module).pop(_name, None)
    _sys.path.insert(0, str(_subject / "src"))
    _sys.path.insert(0, str(_subject))
    _sys.addaudithook(_audit)
    _sys.addaudithook = _refuse_interpreter_callback
    _sys.call_tracing = _refuse_interpreter_callback
    _sys.set_asyncgen_hooks = _refuse_interpreter_callback
    _sys.setprofile = _refuse_interpreter_callback
    _sys.settrace = _refuse_interpreter_callback
    _returncode = _int(_pytest_main([
        "-q", "--capture=no", "--disable-warnings", "--maxfail=1", "--noconftest",
        "-p", "no:cacheprovider", "-p", "no:logging",
        "-c", str(_config_path), "-o", "addopts=",
        "-o", "python_files=test_*.py", "-o", "python_functions=test_*",
        "-o", "python_classes=Test*", "--basetemp", str(_test_tmp),
        "--rootdir", str(_subject), str(_subject / "tests"),
    ], plugins=[_recorder]))
    _payload = _dumps({
        "schema": "nornyx.greenfield.pytest_result.v2",
        "returncode": _returncode,
        "collected": _recorder.collected,
        "executed": _recorder.executed,
        "failed": _recorder.failed,
        "skipped": _recorder.skipped,
        "network_refused": _network_refused[0],
        "executor_digest": _executor_digest,
    }, sort_keys=True).encode("utf-8")
    _trusted_result_writer[0] = _get_ident()
    try:
        _descriptor = _open(
            _result_path,
            _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | getattr(_os, "O_BINARY", 0),
            0o600,
        )
        try:
            if _write(_descriptor, _payload) != _len(_payload):
                raise OSError("short trusted result write")
        finally:
            _close(_descriptor)
    finally:
        _trusted_result_writer[0] = None
    raise _system_exit(73)

_entry()
"""

GREENFIELD_TEST_EXECUTOR_DIGEST = (
    "sha256:" + hashlib.sha256(GREENFIELD_TEST_EXECUTOR_SOURCE.encode("utf-8")).hexdigest()
)
#: What the executor's network guard is, as the verifier records it (A-053):
#: the audit hook refuses and counts each socket connect, bind, send-to and
#: name lookup while the subject's tests run. A TEST MECHANISM, NOT OS
#: CONFINEMENT: code reaching the network through ctypes, a native extension
#: or another process is outside an audit hook. A copy of the verifier's
#: `NETWORK_GUARD`, held equal by a test.
GREENFIELD_NETWORK_GUARD = "executor-audit-hook-refusal-test-mechanism-not-os-confinement"

GREENFIELD_TEST_RUNNER_SOURCE = f"""from __future__ import annotations
import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

EXECUTOR_SOURCE = {GREENFIELD_TEST_EXECUTOR_SOURCE!r}
EXECUTOR_DIGEST = {GREENFIELD_TEST_EXECUTOR_DIGEST!r}
DIGEST_BOOTSTRAP = {GREENFIELD_IN_MEMORY_BOOTSTRAP!r}
subject = Path(sys.argv[1]).resolve(strict=True)
scratch = Path(__file__).resolve().parent
executor = scratch / "greenfield_pytest_executor.py"
inner_result = scratch / ("greenfield_pytest_inner_" + secrets.token_hex(16) + ".json")
final_result = scratch / "greenfield_test_result.json"
config = scratch / "greenfield_pytest.ini"
executor.write_text(EXECUTOR_SOURCE, encoding="utf-8", newline="\\n")
executor.chmod(0o444)
config.write_text("[pytest]\\n", encoding="utf-8", newline="\\n")
config.chmod(0o444)
before_digest = hashlib.sha256(executor.read_bytes()).hexdigest()
executor_command = [
    sys.executable, "-I", "-c", DIGEST_BOOTSTRAP, str(executor), EXECUTOR_DIGEST,
    str(subject), str(inner_result), str(config), EXECUTOR_DIGEST,
]
completed = subprocess.run(
    executor_command,
    cwd=subject,
    env=dict(os.environ),
    check=False,
)
after_digest = hashlib.sha256(executor.read_bytes()).hexdigest()
try:
    metadata = inner_result.stat()
    if metadata.st_size > 4096 or not inner_result.is_file():
        raise ValueError("inner result is not a bounded regular file")
    payload = json.loads(inner_result.read_text(encoding="utf-8"))
except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
    payload = None
keys = {{
    "schema", "returncode", "collected", "executed", "failed", "skipped",
    "network_refused", "executor_digest",
}}
integrity = (
    "sha256:" + before_digest == EXECUTOR_DIGEST
    and "sha256:" + after_digest == EXECUTOR_DIGEST
    and isinstance(payload, dict)
    and set(payload) == keys
    and payload.get("schema") == "nornyx.greenfield.pytest_result.v2"
    and payload.get("executor_digest") == EXECUTOR_DIGEST
    and completed.returncode == 73
    and all(
        isinstance(payload.get(name), int) and not isinstance(payload.get(name), bool)
        for name in (
            "returncode", "collected", "executed", "failed", "skipped", "network_refused",
        )
    )
    and payload.get("network_refused") >= 0
)
passed = integrity and (
    payload.get("returncode") == 0
    and payload.get("collected", 0) >= 1
    and payload.get("executed") == payload.get("collected")
    and payload.get("failed") == 0
    and payload.get("skipped") == 0
)
# The trusted executor completed and produced a well-formed, digest-bound
# record whenever integrity holds, WHETHER OR NOT the subject's tests passed.
# Writing it only on success collapsed two states: a subject that ran and
# failed, and a trusted executor that never completed, both left no record.
# The record is written on either outcome so the parser can tell a genuine
# subject failure (a record showing failures) from a completion that was
# never established (no record). The exit code still marks pass from not-pass.
if integrity:
    payload["executor_command"] = executor_command
    payload["executor_cwd"] = str(subject)
    payload["executor_returncode"] = completed.returncode
    final_result.open("x", encoding="utf-8").write(json.dumps(payload, sort_keys=True))
raise SystemExit(0 if passed else 2)
"""


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


GREENFIELD_PROFILE_DIGEST = _canonical_digest(GREENFIELD_PROFILE_DEFINITION)
GREENFIELD_TEST_RUNNER_DIGEST = (
    "sha256:" + hashlib.sha256(GREENFIELD_TEST_RUNNER_SOURCE.encode("utf-8")).hexdigest()
)
GREENFIELD_RESOURCE_LIMITS = (
    {
        "enforced": True,
        "platform": "windows-job-object",
        "process_memory_bytes": 768 * 1024 * 1024,
        "job_memory_bytes": 1024 * 1024 * 1024,
        "active_processes": 8,
    }
    if os.name == "nt"
    else {
        "enforced": True,
        "platform": "posix-rlimit",
        "process_memory_bytes": 768 * 1024 * 1024,
        # An INCREMENT above the real user id's ambient task count, not a total.
        # RLIMIT_NPROC is charged per real user id host-wide, so a total here
        # would name a rule the verifier does not enforce.
        "additional_processes": 64,
        "process_budget": "ambient-real-uid-tasks-plus-fixed-increment",
        "cpu_seconds": 120,
    }
)

_VERIFIER_BOOTSTRAP = GREENFIELD_IN_MEMORY_BOOTSTRAP


def _digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _greenfield_completion_from_trusted_executor(
    completion: Any, interpreter: Path
) -> bool:
    """Whether a completion record is well-formed and produced by the executor.

    This is the trust axis, not the pass/fail axis: it establishes that the
    record came from the digest-verified executor exiting on its sentinel, and
    says nothing about whether the subject's tests passed. The pass branch adds
    the success predicate on top; the failure branch requires the opposite.
    """
    if not isinstance(completion, dict):
        return False
    if set(completion) != {
        "schema",
        "returncode",
        "collected",
        "executed",
        "failed",
        "skipped",
        "network_refused",
        "executor_digest",
        "executor_command",
        "executor_cwd",
        "executor_returncode",
    }:
        return False
    command = completion.get("executor_command")
    counts = [
        completion.get(name)
        for name in (
            "returncode", "collected", "executed", "failed", "skipped", "network_refused",
        )
    ]
    return not (
        completion.get("schema") != "nornyx.greenfield.pytest_result.v2"
        or completion.get("executor_digest") != GREENFIELD_TEST_EXECUTOR_DIGEST
        or not isinstance(command, list)
        or len(command) != 10
        or command[:4] != [str(interpreter), "-I", "-c", GREENFIELD_IN_MEMORY_BOOTSTRAP]
        or any(not isinstance(item, str) for item in command)
        or command[5] != GREENFIELD_TEST_EXECUTOR_DIGEST
        or command[9] != GREENFIELD_TEST_EXECUTOR_DIGEST
        or not Path(command[4]).is_absolute()
        or not Path(command[6]).is_absolute()
        or not Path(command[7]).is_absolute()
        or not Path(command[8]).is_absolute()
        or completion.get("executor_cwd") != command[6]
        or completion.get("executor_returncode") != 73
        or any(not isinstance(value, int) or isinstance(value, bool) for value in counts)
        or completion.get("network_refused") < 0
    )


def _greenfield_completion_shows_pass(completion: Any) -> bool:
    """Whether a trusted completion record reports a clean subject pass."""
    if not isinstance(completion, dict):
        return False
    collected = completion.get("collected")
    return (
        completion.get("returncode") == 0
        and isinstance(collected, int)
        and not isinstance(collected, bool)
        and collected >= 1
        and completion.get("executed") == collected
        and completion.get("failed") == 0
        and completion.get("skipped") == 0
    )


def _greenfield_verifier_path() -> Path:
    return Path(__file__).with_name("greenfield_verifier.py").resolve(strict=True)


def _git_directory(marker: Path) -> Path | None:
    if marker.is_dir():
        return marker
    if not marker.is_file():
        return None
    try:
        line = marker.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not line.startswith("gitdir: "):
        return None
    candidate = Path(line.removeprefix("gitdir: "))
    if not candidate.is_absolute():
        candidate = marker.parent / candidate
    try:
        return candidate.resolve(strict=True)
    except OSError:
        return None


def _forge_revision(origin: Path, version: str) -> str:
    for ancestor in origin.parents:
        git_dir = _git_directory(ancestor / ".git")
        if git_dir is None:
            continue
        try:
            head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
            if re.fullmatch(r"[0-9a-fA-F]{40}", head):
                return "git:" + head.lower()
            if head.startswith("ref: "):
                ref = head.removeprefix("ref: ")
                loose = git_dir / ref
                if loose.is_file():
                    value = loose.read_text(encoding="utf-8").strip()
                    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
                        return "git:" + value.lower()
                packed = git_dir / "packed-refs"
                if packed.is_file():
                    for line in packed.read_text(encoding="utf-8").splitlines():
                        if line.startswith(("#", "^")):
                            continue
                        parts = line.split(" ", 1)
                        if len(parts) == 2 and parts[1] == ref:
                            return "git:" + parts[0].lower()
        except OSError:
            break
    return "package:" + version


def _forge_version() -> str:
    try:
        return importlib.metadata.version("nornyx-forge-live-demo")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _trusted_loader_path(project: Path) -> Path | None:
    """Derive Linux's loader directory from the trusted running Python.

    ``actions/setup-python`` installs a shared-library build whose absolute
    interpreter still needs its own ``lib`` directory in ``LD_LIBRARY_PATH``.
    Inheriting that variable would let provider state select native code, so
    derive the one allowed directory from ``sys.base_prefix`` instead.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        candidate = (Path(sys.base_prefix) / "lib").resolve(strict=True)
    except OSError:
        return None
    if not candidate.is_dir() or _inside(candidate, project):
        return None
    return candidate


def _verifier_environment(loader_path: Path | None = None) -> dict[str, str]:
    """A small host allowlist; project PATH/PYTHON* state is not inherited."""
    allowed = ("COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR")
    result = {name: os.environ[name] for name in allowed if name in os.environ}
    if loader_path is not None:
        result["LD_LIBRARY_PATH"] = str(loader_path)
    return result


def _closed_failure(
    detail: str,
    *,
    command: tuple[str, ...] = (),
    returncode: int = 2,
    provenance: dict[str, Any] | None = None,
) -> tuple[list[GateResult], dict[str, Any]]:
    record = provenance or {
        "schema": "nornyx.forge.verifier_provenance.v1",
        "trust": "not_established",
        "gate_profile": {"id": GREENFIELD_PROFILE_ID},
        "verifier": {"id": GREENFIELD_VERIFIER_ID},
    }
    return (
        [
            GateResult(
                "greenfield:trusted-verifier-identity",
                False,
                detail,
                command,
                returncode,
                record,
            )
        ],
        record,
    )


def trusted_greenfield_gates(root: Path) -> tuple[list[GateResult], dict[str, Any]]:
    """Run the Forge-owned greenfield profile without trusting project state.

    The project is an argument, never the verifier working directory. The
    interpreter path is absolute, ``-I`` ignores project import/environment
    precedence, and each child receives a constructed environment with no PATH,
    PYTHONPATH, or PYTHONHOME. Verifier, runner, and executor snapshots are each
    read once, digest-checked, and executed from those in-memory bytes. Tests run
    from a separate private subject copy under OS resource limits.
    """
    try:
        project = Path(root).resolve(strict=True)
        verifier = _greenfield_verifier_path()
        interpreter = Path(sys.executable)
        if not interpreter.is_absolute():
            return _closed_failure(
                "Python interpreter path is not absolute; executable trust is absent"
            )
        interpreter = Path(os.path.abspath(interpreter))
        interpreter_target = interpreter.resolve(strict=True)
    except OSError as exc:
        return _closed_failure(f"trusted verifier identity cannot be resolved: {exc}")
    if not project.is_dir():
        return _closed_failure(f"greenfield project root is not a directory: {project}")
    if _inside(verifier, project):
        return _closed_failure(
            "trusted verifier is inside the provider workspace; structural trust is absent"
        )
    if _inside(interpreter, project) or _inside(interpreter_target, project):
        return _closed_failure(
            "Python interpreter is inside the provider workspace; executable trust is absent"
        )
    loader_path = _trusted_loader_path(project)

    try:
        verifier_bytes = verifier.read_bytes()
    except OSError as exc:
        return _closed_failure(f"trusted verifier bytes cannot be read: {exc}")
    before_digest = "sha256:" + hashlib.sha256(verifier_bytes).hexdigest()
    forge_version = _forge_version()
    forge_revision = _forge_revision(verifier, forge_version)
    command: tuple[str, ...] = ()
    try:
        with tempfile.TemporaryDirectory(prefix="nornyx-forge-verifier-") as scratch:
            snapshot = Path(scratch) / "greenfield_verifier.py"
            snapshot.write_bytes(verifier_bytes)
            snapshot.chmod(0o444)
            snapshot_status = os.lstat(snapshot)
            command = (
                str(interpreter),
                "-I",
                "-c",
                _VERIFIER_BOOTSTRAP,
                str(snapshot),
                before_digest,
                "--project-root",
                str(project),
                "--trusted-origin",
                str(verifier),
                "--trusted-digest",
                before_digest,
                "--forge-version",
                forge_version,
                "--forge-revision",
                forge_revision,
            )
            if loader_path is not None:
                command += ("--trusted-loader-path", str(loader_path))
            invocation = {
                "python": str(interpreter),
                "python_resolved_target": str(interpreter_target),
                "trusted_loader_path": str(loader_path) if loader_path else None,
                "isolated_python": True,
                "cwd": str(verifier.parent),
                "environment": "constructed-host-allowlist-without-path-or-pythonpath",
                "verifier_execution": "digest-verified-in-memory-byte-snapshot",
                "command": list(command),
            }
            completed = subprocess.run(
                command,
                cwd=verifier.parent,
                env=_verifier_environment(loader_path),
                text=True,
                capture_output=True,
                check=False,
                timeout=120,
            )
            # Read back through one descriptor, never by name (the class of
            # Codex P1 4353133109, A-049): a pipe put in its place blocked
            # this read with no timeout left to end it. Anything but the file
            # written is no digest, which the identity check below refuses.
            snapshot_bytes, snapshot_refusal = _read_inspected_file(
                snapshot, snapshot_status, len(verifier_bytes)
            )
            snapshot_digest = (
                "sha256:" + hashlib.sha256(snapshot_bytes).hexdigest()
                if snapshot_bytes is not None
                else f"unreadable: the snapshot {snapshot_refusal}"
            )
            execution_origin = str(snapshot.resolve(strict=True))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _closed_failure(
            f"trusted verifier could not run: {type(exc).__name__}: {exc}",
            command=command,
            returncode=124 if isinstance(exc, subprocess.TimeoutExpired) else 2,
        )

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        return _closed_failure(
            f"trusted verifier returned invalid JSON: {exc}; stderr={completed.stderr.strip()!r}",
            command=command,
            returncode=completed.returncode,
        )
    if not isinstance(payload, dict):
        return _closed_failure(
            "trusted verifier result is not an object",
            command=command,
            returncode=completed.returncode,
        )

    profile = payload.get("gate_profile")
    verifier_claim = payload.get("verifier")
    raw_gates = payload.get("gates")
    subject_claim = payload.get("subject")
    resource_limits = payload.get("resource_limits")
    test_execution = payload.get("test_execution")
    after_digest = _digest_file(verifier)
    identity_problems: list[str] = []
    if payload.get("schema") != "nornyx.forge.greenfield_verification.v1":
        identity_problems.append("unexpected verifier result schema")
    expected_profile = {
        **GREENFIELD_PROFILE_DEFINITION,
        "digest": GREENFIELD_PROFILE_DIGEST,
    }
    if profile != expected_profile:
        identity_problems.append("gate profile does not match the parent-owned definition")
    if not isinstance(verifier_claim, dict):
        identity_problems.append("verifier provenance is absent")
    else:
        if verifier_claim.get("id") != GREENFIELD_VERIFIER_ID:
            identity_problems.append("unexpected verifier identity")
        if verifier_claim.get("origin") != str(verifier):
            identity_problems.append("verifier origin does not match the trusted installation")
        if verifier_claim.get("execution_origin") != execution_origin:
            identity_problems.append("verifier execution origin is not the private snapshot")
        if (
            verifier_claim.get("digest") != before_digest
            or verifier_claim.get("execution_digest") != snapshot_digest
            or snapshot_digest != before_digest
            or after_digest != before_digest
        ):
            identity_problems.append("installed or snapshotted verifier digest changed or disagrees")
        if forge_version == "unknown" or verifier_claim.get("forge_version") != forge_version:
            identity_problems.append("Forge version does not match the trusted installation")
        if verifier_claim.get("forge_revision") != forge_revision:
            identity_problems.append("Forge revision does not match the trusted installation")
    if not isinstance(subject_claim, dict):
        identity_problems.append("subject provenance is absent")
    else:
        if subject_claim.get("root") != str(project):
            identity_problems.append("subject root does not match the inspected project")
        if not re_full_digest(subject_claim.get("digest")):
            identity_problems.append("subject digest is absent or malformed")
        file_count = subject_claim.get("file_count")
        if not isinstance(file_count, int) or isinstance(file_count, bool) or file_count < 1:
            identity_problems.append("subject file count is absent or invalid")
    if resource_limits != GREENFIELD_RESOURCE_LIMITS:
        identity_problems.append("OS resource limits do not match the parent-owned policy")
    if not isinstance(test_execution, dict):
        identity_problems.append("test-execution provenance is absent")
    if not isinstance(raw_gates, list):
        identity_problems.append("verifier returned no gate list")
    else:
        raw_ids = [raw.get("id") if isinstance(raw, dict) else None for raw in raw_gates]
        if raw_ids != list(GREENFIELD_GATE_IDS):
            identity_problems.append("verifier gate identifiers do not exactly match the profile")
    if completed.stderr.strip():
        identity_problems.append("trusted verifier wrote unexpected stderr")
    if identity_problems:
        return _closed_failure(
            "; ".join(identity_problems),
            command=command,
            returncode=completed.returncode,
        )

    assert isinstance(profile, dict) and isinstance(verifier_claim, dict)
    provenance = {
        "schema": "nornyx.forge.verifier_provenance.v1",
        "trust": "structural-origin-and-digest",
        "gate_profile": profile,
        "verifier": verifier_claim,
        "subject": subject_claim,
        "resource_limits": resource_limits,
        "test_execution": test_execution,
        "invocation": invocation,
    }
    results: list[GateResult] = []
    identifiers: set[str] = set()
    for raw in raw_gates:
        if (
            not isinstance(raw, dict)
            or set(raw) != {"id", "passed", "detail"}
            or not isinstance(raw.get("id"), str)
            or not isinstance(raw.get("passed"), bool)
            or not isinstance(raw.get("detail"), str)
            or raw["id"] in identifiers
        ):
            return _closed_failure(
                "trusted verifier returned a malformed or duplicate gate record",
                command=command,
                returncode=completed.returncode,
                provenance=provenance,
            )
        identifiers.add(raw["id"])
        results.append(
            GateResult(
                f"greenfield:{raw['id']}",
                raw["passed"],
                raw["detail"],
                command,
                0 if raw["passed"] else 2,
                provenance,
            )
        )
    passed = all(result.passed for result in results)
    test_gate = next(result for result in results if result.name == "greenfield:test-execution")
    if test_gate.passed:
        test_command = test_execution.get("command") if isinstance(test_execution, dict) else None
        test_subject = test_execution.get("subject_digest") if isinstance(test_execution, dict) else None
        test_cwd = test_execution.get("cwd") if isinstance(test_execution, dict) else None
        completion = test_execution.get("completion") if isinstance(test_execution, dict) else None
        if (
            not isinstance(test_command, list)
            or len(test_command) != 7
            or test_command[:4]
            != [str(interpreter), "-I", "-c", GREENFIELD_IN_MEMORY_BOOTSTRAP]
            or not Path(test_command[4]).is_absolute()
            or test_command[5] != GREENFIELD_TEST_RUNNER_DIGEST
            or not Path(test_command[6]).is_absolute()
            or _inside(Path(test_command[4]), project)
            or _inside(Path(test_command[6]), project)
            or test_execution.get("isolated_python") is not True
            or test_execution.get("python") != str(interpreter)
            or test_execution.get("environment")
            != "constructed-host-allowlist-without-path-or-pythonpath"
            or test_execution.get("subject") != "private-temporary-copy"
            or test_subject != subject_claim.get("digest")
            or test_cwd != str(verifier.parent)
            or test_execution.get("runner") != "private-readonly-trusted-runner"
            or test_execution.get("runner_digest") != GREENFIELD_TEST_RUNNER_DIGEST
            or test_execution.get("runner_execution")
            != "digest-verified-in-memory-byte-snapshot"
            or test_execution.get("executor_digest") != GREENFIELD_TEST_EXECUTOR_DIGEST
            or test_execution.get("executor_execution")
            != "digest-verified-in-memory-byte-snapshot"
            or test_execution.get("output_capture")
            != "bounded-20000-byte-tail-no-disk-spool"
            or not isinstance(test_execution.get("output_bytes"), int)
            or isinstance(test_execution.get("output_bytes"), bool)
            or test_execution.get("output_bytes") < 0
            or test_execution.get("result_protocol")
            != "nornyx.greenfield.pytest_result.v2"
            or not isinstance(completion, dict)
            or set(completion)
            != {
                "schema",
                "returncode",
                "collected",
                "executed",
                "failed",
                "skipped",
                "network_refused",
                "executor_digest",
                "executor_command",
                "executor_cwd",
                "executor_returncode",
            }
            or completion.get("schema") != "nornyx.greenfield.pytest_result.v2"
            or completion.get("executor_digest") != GREENFIELD_TEST_EXECUTOR_DIGEST
            or not isinstance(completion.get("executor_command"), list)
            or len(completion.get("executor_command", [])) != 10
            or completion.get("executor_command", [])[:4]
            != [str(interpreter), "-I", "-c", GREENFIELD_IN_MEMORY_BOOTSTRAP]
            or any(
                not isinstance(item, str)
                for item in completion.get("executor_command", [])
            )
            or completion.get("executor_command", [None] * 10)[5]
            != GREENFIELD_TEST_EXECUTOR_DIGEST
            or completion.get("executor_command", [None] * 10)[9]
            != GREENFIELD_TEST_EXECUTOR_DIGEST
            or not Path(completion.get("executor_command", [None] * 10)[4]).is_absolute()
            or not Path(completion.get("executor_command", [None] * 10)[6]).is_absolute()
            or _inside(Path(completion.get("executor_command", [None] * 10)[4]), project)
            or _inside(Path(completion.get("executor_command", [None] * 10)[6]), project)
            or completion.get("executor_cwd")
            != completion.get("executor_command", [None] * 10)[6]
            or completion.get("executor_returncode") != 73
            or completion.get("returncode") != 0
            or not isinstance(completion.get("collected"), int)
            or isinstance(completion.get("collected"), bool)
            or completion.get("collected", 0) < 1
            or completion.get("executed") != completion.get("collected")
            or completion.get("failed") != 0
            or completion.get("skipped") != 0
            or not isinstance(completion.get("network_refused"), int)
            or isinstance(completion.get("network_refused"), bool)
            or completion.get("network_refused") < 0
            or test_execution.get("network_guard") != GREENFIELD_NETWORK_GUARD
            or test_execution.get("final_subject_digest") != subject_claim.get("digest")
        ):
            return _closed_failure(
                "test-execution provenance does not match the trusted invocation",
                command=command,
                returncode=completed.returncode,
                provenance=provenance,
            )
    elif test_execution.get("status") != "not_run":
        # A failing pytest run still has a real invocation record; only a
        # preceding static refusal is represented as not_run.
        test_command = test_execution.get("command")
        if (
            not isinstance(test_command, list)
            or len(test_command) != 7
            or test_command[:4]
            != [str(interpreter), "-I", "-c", GREENFIELD_IN_MEMORY_BOOTSTRAP]
            or test_command[5] != GREENFIELD_TEST_RUNNER_DIGEST
            or test_execution.get("runner_digest") != GREENFIELD_TEST_RUNNER_DIGEST
            or test_execution.get("executor_digest") != GREENFIELD_TEST_EXECUTOR_DIGEST
        ):
            return _closed_failure(
                "failed test-execution provenance is absent or malformed",
                command=command,
                returncode=completed.returncode,
                provenance=provenance,
            )
        # Two failing shapes, kept apart (F-002). A record that is present must
        # be a trusted subject-FAILURE record: from the executor, and NOT
        # showing a pass. A failed gate carrying a completion that is untrusted,
        # or that reports a pass, is a forgery or an inconsistency, not an
        # ordinary subject failure, so it fails closed. A genuinely absent
        # record (the executor never established completion) is the other
        # failing shape and is left to the gate reason, which names it.
        completion = test_execution.get("completion")
        if completion is not None and (
            not _greenfield_completion_from_trusted_executor(completion, interpreter)
            or _greenfield_completion_shows_pass(completion)
        ):
            return _closed_failure(
                "a failed test-execution carries a completion record that is not a "
                "trusted subject-failure record",
                command=command,
                returncode=completed.returncode,
                provenance=provenance,
            )
    expected_status = "pass" if passed else "fail"
    expected_returncode = 0 if passed else 2
    if payload.get("status") != expected_status or completed.returncode != expected_returncode:
        return _closed_failure(
            "verifier status, gate outcomes, and process return code disagree",
            command=command,
            returncode=completed.returncode,
            provenance=provenance,
        )
    return results, provenance


def re_full_digest(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


#: The codec a gate child writes, where it is not the one text mode reads,
#: keyed by the command's first word. A Python child started with this
#: interpreter's environment writes its stdio in the locale codec -- the codec
#: text mode reads. The Nornyx CLI is read with that codec too: its source
#: prints through the default text stream with no stdio setting of its own.
#: That was read in its source; its output on Windows was not measured. ruff
#: is a native binary and writes UTF-8 whatever the locale (measured on
#: Windows), so text mode read it as the ANSI code page there: mojibake in the
#: recorded detail, or, for a byte that code page leaves undefined, a stream
#: of None and a TypeError escaping `run`, so acceptance raised instead of
#: recording a gate.
GATE_OUTPUT_ENCODINGS = {"ruff": "utf-8"}


def _gate_text(raw: bytes, stream: str, encoding: str) -> str:
    """One gate stream as text mode would have read it, or Forge's account.

    STRICT, AND NEVER SUBSTITUTED: the rule `claude_worker._decode` and A-025
    set for a provider's output. A stream that cannot be decoded is not rendered
    as replacement characters or as confident text in another codec; the detail
    says which stream, why and where, and identifies the exact bytes by length
    and SHA-256. The gate's verdict is its exit status, as before; the detail is
    what a reader and the repair loop see.
    """
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError as exc:
        return (
            f"\n[{stream} could not be decoded as {encoding} ({exc.reason} at byte "
            f"{exc.start}); {len(raw)} bytes, sha256:{hashlib.sha256(raw).hexdigest()}]\n"
        )
    return text.replace("\r\n", "\n").replace("\r", "\n")


def run(command: tuple[str, ...], *, cwd: Path, encoding: str | None = None) -> GateResult:
    """Run one gate. `encoding` is the codec the child writes; None is the one
    text mode reads, which a Python child started with this environment writes."""
    result = subprocess.run(command, cwd=cwd, capture_output=True, check=False)
    codec = encoding or locale.getpreferredencoding(False)
    detail = (
        _gate_text(result.stdout, "stdout", codec) + _gate_text(result.stderr, "stderr", codec)
    ).strip()
    return GateResult(" ".join(command), result.returncode == 0, detail, command, result.returncode)


def default_gates(root: Path, *, quick: bool = False) -> list[GateResult]:
    commands: list[tuple[str, ...]] = [
        (sys.executable, "-m", "compileall", "-q", "src", "scripts"),
        (sys.executable, "scripts/validate_repository.py", "--internal"),
        (sys.executable, "scripts/check_architecture.py"),
        (sys.executable, "scripts/check_security.py"),
    ]
    if not quick and shutil.which("pytest"):
        commands.append((sys.executable, "-m", "pytest", "-q"))
    if shutil.which("ruff"):
        commands.append(("ruff", "check", "src", "scripts", "tests"))
    if shutil.which("nornyx"):
        commands.extend(
            [
                ("nornyx", "check", ".nornyx/contracts/forge_control.nyx"),
                ("nornyx", "check", ".nornyx/contracts/architecture_governance.nyx"),
                ("nornyx", "check", ".nornyx/contracts/runtime_network.nyx"),
                ("nornyx", "check", ".nornyx/generated/brd_contract.nyx"),
                (sys.executable, "scripts/prepare_runtime.py"),
            ]
        )
    return [
        run(command, cwd=root, encoding=GATE_OUTPUT_ENCODINGS.get(command[0]))
        for command in commands
    ]


def _governance_record(
    outcome: str,
    generated_digest: str | None,
    checked_digest: str | None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "schema": GOVERNANCE_CHECK_SCHEMA,
        "outcome": outcome,
        "subject": {
            "path": GENERATED_CONTRACT_PATH,
            "generated_digest": generated_digest,
            "checked_digest": checked_digest,
        },
        **extra,
    }


def _nornyx_verdict(stdout: str) -> tuple[list[dict[str, Any]], bool] | None:
    """Read the CLI's stdout as Nornyx writes it, or `None` when it is not.

    Nornyx prints each diagnostic as a JSON object and, for a contract it
    passes, the line `Nornyx check passed` after them. Anything else in the
    stream -- a traceback, a stray print, a different program's output -- is
    not Nornyx's verdict, and the caller treats it as an error rather than
    reading a pass or a refusal into it.
    """
    decoder = json.JSONDecoder()
    diagnostics: list[dict[str, Any]] = []
    index, length = 0, len(stdout)
    while True:
        while index < length and stdout[index].isspace():
            index += 1
        if index >= length:
            return diagnostics, False
        if stdout[index] != "{":
            return (diagnostics, True) if stdout[index:].strip() == _NORNYX_PASSED_LINE else None
        try:
            item, index = decoder.raw_decode(stdout, index)
        except json.JSONDecodeError:
            return None
        if not isinstance(item, dict) or not isinstance(item.get("level"), str):
            return None
        diagnostics.append(item)


#: Where the contract check's private directory is made (A-054):
#: under the inherited temporary directory, as before, or under a root the
#: caller configured explicitly and the check judged Forge-owned first.
SCRATCH_PLACEMENT_INHERITED = "inherited-temp"
SCRATCH_PLACEMENT_CONFIGURED = "configured-root"
#: Besides its owner, the only principals a configured Windows root's DACL may
#: grant to: SYSTEM and Administrators, the executor's declared zone shape.
_ROOT_DACL_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544"})
_SID_SHAPE = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+")
_WINDOWS_DRIVE_PATH = re.compile(r"[A-Za-z]:\\")


def _scratch_root_spelling(text: str) -> str:
    """THE ONE NAME RULE for a configured root: an absolute path whose every
    component is a plain name. Windows also refuses a stream, a namespace or
    UNC prefix, a forward slash and a trailing dot or space -- each is
    another spelling of some directory, and the check judges one spelling."""
    if "\x00" in text:
        return "contains a NUL"
    if sys.platform == "win32":
        if not _WINDOWS_DRIVE_PATH.match(text) or "/" in text:
            return "is not an absolute drive path in backslashes (relative, UNC, namespace " \
                   "and forward-slash spellings are refused)"
        parts = text[3:].split("\\")
    else:
        if not text.startswith("/"):
            return "is relative"
        parts = text[1:].split("/")
    for part in parts:
        if part in ("", ".", "..") or (sys.platform == "win32" and (
                ":" in part or part != part.rstrip(" ."))):
            return f"has the component {part!r}, which is not a plain name"
    return ""


def _scratch_root_judgement(candidate: Any) -> tuple[tuple[int, int] | None, str]:
    """`(identity, "")` for a configured root the check may use, or
    `(None, reason)`. Fails closed: an unreadable answer is a refusal."""
    if not isinstance(candidate, (str, os.PathLike)) or not isinstance(
            os.fspath(candidate), str):
        return None, "the configured scratch root is not a path"
    text = os.fspath(candidate)
    spelling = _scratch_root_spelling(text)
    if spelling:
        return None, f"the configured scratch root {text!r} {spelling}"
    path = Path(text)
    for component in [*reversed(path.parents), path]:
        try:
            status = os.lstat(component)
        except FileNotFoundError:
            return None, f"the configured scratch root {text!r} does not exist"
        except OSError as exc:
            return None, f"the configured scratch root {text!r} cannot be inspected: {exc}"
        if stat.S_ISLNK(status.st_mode) or (
                getattr(status, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            return None, (f"the configured scratch root {text!r} is a link or reparse point, "
                          f"or is reached through one at {str(component)!r}")
    if not stat.S_ISDIR(status.st_mode):
        return None, f"the configured scratch root {text!r} is not a directory"
    try:
        path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return None, f"the configured scratch root {text!r} cannot be resolved: {exc}"
    if sys.platform == "win32":
        refusal = _windows_root_refusal(path)
    elif hasattr(os, "geteuid"):
        refusal = _posix_root_refusal(status)
    else:
        refusal = "has no owner check on this platform"
    if refusal:
        return None, f"the configured scratch root {text!r} {refusal}"
    return (status.st_dev, status.st_ino), ""


def _posix_root_refusal(status: os.stat_result) -> str:
    if status.st_uid != os.geteuid():
        return f"is owned by uid {status.st_uid}, not this process's effective uid"
    if status.st_mode & 0o022:
        return f"is group- or other-writable (mode {oct(status.st_mode & 0o777)})"
    return ""


def _windows_root_refusal(path: Path) -> str:
    try:
        owner, protected, aces = _windows_root_security(path)
        token_sids = set(_windows_token_sids())
    except Exception as exc:  # noqa: BLE001 - any failure of the read refuses
        return (f"has an owner, DACL or token that could not be read "
                f"({type(exc).__name__}); Forge refuses rather than assume")
    if owner not in token_sids:
        return (f"is owned by {owner}, which is neither this process's token user nor its "
                "token owner")
    if aces is None:
        return "has a NULL DACL, which grants every principal everything"
    if not protected:
        return "has a DACL that is not protected, so it takes whatever its parent grants"
    for ace_type, sid in aces:
        if ace_type != 0 or sid not in _ROOT_DACL_SIDS | {owner}:
            return (f"has a DACL entry of type {ace_type} for {sid}, outside SYSTEM, "
                    "Administrators and its owner")
    return ""


def _windows_api() -> tuple[Any, Any, Any, Any]:
    """`(ctypes, wintypes, kernel32, advapi32)`, each DLL a private instance
    so the prototypes set here alter no shared `ctypes.windll` object."""
    import ctypes  # noqa: PLC0415 - Windows only
    from ctypes import wintypes  # noqa: PLC0415

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    handle, dword, pointer = wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p
    kernel32.GetCurrentProcess.restype = handle
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.CloseHandle.argtypes = [handle]
    kernel32.LocalFree.argtypes = [pointer]
    kernel32.LocalFree.restype = pointer
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, dword, dword, pointer, dword, dword,
                                     handle]
    kernel32.CreateFileW.restype = handle
    advapi32.OpenProcessToken.argtypes = [handle, dword, ctypes.POINTER(handle)]
    advapi32.GetTokenInformation.argtypes = [handle, ctypes.c_int, pointer, dword,
                                             ctypes.POINTER(dword)]
    advapi32.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.GetSecurityInfo.argtypes = [handle, ctypes.c_int, dword,
                                         *[ctypes.POINTER(pointer)] * 4,
                                         ctypes.POINTER(pointer)]
    advapi32.GetSecurityInfo.restype = dword
    advapi32.GetSecurityDescriptorControl.argtypes = [pointer, ctypes.POINTER(wintypes.WORD),
                                                      ctypes.POINTER(dword)]
    advapi32.GetAce.argtypes = [pointer, dword, ctypes.POINTER(pointer)]
    return ctypes, wintypes, kernel32, advapi32


def _sid_text(api: tuple[Any, Any, Any, Any], sid: Any) -> str:
    ctypes, wintypes, kernel32, advapi32 = api
    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
    try:
        value = str(text.value)
    finally:
        kernel32.LocalFree(text)
    if not _SID_SHAPE.fullmatch(value):
        raise ValueError("the SID read is not a SID")
    return value


def _windows_token_sids() -> tuple[str, str]:
    """This process's TokenUser and TokenOwner (classes 1 and 4), as string
    SIDs; the read of PR #86's owner-principal cycle plus TokenOwner. Raises
    on any failure, which the root check turns into a refusal."""
    api = _windows_api()
    ctypes, wintypes, kernel32, advapi32 = api
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008,  # TOKEN_QUERY
                                     ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        found = []
        for information_class in (1, 4):  # TokenUser, TokenOwner
            size = wintypes.DWORD(0)
            advapi32.GetTokenInformation(token, information_class, None, 0, ctypes.byref(size))
            if not size.value:
                raise OSError(ctypes.get_last_error(), "GetTokenInformation gave no size")
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(token, information_class, buffer, size,
                                                ctypes.byref(size)):
                raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
            # TOKEN_USER and TOKEN_OWNER both begin with the PSID.
            found.append(_sid_text(api, ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]))
        return found[0], found[1]
    finally:
        kernel32.CloseHandle(token)


def _windows_root_security(path: Path) -> tuple[str, bool, list[tuple[int, str | None]] | None]:
    """`(owner SID, DACL protected, [(ACE type, SID)] or None for a NULL DACL)`
    of the directory itself, read through a handle opened on the reparse
    point rather than through it. Raises on any failure."""
    api = _windows_api()
    ctypes, wintypes, kernel32, advapi32 = api
    handle = kernel32.CreateFileW(
        str(path), 0x00020000 | 0x0080,  # READ_CONTROL | FILE_READ_ATTRIBUTES
        0x7, None, 3,  # share all; OPEN_EXISTING
        0x02000000 | 0x00200000, None)  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    try:
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        status = advapi32.GetSecurityInfo(handle, 1, 0x1 | 0x4, ctypes.byref(owner), None,
                                          ctypes.byref(dacl), None, ctypes.byref(descriptor))
        if status:
            raise OSError(status, "GetSecurityInfo failed")
        try:
            control, revision = wintypes.WORD(), wintypes.DWORD()
            if not advapi32.GetSecurityDescriptorControl(descriptor, ctypes.byref(control),
                                                         ctypes.byref(revision)):
                raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorControl failed")
            owner_sid = _sid_text(api, owner)
            if not dacl.value:
                return owner_sid, bool(control.value & 0x1000), None
            # ACL header: revision, pad, size (WORD), ACE count (WORD), pad.
            count = ctypes.cast(dacl, ctypes.POINTER(ctypes.c_ushort))[2]
            aces: list[tuple[int, str | None]] = []
            for index in range(count):
                ace = ctypes.c_void_p()
                if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                    raise OSError(ctypes.get_last_error(), "GetAce failed")
                ace_type = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))[0]
                # ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE: header, mask, SID.
                sid = _sid_text(api, ace.value + 8) if ace_type in (0, 1) else None
                aces.append((ace_type, sid))
            return owner_sid, bool(control.value & 0x1000), aces  # SE_DACL_PROTECTED
        finally:
            kernel32.LocalFree(descriptor)
    finally:
        kernel32.CloseHandle(handle)


def trusted_contract_check(
    root: Path, generated_digest: Any, *, scratch_root: Path | None = None
) -> GateResult:
    """`nornyx check` of the contract this build generated, or a failing gate.

    THE GREENFIELD GOVERNANCE CHECK (A-049). The development flow generates
    `.nornyx/generated/brd_contract.nyx` from the BRD and records the SHA-256
    of the bytes it wrote. This reads the file once, refuses anything that is
    not a regular file inside the project or is larger than a generated
    contract can be, and compares its digest with that record: bytes the
    provider changed or removed after generation are not this build's
    contract, so no check runs and the gate fails. The bound bytes are then
    copied to a private temporary directory and the installed Nornyx CLI's
    own entry point checks that copy, run by the trusted interpreter with
    `-I`, from that directory, in the constructed environment the verifier
    uses, under a timeout. Its verdict is read from what Nornyx writes, not
    from the exit status alone.

    Three outcomes besides a pass, none of them passing: `not_run` (no
    recorded digest, a missing, linked, oversized or changed contract, or an
    interpreter inside the project), `refused` (Nornyx reported an error in
    the contract) and `errored` (the check could not run, or answered in
    something other than Nornyx's own words).

    THE SCRATCH ROOT (A-054). With `scratch_root` unset the
    private directory is made where it always was, under the inherited
    temporary directory, recorded as `inherited-temp`. A configured root is judged before anything is made in
    it -- a plain absolute spelling, no link or reparse point at any
    component, a directory, owned by this process (the effective uid, or on
    Windows the token user or token owner) and writable by no one else (no
    group or other write bit, or a protected DACL granting only SYSTEM,
    Administrators and the owner) -- and judged again after the private
    directory is made, by identity. Any refusal, including an owner or DACL
    that cannot be read, is `not_run` and no child starts. It is recorded as
    `configured-root`. Such a root can protect against OTHER principals
    under those access conditions; it does NOT protect against a process of
    the same principal, which owns it as Forge does, and it establishes
    nothing about who else can write it -- an access fact of the host,
    measured outside this process. Codex P1 4356060742 stays OPEN under both
    placements; `tests/test_contract_check_snapshot_residual.py` shows it.
    """
    name = f"greenfield:{GREENFIELD_GOVERNANCE_CHECK}"
    recorded = generated_digest if re_full_digest(generated_digest) else None

    def not_run(reason: str) -> GateResult:
        return GateResult(
            name,
            False,
            f"no Nornyx check ran: {reason}",
            (),
            2,
            _governance_record("not_run", recorded, None),
        )

    if recorded is None:
        return not_run(
            "this build recorded no digest for the contract it generated, so there "
            "are no generated bytes to bind a check to"
        )
    try:
        project = Path(root).resolve(strict=True)
    except OSError as exc:
        return not_run(f"the project root cannot be resolved: {exc}")
    interpreter = Path(sys.executable)
    if not interpreter.is_absolute():
        return not_run("the Python interpreter path is not absolute")
    interpreter = Path(os.path.abspath(interpreter))
    try:
        interpreter_target = interpreter.resolve(strict=False)
    except OSError as exc:
        return not_run(f"the Python interpreter cannot be resolved: {exc}")
    if _inside(interpreter, project) or _inside(interpreter_target, project):
        return not_run("the Python interpreter is inside the provider workspace")

    contract = project / GENERATED_CONTRACT_PATH
    try:
        status = os.lstat(contract)
    except FileNotFoundError:
        return not_run(f"the generated build contract {GENERATED_CONTRACT_PATH} is missing")
    except OSError as exc:
        return not_run(f"the generated build contract cannot be read: {exc}")
    try:
        resolved = contract.resolve(strict=True)
    except OSError as exc:
        return not_run(f"the generated build contract cannot be resolved: {exc}")
    if not _regular_file_mode(status.st_mode) or resolved != contract:
        return not_run(
            f"the generated build contract {GENERATED_CONTRACT_PATH} is not a regular "
            "file inside the project"
        )
    if status.st_size > GOVERNANCE_CONTRACT_MAX_BYTES:
        return not_run(
            f"the generated build contract is larger than {GOVERNANCE_CONTRACT_MAX_BYTES} "
            "bytes, which no contract Forge generates is"
        )
    data, refusal = _read_inspected_file(contract, status, GOVERNANCE_CONTRACT_MAX_BYTES)
    if data is None:
        return not_run(f"the generated build contract {GENERATED_CONTRACT_PATH} {refusal}")
    found = "sha256:" + hashlib.sha256(data).hexdigest()
    if found != recorded:
        return not_run(
            f"the generated build contract changed after generation (generated {recorded}, "
            f"now {found}); a check of other bytes is not a check of this build's contract"
        )

    placement = SCRATCH_PLACEMENT_INHERITED
    held: tuple[int, int] | None = None
    if scratch_root is not None:
        held, refusal = _scratch_root_judgement(scratch_root)
        if held is None:
            return not_run(refusal)
        placement = SCRATCH_PLACEMENT_CONFIGURED

    cli = {
        "package": "nornyx",
        "entry": "nornyx.cli:main",
        "installed_version": _installed_version("nornyx"),
    }
    command: tuple[str, ...] = ()
    invocation = {
        "python": str(interpreter),
        "isolated_python": True,
        "cwd": "private-temporary-directory",
        "environment": "constructed-host-allowlist-without-path-or-pythonpath",
        "subject": "private-read-only-snapshot-of-the-bound-bytes",
        "scratch_placement": placement,
        "timeout_seconds": GOVERNANCE_CHECK_TIMEOUT_SECONDS,
    }

    def errored(reason: str, returncode: int, snapshot_digest: str | None = None) -> GateResult:
        return GateResult(
            name,
            False,
            f"nornyx check errored on the generated build contract {recorded}: {reason}",
            command,
            returncode,
            _governance_record(
                "errored", recorded, snapshot_digest, cli=cli, invocation=invocation
            ),
        )

    try:
        with tempfile.TemporaryDirectory(
            prefix=GOVERNANCE_SNAPSHOT_PREFIX,
            dir=None if scratch_root is None else os.fspath(scratch_root),
        ) as scratch:
            if held is not None:
                again, refusal = _scratch_root_judgement(scratch_root)
                made = os.lstat(scratch)
                parent = os.lstat(os.path.dirname(scratch))
                if again != held or (parent.st_dev, parent.st_ino) != held or not (
                        stat.S_ISDIR(made.st_mode)):
                    return not_run(refusal or (
                        "the configured scratch root changed while the private directory "
                        "was made in it"))
            snapshot = Path(scratch).resolve() / GOVERNANCE_SNAPSHOT_NAME
            snapshot.write_bytes(data)
            snapshot.chmod(0o444)
            snapshot_status = os.lstat(snapshot)
            command = (
                str(interpreter),
                "-I",
                "-c",
                NORNYX_CHECK_BOOTSTRAP,
                "check",
                str(snapshot),
            )
            completed = subprocess.run(
                command,
                cwd=scratch,
                env=_verifier_environment(_trusted_loader_path(project)),
                capture_output=True,
                check=False,
                timeout=GOVERNANCE_CHECK_TIMEOUT_SECONDS,
            )
            # Read back as the contract was read: the file that was written,
            # through one descriptor, or nothing.
            after, refusal = _read_inspected_file(
                snapshot, snapshot_status, GOVERNANCE_CONTRACT_MAX_BYTES
            )
    except subprocess.TimeoutExpired:
        return errored(
            f"it did not finish within {GOVERNANCE_CHECK_TIMEOUT_SECONDS} seconds", 124
        )
    except OSError as exc:
        return errored(f"it could not run: {type(exc).__name__}: {exc}", 2)

    codec = locale.getpreferredencoding(False)
    stdout = _gate_text(completed.stdout, "stdout", codec)
    stderr = _gate_text(completed.stderr, "stderr", codec)
    output = (stdout + stderr).strip()
    returncode = completed.returncode
    if after is None:
        return errored(f"the private snapshot {refusal} after the check", returncode)
    checked = "sha256:" + hashlib.sha256(after).hexdigest()
    if checked != recorded:
        return errored("the private snapshot changed while it was checked", returncode, checked)
    verdict = None if stderr.strip() else _nornyx_verdict(stdout)
    if verdict is None:
        return errored(
            f"its output is not Nornyx's verdict (exit {returncode}): {output}",
            returncode,
            checked,
        )
    diagnostics, passed_line = verdict
    errors = [item for item in diagnostics if item.get("level") == "error"]
    if returncode == 0 and passed_line and not errors:
        return GateResult(
            name,
            True,
            f"nornyx check passed the generated build contract {recorded}: {output}",
            command,
            0,
            _governance_record("passed", recorded, checked, cli=cli, invocation=invocation),
        )
    if returncode in _NORNYX_REFUSAL_STATUSES and errors and not passed_line:
        codes = ", ".join(str(item.get("code")) for item in errors)
        return GateResult(
            name,
            False,
            f"nornyx check refused the generated build contract {recorded} "
            f"(exit {returncode}; {codes}): {output}",
            command,
            returncode,
            _governance_record("refused", recorded, checked, cli=cli, invocation=invocation),
        )
    return errored(
        f"its exit status and its diagnostics disagree (exit {returncode}): {output}",
        returncode,
        checked,
    )


def _read_inspected_file(
    path: Path, inspected: os.stat_result, limit: int
) -> tuple[bytes | None, str]:
    """The bytes of the file that was inspected, read through one descriptor.

    Codex P1 4353133109 on `8ae32b3`: the path was inspected with `lstat` and
    `resolve` and then opened by name, so a file put in its place in between
    -- by a process the provider left running -- was read unexamined. A FIFO
    blocked the read, before any timeout applied, for as long as nobody wrote
    to it; a link was followed to whatever it named. Now the path is opened
    without following a link where the platform can refuse one, and without
    blocking where it can open a pipe that way, and what is judged is the
    DESCRIPTOR: a regular file, the same device and inode that were
    inspected, within the bound, read only from that descriptor. Windows has
    neither flag; the identity comparison is what refuses a link there.

    Returns the bytes and an empty reason, or `None` and the reason, worded
    to follow the contract's path.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        return None, f"is not a regular file inside the project ({exc.strerror or exc})"
    try:
        opened = os.fstat(descriptor)
        if not _regular_file_mode(opened.st_mode):
            return None, "is not a regular file inside the project"
        if (opened.st_dev, opened.st_ino) != (inspected.st_dev, inspected.st_ino):
            return None, "changed while it was inspected: the file opened is not the one inspected"
        larger = (
            f"is larger than {limit} bytes, which no contract Forge generates is"
        )
        if opened.st_size > limit:
            return None, larger
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1 << 20, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                return None, larger
        return b"".join(chunks), ""
    except OSError as exc:
        return None, f"cannot be read: {exc}"
    finally:
        os.close(descriptor)


def _regular_file_mode(mode: int) -> bool:
    """A regular file, not a link, directory, device or pipe."""
    return (mode & 0o170000) == 0o100000


def _installed_version(distribution: str) -> str:
    """The version the trusted interpreter's installed metadata names; the
    child imports the CLI from that same interpreter's site-packages."""
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"
