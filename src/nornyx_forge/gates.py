from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import shutil
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
    "version": 3,
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
}
GREENFIELD_GATE_IDS = tuple(GREENFIELD_PROFILE_DEFINITION["checks"])
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
    _trusted_result_write = [False]
    _write_flags = (
        _os.O_WRONLY | _os.O_RDWR | _os.O_CREAT | _os.O_TRUNC | _os.O_APPEND
    )

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
        if _trusted_result_write[0] and _path == _result_path:
            return True
        return _inside(_path, _test_tmp)

    def _audit(_event, _args):
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
            "os.truncate", "os.utime", "os.link", "os.symlink",
        }:
            if _args and not _write_is_allowed(_args[0]):
                raise PermissionError("test process cannot mutate outside its private temp root")
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
    _module = _sys.modules.get("__main__")
    if _module is not None:
        for _name in tuple(vars(_module)):
            if _name not in {"__builtins__", "__name__", "__package__", "__spec__"}:
                vars(_module).pop(_name, None)
    _sys.path.insert(0, str(_subject / "src"))
    _sys.path.insert(0, str(_subject))
    _sys.addaudithook(_audit)
    _returncode = _int(_pytest_main([
        "-q", "--capture=no", "--disable-warnings", "--maxfail=1", "--noconftest",
        "-p", "no:cacheprovider", "-p", "no:logging",
        "-c", str(_config_path), "-o", "addopts=",
        "-o", "python_files=test_*.py", "-o", "python_functions=test_*",
        "-o", "python_classes=Test*", "--basetemp", str(_test_tmp),
        "--rootdir", str(_subject), str(_subject / "tests"),
    ], plugins=[_recorder]))
    _payload = _dumps({
        "schema": "nornyx.greenfield.pytest_result.v1",
        "returncode": _returncode,
        "collected": _recorder.collected,
        "executed": _recorder.executed,
        "failed": _recorder.failed,
        "skipped": _recorder.skipped,
        "executor_digest": _executor_digest,
    }, sort_keys=True).encode("utf-8")
    _trusted_result_write[0] = True
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
        _trusted_result_write[0] = False
    raise _system_exit(73)

_entry()
"""

GREENFIELD_TEST_EXECUTOR_DIGEST = (
    "sha256:" + hashlib.sha256(GREENFIELD_TEST_EXECUTOR_SOURCE.encode("utf-8")).hexdigest()
)

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
    "executor_digest",
}}
valid = (
    "sha256:" + before_digest == EXECUTOR_DIGEST
    and "sha256:" + after_digest == EXECUTOR_DIGEST
    and isinstance(payload, dict)
    and set(payload) == keys
    and payload.get("schema") == "nornyx.greenfield.pytest_result.v1"
    and payload.get("executor_digest") == EXECUTOR_DIGEST
    and payload.get("returncode") == 0
    and completed.returncode == 73
    and isinstance(payload.get("collected"), int)
    and not isinstance(payload.get("collected"), bool)
    and payload.get("collected", 0) >= 1
    and payload.get("executed") == payload.get("collected")
    and payload.get("failed") == 0
    and payload.get("skipped") == 0
)
if valid:
    payload["executor_command"] = executor_command
    payload["executor_cwd"] = str(subject)
    payload["executor_returncode"] = completed.returncode
    final_result.open("x", encoding="utf-8").write(json.dumps(payload, sort_keys=True))
raise SystemExit(0 if valid else 2)
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
        "active_processes": 64,
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
            snapshot_digest = _digest_file(snapshot)
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
            != "nornyx.greenfield.pytest_result.v1"
            or not isinstance(completion, dict)
            or set(completion)
            != {
                "schema",
                "returncode",
                "collected",
                "executed",
                "failed",
                "skipped",
                "executor_digest",
                "executor_command",
                "executor_cwd",
                "executor_returncode",
            }
            or completion.get("schema") != "nornyx.greenfield.pytest_result.v1"
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


def run(command: tuple[str, ...], *, cwd: Path) -> GateResult:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    detail = (result.stdout + result.stderr).strip()
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
    return [run(command, cwd=root) for command in commands]
