"""Trusted, standalone verification for an untrusted greenfield project.

This file is executed by absolute path from the Forge installation.  It is
deliberately self-contained: importing application code from the project would
let the subject participate in the verifier, and importing this module through
the project working directory would let a project-local ``nornyx_forge`` win.

The profile is static assurance, not a claim that arbitrary generated software
is correct.  It checks project structure and BRD traceability, parses every
Python source and test without executing either, requires executable-looking
test semantics, keeps process starts behind explicitly named service/tool
modules, and applies deterministic secret/dynamic-execution checks.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tokenize
from pathlib import Path
from typing import Any

PROFILE_DEFINITION = {
    "id": "nornyx.greenfield.python.v1",
    "version": 2,
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

TEST_RUNNER_SOURCE = """from __future__ import annotations
import sys
from pathlib import Path
import pytest

subject = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(subject / "src"))
sys.path.insert(0, str(subject))
raise SystemExit(pytest.main([
    "-q", "--capture=no", "--disable-warnings", "--maxfail=1",
    "-o", "addopts=", "--rootdir", str(subject), str(subject / "tests"),
]))
"""

_IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".nornyx",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
_TEXT_SUFFIXES = {
    ".cfg",
    ".css",
    ".env",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}
_SECRET_PATTERNS = {
    "Anthropic API key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI API key": re.compile(r"sk-[A-Za-z0-9]{32,}"),
    "GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
}
_DYNAMIC_IMPORT_CALLS = {"__import__", "importlib.import_module"}
_SIDE_EFFECT_DIRECTORIES = {"adapters", "services", "tools", "workers"}
_SIDE_EFFECT_SUFFIXES = ("_adapter", "_service", "_tool", "_worker")
_MAX_FILES = 2000
_MAX_FILE_BYTES = 500_000
_MAX_TOTAL_BYTES = 10_000_000
_MAX_TOTAL_AST_NODES = 1_000_000
_MAX_MEMORY_BYTES = 768 * 1024 * 1024
_MAX_JOB_MEMORY_BYTES = 1024 * 1024 * 1024
_MAX_PROCESSES = 4
_MAX_POSIX_PROCESSES = 64
_TEST_TIMEOUT_SECONDS = 60
_WINDOWS_JOB_HANDLES: list[Any] = []

# Kept in lockstep with the repository architecture gate and exercised against
# that gate's full spelling corpus.  The property is capability acquisition,
# not a handful of call spellings: an ordinary ``os`` import is allowed, while
# holding an exec-only module or an exec-family member is not.
_EXEC_ONLY_MODULES = {"subprocess", "pty", "multiprocessing", "posix", "nt"}
_DUAL_USE_MODULES = {"os", "asyncio"}
_EXEC_FUNCTIONS = {
    "system", "popen", "startfile", "fork", "forkpty",
    "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnv", "spawnve", "spawnvp",
    "posix_spawn", "posix_spawnp", "run", "call", "check_call",
    "check_output", "Popen", "getoutput", "getstatusoutput",
    "create_subprocess_exec", "create_subprocess_shell",
}


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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
    """Read a source revision without executing an ambient ``git`` binary."""
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


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_linklike(path: Path) -> bool:
    """Reject symlinks, junctions, mount points, and other reparse points."""
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None and isjunction(path):
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _canonical_inside(path: Path, root: Path) -> bool:
    try:
        return _inside(path.resolve(strict=True), root)
    except OSError:
        return False


def _collect_files(root: Path) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    problems: list[str] = []
    total_bytes = 0
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept: list[str] = []
        for name in sorted(directories):
            child = current_path / name
            if name in _IGNORED_DIRECTORIES:
                continue
            if _is_linklike(child) or not _canonical_inside(child, root):
                problems.append(
                    "linked, reparse, or escaping directory is outside the inspected "
                    f"subject: {_relative(child, root)}"
                )
                continue
            kept.append(name)
        directories[:] = kept
        for name in sorted(names):
            path = current_path / name
            relative = _relative(path, root)
            if _is_linklike(path) or not _canonical_inside(path, root):
                problems.append(
                    f"linked, reparse, or escaping file is outside the inspected subject: {relative}"
                )
                continue
            try:
                size = path.stat().st_size
            except OSError as exc:
                problems.append(f"cannot stat {relative}: {exc}")
                continue
            if size > _MAX_FILE_BYTES:
                problems.append(f"file exceeds the {_MAX_FILE_BYTES}-byte inspection limit: {relative}")
                continue
            total_bytes += size
            files.append(path)
            if len(files) > _MAX_FILES:
                problems.append(f"project exceeds the {_MAX_FILES}-file inspection limit")
                return files, problems
            if total_bytes > _MAX_TOTAL_BYTES:
                problems.append(f"project exceeds the {_MAX_TOTAL_BYTES}-byte inspection limit")
                return files, problems
    return files, problems


def _safe_bytes(path: Path, root: Path) -> tuple[bytes | None, str | None]:
    """Read only a canonical in-root regular file and recheck after the read."""
    relative = _relative(path, root)
    if _is_linklike(path) or not _canonical_inside(path, root):
        return None, f"file escaped the inspected subject before read: {relative}"
    try:
        before = path.stat()
        data = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        return None, f"cannot read {relative}: {exc}"
    if _is_linklike(path) or not _canonical_inside(path, root):
        return None, f"file escaped the inspected subject during read: {relative}"
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity or len(data) != after.st_size:
        return None, f"file changed while it was inspected: {relative}"
    return data, None


def _python_text(data: bytes, path: Path, root: Path) -> tuple[str | None, str | None]:
    try:
        reader = io.BytesIO(data).readline
        encoding, _ = tokenize.detect_encoding(reader)
        return data.decode(encoding), None
    except (LookupError, SyntaxError, UnicodeError) as exc:
        return None, f"cannot read {_relative(path, root)} as Python source: {exc}"


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    # Simple assignment aliases are common enough that treating them as an
    # escape hatch would make the explicit-side-effect rule a spelling test.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        value = _resolved_call_name(node.value, aliases)
        if value:
            aliases[target.id] = value
    return aliases


def _resolved_call_name(node: ast.expr, aliases: dict[str, str]) -> str:
    name = _call_name(node)
    if not name:
        return ""
    first, separator, rest = name.partition(".")
    resolved = aliases.get(first, first)
    return resolved + (separator + rest if separator else "")


def _static_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string(node.left)
        right = _static_string(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left = _static_string(node.left)
        right = _static_string(node.right)
        if left is not None and isinstance(node.right, ast.Constant):
            count = node.right.value
            if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 10_000:
                return left * count
        if right is not None and isinstance(node.left, ast.Constant):
            count = node.left.value
            if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 10_000:
                return right * count
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for value in node.values:
            piece = _static_string(value)
            if piece is None:
                return None
            pieces.append(piece)
        return "".join(pieces)
    return None


def _resolved_callable_name(node: ast.expr, aliases: dict[str, str]) -> str:
    name = _resolved_call_name(node, aliases)
    if name:
        return name
    if not isinstance(node, ast.Call):
        return ""
    accessor = _resolved_call_name(node.func, aliases)
    if accessor not in {"getattr", "builtins.getattr"} or len(node.args) < 2:
        return ""
    owner = _resolved_call_name(node.args[0], aliases)
    member = _static_string(node.args[1])
    if not owner or member is None:
        return ""
    return f"{owner}.{member}"


def _process_capability_markers(tree: ast.AST) -> set[str]:
    """Return process capabilities acquired by this module.

    This mirrors the repository architecture gate's capability model and is
    regression-tested against its complete hostile spelling corpus.
    """
    markers: set[str] = set()
    dual_aliases: dict[str, str] = {}
    exec_aliases: dict[str, str] = {}
    importlib_aliases: set[str] = set()
    importer_aliases: set[str] = {"__import__"}
    sys_aliases: set[str] = set()
    modules_aliases: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".", 1)[0]
                bound = item.asname or root
                if root in _EXEC_ONLY_MODULES:
                    markers.add(item.name)
                elif root in _DUAL_USE_MODULES:
                    dual_aliases[bound] = root
                elif root == "importlib":
                    importlib_aliases.add(bound)
                elif root == "sys":
                    sys_aliases.add(bound)
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            if root in _EXEC_ONLY_MODULES:
                markers.add(node.module)
            elif root in _DUAL_USE_MODULES:
                for item in node.names:
                    if item.name == "*":
                        markers.add(f"{node.module}.*")
                    elif item.name in _EXEC_FUNCTIONS:
                        exec_aliases[item.asname or item.name] = f"{node.module}.{item.name}"
            elif root == "importlib":
                for item in node.names:
                    if item.name == "import_module":
                        importer_aliases.add(item.asname or item.name)
            elif root == "sys":
                for item in node.names:
                    if item.name == "modules":
                        modules_aliases.add(item.asname or item.name)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if not targets:
                continue
            value = node.value
            additions: tuple[dict[str, str] | set[str], Any] | None = None
            if isinstance(value, ast.Name) and value.id in dual_aliases:
                additions = (dual_aliases, dual_aliases[value.id])
            elif isinstance(value, ast.Name) and value.id in exec_aliases:
                additions = (exec_aliases, exec_aliases[value.id])
            elif isinstance(value, ast.Name) and value.id in importer_aliases:
                additions = (importer_aliases, True)
            elif (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id in importlib_aliases
                and value.attr == "import_module"
            ):
                additions = (importer_aliases, True)
            elif (
                isinstance(value, ast.Attribute) and value.attr == "modules"
                and isinstance(value.value, ast.Name) and value.value.id in sys_aliases
            ):
                additions = (modules_aliases, True)
            elif isinstance(value, ast.Call):
                accessor = _resolved_call_name(value.func, {})
                member = _static_string(value.args[1]) if len(value.args) > 1 else None
                if accessor in {"getattr", "builtins.getattr"} and member in {None, "__import__"}:
                    additions = (importer_aliases, True)
            if additions is None:
                continue
            container, resolved = additions
            for target in targets:
                if isinstance(container, dict):
                    if container.get(target) != resolved:
                        container[target] = resolved
                        changed = True
                elif target not in container:
                    container.add(target)
                    changed = True

    def dynamic_target(call: ast.Call) -> str | None:
        func = call.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in {"get", "pop", "setdefault"}
            and (
                (
                    isinstance(func.value, ast.Attribute)
                    and func.value.attr == "modules"
                    and isinstance(func.value.value, ast.Name)
                    and func.value.value.id in sys_aliases
                )
                or (isinstance(func.value, ast.Name) and func.value.id in modules_aliases)
            )
        ):
            return _static_string(call.args[0]) if call.args else "<computed>"
        is_importer = (
            isinstance(func, ast.Name) and func.id in importer_aliases
        ) or (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in importlib_aliases
            and func.attr == "import_module"
        ) or (isinstance(func, ast.Attribute) and func.attr == "__import__")
        if not is_importer:
            return None
        return _static_string(call.args[0]) if call.args else "<computed>"

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            owner = dual_aliases.get(node.value.id)
            if owner and node.attr in _EXEC_FUNCTIONS:
                markers.add(f"{owner}.{node.attr}")
            elif owner and node.attr == "__dict__":
                markers.add(f"{owner}.__dict__ (opaque member access)")
        elif isinstance(node, ast.Name) and node.id in exec_aliases:
            markers.add(exec_aliases[node.id])
        elif isinstance(node, ast.Subscript):
            value = node.value
            is_modules = (
                isinstance(value, ast.Attribute)
                and value.attr == "modules"
                and isinstance(value.value, ast.Name)
                and value.value.id in sys_aliases
            ) or (isinstance(value, ast.Name) and value.id in modules_aliases)
            if is_modules:
                target = _static_string(node.slice)
                if target is None:
                    markers.add("sys.modules[<computed>] (opaque module access)")
                elif target.split(".", 1)[0] in _EXEC_ONLY_MODULES:
                    markers.add(f"sys.modules[{target!r}]")
        elif isinstance(node, ast.Call):
            imported = dynamic_target(node)
            if imported == "<computed>":
                markers.add("import_module(<computed>) (opaque module access)")
            elif imported and imported.split(".", 1)[0] in _EXEC_ONLY_MODULES:
                markers.add(imported)
            accessor = _resolved_call_name(node.func, {})
            if accessor in {"getattr", "builtins.getattr"}:
                owner = (
                    dual_aliases.get(node.args[0].id)
                    if node.args and isinstance(node.args[0], ast.Name)
                    else None
                )
                member = _static_string(node.args[1]) if len(node.args) > 1 else None
                if owner and member in _EXEC_FUNCTIONS:
                    markers.add(f"{owner}.{member}")
                elif owner and member is None:
                    markers.add(f"{owner}.<computed> (opaque member access)")
    return markers


def _side_effect_module(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    directories = {part.lower() for part in relative.parts[:-1]}
    return bool(directories & _SIDE_EFFECT_DIRECTORIES) or path.stem.lower().endswith(
        _SIDE_EFFECT_SUFFIXES
    )


def _gate(identifier: str, problems: list[str], success: str) -> dict[str, Any]:
    unique = list(dict.fromkeys(problems))
    detail = success if not unique else "; ".join(unique[:20])
    if len(unique) > 20:
        detail += f"; and {len(unique) - 20} more"
    return {"id": identifier, "passed": not unique, "detail": detail}


def _apply_resource_limits() -> dict[str, Any]:
    """Confine this verifier and the test process it launches, or fail closed."""
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class IoCounters(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong),
                ]

            class BasicLimits(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class ExtendedLimits(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", BasicLimits),
                    ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = (
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            )
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.AssignProcessToJobObject.argtypes = (
                wintypes.HANDLE,
                wintypes.HANDLE,
            )
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
            limits = ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = (
                0x00000008 | 0x00000100 | 0x00000200 | 0x00002000
            )
            limits.BasicLimitInformation.ActiveProcessLimit = _MAX_PROCESSES
            limits.ProcessMemoryLimit = _MAX_MEMORY_BYTES
            limits.JobMemoryLimit = _MAX_JOB_MEMORY_BYTES
            if not kernel32.SetInformationJobObject(
                job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
            ):
                raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
            if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
                raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
            # The handle must remain open for KILL_ON_JOB_CLOSE and child
            # inheritance to remain effective.
            _WINDOWS_JOB_HANDLES.append(job)
            return {
                "enforced": True,
                "platform": "windows-job-object",
                "process_memory_bytes": _MAX_MEMORY_BYTES,
                "job_memory_bytes": _MAX_JOB_MEMORY_BYTES,
                "active_processes": _MAX_PROCESSES,
            }
        except (AttributeError, ImportError, OSError, TypeError, ValueError) as exc:
            return {"enforced": False, "platform": "windows", "error": str(exc)}

    try:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (_MAX_MEMORY_BYTES, _MAX_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(
                resource.RLIMIT_NPROC,
                (_MAX_POSIX_PROCESSES, _MAX_POSIX_PROCESSES),
            )
        return {
            "enforced": True,
            "platform": "posix-rlimit",
            "process_memory_bytes": _MAX_MEMORY_BYTES,
            "active_processes": _MAX_POSIX_PROCESSES,
            "cpu_seconds": 120,
        }
    except (ImportError, OSError, ValueError) as exc:
        return {"enforced": False, "platform": os.name, "error": str(exc)}


def _subject_digest(file_digests: dict[str, str]) -> str:
    return _canonical_digest({"files": sorted(file_digests.items())})


def _constructed_environment() -> dict[str, str]:
    allowed = ("COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR")
    result = {name: os.environ[name] for name in allowed if name in os.environ}
    result["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    return result


def _execute_tests(
    root: Path,
    files: list[Path],
    trusted_origin: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run tests from a private copy, never from project cwd or import state."""
    with tempfile.TemporaryDirectory(prefix="nornyx-greenfield-subject-") as scratch:
        snapshot = Path(scratch) / "subject"
        copied: dict[str, str] = {}
        for path in files:
            data, problem = _safe_bytes(path, root)
            if problem or data is None:
                return (
                    _gate("test-execution", [problem or "subject copy failed"], ""),
                    {"status": "not_run"},
                )
            relative = _relative(path, root)
            target = snapshot / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            copied[relative] = "sha256:" + hashlib.sha256(data).hexdigest()
        runner = Path(scratch) / "greenfield_test_runner.py"
        runner.write_text(TEST_RUNNER_SOURCE, encoding="utf-8", newline="\n")
        runner.chmod(0o444)
        runner_digest = _file_digest(runner)
        command = (
            sys.executable,
            "-I",
            str(runner),
            str(snapshot),
        )
        invocation = {
            "python": sys.executable,
            "isolated_python": True,
            "cwd": str(trusted_origin.parent),
            "environment": "constructed-host-allowlist-without-path-or-pythonpath",
            "subject": "private-temporary-copy",
            "subject_digest": _subject_digest(copied),
            "runner": "private-readonly-trusted-runner",
            "runner_digest": runner_digest,
            "command": list(command),
        }
        try:
            with tempfile.TemporaryFile(mode="w+b") as output:
                completed = subprocess.run(
                    command,
                    cwd=trusted_origin.parent,
                    env=_constructed_environment(),
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=_TEST_TIMEOUT_SECONDS,
                )
                output.seek(0)
                detail = output.read(20_000).decode("utf-8", errors="replace").strip()
                after_runner_digest = _file_digest(runner)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return (
                _gate(
                    "test-execution",
                    [f"isolated test execution failed: {type(exc).__name__}: {exc}"],
                    "",
                ),
                invocation,
            )
        if after_runner_digest != runner_digest:
            return (
                _gate("test-execution", ["trusted test runner changed during execution"], ""),
                invocation,
            )
        problems = [] if completed.returncode == 0 else [
            f"isolated tests exited {completed.returncode}: {detail[-4000:]}"
        ]
        return (
            _gate("test-execution", problems, "isolated project tests passed"),
            invocation,
        )


def verify(
    project_root: Path,
    *,
    trusted_origin: Path | None = None,
    trusted_digest: str | None = None,
    forge_version: str | None = None,
    forge_revision: str | None = None,
    resource_limits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = project_root.resolve(strict=True)
    files, boundary_problems = _collect_files(root)
    python_files = [path for path in files if path.suffix.lower() == ".py"]
    tests = [
        path
        for path in python_files
        if path.relative_to(root).parts
        and path.relative_to(root).parts[0].lower() == "tests"
        and path.name.startswith("test_")
    ]
    sources = [path for path in python_files if path not in tests]

    brd = root / "BRD.md"
    structure = list(boundary_problems)
    if resource_limits is not None and not resource_limits.get("enforced"):
        structure.append("OS resource confinement could not be established")
    if brd not in files:
        structure.append("BRD.md is missing")
    if not sources:
        structure.append("no Python application source was found")
    if not tests:
        structure.append("no tests/test_*.py file was found")

    compilation: list[str] = []
    traceability: list[str] = []
    requirement_ids: list[str] = []
    test_semantics: list[str] = []
    test_functions = 0
    assertions = 0
    architecture: list[str] = []
    security: list[str] = []
    file_digests: dict[str, str] = {}
    test_references: set[str] = set()
    total_ast_nodes = 0

    for path in files:
        relative = _relative(path, root)
        data, read_problem = _safe_bytes(path, root)
        if read_problem or data is None:
            structure.append(read_problem or f"cannot read {relative}")
            continue
        file_digests[relative] = "sha256:" + hashlib.sha256(data).hexdigest()

        if path == brd:
            try:
                brd_text = data.decode("utf-8")
                requirement_ids = sorted(
                    set(re.findall(r"(?m)^#{2,6}\s+(BRD-[A-Z0-9-]+)\b", brd_text))
                )
            except UnicodeError as exc:
                traceability.append(f"BRD.md cannot be inspected: {exc}")

        if path.suffix.lower() != ".py":
            if path.suffix.lower() in _TEXT_SUFFIXES or path.name == ".env":
                try:
                    text = data.decode("utf-8")
                except UnicodeError as exc:
                    security.append(f"cannot inspect text file {relative}: {exc}")
                else:
                    for label, pattern in _SECRET_PATTERNS.items():
                        if pattern.search(text):
                            security.append(f"possible {label} in {relative}")
            continue

        text, problem = _python_text(data, path, root)
        if problem or text is None:
            compilation.append(problem or f"cannot parse {relative}")
            continue
        if path in tests:
            test_references.update(re.findall(r"BRD-[A-Z0-9-]+", text))
        for label, pattern in _SECRET_PATTERNS.items():
            if pattern.search(text):
                security.append(f"possible {label} in {relative}")
        try:
            tree = ast.parse(text, filename=relative)
            compile(tree, relative, "exec", dont_inherit=True)
        except (MemoryError, SyntaxError, ValueError) as exc:
            compilation.append(f"{relative} does not compile: {exc}")
            continue

        nodes = list(ast.walk(tree))
        total_ast_nodes += len(nodes)
        if total_ast_nodes > _MAX_TOTAL_AST_NODES:
            compilation.append(
                f"project exceeds the {_MAX_TOTAL_AST_NODES}-node AST inspection limit"
            )
            break
        aliases = _aliases(tree)
        markers = _process_capability_markers(tree)
        if markers and not _side_effect_module(path, root):
            architecture.append(
                "process capability is not behind an explicit service/tool/adapter/worker: "
                f"{relative} ({', '.join(sorted(markers))})"
            )
        for node in nodes:
            if path in tests:
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name.startswith("test_")
                ):
                    test_functions += 1
                if isinstance(node, ast.Assert):
                    assertions += 1
                if isinstance(node, ast.Call) and _call_name(node.func).endswith(".raises"):
                    assertions += 1

            static_value = _static_string(node)
            if static_value is not None:
                for label, pattern in _SECRET_PATTERNS.items():
                    if pattern.search(static_value):
                        security.append(f"possible {label} in {relative}")
            if not isinstance(node, ast.Call):
                continue
            name = _resolved_callable_name(node.func, aliases)
            if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                security.append(f"dynamic Python execution is not allowed: {relative}:{node.lineno}")
            if name in _DYNAMIC_IMPORT_CALLS:
                security.append(f"dynamic module import is not allowed: {relative}:{node.lineno}")
            for keyword in node.keywords:
                if keyword.arg == "shell" and not (
                    isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ):
                    security.append(
                        f"shell execution is enabled or opaque and not allowed: {relative}:{node.lineno}"
                    )
        del nodes, tree

    if not requirement_ids:
        traceability.append("BRD.md contains no traceable BRD-* requirement heading")
    for requirement_id in requirement_ids:
        if requirement_id not in test_references:
            traceability.append(f"tests do not reference {requirement_id}")
    if test_functions == 0:
        test_semantics.append("no discoverable test_* function was found")
    if assertions == 0:
        test_semantics.append("tests contain no assertion or expected-refusal block")

    gates = [
        _gate("project-structure", structure, "BRD, application source, and tests are present"),
        _gate(
            "requirements-traceability",
            traceability,
            f"tests reference all {len(requirement_ids)} BRD requirement headings",
        ),
        _gate("source-compilation", compilation, f"parsed {len(python_files)} Python files"),
        _gate(
            "test-semantics",
            test_semantics,
            f"found {test_functions} test functions and {assertions} assertion blocks",
        ),
        _gate("architecture-boundary", architecture, "process side effects use explicit boundary modules"),
        _gate("security-static", security, "no static secret or unsafe execution finding"),
    ]

    subject_digest = _subject_digest(file_digests)
    if all(gate["passed"] for gate in gates):
        test_gate, test_invocation = _execute_tests(
            root, files, trusted_origin or Path(__file__).resolve(strict=True)
        )
        if test_invocation.get("subject_digest") != subject_digest:
            test_gate = _gate(
                "test-execution",
                ["subject changed between static inspection and the private test snapshot"],
                "",
            )
    else:
        test_gate = _gate(
            "test-execution",
            ["isolated tests were not run because a preceding static gate failed"],
            "",
        )
        test_invocation = {"status": "not_run"}
    gates.append(test_gate)

    origin = trusted_origin or Path(__file__).resolve(strict=True)
    version = forge_version or _forge_version()
    execution_origin = Path(__file__).resolve(strict=True)
    payload = {
        "schema": "nornyx.forge.greenfield_verification.v1",
        "status": "pass" if all(gate["passed"] for gate in gates) else "fail",
        "gate_profile": {
            **PROFILE_DEFINITION,
            "digest": _canonical_digest(PROFILE_DEFINITION),
        },
        "verifier": {
            "id": "nornyx_forge.greenfield_verifier",
            "origin": str(origin),
            "digest": trusted_digest or _file_digest(origin),
            "execution_origin": str(execution_origin),
            "execution_digest": _file_digest(execution_origin),
            "forge_version": version,
            "forge_revision": forge_revision or _forge_revision(origin, version),
        },
        "subject": {
            "root": str(root),
            "digest": subject_digest,
            "file_count": len(file_digests),
        },
        "resource_limits": resource_limits or {"enforced": False, "platform": "not_applied"},
        "test_execution": test_invocation,
        "gates": gates,
    }
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--trusted-origin")
    parser.add_argument("--trusted-digest")
    parser.add_argument("--forge-version")
    parser.add_argument("--forge-revision")
    args = parser.parse_args(argv)
    resource_limits = _apply_resource_limits()
    try:
        payload = verify(
            Path(args.project_root),
            trusted_origin=Path(args.trusted_origin) if args.trusted_origin else None,
            trusted_digest=args.trusted_digest,
            forge_version=args.forge_version,
            forge_revision=args.forge_revision,
            resource_limits=resource_limits,
        )
    except (MemoryError, OSError, RuntimeError, ValueError) as exc:
        origin = Path(args.trusted_origin) if args.trusted_origin else Path(__file__).resolve()
        version = args.forge_version or _forge_version()
        payload = {
            "schema": "nornyx.forge.greenfield_verification.v1",
            "status": "fail",
            "gate_profile": {
                **PROFILE_DEFINITION,
                "digest": _canonical_digest(PROFILE_DEFINITION),
            },
            "verifier": {
                "id": "nornyx_forge.greenfield_verifier",
                "origin": str(origin),
                "digest": args.trusted_digest or _file_digest(Path(__file__).resolve()),
                "execution_origin": str(Path(__file__).resolve()),
                "execution_digest": _file_digest(Path(__file__).resolve()),
                "forge_version": version,
                "forge_revision": args.forge_revision or "unavailable",
            },
            "subject": {
                "root": str(Path(args.project_root).resolve()),
                "digest": _canonical_digest({"operation_failed": True}),
                "file_count": 0,
            },
            "resource_limits": resource_limits,
            "test_execution": {"status": "not_run"},
            "gates": [
                {
                    "id": "verifier-operation",
                    "passed": False,
                    "detail": f"trusted verifier could not inspect the project: {type(exc).__name__}: {exc}",
                }
            ],
        }
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
