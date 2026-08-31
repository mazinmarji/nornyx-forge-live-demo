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
import json
import os
import re
import tokenize
from pathlib import Path
from typing import Any

PROFILE_DEFINITION = {
    "id": "nornyx.greenfield.python.v1",
    "version": 1,
    "checks": [
        "project-structure",
        "requirements-traceability",
        "source-compilation",
        "test-semantics",
        "architecture-boundary",
        "security-static",
    ],
    "execution": "static-inspection-only",
}

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
_PROCESS_CALLS = {
    f"{module}.{name}"
    for module, names in (
        ("os", ("popen", "system")),
        ("subprocess", ("Popen", "call", "check_call", "check_output", "run")),
    )
    for name in names
}
_DYNAMIC_IMPORT_CALLS = {"__import__", "importlib.import_module"}
_SIDE_EFFECT_DIRECTORIES = {"adapters", "services", "tools", "workers"}
_SIDE_EFFECT_SUFFIXES = ("_adapter", "_service", "_tool", "_worker")
_MAX_FILES = 5000
_MAX_FILE_BYTES = 2_000_000
_MAX_TOTAL_BYTES = 50_000_000


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
            if child.is_symlink():
                problems.append(f"symlinked directory is outside the inspected subject: {_relative(child, root)}")
                continue
            kept.append(name)
        directories[:] = kept
        for name in sorted(names):
            path = current_path / name
            relative = _relative(path, root)
            if path.is_symlink():
                problems.append(f"symlinked file is outside the inspected subject: {relative}")
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


def _python_text(path: Path, root: Path) -> tuple[str | None, str | None]:
    try:
        with tokenize.open(path) as handle:
            return handle.read(), None
    except (OSError, SyntaxError, UnicodeError) as exc:
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


def verify(project_root: Path) -> dict[str, Any]:
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
    if not brd.is_file():
        structure.append("BRD.md is missing")
    if not sources:
        structure.append("no Python application source was found")
    if not tests:
        structure.append("no tests/test_*.py file was found")

    source_text: dict[Path, str] = {}
    compilation: list[str] = []
    parsed: dict[Path, ast.AST] = {}
    for path in python_files:
        text, problem = _python_text(path, root)
        if problem:
            compilation.append(problem)
            continue
        assert text is not None
        source_text[path] = text
        try:
            compile(text, _relative(path, root), "exec", dont_inherit=True)
            parsed[path] = ast.parse(text, filename=_relative(path, root))
        except (SyntaxError, ValueError) as exc:
            compilation.append(f"{_relative(path, root)} does not compile: {exc}")

    traceability: list[str] = []
    requirement_ids: list[str] = []
    if brd.is_file():
        try:
            brd_text = brd.read_text(encoding="utf-8")
            requirement_ids = sorted(
                set(re.findall(r"(?m)^#{2,6}\s+(BRD-[A-Z0-9-]+)\b", brd_text))
            )
        except (OSError, UnicodeError) as exc:
            traceability.append(f"BRD.md cannot be inspected: {exc}")
    if not requirement_ids:
        traceability.append("BRD.md contains no traceable BRD-* requirement heading")
    test_corpus = "\n".join(source_text.get(path, "") for path in tests)
    for requirement_id in requirement_ids:
        if requirement_id not in test_corpus:
            traceability.append(f"tests do not reference {requirement_id}")

    test_semantics: list[str] = []
    test_functions = 0
    assertions = 0
    for path in tests:
        tree = parsed.get(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
                "test_"
            ):
                test_functions += 1
            if isinstance(node, ast.Assert):
                assertions += 1
            if isinstance(node, ast.Call) and _call_name(node.func).endswith(".raises"):
                assertions += 1
    if test_functions == 0:
        test_semantics.append("no discoverable test_* function was found")
    if assertions == 0:
        test_semantics.append("tests contain no assertion or expected-refusal block")

    architecture: list[str] = []
    security: list[str] = []
    for path, tree in parsed.items():
        relative = _relative(path, root)
        aliases = _aliases(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _resolved_call_name(node.func, aliases)
            if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                security.append(f"dynamic Python execution is not allowed: {relative}:{node.lineno}")
            if name in _DYNAMIC_IMPORT_CALLS:
                security.append(f"dynamic module import is not allowed: {relative}:{node.lineno}")
            if name in _PROCESS_CALLS and not _side_effect_module(path, root):
                architecture.append(
                    "process execution is not behind an explicit service/tool/adapter/worker: "
                    f"{relative}:{node.lineno}"
                )
            if name in _PROCESS_CALLS:
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        security.append(
                            f"shell execution is enabled and not allowed: {relative}:{node.lineno}"
                        )

    for path in files:
        if path.suffix.lower() not in _TEXT_SUFFIXES and path.name != ".env":
            continue
        relative = _relative(path, root)
        try:
            text = source_text.get(path)
            if text is None:
                text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            security.append(f"cannot inspect text file {relative}: {exc}")
            continue
        for label, pattern in _SECRET_PATTERNS.items():
            if pattern.search(text):
                security.append(f"possible {label} in {relative}")

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

    origin = Path(__file__).resolve(strict=True)
    version = _forge_version()
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
            "digest": _file_digest(origin),
            "forge_version": version,
            "forge_revision": _forge_revision(origin, version),
        },
        "gates": gates,
    }
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    args = parser.parse_args(argv)
    try:
        payload = verify(Path(args.project_root))
    except (OSError, RuntimeError, ValueError) as exc:
        payload = {
            "schema": "nornyx.forge.greenfield_verification.v1",
            "status": "fail",
            "gate_profile": {
                **PROFILE_DEFINITION,
                "digest": _canonical_digest(PROFILE_DEFINITION),
            },
            "verifier": {
                "id": "nornyx_forge.greenfield_verifier",
                "origin": str(Path(__file__).resolve()),
                "digest": _file_digest(Path(__file__).resolve()),
                "forge_version": _forge_version(),
                "forge_revision": "unavailable",
            },
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
