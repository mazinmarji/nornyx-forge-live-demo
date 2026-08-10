"""Deterministic architecture conformance check.

Dependency direction is derived from the declared architecture contract rather
than from a hardcoded list, so a module that grows an undeclared first-party
import fails this gate instead of passing silently.

The check is driven by what exists on disk, not by what the contract lists.
Every rule below iterated over `declared_modules`, which meant an undeclared
module was not a violation — it was invisible. Eight of nineteen first-party
modules were never read at all, including the Forge CLI, while the gate reported
`violations: []`. Omission was the cheapest way to pass, which is the wrong
incentive for a conformance gate: the contract is meant to be a closed statement
of what exists, so anything present and unmodelled is itself the defect.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import yaml

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # 3.10, which `requires-python` still supports
    tomllib = None

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / ".nornyx/contracts/architecture_governance.nyx"
REPORT = ROOT / ".nornyx/architecture/conformance.json"
SOURCE_ROOT = ROOT / "src"

violations: list[str] = []


def _module_path(dotted: str) -> Path:
    return SOURCE_ROOT / (dotted.replace(".", "/") + ".py")


def _imports(path: Path, relative: str, dotted: str | None = None) -> set[str]:
    """Return the module names imported by one file.

    Relative imports are resolved against ``dotted`` (the importing module's own
    dotted name) so that `from .store import JsonStore` is recognised as a
    dependency on `demo_app.store` and not silently ignored.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    package = dotted.rsplit(".", 1)[0] if dotted and "." in dotted else ""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parent = package
                for _ in range(node.level - 1):
                    parent = parent.rsplit(".", 1)[0] if "." in parent else ""
                base = f"{parent}.{node.module}" if node.module else parent
            else:
                base = node.module or ""
            if not base:
                continue
            names.add(base)
            names.add(base.split(".")[0])
            # `from package import module` also creates a module dependency.
            for alias in node.names:
                names.add(f"{base}.{alias.name}")
        elif isinstance(node, ast.Call):
            names.update(_dynamic_import_targets(node))
    return names


#: Ways to import a module without an import statement. A review reached
#: `subprocess` from the purity-constrained domain module, and
#: `demo_app.store` (infrastructure) from a domain leaf declared
#: `depends_on: []`, through `importlib.import_module` -- and the gate reported
#: `violations: []` both times, because it read only `ast.Import` and
#: `ast.ImportFrom`. The module comment asserting the leaf guarantee was
#: therefore checking a graph the code could step around.
_DYNAMIC_IMPORTERS = {"import_module", "__import__", "find_spec", "spec_from_file_location"}


def _dynamic_import_targets(node: ast.Call) -> set[str]:
    """Module names a dynamic import call names literally.

    Only literal arguments are resolved: a computed name is unknowable here, and
    is refused separately by `_dynamic_import_is_literal` so it cannot become a
    silent hole. Better to be exact about what static analysis can see than to
    guess at what it cannot.
    """
    func = node.func
    if isinstance(func, ast.Attribute):
        name = func.attr
    elif isinstance(func, ast.Name):
        name = func.id
    else:
        return set()
    if name not in _DYNAMIC_IMPORTERS:
        return set()

    targets: set[str] = set()
    for argument in node.args[:1]:
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            targets.add(argument.value)
            targets.add(argument.value.split(".")[0])
    return targets


def _computed_dynamic_imports(path: Path, relative: str) -> list[str]:
    """Dynamic imports whose target this checker cannot read.

    A declared dependency graph means nothing if a module can import a name
    assembled at runtime, so these are refused rather than ignored. Passing a
    literal is the supported form; it is visible, and the gate can model it.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    unknown: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name not in _DYNAMIC_IMPORTERS:
            continue
        first = node.args[0] if node.args else None
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            unknown.append(f"{relative}:{node.lineno}")
    return unknown


FIRST_PARTY_PACKAGES = {
    entry.name for entry in SOURCE_ROOT.iterdir() if (entry / "__init__.py").exists()
}

architecture = yaml.safe_load(CONTRACT.read_text(encoding="utf-8")).get("architecture", {})
declared_modules = {item["id"]: item for item in architecture.get("modules", [])}
declared_layers = {item["id"]: item for item in architecture.get("layers", [])}
module_by_name = {item["name"]: item for item in declared_modules.values()}

def _console_scripts_without_tomllib(path: Path) -> dict[str, str]:
    """Read `[project.scripts]` on Python 3.10, which has no `tomllib`.

    Deliberately narrow: it reads one table of `name = "module:attr"` entries
    from a file this repository owns, and understands nothing else. Anything it
    cannot parse is left out, and an empty result is reported as a violation by
    the caller rather than passing as "no entrypoints to protect".
    """
    scripts: dict[str, str] = {}
    in_section = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped == "[project.scripts]"
            continue
        if not in_section or "=" not in stripped or stripped.startswith("#"):
            continue
        name, _, target = stripped.partition("=")
        value = target.strip().strip('"').strip("'")
        if value:
            scripts[name.strip()] = value
    return scripts


def _console_entrypoints() -> set[str]:
    """Modules `pyproject.toml` installs as console scripts.

    Read from the packaging metadata rather than declared in the contract: which
    module is the entrypoint is already a fact recorded elsewhere, and a second
    hand-maintained copy would only be somewhere for the two to disagree.
    """
    path = ROOT / "pyproject.toml"
    if not path.exists():
        # Fail closed and legibly. Proceeding with an empty set would quietly
        # retire the leaf rule, and a raw traceback reads as a broken gate
        # rather than as the missing input it is.
        violations.append(
            "pyproject.toml is missing, so the console entrypoint cannot be "
            "determined and the entrypoint rule cannot be applied"
        )
        return set()

    if tomllib is not None:
        with path.open("rb") as handle:
            scripts = tomllib.load(handle).get("project", {}).get("scripts", {})
    else:
        scripts = _console_scripts_without_tomllib(path)

    if not scripts:
        violations.append(
            "pyproject.toml declares no console script, so the rule that nothing "
            "may depend on an entrypoint is not being applied to anything"
        )
    return {target.split(":", 1)[0] for target in scripts.values()}


#: An entrypoint is where a program is composed, so it is expected to reach
#: across the toolchain. Nothing may depend on it in return. A module that is
#: both composed and depended upon could carry a dependency between two modules
#: that may not depend on each other, which is the inversion the layer rule
#: exists to prevent, laundered through the one module nobody looks at.
entrypoints = _console_entrypoints()


def _discovered_modules() -> dict[str, Path]:
    """Every first-party module that exists, which is what the gate must cover."""
    found: dict[str, Path] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        dotted = path.relative_to(SOURCE_ROOT).as_posix().removesuffix(".py").replace("/", ".")
        found[dotted.removesuffix(".__init__")] = path
    return found


def _is_inert_package_init(path: Path) -> bool:
    """True for a package marker holding nothing but a docstring and dunders.

    Verified rather than assumed. An `__init__.py` that re-exports names creates
    real dependency edges, so the moment one stops being inert it has to be
    declared like any other module.
    """
    if path.name != "__init__.py":
        return False
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue
        if isinstance(node, ast.Assign) and all(
            isinstance(target, ast.Name) and target.id.startswith("__")
            for target in node.targets
        ):
            continue
        return False
    return True


# --- constraint.architecture_coverage ---
discovered = _discovered_modules()
for dotted, path in sorted(discovered.items()):
    if dotted in module_by_name or _is_inert_package_init(path):
        continue
    violations.append(
        f"{path.relative_to(ROOT).as_posix()} is a first-party module the "
        "architecture contract does not declare; a module the contract does not "
        "model is not exempt from the gate, it is unreviewed"
    )

# --- constraint.declared_dependencies_only and constraint.layer_direction ---
for module_id, module in sorted(declared_modules.items()):
    dotted = module["name"]
    path = _module_path(dotted)
    if not path.exists():
        violations.append(f"declared module {module_id} has no source file at {path.relative_to(ROOT)}")
        continue
    relative = str(path.relative_to(ROOT)).replace("\\", "/")

    # A declared dependency graph means nothing if a module can import a name
    # assembled at runtime. Literal dynamic imports are modelled as ordinary
    # dependencies by `_imports`; computed ones cannot be, so they are refused.
    for site in _computed_dynamic_imports(path, relative):
        violations.append(
            f"{site} imports a module named at runtime, which no declared "
            "dependency graph can describe. Pass a literal module name."
        )

    allowed_ids = set(module.get("depends_on") or [])
    allowed_names = {
        declared_modules[dependency]["name"]
        for dependency in allowed_ids
        if dependency in declared_modules
    }
    own_layer = module.get("layer")
    permitted_layers = set(declared_layers.get(own_layer, {}).get("may_depend_on") or [])
    permitted_layers.add(own_layer)

    for imported in sorted(_imports(path, relative, dotted)):
        target = module_by_name.get(imported)
        if target is None:
            # A first-party source module that the architecture does not model at
            # all is still an undeclared dependency, not an exempt import.
            if (
                imported.split(".")[0] in FIRST_PARTY_PACKAGES
                and imported != dotted
                and _module_path(imported).exists()
            ):
                violations.append(
                    f"{relative} imports first-party module {imported}, "
                    "which is not declared in the architecture contract"
                )
            continue
        if target["id"] == module_id:
            continue
        if imported in entrypoints:
            violations.append(
                f"{relative} depends on console entrypoint {imported}; an "
                "entrypoint composes the program and must stay a leaf"
            )
            continue
        if imported not in allowed_names:
            violations.append(
                f"{relative} imports undeclared dependency {imported} "
                f"(not in {module_id}.depends_on)"
            )
            continue
        target_layer = target.get("layer")
        if target_layer not in permitted_layers:
            violations.append(
                f"{relative} depends on {imported} in {target_layer}, "
                f"which {own_layer} may not depend on"
            )

# --- explicit forbidden-dependency rules retained from the declared constraints ---
#
# These hold unconditionally. They are checked by path rather than through the
# module graph, so declaring an edge cannot grant it: the HTTP surface of the
# governed application may not reach the governance domain whatever the contract
# later says, leaving the action boundary the only route to a consequential
# effect.
forbidden = {
    "src/demo_app/store.py": {"fastapi", "crewai", "subprocess"},
    "src/demo_app/main.py": {"nornyx_forge", "subprocess", "crewai"},
    "src/nornyx_forge/evidence.py": {"fastapi", "crewai", "demo_app"},
    "src/nornyx_forge/policy.py": {"fastapi", "demo_app"},
    "src/nornyx_forge/nornyx_runtime.py": {"fastapi", "demo_app"},
    "src/demo_app/agentic.py": {"fastapi", "demo_app.store"},
    # Module-specific purity, stronger than anything the layer rules impose.
    # Other domain modules legitimately touch a filesystem or SQLite; this one
    # must not, because a subject primitive able to reach ambient state could
    # rediscover its own authority — the re-resolution the model exists to
    # remove. Verified by injecting `subprocess` and requiring a failure.
    "src/nornyx_forge/governed_subject.py": {
        "subprocess", "os", "pathlib", "shutil", "socket", "urllib",
        "requests", "httpx", "yaml", "sqlite3", "tempfile",
    },
}
for relative, banned in forbidden.items():
    path = ROOT / relative
    if not path.exists():
        # A renamed file would otherwise retire its own rule in silence.
        violations.append(
            f"forbidden-dependency rule names {relative}, which does not exist, "
            "so the rule is no longer being applied to anything"
        )
        continue
    # Pass the module's own dotted name so a relative spelling such as
    # `from .store import JsonStore` resolves to demo_app.store and is matched.
    dotted = relative.removeprefix("src/").removesuffix(".py").replace("/", ".")
    for name in sorted(_imports(path, relative, dotted) & banned):
        violations.append(f"{relative} imports forbidden dependency {name}")

# --- constraint.bounded_external_adapter ---
# Interface and application modules must delegate process execution. The
# governance module (nornyx CLI) and infrastructure adapters (claude CLI) are the
# declared places where an external process may be started.
# A domain process-execution prohibition, not a general purity rule: domain
# modules here still legitimately open files and SQLite. What none of them may
# do is start a process, and the previous set let one do so unremarked.
DELEGATING_LAYERS = {"layer.interface", "layer.application", "layer.domain"}
PROCESS_MODULES = {"subprocess", "pty", "multiprocessing"}

#: Exec-family names that start a process. Tracked as bare names as well as
#: attributes, because `from os import system` then `system(cmd)` produced no
#: marker at all: the import filter only looked at PROCESS_MODULES (which does
#: not contain `os`), and the call filter only matched ast.Attribute. An
#: unauthenticated endpoint spelled that way passed both the architecture gate
#: and the security gate with zero findings.
PROCESS_FUNCTIONS = {
    "system",
    "popen",
    "execl",
    "execle",
    "execlp",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnv",
    "spawnve",
    "spawnvp",
    "posix_spawn",
    "posix_spawnp",
    "startfile",
    "fork",
    "forkpty",
    "run",
    "call",
    "check_call",
    "check_output",
    "Popen",
    "getoutput",
    "getstatusoutput",
    "create_subprocess_exec",
    "create_subprocess_shell",
}

#: Modules whose exec-family members count. `os` belongs here and not in
#: PROCESS_MODULES because importing `os` is ordinary; calling its exec family
#: is not.
PROCESS_CALL_OWNERS = {"os", "subprocess", "asyncio", "multiprocessing", "pty"}

PROCESS_CALLS = {
    f"{owner}.{name}" for owner in ("os",) for name in PROCESS_FUNCTIONS
}


def _process_execution_markers(path: Path, relative: str) -> set[str]:
    """Return concrete process-execution markers, by import and by call site."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    markers: set[str] = set()

    # Names bound by `from <owner> import <exec-family>`, including aliases. A
    # call through one of these is an ast.Name, not an ast.Attribute, so without
    # tracking the binding the call site is invisible to the walk below.
    bound_exec_names: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in PROCESS_MODULES:
                    markers.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in PROCESS_MODULES:
                markers.add(node.module)
            elif root in PROCESS_CALL_OWNERS:
                # `from os import system as _s` — the module is ordinary, the
                # name imported is not.
                for alias in node.names:
                    if alias.name in PROCESS_FUNCTIONS:
                        bound = alias.asname or alias.name
                        bound_exec_names[bound] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                owner = func.value.id
                dotted = f"{owner}.{func.attr}"
                if (
                    dotted in PROCESS_CALLS
                    or owner in PROCESS_MODULES
                    or (owner in PROCESS_CALL_OWNERS and func.attr in PROCESS_FUNCTIONS)
                ):
                    markers.add(dotted)
            elif isinstance(func, ast.Name) and func.id in bound_exec_names:
                markers.add(bound_exec_names[func.id])

    # An exec-family name imported into the module is a marker whether or not a
    # call is visible here: it can be re-exported, stored, or invoked through a
    # reference the AST cannot follow.
    markers.update(bound_exec_names.values())
    return markers


for module in declared_modules.values():
    if module.get("layer") not in DELEGATING_LAYERS:
        continue
    path = _module_path(module["name"])
    if not path.exists():
        continue
    relative = str(path.relative_to(ROOT)).replace("\\", "/")
    for marker in sorted(_process_execution_markers(path, relative)):
        violations.append(
            f"{relative} performs process execution ({marker}) outside a declared adapter"
        )

# --- constraint.api_no_commands and governed action boundary ---
main_text = (ROOT / "src/demo_app/main.py").read_text(encoding="utf-8")
if "subprocess" in main_text or "os.system" in main_text:
    violations.append("API layer contains direct command execution")
agentic_text = (ROOT / "src/demo_app/agentic.py").read_text(encoding="utf-8")
if "NornyxActionBoundary" not in agentic_text:
    violations.append("runtime orchestration does not use the declared Nornyx action boundary")
if "evaluate_and_execute" not in agentic_text:
    violations.append("runtime orchestration does not route execution through the action boundary")
if "action()" in main_text:
    violations.append("API layer appears to invoke a consequential action directly")

result = {
    "schema": "nornyx.forge.architecture_report.v1",
    "status": "pass" if not violations else "fail",
    "subject": "nornyx-forge-live-demo",
    "checks": [
        "architecture_coverage",
        "dependency_direction",
        "declared_dependencies_only",
        "layer_direction",
        "entrypoint_is_leaf",
        "bounded_external_adapter",
        "api_command_isolation",
        "governed_action_boundary",
        "persistence_isolation",
    ],
    "declared_modules": sorted(declared_modules),
    "covered_modules": sorted(discovered),
    "violations": violations,
}
REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2))
raise SystemExit(0 if not violations else 2)
