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


#: A module name this checker cannot read, because it is assembled at
#: runtime. DEFINED HERE rather than beside its other user: this module
#: runs its checks at import time, and `_computed_dynamic_imports` is
#: called at module level well before the old definition site executed.
_COMPUTED = "<computed>"


#: Reflection primitives that hand back a namespace without naming a module.
#:
#: `vars` and `getattr` are refused only in the shapes that can yield one; a
#: literal attribute on an ordinary object is ordinary code and stays legal.
_NAMESPACE_BUILTINS = {"vars", "globals", "locals", "eval", "exec", "__import__"}


def _unresolvable_module_access(tree: ast.AST) -> list[tuple[int, str]]:
    """Constructs that can obtain a module namespace without a static import.

    REFUSED, NOT RESOLVED, and that is the whole difference from what came
    before. Two earlier attempts tried to decide WHICH module an expression
    yields by recognising the shape of the expression, and each was reopened by
    a shape nobody had used yet:

        attempt 1   read Import, ImportFrom and dynamic-import calls
                    reopened by `sys.modules["x"]`, a subscript
        attempt 2   add a sys.modules recogniser for subscript and `.get`
                    reopened by vars(sys)['modules'], getattr(sys,'modules'),
                    sys.__dict__['modules'], importlib.sys.modules,
                    `from sys import *`, dict(sys.modules), .copy(),
                    __getitem__, .pop, .setdefault, a dict subclass, and a
                    two-file re-export

    Both are the same strategy, and its assumption is false: `sys.modules` is an
    ordinary dict reachable through every reflection primitive Python has, and
    any expression evaluating to it can be aliased, copied, wrapped or
    re-exported. A rule that resolves targets is always one spelling behind,
    which is AC01 -- and attempt 2 committed AC01 while repairing AC04.
    See `docs/governance/MODULE_ACQUISITION.md` for the matrix.

    So this asks a decidable question instead: CAN this be resolved at all? The
    precedent is `_computed_dynamic_imports`, which never guesses what
    `import_module(name)` loads -- it refuses, because no declared dependency
    graph can model a name assembled at runtime.

    Aliasing does not help an attacker here: to alias `sys.modules` you must
    first write `.modules`, and that write is in governed source.

    WHAT THIS STILL DOES NOT DECIDE, stated rather than implied. A class is not
    a module: `object.__subclasses__()` reaches `Popen` without touching a
    module namespace at all. That is a different acquisition route and refusing
    the class graph is a new product requirement, filed for v1.1 and NOT
    claimed here. Nor does any static rule see a module object passed in as an
    argument from outside governed source.
    """
    sites: list[tuple[int, str]] = []
    sys_aliases, modules_aliases = _sys_module_aliases(tree)

    # THE ONE RESOLVABLE FORM IS EXEMPT, and exempting it is the point rather
    # than a concession. `sys.modules["json"]` names its target literally, so
    # `_sys_modules_target` resolves it and the dependency graph MODELS it as
    # an ordinary edge -- refused when undeclared, accepted when declared.
    # Refusing it as well would refuse a resolvable dependency for being
    # spelled unusually, which is over-reach, and
    # `test_ordinary_module_use_is_not_refused[sys.modules for a benign
    # module]` measured exactly that when this rule first landed blunt.
    #
    # Every OTHER shape reaches the map without naming what it takes from it:
    # a bare binding, a copy, a mutator, an aliased owner, a re-export. Those
    # are unresolvable and are refused unresolved.
    resolvable: set = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Subscript, ast.Call)):
            continue
        target = _sys_modules_target(node, sys_aliases, modules_aliases)
        if target is None or target == _COMPUTED:
            continue
        owner = (
            node.value if isinstance(node, ast.Subscript) else node.func.value
        )
        resolvable.add(id(owner))

    for node in ast.walk(tree):
        # `X.modules`, on ANY expression, unless this exact node is the owner
        # of a lookup that names its target literally. Every route in the
        # matrix writes this at least once -- including the re-export, which
        # is refused in the file that writes `MODMAP = sys.modules`, not the
        # one that reads it.
        if isinstance(node, ast.Attribute) and node.attr == "modules":
            if id(node) not in resolvable:
                sites.append(
                    (node.lineno, "a module map reached by attribute")
                )
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name in _NAMESPACE_BUILTINS:
                sites.append((node.lineno, name + "() yields a namespace"))
            elif name == "getattr":
                # A LITERAL name on an ordinary object is ordinary code. A
                # computed name is unknowable, and the literal "modules" is the
                # thing itself spelled as a string.
                second = node.args[1] if len(node.args) > 1 else None
                literal = (
                    isinstance(second, ast.Constant)
                    and isinstance(second.value, str)
                )
                if not literal:
                    sites.append((node.lineno, "getattr with a computed name"))
                elif second.value == "modules":
                    sites.append((node.lineno, "getattr(..., 'modules')"))
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                sites.append((node.lineno, "a star-import binds unknown names"))
        # `X.__dict__` INDEXED OR CALLED INTO. A bare `instance.__dict__` is
        # ordinary serialisation and this repository uses it eight times; it is
        # `__dict__['modules']` and `__dict__.get(...)` that reach a namespace.
        elif isinstance(node, (ast.Subscript, ast.Attribute)):
            inner = node.value
            if isinstance(inner, ast.Attribute) and inner.attr == "__dict__":
                sites.append((node.lineno, "a namespace reached through __dict__"))
    return sorted(set(sites))


def _sys_module_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Names bound to `sys`, and names bound to `sys.modules` itself.

    Two passes, because `ast.walk` does not promise imports before
    assignments and `m = sys.modules` can only be recognised once `sys`
    is known.
    """
    sys_aliases: set[str] = set()
    modules_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "sys":
                    sys_aliases.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            for alias in node.names:
                if alias.name == "modules":
                    modules_aliases.add(alias.asname or alias.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if (
            isinstance(value, ast.Attribute)
            and value.attr == "modules"
            and isinstance(value.value, ast.Name)
            and value.value.id in sys_aliases
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    modules_aliases.add(target.id)
    return sys_aliases, modules_aliases


def _sys_modules_target(
    node: ast.AST, sys_aliases: set[str], modules_aliases: set[str],
) -> str | None:
    """The module a `sys.modules` lookup names, `_COMPUTED`, or None.

    ONE OF TWO RECOGNISERS, and that is a disclosure rather than a design.
    This docstring used to claim it was the only one and that `Both callers
    use this function`; a review measured both halves false. The capability
    scan routes `ast.Call` to `_dynamically_imported_module`, which carries
    its own `sys.modules` recogniser and covers MORE mutators than this one
    -- `get`, `pop`, `setdefault`, under a comment saying that listing them
    is not thoroughness but that each evaluates to the module. So the
    narrower recogniser was the one wearing the label.

    Neither is load-bearing against a determined spelling any more:
    `_unresolvable_module_access` refuses the constructs instead of
    resolving them, and this function now only enriches the dependency
    graph for the spellings it can name exactly.

    `sys.modules` was already understood
    by the process-capability scan and not by the dependency scan, so a
    first-party edge written this way was invisible to the graph while an
    exec module written the same way was caught. Measured on this
    repository at 032ca63: `sys.modules["nornyx_forge.nornyx_runtime"]`
    appended to `src/demo_app/main.py` -- an interface module reaching the
    governance domain, which the gate refuses unconditionally when spelled
    `import` -- produced `status: pass, violations: [], exit 0`. The same
    for `store.py` reaching `subprocess` under `persistence_isolation`, and
    for the explicit forbidden edge `agentic.py` -> `demo_app.store`.

    A widening applied to one analysis and not the other is AC04, and
    writing a second recogniser here would have been the same defect once
    more. Both callers use this function.

    Covers the subscript and the `.get` spellings, `sys` under any alias,
    and `modules` bound directly by `from sys import modules` or by
    assignment -- all of which hand back the identical module object.
    """
    if isinstance(node, ast.Subscript):
        owner, key = node.value, node.slice
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
    ):
        owner = node.func.value
        key = node.args[0] if node.args else None
    else:
        return None
    is_map = (
        isinstance(owner, ast.Attribute)
        and owner.attr == "modules"
        and isinstance(owner.value, ast.Name)
        and owner.value.id in sys_aliases
    ) or (isinstance(owner, ast.Name) and owner.id in modules_aliases)
    if not is_map:
        return None
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    return _COMPUTED


def _imports(path: Path, relative: str, dotted: str | None = None) -> set[str]:
    """Return the module names imported by one file.

    Relative imports are resolved against ``dotted`` (the importing module's own
    dotted name) so that `from .store import JsonStore` is recognised as a
    dependency on `demo_app.store` and not silently ignored.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    package = dotted.rsplit(".", 1)[0] if dotted and "." in dotted else ""
    names: set[str] = set()
    sys_aliases, modules_aliases = _sys_module_aliases(tree)
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
        # A MODULE OBJECT ARRIVES HERE TOO, with no import statement
        # anywhere in the file. Computed keys are not modelled as edges --
        # they are unknowable -- and are refused by
        # `_computed_dynamic_imports` instead, so they cannot pass quietly.
        target = _sys_modules_target(node, sys_aliases, modules_aliases)
        if target is not None and target != _COMPUTED:
            names.add(target)
            names.add(target.split(".")[0])
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
    is refused separately by `_computed_dynamic_imports` so it cannot become a
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
    sys_aliases, modules_aliases = _sys_module_aliases(tree)
    for node in ast.walk(tree):
        # `sys.modules[name]` with a key assembled at runtime is exactly
        # the hazard this function exists for, by a route that is not a
        # call at all.
        if _sys_modules_target(node, sys_aliases, modules_aliases) == _COMPUTED:
            unknown.append(f"{relative}:{node.lineno}")
            continue
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
            isinstance(target, ast.Name) and target.id in INERT_DUNDERS
            for target in node.targets
        ):
            continue
        return False
    return True


#: Dunders an `__init__.py` may set and still count as inert. An allowlist, not
#: a `startswith("__")` test: `__path__` passed that test and redirects submodule
#: resolution for the whole package, so `__path__ = ["/attacker/payload"]` was
#: classified as a package marker holding nothing. That is at least as
#: consequential as the re-export the original docstring cites, and it was
#: invisible to the declaration check.
INERT_DUNDERS = frozenset({"__all__", "__version__", "__author__", "__doc__"})


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
    # REFUSED BECAUSE UNRESOLVABLE, the same principle as the loop below.
    for lineno, why in _unresolvable_module_access(
        ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    ):
        violations.append(
            f"{relative}:{lineno} obtains a module namespace by {why}, "
            "which no declared dependency graph can model. A governed "
            "module acquires a module only by static import."
        )
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
# The PROCESS_MODULES / PROCESS_FUNCTIONS / PROCESS_CALL_OWNERS /
# PROCESS_CALLS constants were REMOVED here. They were defined, carried
# comments that read as live rules, and were loaded by nothing -- verified by
# AST: zero Load references outside their own definitions, with
# PROCESS_FUNCTIONS used only to build the dead PROCESS_CALLS. The live rules
# are EXEC_ONLY_MODULES, DUAL_USE_MODULES and EXEC_FUNCTIONS.
#
# This file says of exactly this shape: a mutation removing such a branch
# killed no test, which is the signature of dead code that reads as
# load-bearing -- in a security control, the worst kind.





#: Modules whose reason for existing is starting a process. Importing one in a
#: delegating layer IS the capability -- no call site needs to be found.
EXEC_ONLY_MODULES = {"subprocess", "pty", "multiprocessing", "posix", "nt"}

#: Modules that are ordinary to import and have an exec family inside them.
#: Importing is fine; binding one of EXEC_FUNCTIONS from them is not.
# "shutil" is deliberately absent: it has no exec family. "shutil.which" only
# resolves a name against PATH -- it starts nothing -- and flagging it made the
# gate refuse "cli.py doctor", which reports tool availability. A control that
# cries wolf on ordinary code gets switched off, so the false-positive side is
# part of the property, not an afterthought.
DUAL_USE_MODULES = {"os", "asyncio"}

#: Names that start a process, wherever they are reached from.
EXEC_FUNCTIONS = {
    "system", "popen", "startfile", "fork", "forkpty",
    "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnv", "spawnve", "spawnvp",
    "posix_spawn", "posix_spawnp",
    "run", "call", "check_call", "check_output", "Popen",
    "getoutput", "getstatusoutput",
    "create_subprocess_exec", "create_subprocess_shell",
}

#: Reflection that hides the member being reached.
OPAQUE_ACCESSORS = {"getattr"}


#: Returned when a dynamic import names a module that cannot be read
#: statically. Distinct from None, which means "not a dynamic import at all".


def _dynamically_imported_module(
    node: "ast.Call",
    importlib_modules: set[str],
    dynamic_importers: set[str],
    sys_aliases: set[str],
) -> str | None:
    """The module a dynamic-import call names, or None if this is not one.

    Every spelling that reaches a module object without an import statement:
    `importlib.import_module`, an aliased `importlib`, a bare or aliased
    `import_module`, `__import__`, and a name bound to any of them.

    `sys_aliases` was accepted and discarded (`_ = sys_aliases`) -- a parameter
    for a check nobody wrote. Two spellings walked through both gates at exit 0
    with an empty violations list, measured on the real `src/demo_app/main.py`:

        sys.modules.get('sub' + 'process')
        getattr(builtins, '__imp' + 'ort__')('sub' + 'process')

    `sys.modules[...]` was covered and `sys.modules.get(...)` was not, though
    both hand back the same module object; the split literal was needed only to
    get past the separate substring test, which is why this went unseen. The
    question here is how a module ARRIVES, so every route that yields one
    answers it -- subscript, method lookup, or an importer reached by name.
    """
    func = node.func

    # A module object by lookup rather than by import. `pop` and `setdefault`
    # return one too; listing the mutators is not thoroughness, it is that each
    # of them evaluates to the module.
    if (
        isinstance(func, ast.Attribute)
        and func.attr in {"get", "pop", "setdefault"}
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "modules"
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id in sys_aliases
    ):
        key = node.args[0] if node.args else None
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
        return _COMPUTED

    is_dynamic = (
        (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in importlib_modules
            and func.attr == "import_module"
        )
        # `builtins.__import__(...)`, and the same through any other holder. The
        # attribute IS the importer; which object carries it is not the control.
        or (isinstance(func, ast.Attribute) and func.attr == "__import__")
        or (isinstance(func, ast.Name) and func.id in dynamic_importers)
    )
    if not is_dynamic:
        return None
    target = node.args[0] if node.args else None
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        return target.value
    return _COMPUTED


def _process_capability_markers(path: Path, relative: str) -> set[str]:
    """Return the ways this module ACQUIRES process-execution capability.

    THE PROPERTY: a layer forbidden from executing processes cannot acquire the
    capability to execute one. Not "cannot be seen calling os.system" — cannot
    hold the means.

    This function used to recognise invocation syntax: a set of dangerous call
    spellings, matched as `owner.attr` where `owner` was a literal name in a
    list. Two independent reviews walked straight through it. The first used
    `from os import system` (the import filter did not contain `os`, and the
    call was an `ast.Name`, not an `ast.Attribute`). That was patched by adding
    those spellings. The second then used `import os as _o` — and every other
    equivalent form: `getattr(os, "system")`, `os.__dict__["system"]`,
    `import posix`, `_RUN = os.system`, `functools.partial(os.system)`. Each fix
    closed the demonstrated spelling and left the adjacent one open, because a
    list of spellings can always be extended by one more.

    So the question changed. Not "is this call dangerous?" but "does this module
    obtain access to a process-capable module at all?" Reaching `os` is
    ordinary; `os.getenv` and `os.path.join` are everywhere and a gate that
    flagged them would be switched off within a day. Reaching `subprocess`,
    `pty`, `posix`, `nt` or `multiprocessing` is not ordinary in a delegating
    layer — those modules exist to start processes.

    That splits the surface cleanly:

    - EXEC-ONLY MODULES (`subprocess`, `pty`, `posix`, `nt`, `multiprocessing`):
      importing one at all, under any spelling or alias, is the marker. No call
      needs to be seen. This is capability acquisition.

    - DUAL-USE MODULES (`os`, `asyncio`): importing is fine; binding
      one of their exec-family NAMES is the marker. Tracked through aliases and
      assignment, so `_o = os` then `_o.system` is caught, as is
      `_RUN = os.system` with no call site at all.

    - OPAQUE ACCESS (`getattr(...)`, `__dict__[...]`, computed imports): the
      target cannot be resolved statically. Inside a layer forbidden from
      process execution, that is refused rather than ignored — fail closed,
      because "I cannot tell" must never read as "it is fine".

    The result is that the reviewers' whole equivalence class collapses to one
    of three cases, and a new spelling nobody has thought of lands in the third.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    markers: set[str] = set()

    #: Local names currently bound to a dual-use module (`os` and friends),
    #: including aliases and re-bindings.
    module_aliases: dict[str, str] = {}
    #: Local names bound directly to an exec-family callable.
    exec_aliases: dict[str, str] = {}
    #: Local names bound to the `importlib` module, and local names that ARE a
    #: dynamic import callable.
    #:
    #: Measured before this existed: a module forbidden process capability could
    #: acquire it through SEVEN spellings the gate reported clean, while the
    #: static `import subprocess` two lines away was refused --
    #:
    #:     importlib.import_module("subprocess").run(c)          accepted
    #:     from importlib import import_module; import_module(…) accepted
    #:     from importlib import import_module as _im; _im(…)    accepted
    #:     import importlib as _il; _il.import_module(…)         accepted
    #:     __import__("subprocess").run(c)                       accepted
    #:     _imp = __import__; _imp("subprocess").run(c)          accepted
    #:     sys.modules["subprocess"].run(c)                      accepted
    #:
    #: Only the COMPUTED name was refused, and for an unrelated reason: names
    #: that cannot be read are refused wholesale. So the control was not
    #: "process capability must be declared"; it was "process capability must be
    #: declared if you spell it the way the analyser expects", which is a
    #: convention rather than a boundary.
    importlib_modules: set[str] = set()
    #: `__import__` is a builtin, so it needs no import to be in scope and is
    #: seeded here rather than discovered.
    dynamic_importers: set[str] = {"__import__"}
    #: Local names bound to `sys` and to `sys.modules`, shared with the
    #: dependency scan so the two cannot understand different
    #: spellings of one thing.
    sys_aliases, modules_aliases = _sys_module_aliases(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                bound = alias.asname or alias.name.split(".")[0]
                if root in EXEC_ONLY_MODULES:
                    # Holding it IS the capability. No call required.
                    markers.add(alias.name)
                elif root in DUAL_USE_MODULES:
                    module_aliases[bound] = root
                elif root == "importlib":
                    importlib_modules.add(bound)
                elif root == "sys":
                    sys_aliases.add(bound)

        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in EXEC_ONLY_MODULES:
                markers.add(node.module)
            elif root in DUAL_USE_MODULES:
                for alias in node.names:
                    if alias.name == "*":
                        # Cannot know what came in; assume the exec family did.
                        markers.add(f"{node.module}.*")
                    elif alias.name in EXEC_FUNCTIONS:
                        exec_aliases[alias.asname or alias.name] = (
                            f"{node.module}.{alias.name}"
                        )
                    elif alias.name in DUAL_USE_MODULES:
                        module_aliases[alias.asname or alias.name] = alias.name
            elif root == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        dynamic_importers.add(alias.asname or alias.name)

        elif isinstance(node, ast.Assign):
            # `_RUN = os.system`, `_o = os`, `handler = _o.popen`.
            bound = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if not bound:
                continue
            value = node.value
            # No branch here for `_RUN = os.system`: the attribute pass below
            # already marks `os.system` wherever it appears, including on the
            # right-hand side of an assignment. A mutation removing such a
            # branch killed no test, which is the signature of dead code that
            # reads as load-bearing -- in a security control, the worst kind.
            if isinstance(value, ast.Name):
                if value.id in module_aliases:
                    for name in bound:
                        module_aliases[name] = module_aliases[value.id]
                elif value.id in exec_aliases:
                    for name in bound:
                        exec_aliases[name] = exec_aliases[value.id]
                elif value.id in dynamic_importers:
                    # `_imp = __import__`, and the chain that follows from it.
                    dynamic_importers.update(bound)
            elif (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id in importlib_modules
                and value.attr == "import_module"
            ):
                dynamic_importers.update(bound)
            elif (
                isinstance(value, ast.Attribute) and value.attr == "__import__"
            ) or (
                # `_imp = getattr(builtins, "__imp" + "ort__")` -- an importer
                # fetched by a name the checker cannot read. Measured bypassing
                # both gates at exit 0 with an empty violations list. A computed
                # attribute is treated as an importer rather than ignored,
                # because the alternative is deciding it is safe on the strength
                # of not being able to see what it is.
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "getattr"
                and len(value.args) > 1
                and not (
                    isinstance(value.args[1], ast.Constant)
                    and isinstance(value.args[1].value, str)
                    and value.args[1].value != "__import__"
                )
            ):
                dynamic_importers.update(bound)
            elif isinstance(value, ast.Call):
                # `runner = importlib.import_module("os")` -- a dual-use module
                # reached dynamically is still that module, so it joins the
                # ordinary alias map and the exec-family pass below applies.
                imported = _dynamically_imported_module(
                    value, importlib_modules, dynamic_importers, sys_aliases
                )
                if imported and imported.split(".")[0] in DUAL_USE_MODULES:
                    for name in bound:
                        module_aliases[name] = imported.split(".")[0]

    # Second pass: names are all bound, so attribute access and calls resolve.
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            owner = module_aliases.get(node.value.id)
            if owner and node.attr in EXEC_FUNCTIONS:
                markers.add(f"{owner}.{node.attr}")
            elif owner and node.attr == "__dict__":
                # `os.__dict__[...]` — the subscript target is unknowable.
                markers.add(f"{owner}.__dict__ (opaque member access)")

        elif isinstance(node, ast.Name) and node.id in exec_aliases:
            markers.add(exec_aliases[node.id])

        elif isinstance(node, ast.Subscript):
            # `sys.modules["subprocess"]` -- no import node anywhere, and the
            # module object it yields is the capability. THE SHARED
            # RECOGNISER, so this scan and the dependency scan cannot drift
            # into understanding different spellings of one thing; they
            # already had, and a first-party edge walked through the gap.
            target = _sys_modules_target(node, sys_aliases, modules_aliases)
            if target == _COMPUTED:
                markers.add("sys.modules[<computed>] (opaque module access)")
            elif target is not None:
                if target.split(".")[0] in EXEC_ONLY_MODULES:
                    markers.add(f"sys.modules[{target!r}]")

        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            imported = _dynamically_imported_module(
                node, importlib_modules, dynamic_importers, sys_aliases
            )
            if imported is not None:
                if imported == _COMPUTED:
                    markers.add("import_module(<computed>) (opaque module access)")
                elif imported.split(".")[0] in EXEC_ONLY_MODULES:
                    # Acquiring it dynamically acquires it. The spelling is not
                    # the control; holding the module is.
                    markers.add(imported)
            if name in OPAQUE_ACCESSORS:
                target = node.args[0] if node.args else None
                owner = (
                    module_aliases.get(target.id)
                    if isinstance(target, ast.Name)
                    else None
                )
                literal = (
                    node.args[1].value
                    if len(node.args) > 1
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                    else None
                )
                if owner and literal in EXEC_FUNCTIONS:
                    markers.add(f"{owner}.{literal}")
                elif owner and literal is None:
                    markers.add(f"{owner}.<computed> (opaque member access)")

    return markers


def _exported_capability_names(path: Path, relative: str, dotted: str) -> set[str]:
    """Module-level names this module hands out that ARE process capability.

    The per-file marker scan asks what a module acquires from the standard
    library. It cannot see capability arriving through a FIRST-PARTY module,
    because `helper` is not `subprocess` and never will be. So a delegating
    module could write:

        from .helper import runner     # helper.py: runner = subprocess.run
        runner(["curl", url])

    and acquire exactly the capability the layer forbids, through a name the
    scan had no reason to distrust. Closing that by adding `helper` to a list
    would be the enumeration mistake again, one module at a time.

    This computes what each module EXPORTS instead, so the question asked of an
    importer is "is this name capability?" rather than "is this module on a
    list?". Resolved to a fixed point below, because a re-export can itself be
    re-exported.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    exported: set[str] = set()
    _ = dotted  # the shape is per-file; the name is carried for the caller's sake

    for node in tree.body:  # module level only: a local name is not an export
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in EXEC_ONLY_MODULES:
                    # The module object itself is the capability.
                    exported.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in EXEC_ONLY_MODULES:
                for alias in node.names:
                    exported.add(alias.asname or alias.name)
            elif root in DUAL_USE_MODULES:
                for alias in node.names:
                    if alias.name in EXEC_FUNCTIONS:
                        exported.add(alias.asname or alias.name)
        elif isinstance(node, ast.Assign):
            # `runner = subprocess.run`, `runner = os.system`, `runner = other`.
            value = node.value
            capable = False
            if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
                capable = (
                    value.value.id in EXEC_ONLY_MODULES
                    or (value.value.id in DUAL_USE_MODULES and value.attr in EXEC_FUNCTIONS)
                )
            elif isinstance(value, ast.Name):
                capable = value.id in EXEC_ONLY_MODULES or value.id in exported
            if capable:
                exported.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return exported


def _first_party_capability_exports() -> dict[str, set[str]]:
    """Capability exports per first-party module, resolved transitively.

    Iterated to a fixed point rather than walked once: A re-exporting B while B
    re-exports C is an ordinary package layout, and a single pass in the wrong
    order would report A as clean.
    """
    sources: dict[str, tuple[Path, str]] = {}
    for candidate in SOURCE_ROOT.rglob("*.py"):
        name = (
            str(candidate.relative_to(SOURCE_ROOT))
            .replace("\\", "/")
            .removesuffix(".py")
            .replace("/", ".")
        )
        sources[name.removesuffix(".__init__")] = (
            candidate,
            str(candidate.relative_to(ROOT)).replace("\\", "/"),
        )

    exports = {
        name: _exported_capability_names(path, relative, name)
        for name, (path, relative) in sources.items()
    }

    changed = True
    while changed:
        changed = False
        for name, (path, relative) in sources.items():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            package = _containing_package(name, path)
            for node in tree.body:
                if not isinstance(node, ast.ImportFrom):
                    continue
                target = _resolve_relative(node, package)
                if target not in exports:
                    continue
                incoming = exports[target]
                gained = set()
                for alias in node.names:
                    if alias.name == "*":
                        gained |= incoming
                    elif alias.name in incoming:
                        gained.add(alias.asname or alias.name)
                if gained - exports[name]:
                    exports[name] |= gained
                    changed = True
    return exports


def _containing_package(dotted: str, path: Path) -> str:
    """The package a relative import inside this file is anchored to.

    A package's `__init__.py` is anchored to the package ITSELF, while an
    ordinary module is anchored to its parent. Collapsing the two cases is an
    off-by-one that resolves `from ._deep import runner` inside
    `nornyx_forge._helper` to `nornyx_forge._helper._deep` -- a module that does
    not exist, so the capability arriving through it becomes invisible.
    """
    if path.name == "__init__.py":
        return dotted
    return dotted.rsplit(".", 1)[0] if "." in dotted else ""


def _resolve_relative(node: ast.ImportFrom, package: str) -> str:
    """The absolute dotted name an ImportFrom refers to.

    ``package`` is what a single leading dot means here; each extra dot climbs
    one level above it.
    """
    if not node.level:
        return node.module or ""
    parts = package.split(".") if package else []
    climb = node.level - 1
    base = parts[: len(parts) - climb] if climb <= len(parts) else []
    return ".".join([*base, node.module] if node.module else base)


CAPABILITY_EXPORTS = _first_party_capability_exports()


def _inherited_capability(path: Path, relative: str, dotted: str) -> set[str]:
    """Capability this module takes IN from a first-party module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    taken: set[str] = set()
    module_aliases: dict[str, str] = {}
    package = _containing_package(dotted, path)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            target = _resolve_relative(node, package)
            exported = CAPABILITY_EXPORTS.get(target, set())
            for alias in node.names:
                if alias.name == "*" and exported:
                    taken.add(f"{target}.* ({', '.join(sorted(exported))})")
                elif alias.name in exported:
                    taken.add(f"{target}.{alias.name}")
                elif f"{target}.{alias.name}" in CAPABILITY_EXPORTS:
                    # `from nornyx_forge import claude_worker` — the submodule
                    # is bound as a name, so track it for attribute access.
                    module_aliases[alias.asname or alias.name] = f"{target}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in CAPABILITY_EXPORTS:
                    module_aliases[alias.asname or alias.name.split(".")[0]] = alias.name

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            owner = module_aliases.get(node.value.id)
            if owner and node.attr in CAPABILITY_EXPORTS.get(owner, set()):
                taken.add(f"{owner}.{node.attr}")
    return taken


for module in declared_modules.values():
    if module.get("layer") not in DELEGATING_LAYERS:
        continue
    path = _module_path(module["name"])
    if not path.exists():
        continue
    relative = str(path.relative_to(ROOT)).replace("\\", "/")
    for marker in sorted(_process_capability_markers(path, relative)):
        violations.append(
            f"{relative} performs process execution ({marker}) outside a declared adapter"
        )
    for marker in sorted(_inherited_capability(path, relative, module["name"])):
        violations.append(
            f"{relative} acquires process-execution capability re-exported by a "
            f"first-party module ({marker}) outside a declared adapter"
        )

# --- constraint.api_no_commands and governed action boundary ---
main_text = (ROOT / "src/demo_app/main.py").read_text(encoding="utf-8")
# THE CONSTRAINT IS STRUCTURAL, not textual. This was
#
#     if "subprocess" in main_text or "os.system" in main_text
#
# which is a substring test over source text: `"sub" + "process"` passes it, and
# the word in a comment fails it. Wrong in both directions, and it masked a
# second defect -- every probe of the acquisition gate also spelled `subprocess`
# somewhere, so this fired and answered for a gate that had never seen the
# payload. The same AST capability analysis the layer rules use is asked instead:
# what does this module HOLD, by any spelling.
_api_markers = _process_capability_markers(
    ROOT / "src/demo_app/main.py", "src/demo_app/main.py"
)
if _api_markers:
    violations.append(
        "API layer contains direct command execution: "
        + ", ".join(sorted(_api_markers))
    )
# STRUCTURAL, matching what this file says three rules above. These were
# substring tests: `"action()" in main_text` never fired, because main.py
# contains no such spelling, so any differently-named direct call passed it.
# The property is actually held by the path-based import ban on nornyx_forge,
# not by these -- but a rule that cannot fail should not sit in the report
# under the name `governed_action_boundary`.
_agentic_tree = ast.parse(
    (ROOT / "src/demo_app/agentic.py").read_text(encoding="utf-8")
)
_agentic_names = {
    node.id for node in ast.walk(_agentic_tree)
    if isinstance(node, ast.Name)
} | {
    node.attr for node in ast.walk(_agentic_tree)
    if isinstance(node, ast.Attribute)
}
if "NornyxActionBoundary" not in _agentic_names:
    violations.append(
        "runtime orchestration does not use the declared Nornyx action boundary"
    )
if "evaluate_and_execute" not in _agentic_names:
    violations.append(
        "runtime orchestration does not route execution through the action boundary"
    )
_main_tree = ast.parse(main_text)
_main_calls = {
    node.func.id for node in ast.walk(_main_tree)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
}
if _main_calls & {"action", "execute_action", "run_action"}:
    violations.append(
        "API layer appears to invoke a consequential action directly: "
        + ", ".join(sorted(_main_calls & {"action", "execute_action", "run_action"}))
    )

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
# newline="" keeps this report canonical-LF on every platform. The repository
# declares text content canonical-LF and the subject observer refuses CR bytes,
# so a gate that emitted CRLF made its own output unhashable on Windows.
REPORT.write_text(
    json.dumps(result, indent=2) + "\n", encoding="utf-8", newline=""
)
print(json.dumps(result, indent=2))
raise SystemExit(0 if not violations else 2)
