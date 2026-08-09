"""The architecture gate must check every first-party module, not the declared ones.

Every rule in `check_architecture.py` iterated over `declared_modules`, so a
module the contract omitted was not a violation — it was invisible. Eight of
nineteen first-party modules were never read, including the Forge CLI, while the
gate reported `violations: []`. Omission was the cheapest way to pass.

That is backwards for a conformance gate. The contract is meant to be a closed
statement of what exists, so the check is driven by what is on disk and anything
present-but-unmodelled is itself the defect.

Extending coverage immediately found a real one: the CLI held an `os.execvp`,
which `constraint.bounded_external_adapter` forbids outside a declared adapter.
It is moved into one rather than exempted — the constraint's whole purpose is
that the list of places this system can start a process is complete.
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = Path(".nornyx/contracts/architecture_governance.nyx")
GATE = "scripts/check_architecture.py"


def _workspace(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    (work / "scripts").mkdir(parents=True)
    shutil.copytree(ROOT / "src", work / "src")
    shutil.copytree(ROOT / ".nornyx/contracts", work / ".nornyx/contracts")
    shutil.copy2(ROOT / GATE, work / GATE)
    # The gate reads the console entrypoint from packaging metadata.
    shutil.copy2(ROOT / "pyproject.toml", work / "pyproject.toml")
    return work


def _gate(work: Path) -> tuple[int, dict]:
    completed = subprocess.run(
        [sys.executable, GATE], cwd=work, capture_output=True, text=True
    )
    assert completed.stdout, completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def _architecture(work: Path) -> dict:
    return yaml.safe_load((work / CONTRACT).read_text(encoding="utf-8"))


def _write_architecture(work: Path, document: dict) -> None:
    (work / CONTRACT).write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def _violations(report: dict) -> str:
    return "\n".join(report["violations"])


# --------------------------------------------------------------------------
# Coverage is driven by what exists
# --------------------------------------------------------------------------


def test_the_gate_passes_on_the_repository_as_it_stands(tmp_path: Path):
    """The control must permit the tree it is meant to describe."""
    code, report = _gate(_workspace(tmp_path))
    assert code == 0, _violations(report)
    assert report["status"] == "pass"


def test_every_first_party_module_is_declared():
    """Stated directly, so the closure property is asserted and not just implied."""
    architecture = yaml.safe_load((ROOT / CONTRACT).read_text(encoding="utf-8"))["architecture"]
    declared = {module["name"] for module in architecture["modules"]}

    unmodelled: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        dotted = (
            path.relative_to(ROOT / "src").as_posix().removesuffix(".py").replace("/", ".")
        ).removesuffix(".__init__")
        if dotted in declared:
            continue
        body = ast.parse(path.read_text(encoding="utf-8")).body
        inert = path.name == "__init__.py" and all(
            (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))
            or (
                isinstance(n, ast.Assign)
                and all(isinstance(t, ast.Name) and t.id.startswith("__") for t in n.targets)
            )
            for n in body
        )
        if not inert:
            unmodelled.append(dotted)
    assert unmodelled == []


def test_a_new_undeclared_module_fails_the_gate(tmp_path: Path):
    """The regression itself: adding a module must not be a way to avoid review."""
    work = _workspace(tmp_path)
    (work / "src/nornyx_forge/smuggled.py").write_text(
        "from .nornyx_runtime import RuntimeContext\n", encoding="utf-8"
    )
    code, report = _gate(work)
    assert code != 0
    assert "smuggled.py" in _violations(report)


def test_an_undeclared_module_that_inverts_layers_is_caught(tmp_path: Path):
    """Previously this was the invisible case, whatever it imported."""
    work = _workspace(tmp_path)
    (work / "src/nornyx_forge/inverted.py").write_text(
        "from demo_app.main import app\nfrom demo_app.store import JsonStore\n",
        encoding="utf-8",
    )
    code, report = _gate(work)
    assert code != 0
    assert "inverted.py" in _violations(report)


def test_a_package_init_that_stops_being_inert_must_be_declared(tmp_path: Path):
    """Inertness is verified, not assumed: a re-export is a real dependency edge."""
    work = _workspace(tmp_path)
    init = work / "src/demo_app/__init__.py"
    assert _gate(work)[0] == 0, "an empty package marker is exempt"

    init.write_text("from .store import JsonStore\n", encoding="utf-8")
    code, report = _gate(work)
    assert code != 0
    assert "demo_app/__init__.py" in _violations(report)


def test_a_declared_module_with_no_source_file_fails(tmp_path: Path):
    """Coverage runs both ways; the contract may not describe what is not there."""
    work = _workspace(tmp_path)
    (work / "src/nornyx_forge/gates.py").unlink()
    code, report = _gate(work)
    assert code != 0
    assert "gates" in _violations(report)


# --------------------------------------------------------------------------
# The gate may not be more permissive than the governance engine
# --------------------------------------------------------------------------


def test_no_declared_dependency_crosses_a_layer_its_own_layer_forbids():
    """Read from the contract alone, so it holds whatever the checker believes.

    This is the test that would have caught the detour taken while writing this
    unit. The Forge CLI was first declared `layer.interface` with a
    `composition_root: true` flag exempting it from layer direction — honoured
    by `scripts/check_architecture.py`, which then reported pass. Nornyx
    rejected the same contract twice over: the flag is not in the schema at all,
    and `layer.interface` may not depend on `layer.domain` regardless.

    A local gate that is more permissive than the engine is worse than no gate,
    because it produces evidence saying the architecture conforms when the
    authority on the question says it does not. The CLI is now declared
    `layer.application`, which is what its command bodies are, and needs no
    exemption.
    """
    architecture = yaml.safe_load((ROOT / CONTRACT).read_text(encoding="utf-8"))["architecture"]
    layers = {layer["id"]: layer for layer in architecture["layers"]}
    modules = {module["id"]: module for module in architecture["modules"]}

    crossings: list[str] = []
    for module in modules.values():
        permitted = set(layers[module["layer"]].get("may_depend_on") or [])
        permitted.add(module["layer"])
        for dependency in module.get("depends_on") or []:
            target = modules[dependency]
            if target["layer"] not in permitted:
                crossings.append(
                    f"{module['id']} ({module['layer']}) -> {dependency} ({target['layer']})"
                )
    assert crossings == []


def test_the_contract_declares_no_field_outside_the_schema():
    """The flag Nornyx rejected was invisible to the local gate, which invented it."""
    architecture = yaml.safe_load((ROOT / CONTRACT).read_text(encoding="utf-8"))["architecture"]
    allowed = {"id", "name", "component", "layer", "depends_on"}
    for module in architecture["modules"]:
        assert set(module) <= allowed, f"{module['id']} carries {set(module) - allowed}"


# --------------------------------------------------------------------------
# The entrypoint is a leaf
# --------------------------------------------------------------------------


def test_the_entrypoint_still_declares_every_dependency(tmp_path: Path):
    """Composing the program is not licence to import something unlisted."""
    work = _workspace(tmp_path)
    cli = work / "src/nornyx_forge/cli.py"
    cli.write_text(
        "from .policy import PolicyDecision\n" + cli.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    code, report = _gate(work)
    assert code != 0
    assert "undeclared dependency nornyx_forge.policy" in _violations(report)


def test_nothing_may_depend_on_the_console_entrypoint(tmp_path: Path):
    """An entrypoint that others imported could launder an inversion through itself.

    It reaches across the whole toolchain by design, so anything importing it
    inherits that reach — a dependency between two modules that may not depend on
    each other, routed through the one module nobody thinks of as a dependency.
    """
    work = _workspace(tmp_path)
    flow = work / "src/nornyx_forge/development_flow.py"
    flow.write_text("from .cli import app\n" + flow.read_text(encoding="utf-8"), encoding="utf-8")

    code, report = _gate(work)
    assert code != 0
    assert "console entrypoint" in _violations(report)


def test_the_entrypoint_is_read_from_packaging_metadata():
    """One recorded fact, not a second copy in the contract to disagree with it."""
    gate = (ROOT / GATE).read_text(encoding="utf-8")
    assert "pyproject.toml" in gate
    assert 'nornyx-forge = "nornyx_forge.cli:app"' in (
        ROOT / "pyproject.toml"
    ).read_text(encoding="utf-8")


def test_no_contract_edit_can_open_the_action_boundary(tmp_path: Path):
    """The forbidden rules hold whatever the contract later says about a module.

    They are matched by path rather than through the module graph, so declaring
    the edge cannot grant it. That is what stops the HTTP surface reaching the
    governance domain directly and bypassing the action boundary.
    """
    work = _workspace(tmp_path)
    document = _architecture(work)
    for module in document["architecture"]["modules"]:
        if module["name"] == "demo_app.main":
            module["depends_on"].append("module.governance")
    _write_architecture(work, document)

    main = work / "src/demo_app/main.py"
    main.write_text(
        "from nornyx_forge.nornyx_runtime import RuntimeContext\n"
        + main.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    code, report = _gate(work)
    assert code != 0
    assert "forbidden dependency nornyx_forge" in _violations(report)


# --------------------------------------------------------------------------
# Rules may not retire themselves
# --------------------------------------------------------------------------


def test_a_forbidden_rule_whose_file_moved_is_a_violation(tmp_path: Path):
    """A rename would otherwise silently stop a rule applying to anything."""
    work = _workspace(tmp_path)
    (work / "src/demo_app/store.py").rename(work / "src/demo_app/persistence.py")
    code, report = _gate(work)
    assert code != 0
    assert "no longer being applied" in _violations(report)


@pytest.mark.parametrize(
    ("module", "statement"),
    [
        ("src/demo_app/agentic.py", "import subprocess\n"),
        ("src/nornyx_forge/cli.py", "import subprocess\n"),
        # The exact form that was sitting in the CLI, unseen.
        ("src/nornyx_forge/cli.py", "import os\nos.execvp('sh', ['sh'])\n"),
    ],
)
def test_process_execution_outside_a_declared_adapter_fails(
    module: str, statement: str, tmp_path: Path
):
    """The regression the coverage fix surfaced, now asserted for both layers.

    `os.execvp` sat in the CLI while the CLI was undeclared. Interface and
    application modules must delegate process execution so the set of places this
    system can start one stays a list a reviewer can read.
    """
    work = _workspace(tmp_path)
    target = work / module
    target.write_text(statement + target.read_text(encoding="utf-8"), encoding="utf-8")
    code, report = _gate(work)
    assert code != 0
    assert "process execution" in _violations(report)


def test_the_launcher_does_not_import_the_application_it_starts(tmp_path: Path):
    """The adapter starts the server; it does not depend on it."""
    work = _workspace(tmp_path)
    source = (work / "src/nornyx_forge/app_launcher.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        name.split(".")[0]
        for node in ast.walk(tree)
        for name in (
            [alias.name for alias in node.names]
            if isinstance(node, ast.Import)
            else [node.module or ""]
            if isinstance(node, ast.ImportFrom)
            else []
        )
    }
    assert "demo_app" not in imported
    assert "demo_app.main:app" in source
