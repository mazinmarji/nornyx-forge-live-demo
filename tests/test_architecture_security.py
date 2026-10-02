import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = Path(".nornyx/contracts/architecture_governance.nyx")


def test_architecture_gate():
    assert subprocess.run([sys.executable, "scripts/check_architecture.py"], cwd=ROOT).returncode == 0


def test_security_gate():
    assert subprocess.run([sys.executable, "scripts/check_security.py"], cwd=ROOT).returncode == 0


def _forge_tree(tmp_path: Path) -> Path:
    """Copy the parts of the repository the architecture gate reads."""
    workspace = tmp_path / "repo"
    (workspace / "scripts").mkdir(parents=True)
    shutil.copy2(ROOT / "scripts/check_architecture.py", workspace / "scripts")
    # The gate reads the console entrypoint from packaging metadata, so that
    # "nothing may depend on the entrypoint" needs no second copy of the fact.
    shutil.copy2(ROOT / "pyproject.toml", workspace / "pyproject.toml")
    shutil.copytree(ROOT / "src", workspace / "src")
    (workspace / CONTRACT.parent).mkdir(parents=True)
    shutil.copy2(ROOT / CONTRACT, workspace / CONTRACT)
    return workspace


def test_architecture_gate_detects_undeclared_dependency(tmp_path: Path):
    """The gate must fail when a real import is absent from depends_on.

    demo_app.agentic genuinely imports nornyx_forge.claude_worker. Removing that
    edge from the contract has to be caught, otherwise the check is vacuous.
    """
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    for module in document["architecture"]["modules"]:
        if module["id"] == "module.runtime":
            module["depends_on"] = [
                item for item in module["depends_on"] if item != "module.worker_adapter"
            ]
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert report["status"] == "fail"
    assert any(
        "undeclared dependency nornyx_forge.claude_worker" in violation
        for violation in report["violations"]
    ), report["violations"]


def test_architecture_gate_detects_relative_import_of_persistence(tmp_path: Path):
    """The application layer must not reach persistence, even relatively.

    `from .store import JsonStore` is the spelling a checker that only resolves
    absolute imports would miss, so this asserts the relative form is caught.
    """
    workspace = _forge_tree(tmp_path)
    runtime = workspace / "src/demo_app/agentic.py"
    runtime.write_text(
        runtime.read_text(encoding="utf-8") + "\nfrom .store import JsonStore\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert any(
        "undeclared dependency demo_app.store" in violation
        for violation in report["violations"]
    ), report["violations"]
    assert any(
        "forbidden dependency demo_app.store" in violation
        for violation in report["violations"]
    ), report["violations"]


@pytest.mark.parametrize("injected", ["sys", "pathlib"])
def test_architecture_gate_detects_ambient_state_in_the_provider_contract(
        tmp_path: Path, injected: str):
    """The provider contract's purity claim is a GATE, not a habit.

    `provider_contract` decides governed-build eligibility from its own table,
    keyed provider then platform, and the platform word ARRIVES AS DATA --
    `onboarding_app.served_platform()` derives it once and hands it in. The
    module's docstring, the CHANGELOG and A-033 all lean on that module reading
    no `sys`, no process state and no filesystem, and `layer.domain` alone did
    not make it checkable: it forbids starting a process, not reading ambient
    state. Measured before the forbidden-dependency entry existed: an injected
    `import sys` + `import pathlib` + `sys.platform` + `pathlib.Path.cwd()`
    left `check_architecture.py` at `violations: []` and 143 architecture-facing
    tests green.

    Falsified the way the two neighbouring entries were: inject the name,
    require a failure.
    """
    workspace = _forge_tree(tmp_path)
    contract = workspace / "src/nornyx_forge/provider_contract.py"
    contract.write_text(
        contract.read_text(encoding="utf-8") + f"\nimport {injected}\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert report["status"] == "fail"
    assert any(
        f"provider_contract.py imports forbidden dependency {injected}" in violation
        for violation in report["violations"]
    ), report["violations"]


def test_architecture_gate_detects_unmodelled_first_party_import(tmp_path: Path):
    """An import of a real but unmodelled first-party module is a violation.

    Checking only edges between already-declared modules would let a brand-new
    dependency on an unmodelled module pass silently.

    The module has to be created here. This test used to borrow
    `nornyx_forge.gates`, which was unmodelled at the time; every first-party
    module is now declared, so the only way to have an unmodelled one is to add
    it — which is also the realistic shape of the regression, since a module
    arrives before anyone remembers to declare it.
    """
    workspace = _forge_tree(tmp_path)
    (workspace / "src/nornyx_forge/unmodelled.py").write_text(
        "def helper() -> None:\n    return None\n", encoding="utf-8"
    )
    runtime = workspace / "src/demo_app/agentic.py"
    runtime.write_text(
        runtime.read_text(encoding="utf-8")
        + "\nfrom nornyx_forge.unmodelled import helper\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert any(
        "nornyx_forge.unmodelled" in violation for violation in report["violations"]
    ), report["violations"]


def test_architecture_gate_detects_process_execution_outside_adapter(tmp_path: Path):
    """Interface/application modules must not start processes directly.

    Guards the bounded_external_adapter constraint against os.system as well as
    subprocess, since detecting only `import subprocess` would miss it.
    """
    workspace = _forge_tree(tmp_path)
    api = workspace / "src/demo_app/main.py"
    api.write_text(
        api.read_text(encoding="utf-8") + "\n\nimport os\n\n\ndef _bad():\n    os.system('echo hi')\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert any(
        "process execution (os.system)" in violation for violation in report["violations"]
    ), report["violations"]


def test_architecture_gate_detects_layer_violation(tmp_path: Path):
    """A module may not depend on a layer its own layer does not permit."""
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    for layer in document["architecture"]["layers"]:
        if layer["id"] == "layer.application":
            layer["may_depend_on"] = ["layer.domain"]
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert any(
        "which layer.application may not depend on" in violation
        for violation in report["violations"]
    ), report["violations"]


# --------------------------------------------------------------------------
# A key the gate reads is stated once
# --------------------------------------------------------------------------


def _gate(workspace: Path) -> tuple:
    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert completed.stdout, completed.stderr
    return completed.returncode, json.loads(completed.stdout)["violations"]


#: An application module that imports the infrastructure store, declared with
#: that edge. `layer.application` may not depend on `layer.infrastructure`, so
#: the gate refuses it on its own.
_PROBE = {
    "id": "module.layer_probe",
    "name": "nornyx_forge.layer_probe",
    "component": "component.runtime",
    "layer": "layer.application",
    "depends_on": ["module.persistence"],
}
_PROBE_VIOLATION = (
    "layer_probe.py depends on demo_app.store in layer.infrastructure, "
    "which layer.application may not depend on"
)

#: label -> (contract section, the second declaration, the probe's edge, the
#: refusal). Each repeat hides the probe's violation from a gate that keeps
#: the last statement of a key: the first two move the store into the probe's
#: own layer, the third widens the probe's layer to reach the store, and the
#: last two move the store by stating its own `layer` a second time, on a
#: line of its own or through a YAML merge. A dumper cannot write either of
#: those, so `_plant` writes them into the text (section None).
REPEATED_KEYS = {
    "module name": (
        "modules",
        {"id": "module.store_alias", "name": "demo_app.store",
         "component": "component.persistence", "layer": "layer.application",
         "depends_on": []},
        "module.store_alias",
        "declares module name demo_app.store more than once (2 declarations)",
    ),
    "module id": (
        "modules",
        {"id": "module.persistence", "name": "demo_app.store",
         "component": "component.persistence", "layer": "layer.application",
         "depends_on": []},
        "module.persistence",
        "declares module id module.persistence more than once (2 declarations)",
    ),
    "layer id": (
        "layers",
        {"id": "layer.application", "name": "Application",
         "may_depend_on": ["layer.domain", "layer.adapter", "layer.infrastructure"]},
        "module.persistence",
        "declares layer id layer.application more than once (2 declarations)",
    ),
    "key in one declaration": (
        None, "line", "module.persistence",
        "states the key 'layer' more than once in one mapping",
    ),
    "key a merge restates": (
        None, "merge", "module.persistence",
        "states the key 'layer' more than once in one mapping",
    ),
}


def _restate_the_store_layer(text: str, first: bool, how: str) -> str:
    """The store's declaration stating `layer` twice, as raw text.

    The application layer is the repeat, stated after the store's own layer
    or, with `first`, before it. `how` is "line", a line of its own, or
    "merge": a merge's keys come before the mapping's own and the mapping's
    own win, so the merge carries whichever statement comes first.
    """
    lines = text.split("\n")
    start = [i for i, line in enumerate(lines) if line.strip() == "- id: module.persistence"]
    assert len(start) == 1, start
    layer = next(
        i for i in range(start[0], start[0] + 6)
        if lines[i].strip() == "layer: layer.infrastructure"
    )
    indent = lines[layer][: len(lines[layer]) - len(lines[layer].lstrip())]
    original, repeat = "layer: layer.infrastructure", "layer: layer.application"
    if how == "merge":
        merged, own = (repeat, original) if first else (original, repeat)
        lines[layer:layer + 1] = [indent + "<<: {" + merged + "}", indent + own]
    else:
        lines.insert(layer if first else layer + 1, indent + repeat)
    return "\n".join(lines)


def _plant(workspace: Path, repeated=None, first: bool = False) -> None:
    """The probe, and optionally one repeated key, in the copy.

    `first` puts the repeat ahead of the statement it repeats, where a gate
    keeping the last statement still applies the original.
    """
    (workspace / "src/nornyx_forge/layer_probe.py").write_text(
        "from demo_app.store import JsonStore\n\n_STORE = JsonStore\n",
        encoding="utf-8",
    )
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    architecture = document["architecture"]
    probe = dict(_PROBE)
    section = how = None
    if repeated is not None:
        section, declaration, edge, _ = REPEATED_KEYS[repeated]
        probe["depends_on"] = [edge]
        if section is None:
            how = declaration
        else:
            entries = architecture[section]
            entries.insert(0 if first else len(entries), dict(declaration))
    architecture["modules"].append(probe)
    text = yaml.safe_dump(document, sort_keys=False)
    if how is not None:
        text = _restate_the_store_layer(text, first, how)
    contract.write_text(text, encoding="utf-8")


def test_the_planted_layer_violation_is_refused_on_its_own(tmp_path: Path):
    """The control. Without it, each refusal below could be free."""
    workspace = _forge_tree(tmp_path)
    _plant(workspace)
    code, violations = _gate(workspace)
    assert code == 2
    assert any(_PROBE_VIOLATION in violation for violation in violations), violations


@pytest.mark.parametrize(
    "first", [False, True], ids=["after the original", "before the original"]
)
@pytest.mark.parametrize("repeated", sorted(REPEATED_KEYS))
def test_a_repeated_key_is_refused_by_name(
        tmp_path: Path, repeated: str, first: bool):
    """A key the gate reads, stated twice, is refused wherever the repeat stands.

    Measured before the refusals existed, on a copy of this tree: each repeat
    placed AFTER the original took the gate from exit 2 to exit 0 with
    `violations: []`. For the module name, with the probe's edge naming the
    new id, `nornyx check` reported nothing beyond its usual diagnostics
    either, since it keys modules by id and the ids differ. It reports the two
    repeated ids as ARCH_DUPLICATE_ID and refuses the key stated twice in one
    declaration, on a line of its own or through a merge, as PARSE_ERROR, so
    for those four the gate was the more permissive of the two. Placed BEFORE
    the original, the gate still failed, but for the probe's violation and not
    for the repeat, so moving the line was enough to pass.
    """
    workspace = _forge_tree(tmp_path)
    _plant(workspace, repeated, first)
    code, violations = _gate(workspace)
    assert code == 2, violations
    refusal = REPEATED_KEYS[repeated][3]
    assert any(refusal in violation for violation in violations), violations


def test_every_mapping_is_checked_once_with_keys_compared_as_the_loader_builds_them(
        tmp_path: Path):
    """Every mapping the loader builds is checked, and keys compare as built.

    An anchored mapping that two aliases reach is one mapping, so its repeat
    is one finding; a sequence that contains itself is read once, as the
    loader reads it; `1` and `0x1` are one key, because both construct to 1; a key
    a merge (`<<`) supplies and the mapping also states is a repeat; a key a
    merge alone supplies is not; two merges supplying one key are a repeat; a
    repeat that a merge copies into another mapping is still one finding, at
    the place it is written; and a `=` key is an ordinary key.
    """
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    contract.write_text(
        contract.read_text(encoding="utf-8")
        + "x_anchored: &twice {k: 1, k: 2}\n"
        + "x_aliases: [*twice, *twice]\n"
        + "x_spellings: {1: a, 0x1: b}\n"
        + "x_merged: {<<: {m: 1}, m: 2}\n"
        + "x_merge_only: {<<: {n: 1}, o: 2}\n"
        + "x_base: &base {q: 1, q: 2}\n"
        + "x_merges_base: {<<: *base}\n"
        + "x_merge_list: {<<: [{r: 1}, {r: 2}]}\n"
        + "x_equals: {=: 1}\n"
        + "x_loop: &loop [*loop]\n",
        encoding="utf-8",
    )
    code, violations = _gate(workspace)
    repeats = [v for v in violations if "more than once in one mapping" in v]
    assert code == 2
    assert len(repeats) == 5, violations
    assert "states the key 'k' more than once" in repeats[0], repeats
    assert "states the key 1 more than once" in repeats[1], repeats
    assert "states the key 'm' more than once" in repeats[2], repeats
    assert "states the key 'q' more than once" in repeats[3], repeats
    assert "states the key 'r' more than once" in repeats[4], repeats


def test_a_merge_inside_ordered_pairs_is_refused_as_the_loader_refuses_it(
        tmp_path: Path):
    """Construction is left to the loader, so what it refuses is still refused.

    An `!!pairs` (or `!!omap`) entry is a one-pair mapping that SafeLoader
    never flattens, so a merge key there has no constructor. A version of the
    repeated-key refusal that flattened every mapping in place took this file
    from the loader's refusal to `violations: []` at exit 0, measured by an
    in-session review, while `nornyx check` refused it as PARSE_ERROR.
    """
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    contract.write_text(
        contract.read_text(encoding="utf-8") + "x_pairs: !!pairs [{<<: {a: 1}}]\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace, capture_output=True, text=True, timeout=600,
    )
    assert completed.returncode == 1, completed.stdout[-400:]
    assert "ConstructorError" in completed.stderr, completed.stderr[-400:]


def test_the_report_names_both_new_checks(tmp_path: Path):
    """The report lists what the gate now checks, on the tree as it stands."""
    workspace = _forge_tree(tmp_path)
    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace, capture_output=True, text=True, timeout=600,
    )
    report = json.loads(completed.stdout)
    assert completed.returncode == 0, report["violations"]
    assert "unique_declarations" in report["checks"]
    assert "declared_identifiers_and_names" in report["checks"]


#: Spellings that reach src/demo_app/store.py through the gate's own path
#: lookup, the last only on a case-insensitive file system.
_STORE_SPELLINGS = ["demo_app/store", "demo_app//store", "demo_app./store", "demo_app.Store"]


@pytest.mark.parametrize("spelling", _STORE_SPELLINGS)
def test_a_module_name_is_held_to_its_spelling_on_disk(tmp_path: Path, spelling: str):
    """One module, two declarations: the original renamed, an alias in another layer.

    The repeated-name refusal compares strings, and these spellings differ
    from `demo_app.store` while the gate's path lookup takes each to the same
    file. Measured by an in-session review on a copy of this tree: the store
    renamed to each spelling in its own layer, beside a second declaration
    `demo_app.store` in the application layer that the probe's edge names,
    passed the gate at exit 0, and `nornyx check`, whose schema leaves a
    module's name free text, reported nothing.
    """
    workspace = _forge_tree(tmp_path)
    (workspace / "src/nornyx_forge/layer_probe.py").write_text(
        "from demo_app.store import JsonStore\n\n_STORE = JsonStore\n",
        encoding="utf-8",
    )
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    modules = document["architecture"]["modules"]
    for module in modules:
        if module["id"] == "module.persistence":
            module["name"] = spelling
        if module["id"] == "module.api":
            module["depends_on"].append("module.store_view")
    modules.append({"id": "module.store_view", "name": "demo_app.store",
                    "component": "component.runtime", "layer": "layer.application",
                    "depends_on": []})
    modules.append(dict(_PROBE, depends_on=["module.store_view"]))
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    code, violations = _gate(workspace)
    assert code == 2, violations
    refusal = (
        f"with the name {spelling!r}, which is not a first-party module's "
        "dotted name as spelled on disk"
    )
    assert any(refusal in violation for violation in violations), violations


_WIDE = ["layer.domain", "layer.adapter", "layer.infrastructure"]

#: label -> (a layer to declare or None, the probe's layer, the probe's
#: source, the refusal). `nornyx check` refuses each. All but the module layer
#: outside the syntax passed the gate at exit 0 before the rule existed,
#: measured by an in-session review; that one was refused, but only by the
#: dependency rule, since the undeclared layer may depend on nothing. `True`
#: is what YAML 1.1 makes of `yes` and of `on`.
UNREAD_REFERENCES = {
    "a layer id with a confusable letter": (
        "layer.аpplication", "layer.аpplication",
        "from demo_app.store import JsonStore\n",
        "gives a layer id as 'layer.аpplication'",
    ),
    "a layer id with a trailing space": (
        "layer.application ", "layer.application ",
        "from demo_app.store import JsonStore\n",
        "gives a layer id as 'layer.application '",
    ),
    "a module in an undeclared layer": (
        None, "layer.applicatoin", "import subprocess\n",
        "places module 'module.layer_probe' in layer layer.applicatoin, which no "
        "layer declares",
    ),
    "a module layer outside the syntax": (
        None, "layer.zz zz", "from demo_app.store import JsonStore\n",
        "gives the layer of module 'module.layer_probe' as 'layer.zz zz'",
    ),
    "a layer id YAML reads as a boolean": (
        True, True, "from demo_app.store import JsonStore\n",
        "gives a layer id as True",
    ),
}


@pytest.mark.parametrize("label", sorted(UNREAD_REFERENCES))
def test_an_identifier_or_layer_nornyx_would_refuse_is_refused(tmp_path: Path, label: str):
    """Identifiers are held to nornyx's syntax, and a layer named must be declared."""
    layer_id, probe_layer, source, refusal = UNREAD_REFERENCES[label]
    workspace = _forge_tree(tmp_path)
    (workspace / "src/nornyx_forge/layer_probe.py").write_text(source, encoding="utf-8")
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    architecture = document["architecture"]
    if layer_id is not None:
        architecture["layers"].append(
            {"id": layer_id, "name": "Look-alike", "may_depend_on": list(_WIDE)}
        )
    edges = [] if source.startswith("import subprocess") else ["module.persistence"]
    architecture["modules"].append(dict(_PROBE, layer=probe_layer, depends_on=edges))
    contract.write_text(
        yaml.safe_dump(document, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    code, violations = _gate(workspace)
    assert code == 2, violations
    assert any(refusal in violation for violation in violations), violations


#: label -> (the declaration's section and id, its list, the entry added, the
#: refusal). Neither entry hides anything today: an undeclared edge only
#: removes permission. They are refused because nornyx refuses them, so the
#: gate does not read as an identifier what the engine rejects.
LISTED_REFERENCES = {
    "an undeclared layer in may_depend_on": (
        ("layers", "layer.application"), "may_depend_on", "layer.nowhere",
        "lets layer 'layer.application' depend on layer layer.nowhere, which no "
        "layer declares",
    ),
    "a depends_on entry that is not an identifier": (
        ("modules", "module.api"), "depends_on", "module persistence",
        "gives an entry of module 'module.api''s depends_on as 'module persistence'",
    ),
}


@pytest.mark.parametrize("label", sorted(LISTED_REFERENCES))
def test_a_listed_reference_is_held_to_the_same_rule(tmp_path: Path, label: str):
    """Entries of `depends_on` and `may_depend_on` are identifiers, and layers declared."""
    (section, ident), field, entry, refusal = LISTED_REFERENCES[label]
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    for declaration in document["architecture"][section]:
        if declaration["id"] == ident:
            declaration[field].append(entry)
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    code, violations = _gate(workspace)
    assert code == 2, violations
    assert any(refusal in violation for violation in violations), violations


#: label -> (files to plant, the store's new name or None, the refusal).
#: Each passed the gate at exit 0 before, measured by an in-session review.
PLANTED_SPELLINGS = {
    "an inert dotfile discovery names demo_app..store": (
        {"src/demo_app/.store.py": '"""inert"""\n'}, "demo_app..store",
        "with the name 'demo_app..store', which is not a first-party module's "
        "dotted name as spelled on disk",
    ),
    "a package beside the module it shadows": (
        {"src/demo_app/store/__init__.py": "import subprocess\n"}, None,
        "src/demo_app/store/__init__.py and src/demo_app/store.py are both the "
        "module demo_app.store",
    ),
    "a package whose name differs only in case": (
        {"src/demo_app/Store/__init__.py": ""}, "demo_app.Store",
        "src/demo_app/Store/__init__.py and src/demo_app/store.py are both the "
        "module demo_app.store",
    ),
    "a package __init__ in another letter case": (
        {"src/demo_app/store/__Init__.py": "import subprocess\n"}, None,
        "src/demo_app/store/__Init__.py and src/demo_app/store.py are both the "
        "module demo_app.store",
    ),
    "a package __init__ as .pyw": (
        {"src/demo_app/store/__init__.pyw": "import subprocess\n"}, None,
        "src/demo_app/store/__init__.pyw is a module Python can import that this "
        "gate cannot read as source",
    ),
    "sourceless bytecode": (
        {"src/demo_app/helper.pyc": ""}, None,
        "src/demo_app/helper.pyc is a module Python can import that this gate "
        "cannot read as source",
    ),
    "optimized bytecode": (
        {"src/demo_app/helper.pyo": ""}, None,
        "src/demo_app/helper.pyo is a module Python can import that this gate "
        "cannot read as source",
    ),
    "untagged bytecode in a cache directory": (
        {"src/demo_app/__pycache__/evil.pyc": ""}, None,
        "src/demo_app/__pycache__/evil.pyc is a module Python can import that "
        "this gate cannot read as source",
    ),
    "a Windows extension module": (
        {"src/demo_app/helper.pyd": ""}, None,
        "src/demo_app/helper.pyd is a module Python can import that this gate "
        "cannot read as source",
    ),
    "a POSIX extension module": (
        {"src/demo_app/helper.cpython-313-x86_64-linux-gnu.so": ""}, None,
        "src/demo_app/helper.cpython-313-x86_64-linux-gnu.so is a module Python "
        "can import that this gate cannot read as source",
    ),
}


@pytest.mark.parametrize("label", sorted(PLANTED_SPELLINGS))
def test_a_name_discovery_reaches_by_another_file_is_refused(tmp_path: Path, label: str):
    """One dotted name is one file, and only an importable spelling names it.

    A dotfile is discovered as `demo_app..store`, which the gate's path lookup
    takes to store.py, so the store could be declared twice again; a package
    beside a module is what Python imports while the gate read the module, in
    any letter case of the package or of its `__init__`; and `.pyw` and
    sourceless bytecode are modules Python loads that the gate cannot read.
    Only the dotfile and the case-variant package need a contract edit.
    """
    files, renamed, refusal = PLANTED_SPELLINGS[label]
    workspace = _forge_tree(tmp_path)
    for relative, text in files.items():
        (workspace / relative).parent.mkdir(parents=True, exist_ok=True)
        (workspace / relative).write_text(text, encoding="utf-8")
    if renamed is not None:
        (workspace / "src/nornyx_forge/layer_probe.py").write_text(
            "from demo_app.store import JsonStore\n", encoding="utf-8"
        )
        contract = workspace / CONTRACT
        document = yaml.safe_load(contract.read_text(encoding="utf-8"))
        modules = document["architecture"]["modules"]
        for module in modules:
            if module["id"] == "module.persistence":
                module["name"] = renamed
            if module["id"] == "module.api":
                module["depends_on"].append("module.store_view")
        modules.append({"id": "module.store_view", "name": "demo_app.store",
                        "component": "component.runtime", "layer": "layer.application",
                        "depends_on": []})
        modules.append(dict(_PROBE, depends_on=["module.store_view"]))
        contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    code, violations = _gate(workspace)
    assert code == 2, violations
    assert any(refusal in violation for violation in violations), violations


#: label -> (section, declaration id, field, the scalar written, the refusal).
SCALAR_LISTS = {
    "may_depend_on": (
        "layers", "layer.application", "may_depend_on", "layer.domain",
        "gives the may_depend_on of layer 'layer.application' as 'layer.domain', "
        "which is not a list",
    ),
    "depends_on": (
        "modules", "module.api", "depends_on", "module.runtime",
        "gives the depends_on of module 'module.api' as 'module.runtime', which "
        "is not a list",
    ),
}


@pytest.mark.parametrize("label", sorted(SCALAR_LISTS))
def test_a_list_written_as_one_string_is_refused(tmp_path: Path, label: str):
    """One reading: the permission rules took a string for a set of its characters.

    Measured by an in-session review: `may_depend_on: di` let a layer reach
    layers `d` and `i`, and `depends_on: tu` modules `t` and `u`, at exit 0,
    while `nornyx check` refused both as schema errors.
    """
    section, ident, field, scalar, refusal = SCALAR_LISTS[label]
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    for declaration in document["architecture"][section]:
        if declaration["id"] == ident:
            declaration[field] = scalar
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    code, violations = _gate(workspace)
    assert code == 2, violations
    assert any(refusal in violation for violation in violations), violations


#: layer -> whether a module in it may hold process capability.
_PROCESS_LAYERS = {
    "layer.application-2": False,
    "layer.application": False,
    "layer.domain": False,
    "layer.interface": False,
    "layer.adapter": True,
    "layer.infrastructure": True,
}


@pytest.mark.parametrize("layer", list(_PROCESS_LAYERS), ids=list(_PROCESS_LAYERS))
def test_a_layer_not_named_as_executing_may_not_start_a_process(tmp_path: Path, layer: str):
    """Process capability is allowed by layer, so every other layer delegates.

    Measured by an in-session review: a declared `layer.application-2` named
    "Application", holding a module that imports `subprocess`, passed the
    gate at exit 0 while the rule named only three layers it applied to. The
    declared layers keep their verdicts: only the adapter and infrastructure
    layers may start a process.
    """
    workspace = _forge_tree(tmp_path)
    (workspace / "src/nornyx_forge/layer_probe.py").write_text(
        "import subprocess\n\n_RUN = subprocess.run\n", encoding="utf-8"
    )
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    architecture = document["architecture"]
    if layer == "layer.application-2":
        architecture["layers"].append({"id": layer, "name": "Application",
                                       "may_depend_on": ["layer.domain", "layer.adapter"]})
    architecture["modules"].append(dict(_PROBE, layer=layer, depends_on=[]))
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    code, violations = _gate(workspace)
    if _PROCESS_LAYERS[layer]:
        assert (code, violations) == (0, [])
    else:
        assert code == 2, violations
        assert any(
            "layer_probe.py performs process execution (subprocess)" in violation
            for violation in violations
        ), violations


@pytest.mark.parametrize("shape", ["an anchored list", "a long string"])
def test_a_violation_quotes_a_value_within_a_bound(tmp_path: Path, shape: str):
    """An anchored list can stand for a million entries; the report stays small.

    Measured by an in-session review: an unbounded quote of such a value in
    an unused layer's `may_depend_on` made a 522 MB report from ten lines. A
    string is quoted within a bound too: forty aliases of one long id would
    otherwise repeat it forty times.
    """
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    if shape == "a long string":
        text = contract.read_text(encoding="utf-8")
        long_id = "a" * 100000
        entries = "".join(
            f"    - id: {'&long ' + long_id if i == 0 else '*long'}\n"
            "      name: Long\n      may_depend_on: []\n"
            for i in range(40)
        )
        assert text.count("\n  layers:\n") == 1
        contract.write_text(
            text.replace("\n  layers:\n", "\n  layers:\n" + entries, 1),
            encoding="utf-8",
        )
        completed = subprocess.run(
            [sys.executable, "scripts/check_architecture.py"],
            cwd=workspace, capture_output=True, text=True, timeout=600,
        )
        assert completed.returncode == 2, completed.stderr[-400:]
        assert len(completed.stdout) < 65536, len(completed.stdout)
        assert "gives a layer id as 'aaaa" in completed.stdout
        return
    # Anchored inside the layer itself, under keys the gate does not read.
    bomb = "      x_b0: &b0 [a, a, a, a, a, a, a, a, a, a]\n" + "".join(
        f"      x_b{level}: &b{level} [{', '.join([f'*b{level - 1}'] * 10)}]\n"
        for level in range(1, 6)
    )
    text = contract.read_text(encoding="utf-8")
    assert text.count("\n  layers:\n") == 1
    text = text.replace(
        "\n  layers:\n",
        "\n  layers:\n    - id: layer.bomb\n      name: Bomb\n"
        + bomb + "      may_depend_on: [*b5]\n",
        1,
    )
    contract.write_text(text, encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace, capture_output=True, text=True, timeout=600,
    )
    assert completed.returncode == 2, completed.stderr[-400:]
    assert len(completed.stdout) < 65536, len(completed.stdout)
    assert "gives an entry of layer 'layer.bomb'" in completed.stdout


#: id -> whether it is an identifier in nornyx's syntax.
_MODULE_IDS = {"module layer_probe": False, "m" * 161: False, "m" * 160: True}


@pytest.mark.parametrize(
    "ident",
    [pytest.param(ident, id=label) for label, ident in
     (("160", "m" * 160), ("161", "m" * 161), ("space", "module layer_probe"))],
)
def test_a_module_id_is_held_to_the_syntax_and_its_bound(tmp_path: Path, ident: str):
    """At most 160 characters of nornyx's identifier syntax, and no more."""
    workspace = _forge_tree(tmp_path)
    (workspace / "src/nornyx_forge/layer_probe.py").write_text("", encoding="utf-8")
    contract = workspace / CONTRACT
    document = yaml.safe_load(contract.read_text(encoding="utf-8"))
    document["architecture"]["modules"].append(dict(_PROBE, id=ident, depends_on=[]))
    contract.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    code, violations = _gate(workspace)
    if _MODULE_IDS[ident]:
        assert (code, violations) == (0, [])
    else:
        assert code == 2, violations
        assert any("gives a module id as 'm" in v for v in violations), violations


def test_a_document_with_two_construction_errors_fails_as_the_loader_fails(
        tmp_path: Path):
    """The library builds each mapping first, so its first error is the one raised.

    A version of the repeated-key observer built every key of a mapping before
    the library built the first value, so a value error followed by a key
    error raised the key's, measured by an in-session review: the document
    was refused either way, but not by the loader's own error.
    """
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    contract.write_text(
        contract.read_text(encoding="utf-8") + "x_two_errors: {a: !!int xx, !bar b: 1}\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "scripts/check_architecture.py"],
        cwd=workspace, capture_output=True, text=True, timeout=600,
    )
    assert completed.returncode == 1, completed.stdout[-400:]
    assert "ValueError" in completed.stderr, completed.stderr[-600:]
    assert "!bar" not in completed.stderr, completed.stderr[-600:]


def test_merges_the_loader_resolves_are_read_as_it_reads_them(tmp_path: Path):
    """A mapping that merges itself, and a long chain of merges, are not refused.

    `yaml.safe_load` reads both; a version of the repeated-key refusal that
    expanded merges itself recursed without end on the first and stopped at
    Python's recursion limit on the second, measured by an in-session review.
    """
    workspace = _forge_tree(tmp_path)
    contract = workspace / CONTRACT
    chain = "x_c0: &c0 {k0: 1}\n" + "".join(
        f"x_c{i}: &c{i} {{<<: *c{i - 1}, k{i}: 1}}\n" for i in range(1, 200)
    )
    contract.write_text(
        contract.read_text(encoding="utf-8") + "x_self: &self {<<: *self}\n" + chain,
        encoding="utf-8",
    )
    assert _gate(workspace) == (0, [])


def test_a_link_under_the_source_tree_is_refused(tmp_path: Path):
    """Python imports through a linked directory, and discovery does not follow it.

    Measured by an in-session review on a version of this change that read
    every module through discovery: a package linked into
    `src/demo_app/linked`, with a module starting a process, imported from
    the HTTP surface, passed this gate at exit 0. The link is a symbolic link
    where the host can make one, and a junction, which needs no privilege,
    where it cannot (Windows without that privilege).
    """
    workspace = _forge_tree(tmp_path)
    target = workspace / "linked_pkg"
    target.mkdir()
    (target / "m.py").write_text("import subprocess\n", encoding="utf-8")
    link = workspace / "src/demo_app/linked"
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        if sys.platform != "win32":
            raise
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True, capture_output=True,
        )
    main = workspace / "src/demo_app/main.py"
    main.write_text(
        main.read_text(encoding="utf-8") + "\nimport demo_app.linked.m\n", encoding="utf-8"
    )
    code, violations = _gate(workspace)
    assert code == 2, violations
    assert any("src/demo_app/linked is a link" in v for v in violations), violations


def test_a_source_file_in_a_cache_directory_is_read_like_any_other(tmp_path: Path):
    """Only bytecode in `__pycache__` is a cache; a `.py` there is a module.

    `__pycache__` is an identifier, so `import demo_app.__pycache__.evil`
    loads a source placed there. A discovery that skipped the whole directory
    never saw it, and the import was then taken for a non-module and passed.
    """
    workspace = _forge_tree(tmp_path)
    cache = workspace / "src/demo_app/__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "evil.py").write_text("import subprocess\n", encoding="utf-8")
    (cache / "store.cpython-313.pyc").write_bytes(b"")
    main = workspace / "src/demo_app/main.py"
    main.write_text(
        main.read_text(encoding="utf-8") + "\nimport demo_app.__pycache__.evil\n",
        encoding="utf-8",
    )
    code, violations = _gate(workspace)
    assert code == 2, violations
    joined = "\n".join(violations)
    assert "src/demo_app/__pycache__/evil.py is a first-party module" in joined, joined
    assert "store.cpython-313.pyc" not in joined, joined


#: The deciding line of each refusal, and the same line deciding nothing.
_REFUSALS = {
    "    for value, count in repeated.items():\n": "    for value, count in ():\n",
    "                if key in keys:\n": "                if False:\n",
}


@pytest.mark.parametrize("repeated", sorted(REPEATED_KEYS))
def test_without_the_refusals_a_repeated_key_hides_the_violation(
        tmp_path: Path, repeated: str):
    """The refusals are load-bearing, shown by taking them out of a copy.

    With both deciding lines emptied, the same tree passes with no violation
    at all, so a refusal, and no other rule, is what fails it. This is also
    the measurement above, kept: a repeated key hides a real layer violation.
    """
    workspace = _forge_tree(tmp_path)
    checker = workspace / "scripts/check_architecture.py"
    source = checker.read_text(encoding="utf-8")
    for refusal, neutralized in _REFUSALS.items():
        assert source.count(refusal) == 1, f"a refusal moved, so this is stale: {refusal!r}"
        source = source.replace(refusal, neutralized)
    checker.write_text(source, encoding="utf-8")
    _plant(workspace, repeated)
    assert _gate(workspace) == (0, [])
