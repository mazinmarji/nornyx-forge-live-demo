"""Generated contracts describe the workspace they govern (A-063).

`render_brd_contract` used to render one template for every repository mode:
Forge's own layout (`src/`, `scripts/validate_repository.py`, authority in
`.nornyx/contracts/*.nyx`). A greenfield project keeps its code in `app/`, has
no such script, and its contract lives at `.nornyx/generated/brd_contract.nyx`
-- so a greenfield build was governed by a contract describing none of its
code, and `nornyx check` (A-049), which validates structure, passed it.

These tests pin both templates, the explicit choice between them, the
certified template's bytes as they were before templates existed, and the
trusted `greenfield:contract-truth` gate that refuses a contract whose layout
the workspace does not match. The gate proves the LAYOUT matches; nothing here
claims the code is correct, safe or confined.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from review_verdict_support import REVIEW_ROLES, review_output

import nornyx_forge.development_flow as flow_module
from nornyx_forge.contract_generator import (
    CONTRACT_TEMPLATES,
    generate_brd_contract,
    render_brd_contract,
)
from nornyx_forge.contract_truth import (
    CONTRACT_TRUTH_GATE,
    GREENFIELD_LAYOUT_GOAL,
    REPOSITORY_CONTEXT,
    contract_truth_findings,
    pattern_regex,
    trusted_contract_truth_check,
)
from nornyx_forge.development_flow import DevelopmentFlow, contract_template
from nornyx_forge.gates import GREENFIELD_GATE_IDS
from nornyx_forge.models import GateResult, WorkerResult
from nornyx_forge.produced_app_handoff import IGNORED_DIRECTORIES
from nornyx_forge.produced_app_manifest import (
    APPLICATION_PACKAGE,
    ENTRY_POINT,
    GENERATED_CONTRACT_PATH,
    TESTS_DIRECTORY,
    application_source_files,
)
from nornyx_forge.requirements import parse_brd_text

BRD = (
    "# BRD\n\n## BRD-001 Purpose\n\nAdd two numbers for a reader.\n\n"
    "## BRD-002 Functional requirements\n\n### BRD-F-001 Add\n\nThe tool adds two integers.\n\n"
    "### BRD-F-002 Show\n\nThe tool shows the sum.\n"
)
#: The same BRD texts the certified pins below were computed from.
BOUND_BRD = (
    "# BRD — Specimen\n\nSource specification SHA-256: " + "ab" * 32 + "\n\n"
    "## BRD-001 Purpose\n\nKeep a list of tasks.\n\n"
    "## BRD-002 Functional requirements\n\n### BRD-F-001 RQ-1\n\nUsers add a task.\n"
)

#: SHA-256 of the certified template's output, computed with the renderer at
#: fb8b787e587567ff780c3a1719c9e6e8517f704c -- before the templates were
#: separated -- for one BRD without a declared specification digest and one
#: with. The certified template must keep these bytes exactly.
CERTIFIED_PINS = {
    "unbound": (BRD, None,
                "6ef803fee4f8f4bbbea81717eb3f4c01cde0f8985da8ff652e462b0dbb084e40"),
    "bound": (BOUND_BRD, "ab" * 32,
              "3f2df3b9652d43c026b65cef7393aa43703cd5e343149a7a968e4ae834a11b37"),
}

#: The fields Forge's own template declared, which a generated project lacks.
OLD_SCOPE = ["BRD.md", "src/", "tests/", "docs/"]
OLD_SCRIPT = "scripts/validate_repository.py"
OLD_AUTHORITY = ".nornyx/contracts/*.nyx"


def _model(text: str = BRD) -> Any:
    return parse_brd_text(text, "BRD.md")


def _greenfield() -> str:
    return render_brd_contract(_model(), template="greenfield")


def _edited(edit) -> str:
    """The greenfield contract with one field changed through `edit`."""
    contract = yaml.safe_load(_greenfield())
    edit(contract)
    return yaml.safe_dump(contract, sort_keys=False)


def _context(contract: dict) -> dict:
    return next(item for item in contract["contexts"] if item["name"] == REPOSITORY_CONTEXT)


def _write(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="")
    return root


def _well_formed(root: Path, contract: str | None = None) -> Path:
    """A generated project as the greenfield template describes it."""
    return _write(root, {
        "BRD.md": BRD,
        ENTRY_POINT: "from app.calc import add\n\nprint(add(1, 2))\n",
        f"{APPLICATION_PACKAGE}/calc.py": "def add(left: int, right: int) -> int:\n    return left + right\n",
        f"{TESTS_DIRECTORY}/test_calc.py": "# BRD-F-001\nfrom app.calc import add\n\n\n"
                                           "def test_add():\n    assert add(1, 2) == 3\n",
        GENERATED_CONTRACT_PATH: contract if contract is not None else _greenfield(),
    })


def _check(root: Path, contract: str | None = None) -> GateResult:
    return trusted_contract_truth_check(root, _greenfield() if contract is None else contract)


# ---------------------------------------------------------------------------
# The two templates and the explicit choice between them
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(CERTIFIED_PINS))
def test_the_certified_template_keeps_its_bytes_from_before_templates_existed(name):
    text, specification, pinned = CERTIFIED_PINS[name]
    model = _model(text)
    assert model.specification_digest == specification
    rendered = render_brd_contract(model, template="certified")
    assert hashlib.sha256(rendered.encode("utf-8")).hexdigest() == pinned


def test_the_template_is_always_named_and_an_unknown_one_is_refused(tmp_path):
    assert CONTRACT_TEMPLATES == ("certified", "greenfield")
    with pytest.raises(TypeError):
        render_brd_contract(_model())  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        generate_brd_contract(tmp_path, _model())  # type: ignore[call-arg]
    for unknown in ("", "Greenfield", "target", "default"):
        with pytest.raises(ValueError, match="template"):
            render_brd_contract(_model(), template=unknown)
    assert not (tmp_path / GENERATED_CONTRACT_PATH).exists()


def test_the_greenfield_template_declares_the_produced_application_layout():
    contract = yaml.safe_load(_greenfield())
    for goal in contract["goals"]:
        assert goal["scope"] == ["BRD.md", f"{APPLICATION_PACKAGE}/", f"{TESTS_DIRECTORY}/"]
        assert goal["validation"] == ["python -m pytest -q"]
    context = _context(contract)
    assert context["include"] == ["BRD.md", f"{APPLICATION_PACKAGE}/**/*",
                                  f"{TESTS_DIRECTORY}/**/*", GENERATED_CONTRACT_PATH]
    assert context["authority"] == ["BRD.md", GENERATED_CONTRACT_PATH, f"{TESTS_DIRECTORY}/**/*"]
    text = _greenfield()
    for absent in ("src/", "docs/", "README.md", OLD_SCRIPT, OLD_AUTHORITY):
        assert absent not in text, absent


def test_the_greenfield_layout_comes_from_the_manifest_constants():
    assert (APPLICATION_PACKAGE, TESTS_DIRECTORY) == ("app", "tests")
    assert ENTRY_POINT.startswith(APPLICATION_PACKAGE + "/")
    assert GENERATED_CONTRACT_PATH == ".nornyx/generated/brd_contract.nyx"


@pytest.mark.parametrize("template", CONTRACT_TEMPLATES)
def test_the_written_contract_is_the_rendered_one_for_each_template(tmp_path, template):
    """The digest binding: what is written is exactly what the same renderer
    call, with the same template, returns."""
    model = _model(BOUND_BRD)
    written = generate_brd_contract(tmp_path, model, template=template)
    assert written == tmp_path / GENERATED_CONTRACT_PATH
    assert written.read_bytes() == render_brd_contract(model, template=template).encode("utf-8")


@pytest.mark.parametrize("mode, template", [
    ("greenfield", "greenfield"), ("certified", "certified"),
    ("target", "certified"), ("scout", "certified"),
])
def test_each_repository_mode_renders_the_template_for_the_repository_it_serves(mode, template):
    assert contract_template(mode) == template


def test_a_greenfield_flow_records_the_digest_of_the_greenfield_bytes_it_wrote(tmp_path):
    (tmp_path / "BRD.md").write_text(BRD, encoding="utf-8")
    flow = DevelopmentFlow(tmp_path, worker_mode="deterministic", repo_mode="greenfield")
    flow.requirements()
    written = (tmp_path / GENERATED_CONTRACT_PATH).read_bytes()
    assert written == render_brd_contract(_model(), template="greenfield").encode("utf-8")
    assert flow._generated_brd_contract_text.encode("utf-8") == written


# ---------------------------------------------------------------------------
# Builder goals name the scope
# ---------------------------------------------------------------------------

class _Worker:
    """Every stage succeeds and each reviewer returns a valid PASS. `writes`
    maps a role to files it writes into the workspace when it runs."""

    def __init__(self, writes: dict[str, dict[str, str]] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.writes = writes or {}

    def run(self, **request: Any) -> WorkerResult:
        self.calls.append(dict(request))
        role = str(request["role"])
        _write(Path(request["workspace"]), self.writes.get(role, {}))
        output = review_output(role) if role in REVIEW_ROLES else "stub worker at the flow seam"
        return WorkerResult(role=role, goal=str(request["goal"]), success=True,
                            output=output, command=("stub-worker", role), returncode=0)


#: The architect's and builder's goals at fb8b787, before this change.
CERTIFIED_GOALS = {
    "solution-architect": (
        "Review BRD.md, docs/ARCHITECTURE.md, and the Nornyx contracts. "
        "Improve architecture declarations and tests only where required. "
        "Any .nyx file you create or change must pass `nornyx check`; run it "
        "and fix the file, or record the check's diagnostics as a limitation."
    ),
    "application-builder": (
        "Implement every missing BRD acceptance criterion. Keep external side effects "
        "behind the Nornyx action boundary, preserve architecture direction, and add tests."
    ),
}


@pytest.mark.parametrize("mode", ["greenfield", "certified", "target", "scout"])
def test_greenfield_builder_goals_name_the_scope_and_others_are_unchanged(tmp_path, mode):
    (tmp_path / "BRD.md").write_text(BRD, encoding="utf-8")
    flow = DevelopmentFlow(tmp_path, worker_mode="claude-code", repo_mode=mode)
    worker = _Worker()
    flow.worker = worker
    flow.architecture()
    flow.implementation()
    goals = {call["role"]: call["goal"] for call in worker.calls}
    assert set(goals) == set(CERTIFIED_GOALS)
    for role, goal in goals.items():
        if mode == "greenfield":
            assert goal == CERTIFIED_GOALS[role] + GREENFIELD_LAYOUT_GOAL
            assert f"{APPLICATION_PACKAGE}/" in goal and f"{TESTS_DIRECTORY}/" in goal
        else:
            assert goal == CERTIFIED_GOALS[role]


# ---------------------------------------------------------------------------
# The contract-truth gate: one rejecting case per test
# ---------------------------------------------------------------------------

def test_a_well_formed_greenfield_workspace_passes(tmp_path):
    result = _check(_well_formed(tmp_path))
    assert result.name == CONTRACT_TRUTH_GATE
    assert result.passed is True, result.detail
    assert "describes the workspace's layout" in result.detail


def test_an_empty_application_package_is_refused(tmp_path):
    _well_formed(tmp_path)
    for path in (tmp_path / APPLICATION_PACKAGE).iterdir():
        path.unlink()
    assert (tmp_path / APPLICATION_PACKAGE).is_dir()
    result = _check(tmp_path)
    assert result.passed is False
    assert "the declared source scope app/ holds no application source" in result.detail
    assert "the include pattern 'app/**/*' matches no file in the workspace" in result.detail


def test_source_only_in_src_is_refused(tmp_path):
    _well_formed(tmp_path)
    for path in (tmp_path / APPLICATION_PACKAGE).iterdir():
        path.unlink()
    (tmp_path / APPLICATION_PACKAGE).rmdir()
    _write(tmp_path, {"src/calc.py": "def add(a, b):\n    return a + b\n"})
    result = _check(tmp_path)
    assert result.passed is False
    assert "the declared source scope app/ holds no application source" in result.detail
    assert ("application source lies outside the declared source scope app/ and outside "
            "tests/: src/calc.py") in result.detail


@pytest.mark.parametrize("stray", ["lib/helpers.py", "helpers.py", "tools/deep/run.py"])
def test_source_in_the_package_and_elsewhere_is_refused(tmp_path, stray):
    _write(_well_formed(tmp_path), {stray: "VALUE = 1\n"})
    result = _check(tmp_path)
    assert result.passed is False
    assert "holds no application source" not in result.detail
    assert f"outside tests/: {stray}" in result.detail


def test_a_validation_command_naming_a_missing_script_is_refused(tmp_path):
    def edit(contract):
        contract["goals"][0]["validation"].insert(0, "python scripts/check_layout.py --strict")
    contract = _edited(edit)
    _well_formed(tmp_path, contract)
    result = _check(tmp_path, contract)
    assert result.passed is False
    assert ("names a script the workspace does not contain: scripts/check_layout.py"
            in result.detail)
    _write(tmp_path, {"scripts/check_layout.py": "print('ok')\n"})
    # Present now -- and source outside the scope, which the gate also names.
    after = _check(tmp_path, contract)
    assert "does not contain" not in after.detail


def test_an_include_pattern_matching_nothing_is_refused(tmp_path):
    contract = _edited(lambda c: _context(c)["include"].append("docs/**/*.md"))
    _well_formed(tmp_path, contract)
    result = _check(tmp_path, contract)
    assert result.passed is False
    assert result.detail == "the include pattern 'docs/**/*.md' matches no file in the workspace"


def test_an_authority_pattern_matching_nothing_is_refused(tmp_path):
    contract = _edited(lambda c: _context(c)["authority"].append(OLD_AUTHORITY))
    _well_formed(tmp_path, contract)
    result = _check(tmp_path, contract)
    assert result.passed is False
    assert result.detail == (
        f"the authority pattern '{OLD_AUTHORITY}' matches no file in the workspace")


@pytest.mark.parametrize("text, reason", [
    ("goals: [\n", "the generated contract cannot be parsed"),
    ("- a\n- b\n", "the generated contract cannot be parsed: it is not a mapping"),
    ("", "the generated contract cannot be parsed: it is not a mapping"),
])
def test_a_contract_that_cannot_be_parsed_is_refused(tmp_path, text, reason):
    result = _check(_well_formed(tmp_path), text)
    assert result.passed is False
    assert result.detail.startswith(reason), result.detail


def _drop_goals(contract):
    del contract["goals"]


def _drop_context(contract):
    contract["contexts"] = [c for c in contract["contexts"] if c["name"] != REPOSITORY_CONTEXT]


def _drop(field):
    def edit(contract):
        for goal in contract["goals"]:
            del goal[field]
    return edit


def _drop_context_field(field):
    def edit(contract):
        del _context(contract)[field]
    return edit


@pytest.mark.parametrize("edit, reason", [
    (_drop_goals, "the generated contract has no goals"),
    (_drop_context, f"the generated contract has no {REPOSITORY_CONTEXT} context"),
    (_drop("scope"), "has no scope"),
    (_drop("validation"), "has no validation commands"),
    (_drop_context_field("include"), f"the {REPOSITORY_CONTEXT} context has no include patterns"),
    (_drop_context_field("authority"), f"the {REPOSITORY_CONTEXT} context has no authority patterns"),
])
def test_a_contract_missing_a_field_the_check_needs_is_refused(tmp_path, edit, reason):
    result = _check(_well_formed(tmp_path), _edited(edit))
    assert result.passed is False
    assert reason in result.detail, result.detail


def test_a_contract_with_no_source_scope_is_refused():
    def edit(contract):
        for goal in contract["goals"]:
            goal["scope"] = ["BRD.md", "tests/"]
    findings = contract_truth_findings(_edited(edit), ["BRD.md", "tests/test_a.py"])
    assert "the generated contract declares no source scope" in findings


@pytest.mark.parametrize("value", [None, b"goals: []", 7])
def test_no_rendered_text_is_refused(tmp_path, value):
    result = trusted_contract_truth_check(_well_formed(tmp_path), value)
    assert result.passed is False
    assert result.detail in ("no rendered contract was recorded for this build",
                             "the generated contract is not text")


def test_the_old_single_template_on_an_app_project_is_refused(tmp_path):
    """Forge's own layout, as the one template rendered it for every mode,
    applied to a project in the produced-application layout: built here from
    the certified template's fields, nothing copied from a generated app."""
    old = yaml.safe_load(render_brd_contract(_model(), template="certified"))
    assert old["goals"][0]["scope"] == OLD_SCOPE
    assert f"python {OLD_SCRIPT}" in old["goals"][0]["validation"]
    assert OLD_AUTHORITY in _context(old)["authority"]
    contract = yaml.safe_dump(old, sort_keys=False)
    result = _check(_well_formed(tmp_path), contract)
    assert result.passed is False
    for reason in (
        "the declared source scope src/, docs/ holds no application source",
        "application source lies outside the declared source scope src/, docs/ and outside tests/: "
        "app/__main__.py, app/calc.py",
        f"names a script the workspace does not contain: {OLD_SCRIPT}",
        f"the authority pattern '{OLD_AUTHORITY}' matches no file in the workspace",
        "the include pattern 'src/**/*' matches no file in the workspace",
    ):
        assert reason in result.detail, (reason, result.detail)


def test_the_gate_reads_the_rendered_text_not_the_file_in_the_workspace(tmp_path):
    """A provider that rewrites the contract file to describe what it built
    changes nothing: the gate judges the bytes Forge rendered."""
    _well_formed(tmp_path)
    (tmp_path / APPLICATION_PACKAGE / "calc.py").unlink()
    (tmp_path / ENTRY_POINT).unlink()
    _write(tmp_path, {"src/calc.py": "VALUE = 1\n"})
    rewritten = _greenfield().replace(f"{APPLICATION_PACKAGE}/", "src/")
    (tmp_path / GENERATED_CONTRACT_PATH).write_text(rewritten, encoding="utf-8")
    result = trusted_contract_truth_check(tmp_path, _greenfield())
    assert result.passed is False
    assert "outside tests/: src/calc.py" in result.detail


def test_a_linked_generated_contract_is_not_counted(tmp_path):
    _well_formed(tmp_path)
    target = tmp_path / "elsewhere.nyx"
    contract = tmp_path / GENERATED_CONTRACT_PATH
    target.write_bytes(contract.read_bytes())
    contract.unlink()
    contract.symlink_to(target)
    result = _check(tmp_path)
    assert result.passed is False
    assert f"the authority pattern '{GENERATED_CONTRACT_PATH}' matches no file" in result.detail


# ---------------------------------------------------------------------------
# What counts as application source: one definition, exclusions inherited
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("directory", sorted(IGNORED_DIRECTORIES))
def test_the_verifiers_excluded_directories_hold_no_application_source(tmp_path, directory):
    """The workspace is listed by the trusted verifier's collection rule, so a
    Python file in a virtual environment, cache, build output or version
    control directory is never application source, top-level or nested."""
    _write(_well_formed(tmp_path), {f"{directory}/stray.py": "VALUE = 1\n",
                                    f"lib/{directory}/stray.py": "VALUE = 1\n"})
    result = _check(tmp_path)
    assert result.passed is True, result.detail


def test_only_python_files_are_application_source(tmp_path):
    _write(_well_formed(tmp_path), {"README.md": "# readme\n", "pyproject.toml": "[project]\n",
                                    "scripts/run.sh": "echo run\n", "data/table.csv": "a,b\n"})
    assert _check(tmp_path).passed is True
    assert application_source_files(
        ["README.md", "app/x.py", "app/data.json", "lib/y.py", "tests/test_x.py"], None,
    ) == ["app/x.py", "lib/y.py", "tests/test_x.py"]


def test_a_named_store_is_not_product_and_without_one_nothing_is_excused():
    files = ["capsule/hook.py", "app/__main__.py", "capsule/record.json"]
    assert application_source_files(files, "capsule") == ["app/__main__.py"]
    assert application_source_files(files, None) == ["app/__main__.py", "capsule/hook.py"]


@pytest.mark.parametrize("pattern, matches, misses", [
    ("app/**/*", ["app/a.py", "app/x/y/z.py"], ["app", "src/app/a.py", "apps/a.py"]),
    ("tests/**/*", ["tests/test_a.py"], ["tests", "xtests/a.py"]),
    ("BRD.md", ["BRD.md"], ["docs/BRD.md", "BRD.mdx", "BRDXmd"]),
    (".nornyx/contracts/*.nyx", [".nornyx/contracts/a.nyx"], [".nornyx/contracts/x/a.nyx"]),
    ("docs/**/*.md", ["docs/a.md", "docs/x/a.md"], ["docs/a.txt"]),
    ("a?c", ["abc"], ["a/c", "abbc"]),
])
def test_contract_patterns_match_as_documented(pattern, matches, misses):
    regex = pattern_regex(pattern)
    assert all(regex.match(path) for path in matches), pattern
    assert not any(regex.match(path) for path in misses), pattern


# ---------------------------------------------------------------------------
# Through the real DevelopmentFlow: a false contract ends DENY
# ---------------------------------------------------------------------------

def _flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, str],
          writes: dict[str, dict[str, str]] | None = None) -> tuple[dict, list]:
    """A greenfield build whose verifier gates are stubbed to pass and whose
    reviewers all PASS, so only the contract's truth can refuse it."""
    _write(tmp_path, {"BRD.md": BRD, **files})
    gates = [GateResult(f"greenfield:{gate}", True, "stub verifier gate") for gate in GREENFIELD_GATE_IDS]
    provenance = {"test_execution": {"completion": {
        "collected": 1, "executed": 1, "failed": 0, "skipped": 0}}}
    monkeypatch.setattr(flow_module, "trusted_greenfield_gates",
                        lambda _root, **_kw: (list(gates), dict(provenance)))
    monkeypatch.setenv("FORGE_MAX_REPAIR_ATTEMPTS", "0")
    flow = DevelopmentFlow(tmp_path, worker_mode="claude-code", repo_mode="greenfield")
    flow.worker = _Worker(writes)
    result = flow.run_sequential()
    events = [json.loads(line) for line in (tmp_path / ".nornyx/runs/build-events.jsonl")
              .read_text(encoding="utf-8").splitlines()]
    return result, events


def _decision(events: list) -> str:
    return next(e for e in events if e["event_type"] == "build_acceptance")["decision"]


APP_FILES = {ENTRY_POINT: "print('app')\n", f"{TESTS_DIRECTORY}/test_app.py": "def test_a():\n    pass\n"}


def test_a_greenfield_build_whose_contract_describes_it_is_allowed(tmp_path, monkeypatch):
    result, events = _flow(tmp_path, monkeypatch, APP_FILES)
    truth = next(g for g in result["gates"] if g["name"] == CONTRACT_TRUTH_GATE)
    assert truth["passed"] is True, truth
    assert result["accepted"] is True and _decision(events) == "ALLOW"


def test_a_greenfield_build_with_a_false_contract_ends_deny(tmp_path, monkeypatch):
    """The code is in src/ and the contract Forge rendered scopes app/: every
    other gate passes and the build is still refused."""
    result, events = _flow(tmp_path, monkeypatch, {
        "src/calc.py": "VALUE = 1\n", f"{TESTS_DIRECTORY}/test_app.py": "def test_a():\n    pass\n"})
    failed = [g for g in result["gates"] if not g["passed"]]
    assert [g["name"] for g in failed] == [CONTRACT_TRUTH_GATE], failed
    assert "outside tests/: src/calc.py" in failed[0]["detail"]
    assert result["accepted"] is False and _decision(events) == "DENY"


def test_a_greenfield_build_rendering_the_old_template_ends_deny(tmp_path, monkeypatch):
    """The defect itself: a greenfield build rendering Forge's own template.
    `nornyx check` passes it; the contract-truth gate refuses it."""
    monkeypatch.setattr(flow_module, "contract_template", lambda _mode: "certified")
    result, events = _flow(tmp_path, monkeypatch, APP_FILES)
    gates = {g["name"]: g for g in result["gates"]}
    assert gates["greenfield:nornyx-contract-check"]["passed"] is True
    assert gates[CONTRACT_TRUTH_GATE]["passed"] is False
    assert f"names a script the workspace does not contain: {OLD_SCRIPT}" in (
        gates[CONTRACT_TRUTH_GATE]["detail"])
    assert result["accepted"] is False and _decision(events) == "DENY"


def test_the_gate_judges_the_workspace_after_the_reviewers(tmp_path, monkeypatch):
    """The greenfield gates are re-run on the final subject after the review
    stage; source a reviewer leaves outside app/ is refused there."""
    result, events = _flow(tmp_path, monkeypatch, APP_FILES,
                           writes={"security-inspector": {"lib/late.py": "VALUE = 1\n"}})
    truth = next(g for g in result["gates"] if g["name"] == CONTRACT_TRUTH_GATE)
    assert truth["passed"] is False and "outside tests/: lib/late.py" in truth["detail"]
    assert result["accepted"] is False and _decision(events) == "DENY"


def test_the_gate_runs_in_every_greenfield_build_beside_the_contract_check(tmp_path, monkeypatch):
    """No mode, variable or flag removes it: it is recorded once, right after
    the A-049 `nornyx check` gate, whatever the environment says."""
    for name in ("FORGE_SKIP_CONTRACT_TRUTH", "FORGE_CONTRACT_TRUTH", "NORNYX_SKIP_GATES"):
        monkeypatch.setenv(name, "1")
    result, _events = _flow(tmp_path, monkeypatch, {"src/calc.py": "VALUE = 1\n"})
    names = [g["name"] for g in result["gates"]]
    assert names.count(CONTRACT_TRUTH_GATE) == 1
    assert names.index(CONTRACT_TRUTH_GATE) == names.index("greenfield:nornyx-contract-check") + 1
    assert result["accepted"] is False
