"""Every control name in the architecture policy must have a decision point.

Measured across the policy vocabulary:

    undeclared_component_dependency  enforced -- every first-party edge
    api_direct_command_execution     enforced -- by path, and by capability
    ui_direct_persistence_access     ENFORCED BY NOTHING, and it denied an edge
                                     the same contract declares
    architecture_evidence_per_change enforced by the evidence refresher
    bounded_external_adapter         enforced in check_architecture.py

A prohibition in the governance source of truth that no check consumes is worse
than no prohibition: it reads as protection to everyone who audits the contract,
and it cost nothing to write. `ui_direct_persistence_access` was removed for
that reason -- not to make a failing gate pass, since the gate was already
green, but because the contract simultaneously forbade and declared the same
edge.

This module holds the remaining names to their decision points BY RUNNING THEM.
A test asserting a token appears in the contract would be the same defect one
level up.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / ".nornyx/contracts/architecture_governance.nyx"

#: Each policy token, and where its decision is actually taken. A token with no
#: entry fails the audit below, which is what stops vocabulary accumulating.
ENFORCEMENT = {
    "undeclared_component_dependency":
        "check_architecture.py refuses any first-party import absent from the "
        "importing module's declared depends_on, and any module absent from the "
        "contract entirely",
    "api_direct_command_execution":
        "check_architecture.py forbids demo_app.main importing nornyx_forge by "
        "path, and the process-capability rules refuse execution acquisition",
    "architecture_evidence_per_change":
        "refresh_governance_evidence.py recomputes the conformance report and "
        "rebinds it to the subject",
    "revision_binding":
        "the contract carries subject_revision, rebound by the refresher",
    "bounded_external_adapter":
        "check_architecture.py restricts process execution to the declared "
        "adapter module",
    "reviewer_modifies_implementation":
        "the reviewer trust store is separate and read-only; inspection "
        "attestations are authenticated, never authored by the builder",
    "ai_architecture_approval":
        "assurance_state cannot reach independently_inspected from AI output; "
        "human approval is a separately signed artifact",
    "independent_conformance_check":
        "the independent review record is authenticated against reviewer trust",
    "explicit_exception_for_violation":
        "exception_review_record is a required evidence artifact",
}


def _policy_tokens() -> set[str]:
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    tokens: set[str] = set()
    for policy in contract.get("policies", []):
        tokens.update(policy.get("deny", []))
        tokens.update(policy.get("require", []))
    return tokens


def test_every_policy_token_names_a_decision_point():
    """No control name without one. The audit that the removed token failed."""
    undecided = sorted(_policy_tokens() - set(ENFORCEMENT))
    assert undecided == [], (
        "these appear in the architecture policy with nowhere that consumes "
        f"them, so they read as protection and provide none: {undecided}"
    )


def test_the_removed_token_is_gone_from_the_contract():
    """And cannot come back without someone reading why it left."""
    assert "ui_direct_persistence_access" not in _policy_tokens()


def test_the_declared_persistence_edge_is_real_and_declared():
    """The edge the removed token denied. It exists, and the graph permits it.

    Asserted from both ends so the two cannot drift: the import is really there,
    and the contract really declares it. If someone routes the store through the
    application layer later, this fails and the declaration must move with it.
    """
    source = (ROOT / "src/demo_app/main.py").read_text(encoding="utf-8")
    assert "from .store import JsonStore" in source

    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    modules = {m["id"]: m for m in contract["architecture"]["modules"]}
    components = {c["id"]: c for c in contract["architecture"]["components"]}
    assert "module.persistence" in modules["module.api"]["depends_on"]
    assert "component.persistence" in components["component.api"]["depends_on"]


# --------------------------------------------------------------------------
# The two surviving tokens, enforced against a real tree.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> Path:
    work = tmp_path_factory.mktemp("vocabulary") / "repo"
    work.mkdir()
    for item in ("src", "scripts", ".nornyx"):
        shutil.copytree(
            ROOT / item,
            work / item,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
        )
    for item in ("pyproject.toml", "README.md", "BRD.md", "Dockerfile"):
        shutil.copy2(ROOT / item, work / item)
    return work


def _gate(work: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "scripts/check_architecture.py"],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_the_baseline_is_clean(workspace: Path):
    """Or every refusal below would be free."""
    completed = _gate(workspace)
    assert completed.returncode == 0, completed.stdout + completed.stderr


UNDECLARED_EDGES = [
    (
        "the interface layer reaching governance",
        "src/demo_app/main.py",
        "\nfrom nornyx_forge.nornyx_runtime import NornyxActionBoundary\n_B = NornyxActionBoundary\n",
        None,
        "forbidden dependency nornyx_forge",
    ),
    (
        "a brand-new first-party module",
        "src/demo_app/main.py",
        "\nfrom demo_app.brand_new import thing\n_T = thing\n",
        ("src/demo_app/brand_new.py", "def thing():\n    return 1\n"),
        "not declared in the architecture",
    ),
    (
        "an undeclared edge between two DECLARED modules",
        "src/demo_app/store.py",
        "\nfrom demo_app.agentic import run_case\n_R = run_case\n",
        None,
        "undeclared dependency",
    ),
    (
        "reached through an alias rather than by name",
        "src/demo_app/store.py",
        "\nimport demo_app.agentic as _flow\n_R = _flow.run_case\n",
        None,
        "undeclared dependency",
    ),
    (
        "reached dynamically",
        "src/demo_app/store.py",
        "\nimport importlib\n_R = importlib.import_module('demo_app.agentic').run_case\n",
        None,
        "undeclared dependency",
    ),
    # ---- sys.modules: a module object with no import statement --------
    #
    # THE GATE UNDERSTOOD THIS SPELLING ALREADY -- in its process-capability
    # scan, and not in its dependency scan. So `sys.modules['subprocess']`
    # was caught while `sys.modules['nornyx_forge.nornyx_runtime']` in the
    # HTTP surface was not: measured at 032ca63 as `status: pass,
    # violations: [], exit 0` against the rule the checker annotates as
    # unconditional. One analysis widened, its sibling not: AC04.
    #
    # Every row hands back the identical module object by a different
    # spelling, which is the point: a rule that reads one of them is a
    # naming convention.
    (
        "the interface layer reaching governance through sys.modules",
        "src/demo_app/main.py",
        "\nimport sys\n_R = sys.modules['nornyx_forge.nornyx_runtime']\n",
        None,
        "undeclared dependency nornyx_forge.nornyx_runtime",
    ),
    (
        "the same, through sys.modules.get",
        "src/demo_app/main.py",
        "\nimport sys\n_R = sys.modules.get('nornyx_forge.nornyx_runtime')\n",
        None,
        "undeclared dependency nornyx_forge.nornyx_runtime",
    ),
    (
        "the same, through a directly bound modules map",
        "src/demo_app/main.py",
        "\nfrom sys import modules\n_R = modules['nornyx_forge.nornyx_runtime']\n",
        None,
        "undeclared dependency nornyx_forge.nornyx_runtime",
    ),
    (
        "the same, through an aliased sys",
        "src/demo_app/main.py",
        "\nimport sys as _s\n_R = _s.modules['nornyx_forge.nornyx_runtime']\n",
        None,
        "undeclared dependency nornyx_forge.nornyx_runtime",
    ),
    (
        "the same, through a modules map bound by assignment",
        "src/demo_app/main.py",
        "\nimport sys\n_M = sys.modules\n_R = _M['nornyx_forge.nornyx_runtime']\n",
        None,
        "undeclared dependency nornyx_forge.nornyx_runtime",
    ),
    (
        "a key assembled at runtime, which cannot be modelled at all",
        "src/demo_app/main.py",
        "\nimport sys\n_R = sys.modules['nornyx' + '_forge.nornyx_runtime']\n",
        None,
        "imports a module named at runtime",
    ),
    (
        "persistence acquiring subprocess through sys.modules",
        "src/demo_app/store.py",
        "\nimport sys\n_R = sys.modules['subprocess']\n",
        None,
        "forbidden dependency subprocess",
    ),
    (
        "a declared-leaf domain module reaching persistence through sys.modules",
        "src/demo_app/agentic.py",
        "\nimport sys\n_R = sys.modules['demo_app.store']\n",
        None,
        "undeclared dependency demo_app.store",
    ),
    # ---- refused because UNRESOLVABLE, not because recognised ----------
    #
    # Two candidates were invalidated by this class. Each repair enumerated
    # the spellings a reviewer had just used, and each was reopened by one
    # nobody had used yet -- eleven of them the second time. The rule now
    # REFUSES the construct instead of resolving its target, so these rows
    # are not the boundary of what is caught; they are witnesses that the
    # construct rule reaches every route a review demonstrated.
    # See docs/governance/MODULE_ACQUISITION.md.
    (
        "the modules map through vars",
        "src/demo_app/main.py",
        "\nimport sys\n_R = vars(sys)['modules']['nornyx_forge.nornyx_runtime']\n",
        None,
        "obtains a module namespace",
    ),
    (
        "the modules map through getattr",
        "src/demo_app/main.py",
        "\nimport sys\n_R = getattr(sys, 'modules')['nornyx_forge.nornyx_runtime']\n",
        None,
        "obtains a module namespace",
    ),
    (
        "the modules map through __dict__",
        "src/demo_app/main.py",
        "\nimport sys\n_R = sys.__dict__['modules']['nornyx_forge.nornyx_runtime']\n",
        None,
        "obtains a module namespace",
    ),
    (
        "the modules map mutated by pop",
        "src/demo_app/main.py",
        "\nimport sys\n_R = sys.modules.pop('nornyx_forge.nornyx_runtime')\n",
        None,
        "obtains a module namespace",
    ),
    (
        "the modules map mutated by setdefault",
        "src/demo_app/main.py",
        "\nimport sys\n_R = sys.modules.setdefault('nornyx_forge.nornyx_runtime', None)\n",
        None,
        "obtains a module namespace",
    ),
    (
        "sys itself bound by assignment",
        "src/demo_app/main.py",
        "\nimport sys\n_A = sys\n_R = _A.modules['nornyx_forge.nornyx_runtime']\n",
        None,
        "obtains a module namespace",
    ),
    (
        "a copy of the modules map",
        "src/demo_app/main.py",
        "\nimport sys\n_R = dict(sys.modules)['nornyx_forge.nornyx_runtime']\n",
        None,
        "obtains a module namespace",
    ),
    (
        "the modules map through __getitem__",
        "src/demo_app/main.py",
        "\nimport sys\n_R = sys.modules.__getitem__('nornyx_forge.nornyx_runtime')\n",
        None,
        "obtains a module namespace",
    ),
    (
        "a star-import binding the modules map",
        "src/demo_app/main.py",
        "\nfrom sys import *\n_R = modules['nornyx_forge.nornyx_runtime']\n",
        None,
        "obtains a module namespace",
    ),
    (
        "persistence reaching subprocess through vars",
        "src/demo_app/store.py",
        "\nimport sys\n_R = vars(sys)['modules']['subprocess']\n",
        None,
        "obtains a module namespace",
    ),
    (
        "a domain leaf reaching persistence through getattr",
        "src/demo_app/agentic.py",
        "\nimport sys\n_R = getattr(sys, 'modules')['demo_app.store']\n",
        None,
        "obtains a module namespace",
    ),
]


@pytest.mark.parametrize(
    ("label", "target", "snippet", "extra", "expected"),
    UNDECLARED_EDGES,
    ids=[case[0] for case in UNDECLARED_EDGES],
)
def test_an_undeclared_edge_is_refused_however_it_is_spelled(
    workspace: Path, label: str, target: str, snippet: str, extra, expected: str
):
    """`undeclared_component_dependency` is REAL, over every first-party edge.

    Not a hardcoded subset: a module that does not appear in the contract at all
    is refused, which is the case a list-driven check would miss entirely. The
    alias and dynamic spellings are here because a rule that only reads
    `ast.ImportFrom` is a naming convention.
    """
    path = workspace / target
    original = path.read_bytes()
    created = None
    if extra:
        created = workspace / extra[0]
        created.write_text(extra[1], encoding="utf-8")
    path.write_bytes(original + snippet.encode("utf-8"))
    try:
        completed = _gate(workspace)
    finally:
        path.write_bytes(original)
        if created:
            created.unlink(missing_ok=True)

    assert completed.returncode != 0, f"{label} was accepted"
    assert expected in completed.stdout, (
        f"{label} was refused, but not for the reason under test:\n"
        f"{completed.stdout[-600:]}"
    )


def test_ordinary_reflection_on_ordinary_objects_is_not_refused(
    workspace: Path,
):
    """The over-reach control for the construct refusal.

    Refusing every `getattr` and every `__dict__` would satisfy every row
    above and would also refuse this repository's own governed source: it
    holds five `getattr` calls with literal names on dataclass instances and
    streams, and eight bare `instance.__dict__` uses for serialisation. The
    rule is about reaching a MODULE NAMESPACE, not about reflection, and a
    gate that could not tell the difference would be unusable rather than
    strict.
    """
    path = workspace / "src/demo_app/main.py"
    original = path.read_bytes()
    path.write_bytes(
        original
        + b"\nimport sys\n"
        + b"_WHERE = sys.executable\n"
        + b"class _Row:\n    pass\n"
        + b"_ROW = _Row()\n"
        + b"_SEEN = getattr(_ROW, 'missing', None)\n"
        + b"_FLAT = _ROW.__dict__\n"
    )
    try:
        completed = _gate(workspace)
    finally:
        path.write_bytes(original)
    assert completed.returncode == 0, (
        "ordinary reflection on ordinary objects was refused, so the rule "
        "cannot tell a namespace from an attribute lookup:\n"
        + completed.stdout[-800:]
    )


def test_binding_the_modules_map_is_itself_refused(workspace: Path):
    """THE PROPERTY CHANGED, deliberately, and this records the change.

    This test used to assert the opposite -- that `_M = sys.modules` with no
    lookup is NOT refused -- and under the rule in force then, that was
    right: the gate resolved which module an expression yielded, and a bare
    binding yields none.

    That rule was replaced after it was reopened twice, by eleven spellings
    the second time. The gate no longer resolves targets; it refuses
    constructs whose target cannot be resolved. Binding the modules map is
    acquiring the means to reach ANY module without declaring one, so under
    the new property it is a violation -- and it has to be, because every
    alias, copy, wrapper and re-export in that table of eleven begins with
    exactly this line.

    The expectation was not flipped to make an implementation pass: it now
    refuses MORE than before, and the over-reach direction is held by
    `test_ordinary_reflection_on_ordinary_objects_is_not_refused`, which
    proves ordinary `getattr` and `__dict__` on ordinary objects still pass.
    """
    path = workspace / "src/demo_app/main.py"
    original = path.read_bytes()
    planted = (
        b"\nimport sys\n_M = sys.modules\n"
    )
    path.write_bytes(original + planted)
    try:
        completed = _gate(workspace)
    finally:
        path.write_bytes(original)
    assert completed.returncode != 0, (
        "binding the modules map was accepted, so every spelling that starts "
        "by binding it is reachable again"
    )
    assert "obtains a module namespace" in completed.stdout, (
        "it was refused, but not as an unresolvable acquisition:\n"
        + completed.stdout[-600:]
    )


def test_deleting_the_undeclared_dependency_control_changes_the_verdict(
    workspace: Path, tmp_path: Path
):
    """The control is load-bearing, proven by removing it.

    Without this the tests above could all be passing because of some other
    rule, and the named control could be dead code that reads as enforcement --
    which is exactly what `ui_direct_persistence_access` turned out to be.
    """
    checker = workspace / "scripts/check_architecture.py"
    original = checker.read_text(encoding="utf-8")
    anchor = "imports first-party module"
    assert original.count(anchor) == 1, "the control moved; this mutation is stale"

    target = workspace / "src/demo_app/main.py"
    keep = target.read_bytes()
    created = workspace / "src/demo_app/brand_new.py"
    created.write_text("def thing():\n    return 1\n", encoding="utf-8")
    target.write_bytes(keep + b"\nfrom demo_app.brand_new import thing\n_T = thing\n")
    try:
        with_control = _gate(workspace)
        checker.write_text(
            original.replace(anchor, "NEVER MATCHES ANYTHING"), encoding="utf-8"
        )
        # Re-run with the diagnostic removed. The mutant must still RUN -- a
        # crash would earn no credit -- and must stop reporting this edge.
        without_control = _gate(workspace)
    finally:
        checker.write_text(original, encoding="utf-8")
        target.write_bytes(keep)
        created.unlink(missing_ok=True)

    assert with_control.returncode != 0
    assert "not declared in the architecture" in with_control.stdout
    assert "NEVER MATCHES ANYTHING" in without_control.stdout, (
        "the mutated build did not reach the control at all, so this proves "
        f"nothing about it:\n{without_control.stdout[-400:]}"
    )


def test_every_declared_component_belongs_to_a_system():
    """C2-P3-6. A component in no system is governed by nothing.

    `component.reviewer_trust` is declared with a name, layer, context and
    modules, and `docs/ARCHITECTURE.md` presents it as a first-class component
    -- while `system.forge.components` omits it. Neither
    `scripts/check_architecture.py` (which reads only `modules` and `layers`)
    nor `nornyx check` reports it, so it looked declared and was structurally
    invisible.

    Asserted in both directions: a system may not list a component that was
    never declared either, since padding the list would satisfy this check
    while governing nothing.
    """
    import re  # noqa: PLC0415

    raw = (ROOT / ".nornyx/contracts/architecture_governance.nyx").read_text(
        encoding="utf-8"
    )
    declared = set(re.findall(r"- id: (component\.[a-z_]+)", raw))
    inline = re.search(r"components: \[([^\]]+)\]", raw)
    assert inline, "system.forge declares no component list"
    listed = set(re.findall(r"component\.[a-z_]+", inline.group(1)))

    assert declared, "no components were parsed, so this check proves nothing"
    assert declared - listed == set(), (
        "these components are declared but belong to no system, so nothing "
        f"governs them: {sorted(declared - listed)}"
    )
    assert listed - declared == set(), (
        "the system lists components that are never declared: "
        f"{sorted(listed - declared)}"
    )
