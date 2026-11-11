from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from .nornyx_runtime import OPERATION_REGISTRY, OPERATION_UNREGISTERED, exercised_capability
from .produced_app_manifest import (
    APPLICATION_PACKAGE,
    GENERATED_CONTRACT_PATH,
    TESTS_DIRECTORY,
)
from .requirements import RequirementsModel
from .util import digest, write_canonical_text

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.:-]+")


def _safe_id(value: str) -> str:
    cleaned = _SAFE_ID_RE.sub("-", value).strip("-")
    return cleaned or "BRD-UNSPECIFIED"


#: The contract templates, closed. Every caller names one; none is a default.
#:
#: * `certified`: the layout of a repository Forge adopts as its foundation,
#:   such as Forge's own: code in `src/`, docs in `docs/`, a validation script,
#:   and contracts in `.nornyx/contracts/`. Byte-identical to the one template
#:   Forge rendered before templates existed.
#: * `greenfield`: the layout of an application Forge produces from nothing:
#:   code in the produced-application package (`produced_app_manifest`), tests
#:   in `tests/`, and the generated contract as the authority. It names only
#:   paths a valid generated project is required to contain (A-063).
CONTRACT_TEMPLATES = ("certified", "greenfield")

_GREENFIELD_SOURCE = APPLICATION_PACKAGE + "/"
_GREENFIELD_TESTS = TESTS_DIRECTORY + "/"

#: What each template declares where the two differ: every goal's scope and
#: validation commands, and the repository context's include and authority.
_LAYOUTS: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "certified": {
        "scope": ("BRD.md", "src/", "tests/", "docs/"),
        "validation": ("python scripts/validate_repository.py", "python -m pytest -q"),
        "include": (
            "BRD.md",
            "README.md",
            "docs/**/*.md",
            "src/**/*",
            "tests/**/*",
            ".nornyx/contracts/*.nyx",
        ),
        "authority": ("BRD.md", ".nornyx/contracts/*.nyx", "tests/**/*"),
    },
    "greenfield": {
        "scope": ("BRD.md", _GREENFIELD_SOURCE, _GREENFIELD_TESTS),
        "validation": ("python -m pytest -q",),
        "include": (
            "BRD.md",
            _GREENFIELD_SOURCE + "**/*",
            _GREENFIELD_TESTS + "**/*",
            GENERATED_CONTRACT_PATH,
        ),
        "authority": ("BRD.md", GENERATED_CONTRACT_PATH, _GREENFIELD_TESTS + "**/*"),
    },
}

def _layout(template: str) -> Mapping[str, tuple[str, ...]]:
    if type(template) is not str or template not in _LAYOUTS:
        raise ValueError(
            f"contract template {template!r} is not one of {list(CONTRACT_TEMPLATES)}"
        )
    return _LAYOUTS[template]


def generate_brd_contract(root: Path, model: RequirementsModel, *, template: str) -> Path:
    """Generate a deterministic Nornyx repo-harness contract from a BRD model,
    in the named `template` (`CONTRACT_TEMPLATES`)."""
    target = root / GENERATED_CONTRACT_PATH
    write_canonical_text(target, render_brd_contract(model, template=template))
    return target


_UNBOUND_GOAL = ("Convert the exact BRD revision into a tested, architecture-conformant, "
                 "evidence-backed application.")


def _delivery_goal(model: RequirementsModel) -> str:
    """The delivery intent's goal, naming what it is bound to (A-060).

    A BRD that declares its source specification gets a goal naming both
    digests: the BRD revision the build reads (`source_digest`, of the BRD
    text) and the specification that BRD declares it came from. A BRD that
    declares none keeps the goal it always had, word for word, so no
    contract claims a binding its BRD does not state."""
    if model.specification_digest is None:
        return _UNBOUND_GOAL
    return (
        f"Convert the exact BRD revision {model.source_digest}, which declares that it "
        f"was derived from the source specification sha256:{model.specification_digest}, "
        "into a tested, architecture-conformant, evidence-backed application."
    )


def render_brd_contract(model: RequirementsModel, *, template: str) -> str:
    """The contract `generate_brd_contract` writes, as text, written nowhere.

    Pure and deterministic, so the digest a build records for its contract
    (A-049) is computed from the text it wrote rather than read back from a
    path something else could have replaced in between. `template` names the
    layout the contract describes, and has no default: a caller that names
    none is refused rather than handed one (A-063).
    """
    layout = _layout(template)

    purpose = next(
        (item.statement for item in model.requirements if item.id == "BRD-001"),
        "Deliver the BRD through governed AI-assisted software engineering.",
    )
    goals = []
    for item in model.requirements:
        goals.append(
            {
                "id": _safe_id(item.id),
                "title": item.title,
                "phase": "brd-delivery",
                "goal": item.statement,
                "scope": list(layout["scope"]),
                "non_goals": [
                    "production_deployment",
                    "automatic_human_approval",
                ],
                "validation": list(layout["validation"]),
                "evidence": ".nornyx/runs/",
                "approval": (
                    "autonomous demonstration acceptance only; "
                    "human production approval is not granted"
                ),
                "stop_rules": [
                    "stop_on_secret_exposure",
                    "stop_on_unresolved_security_or_license_risk",
                    "stop_after_three_failed_repairs",
                ],
            }
        )

    contract = {
        "nornyx": "0.2",
        "project": {
            "name": "GeneratedBRDDeliveryContract",
            "profile": "agentic_repo_harness",
            "purpose": purpose,
        },
        "intents": [
            {
                "name": "DeliverBRD",
                "goal": _delivery_goal(model),
            }
        ],
        "contexts": [
            {
                "name": "GeneratedRepoContext",
                "include": list(layout["include"]),
                "exclude": [
                    ".env",
                    "secrets/**",
                    ".venv/**",
                    ".nornyx/runs/**",
                ],
                "authority": list(layout["authority"]),
                "budget": {
                    "max_tokens": 100000,
                    "reserve_output_tokens": 8000,
                },
            }
        ],
        "agents": [
            {
                "name": "RequirementsAnalyst",
                "role": "Normalize BRD requirements and acceptance criteria.",
                "policy": "GeneratedSafeDelivery",
            },
            {
                "name": "SolutionArchitect",
                "role": "Design bounded components and architecture constraints.",
                "policy": "GeneratedSafeDelivery",
            },
            {
                "name": "ApplicationBuilder",
                "role": "Implement bounded goals with tests.",
                "policy": "GeneratedSafeDelivery",
            },
            {
                "name": "IndependentReviewer",
                "role": "Inspect tests, architecture, security, and evidence without editing.",
                "policy": "GeneratedIndependentReview",
            },
        ],
        "skills": [
            {
                "name": "RequirementsDesign",
                "purpose": "Convert BRD statements into traceable goals.",
                "input": ["BRD"],
                "output": ["RequirementsModel"],
            },
            {
                "name": "PatchBuild",
                "purpose": "Implement one bounded goal with tests.",
                "input": ["Goal", "Architecture"],
                "output": ["Patch"],
            },
            {
                "name": "IndependentInspection",
                "purpose": "Inspect implementation and evidence independently.",
                "input": ["Patch", "TestReport", "ArchitectureReport"],
                "output": ["ReviewReport"],
            },
        ],
        "policies": [
            {
                "name": "GeneratedSafeDelivery",
                "deny": [
                    "secrets_to_llm",
                    "production_write_without_approval",
                    "policy_weakening_for_green_build",
                    "destructive_command",
                ],
                "require": [
                    "tests_if_code_changed",
                    "architecture_evidence_if_boundary_changed",
                    "evidence_if_goal_completed",
                ],
            },
            {
                "name": "GeneratedIndependentReview",
                "deny": [
                    "reviewer_modifies_patch",
                    "autonomous_production_approval",
                ],
                "require": [
                    "risk_check",
                    "evidence_check",
                    "architecture_check",
                    "test_check",
                ],
            },
        ],
        "harnesses": [
            {
                "name": "GeneratedDevelopmentHarness",
                "context": "GeneratedRepoContext",
                "flow": [
                    {"agent": "RequirementsAnalyst", "action": "normalize"},
                    {"agent": "SolutionArchitect", "action": "design"},
                    {"agent": "ApplicationBuilder", "action": "implement"},
                    {"tool": "tests", "action": "run"},
                    {"tool": "architecture", "action": "check"},
                    {"agent": "IndependentReviewer", "action": "review"},
                    {"tool": "evidence", "action": "pack"},
                ],
                "gates": [
                    "tests.pass",
                    "architecture.pass",
                    "security.pass",
                    "evidence.exists",
                ],
            }
        ],
        "evidence": {
            "required": [
                "requirements/requirements.json",
                "requirements/traceability.md",
                "runs/build-summary.json",
                "runs/build-evidence-report.json",
            ]
        },
        "goals": goals,
        "budgets": [
            {
                "name": "GeneratedDeliveryBudget",
                "max_tokens": 100000,
                "max_tool_calls": 80,
                "max_runtime_minutes": 90,
            }
        ],
    }
    return yaml.safe_dump(contract, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# The runtime operation contract (A-053)
#
# WHAT IT IS. A closed table of the operations a produced application may be
# asked to perform, each with the consequence it carries, the risk of that
# consequence, the capability it exercises, the BRD requirement it serves and
# what the application's embedded boundary does with it. An operation the
# table does not list is refused.
#
# DECLARED, NEVER INFERRED. An operation enters the table only because a caller
# DECLARED it for a requirement, by its exact registered spelling, and every
# field the table holds about it comes from `nornyx_runtime.OPERATION_REGISTRY`
# (A-047). Nothing here reads a requirement's title or statement: deciding a
# consequence from the words of a row is the defect class A-047 repaired, and
# a row whose prose says "delete" or "send" declares nothing. A declared
# operation the registry does not define is refused, never guessed at.
#
# WHAT THE SHIPPED BUILD DECLARES: nothing. No confirmed field carries an
# operation declaration yet, so the development flow renders the empty table
# -- every operation refused -- and binds its digest. Declarations reach this
# renderer only from a caller that passes them, which today is Forge's own
# test specimen.
#
# NO APPROVAL MECHANISM EXISTS for a produced application, so every operation
# whose registered capability needs a human approval is refused by the
# boundary, and the two consequences named in `ALWAYS_REFUSED_CONSEQUENCES`
# are refused whatever the table says about them.
# ---------------------------------------------------------------------------

RUNTIME_CONTRACT_SCHEMA = "nornyx.forge.runtime_contract.v1"
RUNTIME_CONTRACT_PATH = ".nornyx/generated/runtime-contract.json"
#: The registry an operation is classified against, named in the contract.
OPERATION_REGISTRY_NAME = "nornyx_forge.nornyx_runtime.OPERATION_REGISTRY"
#: Refused by the boundary whatever the table says: no approval mechanism
#: exists for a produced application, so neither can ever be released.
ALWAYS_REFUSED_CONSEQUENCES = ("destructive_bulk_deletion", "external_transmission")
PERMITTED = "permitted"
REFUSED_NO_APPROVAL = "refused_no_approval_mechanism"
UNLISTED_OPERATION = "refused"
_LOW_RISK_CAPABILITY = "execute_low_risk_action"
_TOP_KEYS = frozenset({
    "always_refused_consequences", "brd", "operation_registry", "operations",
    "schema", "unlisted_operation",
})
_ENTRY_KEYS = frozenset({
    "capability", "consequence", "disposition", "operation", "requirement", "risk",
})


class RuntimeContractRefused(ValueError):
    """A declaration or a contract the runtime operation contract refuses."""


def operation_registry_digest() -> str:
    """The digest of the registry a contract was classified against.

    A contract carries it, so a contract rendered against another registry --
    one where an operation's consequence or risk differed -- no longer
    validates.
    """
    return digest([
        [entry.operation, entry.consequence, entry.risk, entry.capability]
        for _name, entry in sorted(OPERATION_REGISTRY.items())
    ])


def _shown(value: object) -> str:
    shown = repr(value)
    return shown if len(shown) <= 120 else shown[:117] + "..."


def _disposition(consequence: str, capability: str) -> str:
    if consequence in ALWAYS_REFUSED_CONSEQUENCES or capability != _LOW_RISK_CAPABILITY:
        return REFUSED_NO_APPROVAL
    return PERMITTED


def _operation_entry(operation: object, requirement: object, served: set[str]) -> dict[str, str]:
    # EXACTLY `str`, as `classify_operation` requires: a subclass can redefine
    # equality and hashing and so match a registered key it does not spell.
    if type(operation) is not str or operation not in OPERATION_REGISTRY:
        raise RuntimeContractRefused(
            f"{OPERATION_UNREGISTERED}: declared operation {_shown(operation)} is not a "
            f"registered operation; the registered operations are "
            f"{sorted(OPERATION_REGISTRY)}. An unregistered operation is refused, "
            "never classified from its words."
        )
    if type(requirement) is not str or requirement not in served:
        raise RuntimeContractRefused(
            f"declared operation {operation!r} names requirement {_shown(requirement)}, "
            f"which is not a requirement of this BRD; its requirements are {sorted(served)}"
        )
    registered = OPERATION_REGISTRY[operation]
    if exercised_capability(registered.risk) != registered.capability:
        raise RuntimeContractRefused(
            f"registered operation {operation!r} names a capability its risk does not exercise"
        )
    return {
        "operation": registered.operation,
        "consequence": registered.consequence,
        "risk": registered.risk,
        "capability": registered.capability,
        "requirement": requirement,
        "disposition": _disposition(registered.consequence, registered.capability),
    }


def render_runtime_contract(
    model: RequirementsModel, declarations: Mapping[str, str] | None = None
) -> str:
    """The runtime operation contract, as text, written nowhere.

    `declarations` maps each declared operation, by its exact registered
    spelling, to the identifier of the BRD requirement it serves. Pure and
    deterministic: the same model and declarations always give the same
    bytes, so the digest a build records is computed from this text rather
    than read back from a path. Raises `RuntimeContractRefused` for an
    unregistered operation, a requirement the BRD does not have, or
    declarations that are not a mapping.
    """
    if declarations is None:
        declarations = {}
    if not isinstance(declarations, Mapping):
        raise RuntimeContractRefused(
            f"operation declarations must be a mapping, not {type(declarations).__name__}"
        )
    served = {item.id for item in model.requirements}
    operations = sorted(
        (_operation_entry(operation, requirement, served)
         for operation, requirement in declarations.items()),
        key=lambda entry: entry["operation"],
    )
    contract = {
        "schema": RUNTIME_CONTRACT_SCHEMA,
        "brd": {"source": model.source, "source_digest": model.source_digest},
        "operation_registry": {
            "name": OPERATION_REGISTRY_NAME,
            "digest": operation_registry_digest(),
        },
        "unlisted_operation": UNLISTED_OPERATION,
        "always_refused_consequences": list(ALWAYS_REFUSED_CONSEQUENCES),
        "operations": operations,
    }
    return json.dumps(contract, indent=2, sort_keys=True) + "\n"


def generate_runtime_contract(
    root: Path, model: RequirementsModel, declarations: Mapping[str, str] | None = None
) -> Path:
    """Write `render_runtime_contract`'s text to `RUNTIME_CONTRACT_PATH`, LF only."""
    target = root / RUNTIME_CONTRACT_PATH
    write_canonical_text(target, render_runtime_contract(model, declarations))
    return target


def _refuse_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeContractRefused(f"runtime contract repeats the key {key!r}")
        result[key] = value
    return result


def _refuse_constant(name: str) -> Any:
    raise RuntimeContractRefused(f"runtime contract holds the non-JSON constant {name}")


def validate_runtime_contract(text: object, model: RequirementsModel) -> dict[str, Any]:
    """Accept a runtime contract only if it is exactly what Forge renders.

    The declarations are read back from the contract's own entries and the
    contract is rendered again from them and the model; anything but the same
    text is refused. So no field is accepted unchecked: every consequence,
    risk, capability and disposition is re-derived from the registry, the BRD
    binding from the model, and the registry binding from the registry, and
    an extra, missing, reordered or reformatted field changes the text.
    Returns the parsed contract.
    """
    if type(text) is not str:
        raise RuntimeContractRefused("runtime contract is not text")
    try:
        data = json.loads(
            text, object_pairs_hook=_refuse_duplicate_keys, parse_constant=_refuse_constant
        )
    except json.JSONDecodeError as exc:
        raise RuntimeContractRefused(f"runtime contract is not JSON: {exc}") from exc
    if not isinstance(data, dict) or set(data) != _TOP_KEYS:
        raise RuntimeContractRefused(
            f"runtime contract must hold exactly the keys {sorted(_TOP_KEYS)}"
        )
    entries = data["operations"]
    if not isinstance(entries, list):
        raise RuntimeContractRefused("runtime contract operations are not a list")
    declarations: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
            raise RuntimeContractRefused(
                f"runtime contract operation must hold exactly the keys {sorted(_ENTRY_KEYS)}"
            )
        operation = entry["operation"]
        if type(operation) is not str or operation in declarations:
            raise RuntimeContractRefused(
                f"runtime contract lists operation {_shown(operation)} more than once "
                "or not as text"
            )
        declarations[operation] = entry["requirement"]
    if render_runtime_contract(model, declarations) != text:
        raise RuntimeContractRefused(
            "runtime contract is not the contract Forge renders for this BRD and these "
            "declarations: a field differs from the registry, the BRD or the canonical form"
        )
    return data
