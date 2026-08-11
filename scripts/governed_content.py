"""Invocation shim. The authority primitives live in the package, not here.

Subject identity moved into `nornyx_forge` because the runtime is its primary
consumer, and the runtime cannot import from `scripts/` without `sys.path`
manipulation in production code and a dependency edge into a directory the
architecture gate does not model. Both are the species of ambient wiring this
work exists to remove.

Nothing is *defined* here: no digest, no governed-root list, no enumeration.
A second implementation is a second thing to drift, and the divergence would be
invisible precisely because each would look correct in isolation. The functions
below only bind an explicit root to the packaged implementation, and a test
asserts this file adds no definitions of its own.

`scripts/` is an invocation surface. It is not where authority semantics live.
"""

from __future__ import annotations

from pathlib import Path

from nornyx_forge.governed_subject import (  # noqa: F401
    EXCLUDED_PREFIXES,
    GENERATED_BLOCKS,
    GENERATED_KEYS,
    GOVERNED_INPUT_PATHS,
    MANIFEST_SCHEMA,
    REPOSITORY_SCOPE,
    SETTLED_SCHEMA,
    SUBJECT_SCHEMA,
    GovernedSubjectError,
    RuntimeSubject,
    SubjectEntry,
    assert_canonical,
    contract_semantics,
    control_pack_digest,
    digest_of,
    inspection_subject_digest,
    is_declared_text,
    manifest_of,
    revision_digest,
    subject_digest,
)
from nornyx_forge.governed_subject import (
    normalise_path as _normalise,  # noqa: F401
)
from nornyx_forge.subject_bootstrap import (  # noqa: F401
    build_subject_manifest as _build_subject_manifest,
)
from nornyx_forge.subject_bootstrap import (
    establish_subject as _establish_subject,
)
from nornyx_forge.subject_observer import (  # noqa: F401
    contract_set_digest as _contract_set_digest,
)
from nornyx_forge.subject_observer import (
    evidence_manifest as _evidence_manifest,
)
from nornyx_forge.subject_observer import (
    observe_contract_semantics_digest,
    observe_governed_paths,
    observe_input_manifest,
    observe_settled_contracts,
    observe_source_commit,
)

#: The repository root, for callers that predate explicit roots. New code should
#: pass one: the same observation has to answer for a checkout and for an
#: installed application tree, and a root derived from `__file__` cannot.
ROOT = Path(__file__).resolve().parents[1]

#: The name this module used to raise under.
GovernedContentError = GovernedSubjectError


def _contracts(contracts_dir: Path | None) -> Path:
    return contracts_dir if contracts_dir is not None else ROOT / ".nornyx/contracts"


def governed_paths() -> list[str]:
    return observe_governed_paths(ROOT, REPOSITORY_SCOPE)


def governed_input_manifest() -> dict:
    return observe_input_manifest(ROOT, REPOSITORY_SCOPE)


def governed_input_digest() -> str:
    return digest_of(observe_input_manifest(ROOT, REPOSITORY_SCOPE))


def contract_semantics_digest(contracts_dir: Path | None = None) -> str:
    return observe_contract_semantics_digest(_contracts(contracts_dir))


def settled_contract_manifest(contracts_dir: Path | None = None) -> dict:
    return observe_settled_contracts(ROOT, _contracts(contracts_dir), REPOSITORY_SCOPE)


def governed_revision_digest(contracts_dir: Path | None = None) -> str:
    return _establish_subject(
        ROOT, contracts_dir=_contracts(contracts_dir)
    ).governed_revision_digest


def governed_subject_digest(contracts_dir: Path | None = None) -> str:
    return _establish_subject(
        ROOT, contracts_dir=_contracts(contracts_dir)
    ).governed_subject_digest


def build_subject_manifest(contracts_dir: Path | None = None) -> dict:
    return _build_subject_manifest(ROOT, contracts_dir=_contracts(contracts_dir))


def source_commit() -> str | None:
    return observe_source_commit(ROOT)


def contract_set_digest(contracts_dir: Path | None = None) -> str:
    return _contract_set_digest(_contracts(contracts_dir), ROOT)


def evidence_manifest(
    evidence_dir: Path,
    *,
    exclude: tuple[str, ...] = (),
    ignore_provenance: bool = False,
) -> dict:
    return _evidence_manifest(
        evidence_dir, ROOT, exclude=exclude, ignore_provenance=ignore_provenance
    )
