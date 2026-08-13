"""Establish the runtime subject once, at startup, from a trusted root.

The boundary consumes an already-established subject. It never discovers one:
an action request must not be able to cause subject identity to be re-resolved,
or the request has a say in the authority that judges it.

Availability and authority are separate outcomes here. An application may start
with an unestablished subject and serve low-risk, read-only work; what it may
not do is release a consequential effect. That distinction is deliberate — the
container case previously fell back to an *unverified revision* and kept going,
which conflated the two.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .governed_subject import (
    INTEGRITY_UNAVAILABLE,
    REPOSITORY_SCOPE,
    GovernanceIntegrityState,
    GovernedSubjectError,
    RuntimeAuthorityConfig,
    RuntimeSubject,
    SubjectScope,
    TrustConfiguration,
    digest_of,
    revision_digest,
    subject_digest,
)
from .subject_observer import (
    observe_contract_semantics_digest,
    observe_governance_integrity,
    observe_input_manifest,
    observe_settled_contracts,
    observe_source_commit,
)

SUBJECT_MANIFEST_RELATIVE = ".nornyx/subjects/current.json"


@dataclass(frozen=True)
class RuntimeSecurityContext:
    """Everything a governed run's authority depends on, established once.

    One construction point, injected downward. The alternative — each flow or
    each request resolving its own subject and configuration — is how the trust
    store came to be re-read per boundary and how mutating a file between two
    cases could silently re-aim the second one.

    Immutable, and identity matters: flows receive *this* object, not an equal
    copy. Comparing digest strings would pass even if every flow had rebuilt its
    own context, which is the thing being prevented.

    R3 adds the approval trust store and the consumption ledger here. They are
    absent rather than stubbed, because a placeholder that later turns out to be
    consulted is worse than a field that does not exist.
    """

    runtime_subject: RuntimeSubject
    authority_config: RuntimeAuthorityConfig
    trust: TrustConfiguration
    #: Problems found comparing what the contracts RECORD about the evidence
    #: set against the artifacts themselves. Empty means intact.
    #:
    #: Derived governance state sits outside the inspection subject, which is
    #: only admissible while compromising it withdraws every authority that
    #: could depend on it. Runtime authority did not: a mutated content_hash
    #: or an upgraded status changed the Nornyx verdict, left the subject
    #: untouched, and the boundary released the effect anyway.
    governance_integrity: GovernanceIntegrityState | None = None
    #: The trusted approvers, PARSED AND FROZEN at bootstrap.
    #:
    #: `trust` carries locations, and a location is not authority. The
    #: boundary reopened the approver store on every construction -- which is
    #: per request -- so editing the file between two calls changed who the
    #: second one trusted. Measured: one context served request 1 with
    #: signer `test-approval-01` and request 2 with `attacker-key`, having
    #: been handed nothing new.
    #:
    #: Held as an object rather than re-derived, so a request cannot reach
    #: the filesystem to decide who may approve it.
    #:
    #: TWO memberships, provisioned independently. One store served both
    #: authorities, and the role vocabularies overlap on
    #: `network_governance_owner`, so trusting a key to approve governed
    #: content also trusted it -- as far as trust was concerned -- to release
    #: consequential effects. Only a role check downstream stood between those,
    #: and a control that rests on every caller remembering it is not a
    #: boundary. These are separate objects because they answer separate
    #: questions, and neither can be reached from the other.
    governance_approval_trust: object | None = None
    action_approval_trust: object | None = None

    @property
    def consequential_authority_available(self) -> bool:
        """A subject that cannot be described authorizes nothing."""
        return self.runtime_subject.subject_verified


def bootstrap_security_context(
    root: Path | None = None,
    *,
    scope: SubjectScope = REPOSITORY_SCOPE,
    config: RuntimeAuthorityConfig | None = None,
) -> RuntimeSecurityContext:
    """Establish the security context. Called once, at application startup.

    A failed observation yields a context whose subject is unavailable, not an
    exception and not a fabricated digest: the application may still start and
    serve low-risk work, while consequential authority is simply not on offer.
    Those are different outcomes and were previously conflated — the container
    fell back to an unverified revision and carried on.

    That claim now covers root resolution too. It did not: `resolve_packaged_
    root()` raises when the deployment markers are absent, so a docstring
    promising "not an exception" was describing observation failure only, and an
    unresolvable root took the application down at import instead of leaving it
    running without consequential authority. Both are failures; only one of them
    is the one this function says it produces.

    A context with no resolvable root carries no ledger location, so anything
    reaching for replay state refuses in its own vocabulary rather than being
    handed a plausible-looking path that points nowhere.
    """
    authority_config = config if config is not None else RuntimeAuthorityConfig()
    try:
        resolved = root if root is not None else resolve_packaged_root()
    except GovernedSubjectError as exc:
        return RuntimeSecurityContext(
            runtime_subject=RuntimeSubject.unavailable(str(exc), scope_id=scope.scope_id),
            authority_config=authority_config,
            trust=unrooted_trust_configuration(),
            # No root means nothing was observed. Left as None this would be
            # indistinguishable from "observed and sound", which is the
            # unknown-reads-as-intact failure the state type exists to remove.
            governance_integrity=GovernanceIntegrityState(
                status=INTEGRITY_UNAVAILABLE,
                problems=(str(exc),),
            ),
        )
    return RuntimeSecurityContext(
        runtime_subject=establish_subject(resolved, scope=scope, config=authority_config),
        authority_config=authority_config,
        trust=resolve_trust_configuration(resolved),
        governance_integrity=observe_governance_integrity(resolved / ".nornyx/contracts"),
        **_load_approval_domains(resolved),
    )



def _load_approval_domains(root: Path) -> dict[str, object]:
    """Parse BOTH approval trust domains once, here, at startup.

    One read of one document, two independent memberships. An unparseable store
    is held as a refusal rather than raised: the application may start and serve
    read-only work while consequential approval authority is simply unavailable,
    which is the same distinction the subject makes. What must not happen is
    starting up as though no store were configured, because "nobody is trusted"
    and "the trust material is broken" authorize the same amount but mean
    different things to an operator.

    A failure takes BOTH domains down together, deliberately. The failure is a
    property of the document, so keeping one domain alive would report an
    authority the operator never successfully provisioned.
    """
    from .approval_trust import (
        ACTION_TRUST_DOMAIN,
        GOVERNANCE_TRUST_DOMAIN,
        ApprovalTrustDomains,
        ApprovalTrustStore,
        TrustStoreUnavailable,
    )

    _ = root  # the store lives outside the governed tree, by design
    try:
        domains = ApprovalTrustDomains.load()
    except TrustStoreUnavailable as exc:
        return {
            "governance_approval_trust": ApprovalTrustStore(
                source=str(exc), domain=GOVERNANCE_TRUST_DOMAIN
            ),
            "action_approval_trust": ApprovalTrustStore(
                source=str(exc), domain=ACTION_TRUST_DOMAIN
            ),
        }
    return {
        "governance_approval_trust": domains.governance,
        "action_approval_trust": domains.action,
    }


def unrooted_trust_configuration() -> TrustConfiguration:
    """Trust anchors for a deployment whose root could not be resolved.

    The two stores are absolute locations that never depended on the root, so
    they are still reported honestly. The ledger is empty rather than guessed:
    a replay history is per-deployment, and inventing a path for one whose
    deployment tree is unknown would create replay state somewhere arbitrary.
    """
    from .approval_trust import trust_store_path as approver_store_path
    from .reviewer_trust import excluded_inspector_identities, reviewer_store_path

    return TrustConfiguration(
        approver_store=str(approver_store_path()),
        reviewer_store=str(reviewer_store_path()),
        approval_ledger="",
        builder_identities=excluded_inspector_identities(),
    )


def resolve_trust_configuration(root: Path) -> TrustConfiguration:
    """Read the environment once, here, and never again downstream.

    Every one of these was previously resolved at the point of use, which meant
    a variable set between two calls could re-aim the control the second call
    depended on. Reading them together at startup makes the trust anchors part
    of the established security context rather than four independent ambient
    lookups.

    Only locations are resolved. Nothing is opened, and a missing store or
    ledger is not an error here — refusal belongs to whatever tries to use it,
    where the refusal can be reported in that subsystem's own vocabulary.
    """
    from .approval_trust import trust_store_path as approver_store_path
    from .nornyx_runtime import approval_ledger_path
    from .reviewer_trust import excluded_inspector_identities, reviewer_store_path

    return TrustConfiguration(
        approver_store=str(approver_store_path()),
        reviewer_store=str(reviewer_store_path()),
        approval_ledger=str(approval_ledger_path(root)),
        builder_identities=excluded_inspector_identities(),
    )


def resolve_packaged_root() -> Path:
    """The deployment root, derived from where the application is installed.

    Structural and deterministic. The running application must not accept an
    ambient variable, the current working directory, a caller request, or any
    other mutable process state as the selector of its authority tree —
    `FORGE_ROOT` did exactly that, so an environment variable chose which tree
    the application governed.

    `Path.cwd()` is not a fix; it is the same defect wearing different clothes,
    since the launch directory is equally mutable. This walks up from the
    installed package instead: `<root>/src/nornyx_forge/subject_bootstrap.py`
    yields `<root>`, in a checkout and under `/app` alike.

    Development and test callers pass an explicit root to `establish_subject`.
    That is deliberate: an explicit argument establishes a different security
    context, which is a decision someone made rather than one the environment
    made for them.

    The relationship is fixed, not searched. Scanning ancestors for "something
    that looks like a project root" would be a heuristic authority selector —
    a different ambient mechanism reaching the same bad outcome, and one an
    attacker could steer by planting a marker higher up. Exactly one candidate
    is considered, and it must carry the expected structural markers or this
    refuses.

    This pins a packaging assumption: the image installs editable, so the
    package sits at `<root>/src/nornyx_forge/`. A switch to a wheel would move
    `__file__` into site-packages and break the fixed relationship — which is
    why the in-image scope proof has to run the real verifier inside the built
    image rather than infer deployment correctness from the Dockerfile.
    """
    candidate = Path(__file__).resolve().parents[2]
    missing = [
        marker
        for marker in ("src/nornyx_forge", "src/demo_app", ".nornyx/contracts")
        if not (candidate / marker).is_dir()
    ]
    if missing:
        raise GovernedSubjectError(
            f"PACKAGED_ROOT_UNRESOLVED: {candidate} does not carry the expected "
            f"deployment markers ({', '.join(missing)}). Refusing to guess which "
            "tree this application governs."
        )
    return candidate


def establish_subject(
    root: Path,
    *,
    scope: SubjectScope = REPOSITORY_SCOPE,
    config: RuntimeAuthorityConfig | None = None,
    contracts_dir: Path | None = None,
) -> RuntimeSubject:
    """Observe the tree and construct the subject. Fails closed.

    Any observation error yields an unavailable subject rather than a partial
    one: a subject that cannot be described is not a subject that authorizes
    less, it is one that authorizes nothing.
    """
    directory = contracts_dir if contracts_dir is not None else root / ".nornyx/contracts"
    authority_config = config if config is not None else RuntimeAuthorityConfig()
    try:
        manifest = observe_input_manifest(root, scope)
        input_digest = digest_of(manifest)
        semantics = observe_contract_semantics_digest(directory)
        settled = digest_of(observe_settled_contracts(root, directory, scope))
    except GovernedSubjectError as exc:
        return RuntimeSubject.unavailable(str(exc), scope_id=scope.scope_id)

    return RuntimeSubject(
        scope_id=scope.scope_id,
        scope_definition_digest=scope.definition_digest(),
        runtime_authority_config_digest=authority_config.digest(),
        governed_revision_digest=revision_digest(
            input_digest=input_digest, semantics_digest=semantics
        ),
        governed_subject_digest=subject_digest(
            scope=scope,
            config=authority_config,
            input_digest=input_digest,
            settled_digest=settled,
        ),
        subject_verified=True,
        # Attached after the digests are computed, so it cannot participate in
        # them even by accident.
        source_commit=observe_source_commit(root),
    )


def build_subject_manifest(
    root: Path,
    *,
    scope: SubjectScope = REPOSITORY_SCOPE,
    config: RuntimeAuthorityConfig | None = None,
    contracts_dir: Path | None = None,
) -> dict:
    """The external record of the subject. Diagnostic and packaging only.

    This file can never be the source of an approved subject digest. A runtime
    trusting it would be trusting a file inside the tree it is verifying: the
    authorization compares a *recomputed* subject against a *signed* approval,
    and this manifest participates in neither side.
    """
    directory = contracts_dir if contracts_dir is not None else root / ".nornyx/contracts"
    subject = establish_subject(
        root, scope=scope, config=config, contracts_dir=directory
    )
    if not subject.subject_verified:
        raise GovernedSubjectError(
            f"the subject could not be observed: {subject.unavailable_reason}"
        )
    manifest = observe_input_manifest(root, scope)
    return {
        "schema": "nornyx.forge.governed_subject.v1",
        # Reported, never authoritative: the scope came from code.
        "subject_scope_id": subject.scope_id,
        "scope_definition_digest": subject.scope_definition_digest,
        "runtime_authority_config_digest": subject.runtime_authority_config_digest,
        "governed_subject_digest": subject.governed_subject_digest,
        "governed_revision_digest": subject.governed_revision_digest,
        "governed_input_digest": digest_of(manifest),
        "settled_contracts_digest": digest_of(
            observe_settled_contracts(root, directory, scope)
        ),
        "entries": manifest["entries"],
        "provenance": {
            "source_commit": subject.source_commit,
            "note": (
                "Provenance only. Authority is governed_subject_digest, which the "
                "runtime recomputes; nothing here supplies it."
            ),
        },
    }
