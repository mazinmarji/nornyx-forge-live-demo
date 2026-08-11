"""What a governed claim is *about*, as pure values. No I/O lives here.

Two content identities, deliberately distinct. Collapsing them is what made the
previous model unsound.

``governed_revision_digest``
    Which authored revision the generated governance state was produced from.
    Authored inputs plus contract *semantics*, with tool-written fields
    projected out. This is what gets stamped into a contract as Nornyx's
    ``subject_revision`` — a commit hash cannot serve, because a contract that
    declares the commit containing it has no fixed point.

``governed_subject_digest``
    What will actually execute, once the contracts have settled. Authored
    inputs plus the *complete* settled contract bytes, with nothing projected
    out. This is the authority an action approval signs.

The distinction was forced by measurement. An audit mutated every field the
projection excluded and re-ran Nornyx: seven of them changed its verdict —
``content_hash``, ``status``, the records list, ``subject_revision``,
``revision_binding.revision``, and both time fields pushed adversarially. A
digest omitting those cannot honestly claim to identify what will execute, so
it does not claim to. It identifies the revision that produced them, and a
second digest covers the settled result.

``governed_subject_digest`` never appears inside the content it hashes; it
lives only in an external manifest. That is the whole reason the authoritative
identifier had to leave the contract.

This module is domain: it imports nothing that touches a filesystem, a
subprocess, the environment, or a network. Observation belongs to
``subject_observer``; assembling the two belongs to ``subject_bootstrap``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

MANIFEST_SCHEMA = "nornyx.forge.governed_input_manifest.v1"
SEMANTICS_SCHEMA = "nornyx.forge.contract_semantics.v1"
SETTLED_SCHEMA = "nornyx.forge.settled_contracts.v1"
REVISION_SCHEMA = "nornyx.forge.governed_revision.v1"
SUBJECT_SCHEMA = "nornyx.forge.governed_subject.v1"
SCOPE_SCHEMA = "nornyx.forge.subject_scope.v1"
AUTHORITY_CONFIG_SCHEMA = "nornyx.forge.runtime_authority_config.v1"

#: What an assurance claim is about: the authored content an inspector reads.
#: Contracts are not here — they are covered by the two contract digests below,
#: which sit at different layers of the chain.
GOVERNED_INPUT_PATHS = (
    "src",
    "scripts",
    "tests",
    "docs",
    ".github",
    "pyproject.toml",
    "Dockerfile",
    "docker-compose.yml",
    ".dockerignore",
    ".gitignore",
    "BRD.md",
    "CLAUDE.md",
)

#: Generated or tool-written, and therefore downstream of the input digest.
EXCLUDED_PREFIXES = (".nornyx/contracts/",)

#: Never governed content, in any enumeration: artifacts of *running* the code
#: rather than the code. Declared here rather than read from `.gitignore`,
#: because an ignored file under a governed root still executes, so ignoring it
#: is not a membership decision a private local file gets to make.
NEVER_GOVERNED = ("__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache")
NEVER_GOVERNED_DIR_SUFFIXES = (".egg-info", ".dist-info")
NEVER_GOVERNED_SUFFIXES = (".pyc", ".pyo")

#: Content this repository declares canonical-LF. An explicit list, because
#: sniffing for a NUL byte would let content choose which rule applies to it.
#: Extended after CI proved the gap: `app.js`, `index.html` and `styles.css`
#: were governed content outside this list, so they were hashed raw and carried
#: CR bytes on a Windows checkout. The digest then differed from a Linux
#: checkout of the identical commit — the exact defect the canonical rule
#: exists to prevent, surviving in the files the list did not enumerate.
CANONICAL_TEXT_SUFFIXES = (
    ".py", ".pyi", ".md", ".toml", ".yml", ".yaml", ".json", ".cfg", ".ini",
    ".txt", ".sh", ".nyx", ".gitignore", ".gitattributes", ".dockerignore",
    ".js", ".mjs", ".cjs", ".ts", ".html", ".htm", ".css", ".svg", ".xml",
    ".sql", ".env", ".lock", ".rst", ".csv",
)
CANONICAL_TEXT_NAMES = ("Dockerfile", ".gitignore", ".gitattributes", "Makefile")

#: Values tooling writes into a contract, at any depth. Excluded from the
#: revision projection only — never from the settled subject, which the audit
#: proved must contain them.
GENERATED_KEYS = frozenset(
    {
        "content_hash",
        "generated_at",
        "expires_at",
        "subject_revision",
        "revision_binding",
        "scope_hash",
        "governed_subject_digest",
        "governed_revision_digest",
        "source_commit",
    }
)

#: Wholly tool-written. The authored requirement it serves is `evidence.required`,
#: which stays in the projection.
GENERATED_BLOCKS = frozenset({"governance_evidence"})


class GovernedSubjectError(RuntimeError):
    """The governed subject cannot be described honestly."""


class SubjectScopeIncomplete(GovernedSubjectError):
    """A declared part of the authority surface was not present."""


class SubjectScopeEscape(GovernedSubjectError):
    """An authority-capable artifact exists that the subject does not cover."""


@dataclass(frozen=True)
class SubjectScope:
    """The authority surface a runtime claims to cover. Code-owned and versioned.

    Without this, `subject_verified` means only "the observer hashed whatever
    happened to exist" — which is the same defect as an architecture gate that
    checks whatever happens to be declared. A container whose build silently
    dropped a contract would compute a smaller subject and report itself
    verified, because nothing said what "complete" was.

    Scope is never read from an artifact. A manifest that could declare its own
    `required_roots` would let forging the manifest shrink the subject, so the
    direction is strictly: code-owned scope -> observer -> manifest *reports*
    what was observed.

    `optional_roots` is for content genuinely incapable of altering consequential
    authorization. Anything that can change an authorization decision is
    required, or it is not in the scope at all.
    """

    scope_id: str
    required_roots: tuple[str, ...] = ()
    required_files: tuple[str, ...] = ()
    required_contracts: tuple[str, ...] = ()
    optional_roots: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()

    #: Structural roots inside which any authority-capable artifact must end up
    #: covered by the subject. Structural on purpose: a hand-maintained second
    #: list of "authority files" would let a new module be forgotten from both
    #: lists and pass — the P2-E defect wearing different clothes. A new file
    #: under one of these roots is inside the universe the moment it exists.
    authority_universe: tuple[str, ...] = ()

    #: Artifact classes treated as authority-capable within that universe. This
    #: is a stated, checkable rule, not a claim to detect authority in general.
    authority_classes: tuple[str, ...] = (".py", ".nyx")

    #: Narrowly justified non-authoritative exclusions. Each entry is a prefix
    #: and must carry a reason in `exclusion_reasons`; an exclusion without one
    #: is itself a scope defect.
    non_authoritative: tuple[str, ...] = ()
    exclusion_reasons: tuple[tuple[str, str], ...] = ()

    def is_authority_capable(self, path: str) -> bool:
        """Inside the universe, and of a class this scope treats as authority.

        Deliberately narrow and stated. This does not claim to identify every
        artifact capable of influencing behaviour; it identifies executable and
        governance-contract classes under declared roots, which is a property
        the implementation actually checks.
        """
        inside = any(
            path == root or path.startswith(root.rstrip("/") + "/")
            for root in self.authority_universe
        )
        return inside and path.endswith(self.authority_classes)

    def is_non_authoritative(self, path: str) -> bool:
        return any(
            path == item or path.startswith(item.rstrip("/") + "/")
            for item in self.non_authoritative
        )

    def canonical_definition(self) -> dict:
        """The scope's meaning, as canonical data."""
        return {
            "schema": SCOPE_SCHEMA,
            "scope_id": self.scope_id,
            "required_roots": sorted(self.required_roots),
            "required_files": sorted(self.required_files),
            "required_contracts": sorted(self.required_contracts),
            "optional_roots": sorted(self.optional_roots),
            "excluded_paths": sorted(self.excluded_paths),
            "authority_universe": sorted(self.authority_universe),
            "authority_classes": sorted(self.authority_classes),
            "non_authoritative": sorted(self.non_authoritative),
        }

    def definition_digest(self) -> str:
        """Bind what the scope *means*, not just what it is called.

        A scope id is a label, and a label can be kept while its meaning is
        quietly narrowed. Relying on the fact that shrinking a scope happens to
        move the subject — because the module declaring it is itself governed
        content — is indirect and holds only while that stays true. This makes
        the relationship direct: change what `forge.runtime-image.v1` covers and
        the authority subject changes, even if every other byte is identical.
        """
        return digest_of(self.canonical_definition())

    def enumeration_entries(self) -> tuple[str, ...]:
        return self.required_roots + self.required_files + self.optional_roots

    def is_excluded(self, path: str) -> bool:
        return any(
            path == item or path.startswith(item.rstrip("/") + "/")
            for item in self.excluded_paths
        )


#: The development surface: everything an inspector reads.
REPOSITORY_SCOPE = SubjectScope(
    scope_id="forge.repository.v1",
    # `docs` is here because a reviewer reads it. An inspection signs a subject
    # digest, and a digest that omits the documents making the claims under
    # inspection covers the code but not what the code is said to do.
    required_roots=("src", "scripts", "tests", "docs", ".github"),
    required_files=(
        "pyproject.toml",
        "Dockerfile",
        "docker-compose.yml",
        # Decides what enters the runtime image, so it is authority-relevant in
        # the most direct sense available.
        ".dockerignore",
        ".gitignore",
        "BRD.md",
        "CLAUDE.md",
    ),
    required_contracts=(
        "runtime_network.nyx",
        "architecture_governance.nyx",
        "forge_control.nyx",
    ),
    authority_universe=("src", "scripts", ".nornyx/contracts"),
    non_authoritative=(".nornyx/contracts/evidence",),
    exclusion_reasons=(
        (
            ".nornyx/contracts/evidence",
            "Generated evidence is downstream of the subject and is covered by "
            "the settled-contract digests that reference it; folding it into "
            "the input side would make the digest depend on its own output.",
        ),
    ),
)

#: What actually ships and can affect runtime governance. Deliberately smaller,
#: and deliberately *named* rather than inferred from whether `.git` exists —
#: the environment selects a scope identifier, it does not redefine what scope
#: means.
#:
#: `scripts/` is absent because the image does not carry it. That is the point:
#: the issuer-side signing utility is outside the runtime authority surface
#: because it is outside the runtime image.
RUNTIME_IMAGE_SCOPE = SubjectScope(
    scope_id="forge.runtime-image.v1",
    required_roots=("src/nornyx_forge", "src/demo_app"),
    # Everything the Dockerfile copies at the top level. `pyproject.toml` pins
    # the dependency set and declares the console entrypoint, so it decides what
    # code the image can run -- it belongs in the subject that authorises that
    # image. A review found it shipping outside the scope, along with README.md,
    # while this scope's own comment claimed that covering what ships is a fact.
    required_files=("BRD.md", "pyproject.toml", "README.md"),
    # All three, because the image copies the whole `.nornyx` tree and Model B
    # binds authority to what is actually packaged. The closure check found this
    # on its first run: two governance contracts shipped in the image while the
    # runtime subject described neither, so tampering with either would have
    # been invisible to runtime authority. Narrowing the subject to "what we
    # believe the runtime reads" would be a belief; covering what ships is a
    # fact.
    required_contracts=(
        "runtime_network.nyx",
        "architecture_governance.nyx",
        "forge_control.nyx",
    ),
    authority_universe=("src", ".nornyx/contracts"),
    non_authoritative=(".nornyx/contracts/evidence",),
    exclusion_reasons=(
        (
            ".nornyx/contracts/evidence",
            "Generated evidence, downstream of the subject.",
        ),
    ),
)

SCOPES = {scope.scope_id: scope for scope in (REPOSITORY_SCOPE, RUNTIME_IMAGE_SCOPE)}


class SubjectNoncanonicalText(GovernedSubjectError):
    """Declared text content is not canonical LF."""


#: Named governance backends. A boolean environment flag cannot express these:
#: it hides which one is running, and two different governance behaviours were
#: reachable under one identical authority identity.
POLICY_BACKENDS = ("nornyx", "deterministic_demo")
EXECUTION_BACKENDS = ("crewai", "sequential")


@dataclass(frozen=True)
class RuntimeAuthorityConfig:
    """Security-relevant runtime mode, bound into authority identity.

    The audit found two ambient booleans — `FORGE_ALLOW_POLICY_FALLBACK` and
    `FORGE_STRICT_CREWAI` — that change which governance or execution path runs
    while every governed byte stays identical. Making them immutable is not
    enough: the same packaged content under a different governance mode is not
    the same thing to approve, so the mode belongs in the subject.

    Deliberately narrow. Paths, trust-store locations, database locations,
    timestamps and general environment do not belong here — the subject must not
    become a digest of the whole process environment. Only behaviour that can
    change a governance or execution decision.
    """

    policy_backend: str = "nornyx"
    execution_backend: str = "crewai"

    def __post_init__(self) -> None:
        if self.policy_backend not in POLICY_BACKENDS:
            raise GovernedSubjectError(
                f"unknown policy backend {self.policy_backend!r}; "
                f"expected one of {POLICY_BACKENDS}"
            )
        if self.execution_backend not in EXECUTION_BACKENDS:
            raise GovernedSubjectError(
                f"unknown execution backend {self.execution_backend!r}; "
                f"expected one of {EXECUTION_BACKENDS}"
            )

    def canonical_definition(self) -> dict:
        return {
            "schema": AUTHORITY_CONFIG_SCHEMA,
            "policy_backend": self.policy_backend,
            "execution_backend": self.execution_backend,
        }

    def digest(self) -> str:
        return digest_of(self.canonical_definition())


@dataclass(frozen=True)
class SubjectEntry:
    """One governed file, as it contributes to a digest."""

    path: str
    sha256: str
    size: int

    def as_dict(self) -> dict:
        return {"path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class TrustConfiguration:
    """Where authority is anchored, fixed at the moment the process started.

    A pure value: it holds already-resolved locations and never reads them.
    Resolution is the application layer's job (`subject_bootstrap`), so this can
    be handed *down* to the domain without the domain reaching outward for it.

    The point is that these stop being questions each caller answers for itself.
    Every one of them was previously an environment read at the point of use —
    the approver store per boundary construction, the reviewer store per
    verification, the ledger per boundary, the builder identity per assurance
    derivation. Each is authority-relevant, and each was therefore re-aimable by
    anything that could set a variable between two calls.

    `builder_identities` is a set for the same reason it is a union at its
    source: ambient input may add an identity that cannot inspect, never remove
    one.
    """

    #: Locations as strings, not `Path`. This module is held to a purity
    #: constraint the architecture gate enforces — no `pathlib`, no I/O — because
    #: subject identity must be computable without touching a filesystem.
    #: Turning a location into something openable is the caller's job.
    approver_store: str
    reviewer_store: str
    approval_ledger: str
    builder_identities: frozenset[str]

    def describe(self) -> dict[str, object]:
        """Locations for evidence. Never contents, and never key material."""
        return {
            "approver_store": self.approver_store,
            "reviewer_store": self.reviewer_store,
            "approval_ledger": self.approval_ledger,
            "builder_identities": sorted(self.builder_identities),
        }


@dataclass(frozen=True)
class RuntimeSubject:
    """The established identity of what is running. Immutable for the process.

    Constructed once, through ``subject_bootstrap``, and then carried. The
    action boundary receives one; it never discovers or recomputes its own
    authority, because a boundary that re-resolves identity per request has
    reintroduced exactly the ambient state this model removes.

    No root path and no environment-derived configuration is held here: those
    are bootstrap inputs, not authority.
    """

    scope_id: str
    scope_definition_digest: str
    runtime_authority_config_digest: str
    governed_revision_digest: str
    governed_subject_digest: str
    subject_verified: bool
    #: Provenance only. Never consulted for an authorization decision, and
    #: changing it while the content is identical must change nothing.
    source_commit: str | None = None
    unavailable_reason: str | None = None

    @classmethod
    def unavailable(cls, reason: str, *, scope_id: str = "") -> RuntimeSubject:
        """A subject that cannot authorize anything, and says why."""
        return cls(
            scope_id=scope_id,
            scope_definition_digest="",
            runtime_authority_config_digest="",
            governed_revision_digest="",
            governed_subject_digest="",
            subject_verified=False,
            unavailable_reason=reason,
        )


def normalise_path(path: str) -> str:
    """A repository-relative POSIX path, or a refusal."""
    candidate = path.replace("\\", "/").strip()
    if not candidate:
        raise GovernedSubjectError("a governed path must not be empty")
    if candidate.startswith("/") or (len(candidate) > 1 and candidate[1] == ":"):
        raise GovernedSubjectError(f"governed paths must be relative: {path!r}")
    if any(part == ".." for part in candidate.split("/")):
        raise GovernedSubjectError(f"governed paths must not escape the tree: {path!r}")
    return candidate


def is_governed(path: str) -> bool:
    return not any(path.startswith(prefix) for prefix in EXCLUDED_PREFIXES)


def is_never_governed(path: str) -> bool:
    parts = path.split("/")
    if any(part in NEVER_GOVERNED for part in parts):
        return True
    if any(part.endswith(NEVER_GOVERNED_DIR_SUFFIXES) for part in parts[:-1]):
        return True
    return path.endswith(NEVER_GOVERNED_SUFFIXES)


def is_declared_text(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name in CANONICAL_TEXT_NAMES or path.endswith(CANONICAL_TEXT_SUFFIXES)


def assert_canonical(path: str, blob: bytes) -> bytes:
    """Return the bytes to hash, refusing text that is not already canonical LF.

    Silently normalising CRLF made the digest describe content the disk did not
    hold. Harmless for a Python module; not for a shell script, where line
    endings can change execution. A value whose entire purpose is to say "this
    is the content" must not hash different content than the content that runs,
    so noncanonical text is an error naming the file rather than a quiet
    substitution.
    """
    if is_declared_text(path) and b"\r" in blob:
        raise SubjectNoncanonicalText(
            f"SUBJECT_NONCANONICAL_TEXT: {path} contains CR bytes. This "
            "repository declares text content canonical-LF, and hashing it "
            "normalised would describe content the file does not hold."
        )
    return blob


def digest_of(document: dict) -> str:
    """Hash canonical JSON bytes. One serialisation, one digest."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def digest_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def manifest_of(entries: list[SubjectEntry], *, schema: str = MANIFEST_SCHEMA) -> dict:
    """A manifest of paths, sizes and digests.

    Structured rather than concatenated: hashing `A` + `BC` and `AB` + `C`
    yields identical bytes, so content moving across a file boundary would be
    invisible. Explicit paths and sizes cannot collapse that way.
    """
    if not entries:
        raise GovernedSubjectError("refusing to digest nothing")
    ordered = sorted((entry.as_dict() for entry in entries), key=lambda item: item["path"])
    return {"schema": schema, "entries": ordered}


def semantic_projection(node: object) -> object:
    """Strip generated values, structurally.

    Parsed rather than text-stripped: a comment marker or an indentation change
    must not be able to alter what the projection contains, and a regex over
    YAML would let it.
    """
    if isinstance(node, dict):
        return {
            key: semantic_projection(value)
            for key, value in sorted(node.items())
            if key not in GENERATED_KEYS and key not in GENERATED_BLOCKS
        }
    if isinstance(node, list):
        return [semantic_projection(item) for item in node]
    return node


def contract_semantics(documents: dict[str, object]) -> dict:
    """What the contracts say, with what the tooling stamped removed."""
    if not documents:
        raise GovernedSubjectError("no contracts were supplied; refusing to digest nothing")
    return {
        "schema": SEMANTICS_SCHEMA,
        "contracts": {name: semantic_projection(doc) for name, doc in sorted(documents.items())},
    }


def revision_digest(*, input_digest: str, semantics_digest: str) -> str:
    """The authored revision that produced the generated governance state."""
    return digest_of(
        {
            "schema": REVISION_SCHEMA,
            "governed_input_digest": input_digest,
            "contract_semantics_digest": semantics_digest,
        }
    )


def subject_digest(
    *,
    scope: SubjectScope,
    config: RuntimeAuthorityConfig,
    input_digest: str,
    settled_digest: str,
) -> str:
    """The complete settled state that will execute, under a named scope.

    Scope identity and scope *meaning* are both bound in: two scopes covering
    different authority surfaces must never be able to produce the same subject,
    and a scope whose definition is narrowed must move the subject even though
    its id is unchanged.
    """
    return digest_of(
        {
            "schema": SUBJECT_SCHEMA,
            "subject_scope_id": scope.scope_id,
            "scope_definition_digest": scope.definition_digest(),
            "runtime_authority_config_digest": config.digest(),
            "governed_input_digest": input_digest,
            "settled_contracts_digest": settled_digest,
        }
    )


def control_pack_digest(
    *, input_digest: str, contract_digest: str, evidence_digest: str
) -> str:
    """Digest the inputs a review covered, never the commit containing them.

    ``control_pack_commit`` was structurally impossible: the field named the
    commit carrying the file it lived in, so writing the file produced a new
    commit and the value was wrong the instant it was recorded. A digest over
    inputs has no such problem — it can be committed afterwards without
    invalidating what it says it reviewed.
    """

    return digest_of(
        {
            "schema": "nornyx.forge.control_pack.v1",
            "governed_input_digest": input_digest,
            "contract_set_digest": contract_digest,
            "evidence_manifest_digest": evidence_digest,
        }
    )


def inspection_subject_digest(
    *, input_digest: str, contract_digest: str, evidence_digest: str
) -> str:
    """Exactly what the independent inspectors reviewed.

    Not the authored inputs alone: source can be untouched while a contract has
    changed, and an inspection that only bound the source would still claim to
    cover a control pack it never saw. The subject freezes at this point, and
    anything that moves it afterwards makes the inspection stale.
    """
    return digest_of(
        {
            "schema": "nornyx.forge.inspection_subject.v1",
            "governed_input_digest": input_digest,
            "contract_set_digest": contract_digest,
            "pre_inspection_evidence_manifest_digest": evidence_digest,
        }
    )


#: The three answers an integrity observation can give. Three, not two: "I could
#: not look" is a different fact from "I looked and it is sound", and collapsing
#: them is how an absent governance surface came to read as intact.
INTEGRITY_INTACT = "intact"
INTEGRITY_COMPROMISED = "compromised"
INTEGRITY_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class GovernanceIntegrityState:
    """Whether the derived governance state matches what produced it.

    Derived governance values -- an evidence record's `status`, a recorded
    `content_hash` -- sit outside the inspection subject, because binding an
    inspection to values the tooling rewrites made authenticated inspection
    unreachable. The exclusion is admissible only while compromising those
    values withdraws every authority depending on them, so this is the state a
    consequential decision consults.

    `verified_claims` is carried deliberately. A result reporting no problems
    could mean every claim was checked and matched, or that nothing was checked
    at all, and those must not be the same value. A count of zero with status
    `intact` is refused at construction rather than left for a caller to notice.
    """

    status: str
    verified_claims: int = 0
    problems: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {
            INTEGRITY_INTACT,
            INTEGRITY_COMPROMISED,
            INTEGRITY_UNAVAILABLE,
        }:
            raise GovernedSubjectError(
                f"unknown governance integrity status {self.status!r}"
            )
        if self.status == INTEGRITY_INTACT and self.problems:
            raise GovernedSubjectError("intact integrity cannot carry problems")
        if self.status != INTEGRITY_INTACT and not self.problems:
            raise GovernedSubjectError(
                f"{self.status} integrity must say why; a refusal with no reason "
                "cannot be acted on"
            )

    @property
    def authorizes_consequential_action(self) -> bool:
        """Only `intact` does.

        Written as an allow-list of one rather than `status != compromised`:
        that spelling let `unavailable` through, which is the fail-open this
        type exists to remove.
        """
        return self.status == INTEGRITY_INTACT


# --------------------------------------------------------------------------
# What kind of authority an artifact carries
# --------------------------------------------------------------------------
#
# Every artifact that can influence a governance verdict, an assurance verdict,
# an approval state or a consequential authorization needs exactly one declared
# classification, and the classification decides which mechanism must verify it.
#
# The alternative -- an artifact-specific `if` in whichever module happened to
# read it -- is how `architecture_independent_review.json` came to be stamped
# `status: pass` in a contract while its own bytes reported no authenticated
# inspection. Nobody had written down what kind of thing it was, so nothing
# could say which check applied.

#: Authored by a human, in the inspection subject, verified by an independent
#: inspection of what it says. Changing one changes what was reviewed.
AUTHORED_SEMANTIC = "authored_semantic"

#: Signed by a principal outside this build -- a human approver, an independent
#: reviewer. Verified by signature against a trust store established at startup.
#: Never trusted for its content alone, however plausible.
AUTHENTICATED_EXTERNAL = "authenticated_external"

#: Computed by the tooling FROM authenticated external material. Outside the
#: inspection subject, because regeneration rewrites it; verified by recomputing
#: it and by `GovernanceIntegrityState`, which must be `intact` before any
#: consequential authority is available.
DERIVED_AUTHENTICATED = "derived_authenticated"

#: Computed by the tooling from content that is already covered elsewhere.
#: Carries no authority of its own: forging one changes no decision, which is a
#: claim each such artifact has to make good on behaviourally.
DERIVED_NON_AUTHORITATIVE = "derived_non_authoritative"

#: True of the moment something was written, never a claim about content.
PROVENANCE_ONLY = "provenance_only"

AUTHORITY_CLASSIFICATIONS = frozenset({
    AUTHORED_SEMANTIC,
    AUTHENTICATED_EXTERNAL,
    DERIVED_AUTHENTICATED,
    DERIVED_NON_AUTHORITATIVE,
    PROVENANCE_ONLY,
})

#: Every evidence artifact this repository produces or accepts, classified once.
#:
#: `architecture_independent_review.json` and `architecture_approval_record.json`
#: are DERIVED_AUTHENTICATED rather than authoritative in themselves: each is
#: recomputed from signed material (attestations, approval artifacts), and a
#: hand-edited verdict in either is caught by integrity observation before any
#: authority depends on it.
ARTIFACT_AUTHORITY: dict[str, str] = {
    "architecture_human_approval.json": AUTHENTICATED_EXTERNAL,
    "runtime_human_approval.json": AUTHENTICATED_EXTERNAL,
    "architecture_inspection_attestation.json": AUTHENTICATED_EXTERNAL,
    "architecture_independent_review.json": DERIVED_AUTHENTICATED,
    "architecture_approval_record.json": DERIVED_AUTHENTICATED,
    "architecture_conformance_report.json": DERIVED_NON_AUTHORITATIVE,
    "architecture_change_record.json": DERIVED_NON_AUTHORITATIVE,
    "architecture_exception_review.json": DERIVED_NON_AUTHORITATIVE,
    "runtime_network_contract_review.json": DERIVED_NON_AUTHORITATIVE,
    "architecture_evidence_manifest.json": DERIVED_NON_AUTHORITATIVE,
    "runtime_evidence_manifest.json": DERIVED_NON_AUTHORITATIVE,
    "INDEX.json": DERIVED_NON_AUTHORITATIVE,
    "review_binding.json": DERIVED_NON_AUTHORITATIVE,
}

#: Signed attestations live one directory down and are named per role, so they
#: are matched by location rather than by filename.
ATTESTATION_DIRECTORY = "attestations"


class UnclassifiedArtifact(GovernedSubjectError):
    """An artifact nobody has said what kind of authority it carries."""


def artifact_authority(name: str, *, parent: str = "") -> str:
    """The declared classification, or refuse.

    Fails closed. An artifact whose kind nobody declared cannot be verified by
    the right mechanism, and guessing from its filename or its directory is how
    a new authority-bearing file joins the evidence set unnoticed.
    """
    if parent == ATTESTATION_DIRECTORY:
        return AUTHENTICATED_EXTERNAL
    try:
        return ARTIFACT_AUTHORITY[name]
    except KeyError:
        raise UnclassifiedArtifact(
            f"{name} carries no authority classification. Every artifact that "
            "can influence a governance, assurance, approval or authorization "
            "decision must declare one, so the mechanism that verifies it is "
            "decided in the open rather than by whichever module reads it first."
        ) from None
