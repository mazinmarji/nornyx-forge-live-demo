"""Read the governed subject off a filesystem. The only I/O in the chain.

Enumeration is an external observation, so it lives in an adapter rather than
in the domain value it produces. The domain hashes what it is given; this
module decides what is there.

Git is not consulted for membership. Bytes coming from the working tree was not
enough while `git ls-files --others --exclude-standard` still chose which files
belonged: `GIT_DIR`, `core.excludesFile`, a global ignore file, or a
`.gitignore` edit could each change the *domain* of the digest without changing
a byte inside it. Removing environment influence over content while leaving it
over membership would have been a claim that was only half true.

Every entry point takes an explicit root. Nothing here resolves a root from
`__file__`, so the same algorithm answers for a repository checkout and for an
installed application tree — which is what lets a container recompute its own
subject with no `.git` present.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import yaml

from .governed_subject import (
    INTEGRITY_COMPROMISED,
    INTEGRITY_INTACT,
    INTEGRITY_UNAVAILABLE,
    SETTLED_SCHEMA,
    GovernanceIntegrityState,
    GovernedSubjectError,
    SubjectEntry,
    SubjectScope,
    SubjectScopeEscape,
    SubjectScopeIncomplete,
    assert_canonical,
    contract_semantics,
    digest_bytes,
    digest_of,
    is_governed,
    is_never_governed,
    manifest_of,
    normalise_path,
)


def assert_scope_complete(root: Path, scope: SubjectScope) -> None:
    """Every declared part of the authority surface must be present.

    Checked before anything is hashed, so a missing contract or package is a
    refusal rather than a smaller subject that reports itself verified. This is
    the difference between "the complete declared surface was observed" and
    "the observer hashed whatever existed".
    """
    missing = [entry for entry in scope.required_roots if not (root / entry).is_dir()]
    missing += [entry for entry in scope.required_files if not (root / entry).is_file()]
    missing += [
        f".nornyx/contracts/{name}"
        for name in scope.required_contracts
        if not (root / ".nornyx/contracts" / name).is_file()
    ]
    if missing:
        raise SubjectScopeIncomplete(
            f"SUBJECT_SCOPE_INCOMPLETE: scope {scope.scope_id} requires "
            + ", ".join(sorted(missing))
            + " but they are not present under this root. Refusing to compute a "
            "smaller subject and call it verified."
        )


def observe_governed_paths(root: Path, scope: SubjectScope) -> list[str]:
    """Every governed file present under the scope's roots, by walking them."""
    found: set[str] = set()
    for entry in scope.enumeration_entries():
        location = root / entry
        if location.is_file():
            found.add(normalise_path(entry))
            continue
        if not location.is_dir():
            continue
        for item in location.rglob("*"):
            relative = normalise_path(item.relative_to(root).as_posix())
            if is_never_governed(relative) or not is_governed(relative):
                continue
            if scope.is_excluded(relative):
                continue
            if item.is_dir() and not item.is_symlink():
                continue
            found.add(relative)
    return sorted(found)


def assert_scope_closed(root: Path, scope: SubjectScope, covered: set[str]) -> None:
    """No authority-capable artifact may exist outside what the subject covers.

    Completeness asks "is everything declared present?". This asks the harder
    question in the other direction: "is anything authority-capable present that
    the subject does not describe?". Without it, a new runtime module could ship
    and stay invisible to authority — the same shape as a module the
    architecture contract never declared.

    The universe is structural, so a file added under a declared root is inside
    it the moment it exists; there is no second list to forget to update.
    """
    escapes: list[str] = []
    for entry in scope.authority_universe:
        location = root / entry
        if location.is_file():
            candidates = [normalise_path(entry)]
        elif location.is_dir():
            candidates = [
                normalise_path(item.relative_to(root).as_posix())
                for item in location.rglob("*")
                if item.is_file() or item.is_symlink()
            ]
        else:
            continue
        smuggled: list[str] = []
        for path in candidates:
            if is_never_governed(path) or path in covered:
                continue
            if not scope.is_authority_capable(path):
                continue
            if scope.is_non_authoritative(path):
                # An exclusion is a prefix, so it swallows whatever is placed
                # beneath it. `.nornyx/contracts/evidence` is excluded because
                # generated evidence is downstream of the subject -- a statement
                # about JSON, which silently covered `.py` as well. Dropping a
                # module there removed it from the subject with a reason written
                # about something else.
                smuggled.append(path)
                continue
            escapes.append(path)
        if smuggled:
            raise SubjectScopeEscape(
                f"SUBJECT_SCOPE_ESCAPE: scope {scope.scope_id} has "
                "authority-capable content beneath a non-authoritative "
                f"exclusion: {', '.join(sorted(set(smuggled))[:12])}. An "
                "exclusion states why particular content is downstream; it "
                "cannot make executable content downstream by sitting above it."
            )
    if escapes:
        raise SubjectScopeEscape(
            f"SUBJECT_SCOPE_ESCAPE: scope {scope.scope_id} leaves "
            f"authority-capable content outside the subject: "
            + ", ".join(sorted(set(escapes))[:12])
            + ". Cover it, or exclude it explicitly with a stated reason."
        )


def observe_input_manifest(root: Path, scope: SubjectScope) -> dict:
    """Describe every governed file the scope covers: path, size, digest."""
    assert_scope_complete(root, scope)
    entries: list[SubjectEntry] = []
    for path in observe_governed_paths(root, scope):
        location = root / path
        if location.is_symlink():
            # Never silently followed: a symlink under a governed root could
            # point outside the tree entirely, and a digest quietly describing
            # somewhere else would be worse than one that refused.
            raise GovernedSubjectError(
                f"{path} is a symlink. Governed content must be real files, or "
                "the digest describes something the tree does not contain."
            )
        if not location.exists():
            raise GovernedSubjectError(
                f"{path} is listed as governed content but is not present"
            )
        if not location.is_file():
            # A FIFO, device or socket. Reading one is not reproducible and may
            # not terminate, so the subject cannot be described and this fails
            # closed rather than hanging.
            raise GovernedSubjectError(
                f"{path} is not a regular file, so the subject cannot be "
                "described honestly."
            )
        blob = assert_canonical(path, location.read_bytes())
        entries.append(SubjectEntry(path=path, sha256=digest_bytes(blob), size=len(blob)))

    covered = {entry.path for entry in entries}
    covered |= {
        normalise_path(f".nornyx/contracts/{name}") for name in scope.required_contracts
    }
    assert_scope_closed(root, scope, covered)
    return manifest_of(entries)


def observe_contract_documents(contracts_dir: Path) -> dict[str, object]:
    """Parse each contract. Parsing is I/O-adjacent, so it happens here."""
    documents: dict[str, object] = {}
    for path in sorted(contracts_dir.glob("*.nyx")):
        try:
            documents[path.name] = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise GovernedSubjectError(
                f"{path.name} is not parseable, so its semantics cannot be described: {exc}"
            ) from exc
    return documents


def observe_contract_semantics_digest(contracts_dir: Path) -> str:
    return digest_of(contract_semantics(observe_contract_documents(contracts_dir)))


def observe_governance_integrity(contracts_dir: Path) -> GovernanceIntegrityState:
    """Every evidence digest a contract records, checked against the artifact.

    The inspection subject deliberately digests what the contracts SAY, so
    derived governance state -- an evidence record's `status`, a recorded
    `content_hash` -- sits outside it. That is only admissible while compromise
    of those fields withdraws every authority that could depend on them, and
    runtime authority was not among them: a mutated `content_hash` changed the
    Nornyx verdict, left the inspection subject untouched, and the action
    boundary released the effect and spent the approval anyway.

    Measured, before this existed:

        derived status mutated   effect=ALLOW callbacks=1 ledger_spent=True
        content_hash mutated     effect=ALLOW callbacks=1 ledger_spent=True

    So the boundary needs an integrity verdict of its own. Returns the problems
    found; empty means every recorded digest matches the artifact it names. An
    unreadable contract is a problem rather than a pass, because a runtime that
    cannot check its own governance state has not checked it.
    """
    if not contracts_dir.is_dir():
        return GovernanceIntegrityState(
            status=INTEGRITY_UNAVAILABLE,
            problems=(
                f"{contracts_dir} is not a directory, so the governance evidence "
                "this runtime would be judged under cannot be observed at all",
            ),
        )
    contracts = sorted(contracts_dir.glob("*.nyx"))
    if not contracts:
        return GovernanceIntegrityState(
            status=INTEGRITY_UNAVAILABLE,
            problems=(
                f"{contracts_dir} holds no contracts, so there is nothing to "
                "check the derived governance state against",
            ),
        )

    verified = 0
    problems: list[str] = []
    for contract in contracts:
        try:
            document = yaml.safe_load(contract.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            problems.append(f"{contract.name} could not be read: {exc}")
            continue
        for record in _evidence_records(document):
            artifact = record.get("artifact")
            recorded = record.get("content_hash")
            if not isinstance(artifact, str) or not isinstance(recorded, str):
                continue
            location = contracts_dir / artifact
            if not location.is_file():
                problems.append(
                    f"{contract.name} records evidence {artifact}, which is absent"
                )
                continue
            actual = "sha256:" + hashlib.sha256(location.read_bytes()).hexdigest()
            if actual != recorded:
                problems.append(
                    f"{contract.name} records {artifact} as {recorded}, but it "
                    f"digests to {actual}"
                )
                continue
            verified += 1
            problems.extend(_status_contradictions(contract.name, artifact, record, location))

    if problems:
        return GovernanceIntegrityState(
            status=INTEGRITY_COMPROMISED,
            verified_claims=verified,
            problems=tuple(problems),
        )
    if not verified:
        # Contracts exist but record no evidence digest at all. Nothing was
        # checked, so nothing is known -- and "nothing known" must not be
        # spelled the same way as "everything matched".
        return GovernanceIntegrityState(
            status=INTEGRITY_UNAVAILABLE,
            problems=(
                f"{contracts_dir} records no evidence digests, so the derived "
                "governance state is unverifiable rather than sound",
            ),
        )
    return GovernanceIntegrityState(status=INTEGRITY_INTACT, verified_claims=verified)


def _status_contradictions(
    contract: str, artifact: str, record: dict, location: Path
) -> list[str]:
    """A recorded verdict that its own artifact contradicts.

    The digest check above catches a tampered `content_hash` but not a flipped
    `status`, because a status is not a digest -- and a flipped status changes
    the Nornyx verdict just as surely. Measured: with `status` moved from
    `observed` to `pass`, the boundary released the effect and spent the
    approval while every digest still matched.

    A status is DERIVED. So it is checked against the derivation: an artifact
    that reports no authenticated inspection cannot be a passing independent
    review, and an artifact that reports approval was not granted cannot be a
    passing approval record. Narrow on purpose -- it asserts only what the
    artifacts actually state about themselves, rather than guessing a general
    rule from two examples.
    """
    if str(record.get("status")) != "pass":
        return []
    try:
        payload = json.loads(location.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"{contract} records {artifact} as passing, but it is unreadable: {exc}"]
    if not isinstance(payload, dict):
        return []

    found: list[str] = []
    inspections = payload.get("authenticated_inspections")
    if isinstance(inspections, dict) and not inspections:
        found.append(
            f"{contract} records {artifact} as passing, but the artifact "
            "reports no authenticated inspection"
        )
    if payload.get("approval") == "not_granted":
        found.append(
            f"{contract} records {artifact} as passing, but the artifact "
            "reports approval was not granted"
        )
    return found


def _evidence_records(document: object) -> list[dict]:
    """Every governance-evidence record in a parsed contract, at any depth.

    Walked structurally rather than read from one known key: a contract that
    grows a second evidence block would otherwise go unchecked, and the point of
    this observation is that nothing recording a digest escapes it.
    """
    found: list[dict] = []
    if isinstance(document, dict):
        for key, value in document.items():
            if key == "records" and isinstance(value, list):
                found.extend(item for item in value if isinstance(item, dict))
            else:
                found.extend(_evidence_records(value))
    elif isinstance(document, list):
        for item in document:
            found.extend(_evidence_records(item))
    return found


def observe_settled_contracts(root: Path, contracts_dir: Path, scope: SubjectScope) -> dict:
    """Every contract exactly as Nornyx will evaluate it. No projection.

    Exact canonical-LF bytes: a comment or a reformat moves this value
    unnecessarily, but nothing Nornyx treats as authoritative can silently fall
    outside it. Given that seven excluded fields were measured to change its
    verdict, that is the right way round — over-sensitivity is a nuisance,
    under-coverage is a bypass.
    """
    entries: list[SubjectEntry] = []
    # Only the contracts the scope declares. A runtime image carrying an extra
    # contract must not have it silently folded into the authority surface, and
    # a missing one is caught by assert_scope_complete rather than shrinking it.
    for name in sorted(scope.required_contracts):
        path = contracts_dir / name
        relative = normalise_path(path.relative_to(root).as_posix())
        blob = assert_canonical(relative, path.read_bytes())
        entries.append(SubjectEntry(path=relative, sha256=digest_bytes(blob), size=len(blob)))
    return manifest_of(entries, schema=SETTLED_SCHEMA)


def observe_source_commit(root: Path) -> str | None:
    """Provenance only, and deliberately isolated from subject construction.

    Nothing this returns reaches either digest. `GIT_DIR` pointing elsewhere
    yields undesirable provenance, and hardening that is worthwhile — but the
    decisive property is that it cannot move an authorization, because git has
    no path into the subject at all.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError:
        return None
    if result.returncode:
        return None
    candidate = result.stdout.strip()
    return f"git:{candidate}" if candidate else None


def contract_set_digest(contracts_dir: Path, root: Path) -> str:
    """The settled governance contracts, after synchronisation.

    A separate layer because contracts are downstream of the machine evidence
    that gets written into them, and upstream of the inspection that reviews the
    settled result.
    """
    entries = [
        {
            "path": normalise_path(str(path.relative_to(root))),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
        for path in sorted(contracts_dir.glob("*.nyx"))
    ]
    return digest_of({"schema": "nornyx.forge.contract_set.v1", "entries": entries})


#: Fields that record WHEN an artifact was written and WHICH revision it
#: describes. They are provenance, not claims about content, and the same
#: classification already governs `review_binding.json`.
#:
#: They are stripped when digesting evidence for an INSPECTION subject. An
#: inspector binds to what they reviewed; re-running the evidence tooling over
#: unchanged code and contracts rewrites `subject_revision` from the new HEAD
#: and `generated_at` from the clock, and if those reach the subject then the
#: subject moves although nothing inspectable changed -- which silently
#: re-couples content identity to commit identity, the thing A-011 retired.
#:
#: Measured: committing the attestations did not move the subject, but the next
#: regeneration did, and `subject_revision` was the difference.
PROVENANCE_KEYS = frozenset({
    "generated_at", "expires_at", "subject_revision", "source_commit",
})


def _without_provenance(value: object) -> object:
    """Recursively drop provenance keys, so what remains is the claim."""
    if isinstance(value, dict):
        return {
            key: _without_provenance(item)
            for key, item in value.items()
            if key not in PROVENANCE_KEYS
        }
    if isinstance(value, list):
        return [_without_provenance(item) for item in value]
    return value


def evidence_manifest(
    evidence_dir: Path,
    root: Path,
    *,
    exclude: tuple[str, ...] = (),
    ignore_provenance: bool = False,
) -> dict:
    """Describe the generated evidence set, separately from the content.

    Its own layer, because evidence is derived from governed content and must
    not be folded back into the digest of the thing it describes.

    ``ignore_provenance`` digests each artifact's CLAIMS rather than its bytes,
    which is what an inspection subject needs: stable across a regeneration that
    changed only when it ran and which commit it names. It is deliberately not
    the default -- the integrity manifest still covers exact bytes, so tampering
    with a recorded timestamp is still caught where that matters.
    """

    entries: list[dict[str, object]] = []
    for location in sorted(evidence_dir.glob("*.json")):
        if location.name in exclude:
            continue
        blob = location.read_bytes()
        if ignore_provenance:
            try:
                claims = _without_provenance(json.loads(blob.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                # Unreadable as JSON: digest the bytes rather than skip it, so
                # a corrupt artifact still changes the subject.
                pass
            else:
                blob = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
        entries.append(
            {
                "path": normalise_path(str(location.relative_to(root))),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
            }
        )
    entries.sort(key=lambda entry: entry["path"])
    return {"schema": "nornyx.forge.evidence_manifest.v1", "entries": entries}
