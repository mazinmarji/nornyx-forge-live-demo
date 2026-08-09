"""One canonical answer to "what content is this claim about?".

Evidence used to bind to a git revision, and freshness was checked by asking
whether that revision was an *ancestor* of HEAD. Ancestry is a fact about
history, not about content: every commit is an ancestor of infinitely many
futures, so the check passed for a binding one commit stale and one twenty
commits stale alike. Evidence at HEAD claimed to describe `git:75c32e33` while
`src/`, `tests/` and `.github/` had all changed since, and no gate could see it.

The primitive here is content. A manifest of every governed file with its size
and digest, canonically serialised and hashed:

    governed source + contracts + configuration
                    |
                    v
            governed content manifest
                    |
                    v
            governed_content_digest

A git SHA remains useful and is retained — as provenance, navigation, historical
identity. It is not an integrity proof, and nothing here treats it as one.

WHY A MANIFEST RATHER THAN CONCATENATED BYTES. Hashing a concatenation is
ambiguous: files `A` + `BC` and `AB` + `C` produce identical bytes and therefore
identical digests, so a change that moved content across a file boundary would
be invisible. Hashing a structure with explicit paths and sizes cannot collapse
that way.

WHAT IS DELIBERATELY EXCLUDED. Generated evidence. It is *derived from* the
content this digest describes, so including it would make the digest depend on
its own consequences. The layers stay acyclic:

    content -> content digest -> evidence -> evidence digest -> review binding

and never content -> evidence -> binding -> content.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MANIFEST_SCHEMA = "nornyx.forge.governed_content_manifest.v1"

#: What an assurance claim is *about*: the things a human authors and a reviewer
#: reads. Contracts are included — an edited contract must invalidate evidence
#: describing it.
GOVERNED_CONTENT_PATHS = (
    "src",
    "scripts",
    "tests",
    ".github",
    ".nornyx/contracts",
    "pyproject.toml",
    "Dockerfile",
    "docker-compose.yml",
    ".gitignore",
    "BRD.md",
)

#: Excluded because it is generated *from* the governed content. Including it
#: would make the digest depend on artifacts derived from itself.
EXCLUDED_PREFIXES = (".nornyx/contracts/evidence/",)


class GovernedContentError(RuntimeError):
    """The governed content cannot be described honestly."""


def _git_lines(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise GovernedContentError(
            f"git {' '.join(args)} failed: {result.stderr.strip()}"
        )
    return [line for line in result.stdout.splitlines() if line.strip()]


def _normalise(path: str) -> str:
    """A repository-relative POSIX path, or a refusal.

    Path text reaches a digest that assurance claims are anchored to, so the
    rules are stated rather than assumed: no absolute paths, no parent
    references, no platform-dependent separators.
    """
    candidate = path.replace("\\", "/").strip()
    if not candidate:
        raise GovernedContentError("a governed path must not be empty")
    if candidate.startswith("/") or (len(candidate) > 1 and candidate[1] == ":"):
        raise GovernedContentError(f"governed paths must be relative: {path!r}")
    parts = candidate.split("/")
    if any(part == ".." for part in parts):
        raise GovernedContentError(f"governed paths must not escape the tree: {path!r}")
    return candidate


def _is_governed(path: str) -> bool:
    return not any(path.startswith(prefix) for prefix in EXCLUDED_PREFIXES)


def governed_content_manifest() -> dict:
    """Describe every governed file: path, size, digest. Deterministically.

    Tracked files only, so an untracked scratch file cannot silently change what
    an assurance claim is about — the dirty-tree gate is what refuses those, and
    it says so explicitly rather than folding them into a digest.
    """

    entries: list[dict[str, object]] = []
    for raw in _git_lines("ls-files", "--", *GOVERNED_CONTENT_PATHS):
        path = _normalise(raw)
        if not _is_governed(path):
            continue
        location = ROOT / path
        if location.is_symlink():
            # Never silently followed: a symlink under a governed path could
            # point outside the tree entirely, and a digest that quietly
            # described somewhere else would be worse than one that refused.
            raise GovernedContentError(
                f"{path} is a symlink. Governed content must be real files, or "
                "the digest describes something the repository does not contain."
            )
        if not location.is_file():
            # Tracked but absent. A missing governed file is a change, and must
            # move the digest rather than be skipped.
            raise GovernedContentError(
                f"{path} is tracked as governed content but is not present"
            )
        blob = location.read_bytes()
        entries.append(
            {
                "path": path,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
            }
        )

    if not entries:
        raise GovernedContentError("no governed content was found; refusing to digest nothing")

    entries.sort(key=lambda entry: entry["path"])
    return {"schema": MANIFEST_SCHEMA, "entries": entries}


def digest_of(document: dict) -> str:
    """Hash canonical JSON bytes. One serialisation, one digest."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def governed_content_digest() -> str:
    """The integrity primitive every assurance claim binds to."""
    return digest_of(governed_content_manifest())


def evidence_manifest(evidence_dir: Path, *, exclude: tuple[str, ...] = ()) -> dict:
    """Describe the generated evidence set, separately from the content.

    Its own layer, because evidence is derived from governed content and must
    not be folded back into the digest of the thing it describes.
    """

    entries: list[dict[str, object]] = []
    for location in sorted(evidence_dir.glob("*.json")):
        if location.name in exclude:
            continue
        blob = location.read_bytes()
        entries.append(
            {
                "path": _normalise(str(location.relative_to(ROOT))),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
            }
        )
    entries.sort(key=lambda entry: entry["path"])
    return {"schema": "nornyx.forge.evidence_manifest.v1", "entries": entries}


def control_pack_digest(
    *, content_digest: str, evidence_digest: str, contract_digests: dict[str, str]
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
            "governed_content_digest": content_digest,
            "evidence_manifest_digest": evidence_digest,
            "contracts": dict(sorted(contract_digests.items())),
        }
    )


def source_commit() -> str | None:
    """Provenance only. Never an integrity proof, and never a freshness check."""
    try:
        return "git:" + _git_lines("rev-parse", "HEAD")[0]
    except (GovernedContentError, IndexError):
        return None
