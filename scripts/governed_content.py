"""One canonical answer to "what content is this claim about?".

Evidence used to bind to a git revision, and freshness was checked by asking
whether that revision was an *ancestor* of HEAD. Ancestry is a fact about
history, not about content: every commit is an ancestor of infinitely many
futures, so the check passed for a binding one commit stale and one twenty
commits stale alike. Evidence at HEAD claimed to describe `git:75c32e33` while
`src/`, `tests/` and `.github/` had all changed since, and no gate could see it.

The primitive here is content. A manifest of every governed file with its size
and digest, canonically serialised and hashed:

    authored inputs: src, scripts, tests, .github, BRD, config
                    |
                    v
            governed_input_digest
                    |
                    v
            machine evidence (each artifact records the input digest)
                    |
                    v
            contracts settle -> contract_set_digest
                    |
                    v
            inspection_subject_digest   <- what inspectors reviewed
                    |
                    v
            independent inspection -> attestation
                    |
                    v
            final evidence_manifest_digest
                    |
                    v
            control_pack_digest -> review_binding
                    |
                    v
            --verify derives integrity_state and assurance_state

Each layer is downstream of the one above it. No object hashes itself, and no
upstream digest contains anything generated below it.

A git SHA remains useful and is retained — as provenance, navigation, historical
identity. It is not an integrity proof, and nothing here treats it as one.

WHY A MANIFEST RATHER THAN CONCATENATED BYTES. Hashing a concatenation is
ambiguous: files `A` + `BC` and `AB` + `C` produce identical bytes and therefore
identical digests, so a change that moved content across a file boundary would
be invisible. Hashing a structure with explicit paths and sizes cannot collapse
that way.

WHAT IS DELIBERATELY EXCLUDED. Generated evidence *and* the .nyx contracts. Both
are partly written by this tool from the other, so including either would make
the digest depend on its own consequences. Contracts are covered one layer up,
by ``control_pack_digest``. The layers stay acyclic:

    content -> content digest -> evidence -> evidence digest -> review binding

and never content -> evidence -> binding -> content.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MANIFEST_SCHEMA = "nornyx.forge.governed_input_manifest.v1"

#: What an assurance claim is *about*: the authored content an inspector reads.
#:
#: Contracts are deliberately NOT here, and neither is evidence. Both are partly
#: written by this tool from the other — sync writes evidence hashes into
#: contracts — so including either would make the digest depend on artifacts
#: derived from itself. Concretely there is no fixed point: build stamps the
#: artifacts, sync then rewrites the contracts, and the artifacts describe a
#: tree that no longer exists no matter how many times you run it.
#:
#: Contracts are covered instead by ``control_pack_digest``, which the review
#: binding carries and verification recomputes. An edited contract still fails —
#: through the layer that can actually see it.
GOVERNED_INPUT_PATHS = (
    "src",
    "scripts",
    "tests",
    ".github",
    "pyproject.toml",
    "Dockerfile",
    "docker-compose.yml",
    ".gitignore",
    "BRD.md",
)

#: Generated or tool-written, and therefore downstream of the digest.
EXCLUDED_PREFIXES = (".nornyx/contracts/",)


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


def _staged_contents(paths: list[str]) -> dict[str, bytes]:
    """Governed content as git stores it, which is what any checkout contains.

    Read from the index rather than the working tree, because the two can differ
    in bytes while git still calls the tree clean. `.gitattributes` normalises
    this repository to LF, so a Windows editor that writes CRLF leaves a working
    copy whose bytes no checkout will ever hold — and `git status` stays silent,
    because it compares normalised content.

    Hashing the working copy therefore produced evidence describing content that
    did not exist anywhere, and it failed on a Linux runner every time while
    verifying cleanly on the machine that generated it. Reading the index makes
    the digest identical on every platform and equal to what a reviewer fetches.
    """
    if not paths:
        return {}

    request = b"".join(b":" + path.encode("utf-8") + b"\n" for path in paths)
    result = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "--batch"],
        input=request,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise GovernedContentError(
            f"git cat-file failed: {result.stderr.decode('utf-8', 'replace').strip()}"
        )

    contents: dict[str, bytes] = {}
    stream = result.stdout
    offset = 0
    for path in paths:
        end = stream.find(b"\n", offset)
        if end < 0:
            raise GovernedContentError(f"git cat-file gave no record for {path}")
        header = stream[offset:end].decode("utf-8", "replace").split()
        offset = end + 1
        if len(header) < 3 or header[1] != "blob":
            raise GovernedContentError(
                f"{path} is tracked as governed content but the index holds no "
                f"blob for it ({' '.join(header)})"
            )
        size = int(header[2])
        contents[path] = stream[offset : offset + size]
        offset += size + 1  # the record's trailing newline
    return contents


def governed_input_manifest() -> dict:
    """Describe every governed file: path, size, digest. Deterministically.

    Tracked files only, so an untracked scratch file cannot silently change what
    an assurance claim is about — the dirty-tree gate is what refuses those, and
    it says so explicitly rather than folding them into a digest.
    """

    governed = [
        path
        for path in (_normalise(raw) for raw in _git_lines("ls-files", "--", *GOVERNED_INPUT_PATHS))
        if _is_governed(path)
    ]
    staged = _staged_contents(governed)

    entries: list[dict[str, object]] = []
    for path in governed:
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
        blob = staged[path]
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


def governed_input_digest() -> str:
    """The upstream authored inputs: what a human wrote, before any tooling ran.

    Named for what it is. It was `governed_content_digest`, which misled: the
    .nyx contracts are unquestionably governed content, they are simply not
    *upstream authored inputs* — this tool writes evidence hashes into them.
    They are covered by :func:`contract_set_digest`, one layer down the chain.
    """
    return digest_of(governed_input_manifest())


def contract_set_digest(contracts_dir: Path) -> str:
    """The settled governance contracts, after synchronisation.

    A separate layer because contracts are downstream of the machine evidence
    that gets written into them, and upstream of the inspection that reviews the
    settled result.
    """
    entries = [
        {
            "path": _normalise(str(path.relative_to(ROOT))),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
        for path in sorted(contracts_dir.glob("*.nyx"))
    ]
    return digest_of({"schema": "nornyx.forge.contract_set.v1", "entries": entries})


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


def source_commit() -> str | None:
    """Provenance only. Never an integrity proof, and never a freshness check."""
    try:
        return "git:" + _git_lines("rev-parse", "HEAD")[0]
    except (GovernedContentError, IndexError):
        return None
