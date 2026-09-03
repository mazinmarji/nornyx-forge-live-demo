"""Git-backed persistence for the Project Capsule. An adapter, and says so.

WHY GIT, AND WHY HERE. The capsule needs revision binding -- every accepted
mutation identifiable, ordered, and diffable -- and this repository's whole
evidence discipline already runs on exactly that property. Reimplementing a
versioned store would re-derive git at consumer-bug prices, so the store IS a
git repository that Forge manages and the user never sees: git is an
implementation detail of persistence, not a concept the basic-user experience
exposes.

Running git is process execution, so this module is `layer.adapter` under
`constraint.bounded_external_adapter`, keeping the declared list of
process-starting places complete. The domain module (`capsule`) stays pure; it
cannot reach a filesystem or a process, which is what makes its authority
split revert-provable in isolation.

WHAT THE STORE REFUSES TO DO. It never interprets capsule content: nothing
here evaluates, imports, executes, or renders a value from the document. Load
parses JSON, validates the schema, and verifies the digest chain -- fail closed
on all three. A capsule is data about a project; the day some component wants
to treat part of it as instructions, that component must argue for itself in
review, because no path in this adapter will do it quietly.

git IDENTITY. Commits are authored as `forge-capsule <capsule@forge.invalid>`
with `-c` overrides so the store never reads or writes the user's git config.
The capsule directory gets its own repository; the store refuses to operate at
the root of an EXISTING repository it did not initialize, so a capsule can
never silently commit into a project's own history.

THE SEAL, and why in-document integrity is not enough. The store lives under
the basic-user project directory, and the build hands that directory to an
untrusted engineering provider as a writable workspace (Claude with Edit,
Write and Bash; Codex under a workspace-write sandbox). Both digest chains are
one link deep -- a writer who knows the algorithm rewrites a state and
recomputes the final link -- and the store's own git repository is inside the
same workspace, so a committed forgery leaves a clean tree at a new commit.
Measured at 47bd370: a worker's forged READY was rendered by /api/state,
persisted, and survived a restart. So the store keeps a SEAL: after each of
its own commits it records the revision and the exact bytes of the authority
files in a directory OUTSIDE the project (Forge's own, beside the reviewer
trust store), and every load first checks the store against that seal --
revision, working tree, and file bytes -- before trusting anything on disk.
A store that does not match its seal is `CapsuleSealError`, a tamper finding
that carries the sealed snapshot so the caller can restore it. The seal is
Forge-owned persistence; it is not the provider's file and not the provider's
repository. WHAT IT DOES NOT ESTABLISH: the Codex sandbox cannot write outside
its workspace, so the seal is out of its reach; a Claude worker with Bash runs
as the same operating-system user and can reach the seal directory. Within the
current local trust boundary (A-015) that is the bound, and it is stated here
rather than implied away.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .capsule import (
    CapsuleError,
    CapsuleTamperError,
    CapsuleValidationError,
    canonical_json,
    validate_document,
    verify_integrity,
)
from .experience import validate_experience, verify_experience

_CAPSULE_FILE = "capsule.json"
_EXPERIENCE_FILE = "experience.json"
#: The files that ARE the store's authority, in the order the seal records
#: them. Nothing else in the directory is authority; anything else present is
#: unexpected and fails the seal check.
_AUTHORITY_FILES = (_CAPSULE_FILE, _EXPERIENCE_FILE)
_SEAL_SCHEMA = "nornyx.forge.capsule_seal.v1"
#: Where Forge keeps every store's seal when nothing more specific is given:
#: outside every project, in Forge's own place beside the reviewer trust
#: store (the `reviewer_trust.DEFAULT_REVIEWER_STORE` precedent). Callers
#: pass it explicitly; the store never reaches for it on its own.
DEFAULT_SEAL_DIR = Path.home() / ".nornyx" / "forge" / "seals"
#: Written once at initialize; its presence marks a directory as a capsule
#: store THIS adapter created. Loading without it is refused, which is the
#: mechanism behind "never adopt a repository we did not initialize".
_MARKER_FILE = ".forge-capsule"

_GIT_IDENTITY = [
    "-c", "user.name=forge-capsule",
    "-c", "user.email=capsule@forge.invalid",
    "-c", "commit.gpgsign=false",
]


class CapsuleStoreError(CapsuleError):
    """The store cannot satisfy the request. Nothing was partially written."""


@dataclass(frozen=True)
class AuthoritySnapshot:
    """The store's authority as Forge last wrote it: the revision and the exact
    bytes of each authority file (`None` when the file did not exist)."""

    revision: str
    files: Mapping[str, str | None]

    def as_dict(self) -> dict[str, Any]:
        return {"revision": self.revision, "files": dict(self.files)}


class CapsuleSealUnreadable(CapsuleTamperError):
    """The seal file exists and is not a seal this adapter wrote for this
    store: unreadable, another schema, or another store's. The anchor is
    damaged, so nothing on disk can be held to it -- a tamper finding with
    nothing to restore from."""


class CapsuleSealError(CapsuleTamperError):
    """The store does not match Forge's seal: something other than this
    adapter wrote it, or committed to it, since Forge's last save. Carries the
    sealed snapshot so a caller may restore the trusted state, and the
    problems so the finding is legible."""

    def __init__(self, problems: list[str], snapshot: AuthoritySnapshot) -> None:
        super().__init__(
            "the authority store does not match Forge's seal; it was written outside "
            "this adapter and is not trusted: " + "; ".join(problems)
        )
        self.problems = problems
        self.snapshot = snapshot


def _remove_tree(path: Path) -> None:
    """Remove a directory git owns. Git marks its object files read-only, and
    on Windows `rmtree` refuses those unless the bit is cleared first."""
    def _clear_and_retry(function, target, _exc_info):
        os.chmod(target, 0o600)
        function(target)

    shutil.rmtree(path, onerror=_clear_and_retry)


def _run_git(root: Path, *args: str) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        ["git", *_GIT_IDENTITY, *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise CapsuleStoreError(
            f"git {' '.join(args[:2])} failed: {completed.stderr.strip()[:300]}"
        )
    return completed


class CapsuleStore:
    """One capsule, one directory, one git history, one seal."""

    def __init__(self, root: Path, seal_dir: Path | None = None):
        self.root = Path(root)
        #: Where Forge keeps this store's seal: OUTSIDE the project directory,
        #: named by the store's resolved path. `None` means an unsealed store,
        #: which the domain tests use; the application always passes one.
        self.seal_dir = Path(seal_dir) if seal_dir is not None else None

    # -- creation ----------------------------------------------------------
    def initialize(
        self,
        document: Mapping[str, Any],
        experience: Mapping[str, Any] | None = None,
    ) -> str:
        """Create the store and write the first revision.

        Refuses a directory that already contains a git repository or a
        capsule: initialization is a once-only act, and re-initializing over
        history would be exactly the silent rewrite the store exists to make
        impossible.

        An `experience` given here lands in the SAME first commit as the
        capsule. A project and its lifecycle are two persistent facts, and
        writing them as two commits would leave a state in which the first
        existed and the second did not -- a project that looked created and
        had no recorded workflow. One commit holds both or neither; both are
        validated and verified at the door before anything is written,
        exactly as `save` and `save_experience` do for later revisions.
        """
        validate_document(document)
        verify_integrity(document)
        if experience is not None:
            validate_experience(experience)
            verify_experience(experience)
        if (self.root / ".git").exists():
            raise CapsuleStoreError(
                f"{self.root} already contains a git repository; the store "
                "does not adopt histories it did not create"
            )
        if (self.root / _CAPSULE_FILE).exists():
            raise CapsuleStoreError(f"{self.root} already contains a capsule")
        self.root.mkdir(parents=True, exist_ok=True)
        _run_git(self.root, "init", "--quiet", "--initial-branch=main")
        (self.root / _MARKER_FILE).write_text(
            "Forge capsule store. Managed by nornyx_forge.capsule_store; "
            "not a user-facing repository.\n",
            encoding="utf-8",
            newline="",
        )
        self._write_document(document)
        if experience is not None:
            self._write_experience(experience)
        _run_git(self.root, "add", "-A")
        _run_git(self.root, "commit", "--quiet", "-m", "capsule: initialize")
        self.seal()
        return self.revision()

    # -- reading -----------------------------------------------------------
    def load(self) -> dict[str, Any]:
        """Parse, validate, verify -- in that order, each failing closed.

        The order is deliberate: a file that is not JSON is CORRUPT, a JSON
        document that breaks the schema is INVALID, and a valid document whose
        authoritative region disagrees with its chain is TAMPERED. Three
        different findings for three different incidents; collapsing them
        would hide the gravest inside the mildest.
        """
        self.assert_sealed()
        marker = self.root / _MARKER_FILE
        if not marker.exists():
            raise CapsuleStoreError(
                f"{self.root} is not a capsule store this adapter initialized"
            )
        path = self.root / _CAPSULE_FILE
        if not path.exists():
            raise CapsuleStoreError(f"{self.root} contains no capsule document")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapsuleStoreError(f"capsule document is unreadable: {exc}") from exc
        validate_document(document)      # CapsuleValidationError on breach
        verify_integrity(document)       # CapsuleTamperError on breach
        return document

    # -- writing -----------------------------------------------------------
    def save(self, document: Mapping[str, Any], message: str) -> str:
        """Persist an already-validated transition as one commit.

        Validation runs again here rather than being trusted from the caller:
        the store is the last gate before disk, and a transition function with
        a defect must not be able to persist its mistake. Returns the new
        revision.
        """
        if not isinstance(message, str) or not message.strip() or len(message) > 200:
            raise CapsuleStoreError("a save needs a one-line reason under 200 chars")
        validate_document(document)
        verify_integrity(document)
        if not (self.root / _MARKER_FILE).exists():
            raise CapsuleStoreError(
                f"{self.root} is not a capsule store this adapter initialized"
            )
        self._write_document(document)
        _run_git(self.root, "add", "-A")
        status = _run_git(self.root, "status", "--porcelain")
        if not status.stdout.strip():
            raise CapsuleStoreError(
                "save was asked to persist a document identical to the current "
                "revision; a no-op commit would fabricate history"
            )
        _run_git(self.root, "commit", "--quiet", "-m", f"capsule: {message.strip()}")
        self.seal()
        return self.revision()

    # -- history -----------------------------------------------------------
    def revision(self) -> str:
        return _run_git(self.root, "rev-parse", "HEAD").stdout.strip()

    def revisions(self) -> list[str]:
        """All revisions, oldest first."""
        out = _run_git(self.root, "rev-list", "--reverse", "HEAD").stdout
        return [line.strip() for line in out.splitlines() if line.strip()]

    # -- experience state --------------------------------------------------
    def load_experience(self) -> dict[str, Any]:
        """The workflow position, with the same three-way failure split as the
        capsule: unreadable is CORRUPT, schema-breaking is INVALID, and a
        chain mismatch is TAMPERED -- a forged READY must surface as the
        gravest of the three, not blur into the mildest."""
        self.assert_sealed()
        if not (self.root / _MARKER_FILE).exists():
            raise CapsuleStoreError(
                f"{self.root} is not a capsule store this adapter initialized"
            )
        path = self.root / _EXPERIENCE_FILE
        if not path.exists():
            raise CapsuleStoreError(f"{self.root} contains no experience state")
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapsuleStoreError(f"experience state is unreadable: {exc}") from exc
        validate_experience(state)
        verify_experience(state)
        return state

    def save_experience(self, state: Mapping[str, Any], message: str) -> str:
        """Persist one workflow transition as one commit, same refusals as
        `save`: re-validated at the door, no-op commits refused, and only into
        a store this adapter initialized."""
        if not isinstance(message, str) or not message.strip() or len(message) > 200:
            raise CapsuleStoreError("a save needs a one-line reason under 200 chars")
        validate_experience(state)
        verify_experience(state)
        if not (self.root / _MARKER_FILE).exists():
            raise CapsuleStoreError(
                f"{self.root} is not a capsule store this adapter initialized"
            )
        self._write_experience(state)
        _run_git(self.root, "add", "-A")
        status = _run_git(self.root, "status", "--porcelain")
        if not status.stdout.strip():
            raise CapsuleStoreError(
                "save_experience was asked to persist a state identical to the "
                "current revision; a no-op commit would fabricate history"
            )
        _run_git(self.root, "commit", "--quiet", "-m", f"experience: {message.strip()}")
        self.seal()
        return self.revision()

    # -- the seal ------------------------------------------------------------
    def seal_path(self) -> Path | None:
        if self.seal_dir is None:
            return None
        ident = hashlib.sha256(str(self.root.resolve()).encode("utf-8")).hexdigest()[:24]
        return self.seal_dir / f"{ident}.json"

    def snapshot(self) -> AuthoritySnapshot:
        """The authority as it stands on disk right now: HEAD and file bytes."""
        files: dict[str, str | None] = {}
        for name in _AUTHORITY_FILES:
            path = self.root / name
            files[name] = path.read_text(encoding="utf-8") if path.exists() else None
        return AuthoritySnapshot(revision=self.revision(), files=files)

    def seal(self) -> AuthoritySnapshot | None:
        """Record the store's authority as Forge just wrote it. Called after
        every commit this adapter makes, and nowhere else."""
        path = self.seal_path()
        snapshot = self.snapshot()
        if path is None:
            return None
        record = {"schema": _SEAL_SCHEMA, "store": str(self.root.resolve()), **snapshot.as_dict()}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Written whole, then moved into place: a seal is never half a seal.
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(canonical_json(record) + "\n", encoding="utf-8", newline="")
            os.replace(tmp, path)
        except OSError as exc:
            raise CapsuleStoreError(
                f"the authority seal could not be written to {path}: {exc}; the store's "
                "newest commit stands unsealed and will read as a breach until resealed"
            ) from exc
        return snapshot

    def sealed(self) -> AuthoritySnapshot | None:
        """Forge's seal for this store, or None when no seal was ever written
        (a store from before sealing existed, or a domain-test store)."""
        path = self.seal_path()
        if path is None or not path.exists():
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapsuleSealUnreadable(
                f"the authority seal at {path} is unreadable: {exc}; the store cannot be "
                "held to its anchor"
            ) from exc
        if (
            not isinstance(record, dict)
            or record.get("schema") != _SEAL_SCHEMA
            or not isinstance(record.get("revision"), str)
            or not isinstance(record.get("files"), dict)
            or set(record["files"]) != set(_AUTHORITY_FILES)
        ):
            raise CapsuleSealUnreadable(
                f"the authority seal at {path} is not a seal this adapter wrote"
            )
        if record.get("store") != str(self.root.resolve()):
            raise CapsuleSealUnreadable(
                f"the authority seal at {path} names another store "
                f"({str(record.get('store'))[:80]}); it does not anchor this one"
            )
        return AuthoritySnapshot(revision=record["revision"], files=dict(record["files"]))

    def seal_problems(self, snapshot: AuthoritySnapshot) -> list[str]:
        """Every way the store on disk differs from the snapshot: the revision,
        the working tree (a dirty tree, an extra file), and each authority
        file's exact bytes. A clean tree at a different commit is a
        difference; a matching commit with different bytes is a difference."""
        problems: list[str] = []
        if not (self.root / ".git").exists():
            problems.append("the store's git repository is gone")
        else:
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=str(self.root),
                capture_output=True, text=True, check=False,
            )
            if head.returncode != 0:
                problems.append("the store's git repository cannot name HEAD")
            elif head.stdout.strip() != snapshot.revision:
                problems.append(
                    f"HEAD is {head.stdout.strip()[:12]}, sealed revision is "
                    f"{snapshot.revision[:12]}"
                )
            status = subprocess.run(
                ["git", "status", "--porcelain"], cwd=str(self.root),
                capture_output=True, text=True, check=False,
            )
            if status.returncode != 0:
                problems.append("the store's working tree cannot be read")
            elif status.stdout.strip():
                problems.append("the working tree is not clean: " + status.stdout.strip()[:120])
        if not (self.root / _MARKER_FILE).exists():
            problems.append("the store marker is missing")
        for name, sealed_text in snapshot.files.items():
            path = self.root / name
            current = path.read_text(encoding="utf-8") if path.exists() else None
            if current != sealed_text:
                problems.append(f"{name} differs from the sealed bytes")
        return problems

    def assert_sealed(self) -> None:
        """Refuse a store that does not match its seal. No seal: nothing to
        hold it to, and the caller's `sealed()` says so."""
        snapshot = self.sealed()
        if snapshot is None:
            return
        problems = self.seal_problems(snapshot)
        if problems:
            raise CapsuleSealError(problems, snapshot)

    def restore(self, snapshot: AuthoritySnapshot) -> tuple[str, list[str]]:
        """Put the store back to the sealed authority. Returns the revision
        the store now stands at and the notes of what it took.

        First the honest route: reset the repository to the sealed revision
        and remove everything the seal does not know. If the repository
        itself was destroyed or replaced so that revision cannot be reached,
        the repository is rebuilt around the sealed bytes -- the history is
        lost and the note says so, but the AUTHORITY is exactly what Forge
        last wrote, which is the property the seal exists for.
        """
        notes: list[str] = []
        try:
            reset = subprocess.run(
                ["git", *_GIT_IDENTITY, "reset", "--hard", "--quiet", snapshot.revision],
                cwd=str(self.root), capture_output=True, text=True, check=False,
            )
            if reset.returncode == 0:
                subprocess.run(
                    ["git", "clean", "-fdxq"], cwd=str(self.root),
                    capture_output=True, text=True, check=False,
                )
            if reset.returncode != 0 or self.seal_problems(snapshot):
                notes.append("the sealed revision could not be restored from the store's own "
                             "history; the repository was rebuilt around the sealed bytes")
                self._rebuild(snapshot)
        except OSError as exc:
            raise CapsuleStoreError(
                f"the sealed authority could not be restored: {type(exc).__name__}: {exc}"
            ) from exc
        self.seal()
        return self.revision(), notes

    def _rebuild(self, snapshot: AuthoritySnapshot) -> None:
        """A fresh repository around the sealed bytes. Whatever the worker left
        in the store directory -- a `.git` directory, a `.git` FILE, a junction,
        stray files -- is removed by shape, not by assumption."""
        self.root.mkdir(parents=True, exist_ok=True)
        for entry in list(self.root.iterdir()):
            if entry.name in (_MARKER_FILE, *_AUTHORITY_FILES):
                continue
            if entry.is_dir() and not entry.is_symlink():
                _remove_tree(entry)
            else:
                entry.unlink(missing_ok=True)
        _run_git(self.root, "init", "--quiet", "--initial-branch=main")
        (self.root / _MARKER_FILE).write_text(
            "Forge capsule store. Managed by nornyx_forge.capsule_store; "
            "not a user-facing repository.\n",
            encoding="utf-8", newline="",
        )
        for name, text in snapshot.files.items():
            path = self.root / name
            if text is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(text, encoding="utf-8", newline="")
        _run_git(self.root, "add", "-A")
        _run_git(self.root, "commit", "--quiet", "-m", "capsule: authority restored from seal")

    # -- internals ---------------------------------------------------------
    def _write_document(self, document: Mapping[str, Any]) -> None:
        # Canonical bytes on disk, so the git history diffs content rather
        # than formatting, and two saves of equal documents are detectably
        # equal (see the no-op refusal in `save`).
        (self.root / _CAPSULE_FILE).write_text(
            canonical_json(document) + "\n", encoding="utf-8", newline=""
        )

    def _write_experience(self, state: Mapping[str, Any]) -> None:
        (self.root / _EXPERIENCE_FILE).write_text(
            canonical_json(state) + "\n", encoding="utf-8", newline=""
        )


__all__ = [
    "DEFAULT_SEAL_DIR",
    "AuthoritySnapshot",
    "CapsuleSealError",
    "CapsuleSealUnreadable",
    "CapsuleStore",
    "CapsuleStoreError",
    "CapsuleTamperError",
    "CapsuleValidationError",
]
