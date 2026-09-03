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
"""

from __future__ import annotations

import json
import subprocess
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
    """One capsule, one directory, one git history."""

    def __init__(self, root: Path):
        self.root = Path(root)

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
        return self.revision()

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
    "CapsuleStore",
    "CapsuleStoreError",
    "CapsuleTamperError",
    "CapsuleValidationError",
]
