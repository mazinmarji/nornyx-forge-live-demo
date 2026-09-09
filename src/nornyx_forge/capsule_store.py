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
repository. WHAT IT DOES AND DOES NOT ESTABLISH, now measured rather than
assumed. A Claude worker with Bash still runs as the same operating-system
user and can reach the seal directory; nothing about that changed. Codex is
no longer the same case: PA-01 measured its Windows sandbox through the CLI's
own entry point, with no model deciding whether the attempt was made, and it
REFUSED every write to the real seal directory -- including through a
junction planted inside the workspace and proved live first. On Windows the
seal is genuinely outside that provider's filesystem reach. It is still not
enough for admission, for a reason no seal can address: the same measurement
found loopback egress unconfined, and Forge's onboarding surface is an
unauthenticated loopback surface whose routes move authority, so a provider
that cannot rewrite the seal can still ask Forge to change its own mind
through the front door. Within the current local trust boundary (A-015) that
is the bound, and it is stated here rather than implied away; it is why
neither provider is eligible for the governed build (the Provider Contract's
decision). A store that was ever sealed also carries a
committed marker naming its seal, so a protected store whose seal is gone is
refused rather than mistaken for a store from before sealing existed; only a
store with neither marker nor seal is the legacy case, reported unsealed. The
marker sits inside the store and so inside any provider's workspace; it is
trustworthy because the governed path executes no provider (the Provider
Contract's eligibility decision), not the other way round, and a wholesale
rollback of the store carries the marker back with it -- it is not a
freshness mechanism. That basis is `MARKER_TRUST_BASIS` below, whose exact
value is `no_provider_executes_on_the_governed_path`: a value rather than a
paragraph, so a promotion has something to collide with. What the interlock
in `test_the_marker_trust_basis_cannot_survive_an_eligible_provider` does is
narrower than "a test objects the day any provider becomes eligible", and
round 2 measured the difference: it objects to a promotion made while this
value still reads that literal, and the value is separately pinned so it
cannot be quietly retired in advance. It licenses nothing, and it records a
human decision rather than establishing anything about the marker. Forge's
own RESTORATION was itself the cheapest way to remove the marker, and that
is now closed: `_rebuild` used to wipe the marker BEFORE it corrected the
authority bytes, so a death in that instant left the worker's forgery on
disk with the marker gone -- `protected()` False, and a later load reading
that forgery as a legacy store. The rebuild below writes the marker FIRST,
then the sealed bytes, and wipes afterwards, so no instant of it holds
forged authority under an absent marker. The seal establishes what Forge
last wrote, not that it is the LATEST thing Forge wrote: an actor who can
replace the store, marker and seal together with an earlier consistent set
is not detected, so the surface reports the seal's currency as not
independently anchored, and monotonic external anchoring is deferred rather
than claimed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
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
#: Committed into the store the first time Forge seals it, naming the seal.
#: Its presence is what tells a later load that this store REQUIRES a seal:
#: a protected store with no seal is a refusal, a store with neither is
#: legacy. Written before the commit it travels with, so the tree stays clean.
_SEAL_MARKER_FILE = ".forge-seal"
_SEAL_MARKER_SCHEMA = "nornyx.forge.capsule_seal_marker.v1"
#: Where Forge keeps every store's seal when nothing more specific is given:
#: outside every project, in Forge's own place beside the reviewer trust
#: store (the `reviewer_trust.DEFAULT_REVIEWER_STORE` precedent). Callers
#: pass it explicitly; the store never reaches for it on its own.
DEFAULT_SEAL_DIR = Path.home() / ".nornyx" / "forge" / "seals"
#: Written once at initialize; its presence marks a directory as a capsule
#: store THIS adapter created. Loading without it is refused, which is the
#: mechanism behind "never adopt a repository we did not initialize".
_MARKER_FILE = ".forge-capsule"

#: WHY THE SEAL MARKER CAN BE TRUSTED WHERE IT SITS, as a value.
#:
#: The marker lives inside the store and so inside any provider's workspace.
#: A protected store reads as legacy only when the marker AND the seal are
#: both gone, and the seal is outside every workspace -- so the precondition
#: for that fall-open is a same-operating-system-user write, exactly what an
#: unconfined provider holds. What makes the marker trustworthy at this
#: baseline is therefore not its location: it is that NO PROVIDER EXECUTES ON
#: THE GOVERNED PATH AT ALL, the Provider Contract's own eligibility decision
#: (`PROVIDER_CONFINEMENT` establishes nothing, so nothing is eligible).
#:
#: A-022 states that basis in prose and says a later slice making any provider
#: eligible must revisit it or silently reopen R2. A request that a human
#: remember is not a control, so the basis is written here where a test can
#: read it: `test_the_marker_trust_basis_cannot_survive_an_eligible_provider`
#: is an implication -- if any provider is eligible, this value may no longer
#: be this literal. It RECORDS a human decision as a code change; it does not
#: make one, and changing it establishes nothing on its own.
MARKER_TRUST_BASIS = "no_provider_executes_on_the_governed_path"

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


class CapsuleSealMissing(CapsuleTamperError):
    """The store carries Forge's seal marker and its seal is gone. It was
    protected; nothing on disk can now be held to what Forge last wrote, and
    no authority is inferred from it. Not restorable: there is nothing to
    restore from."""


class CapsuleSealError(CapsuleTamperError):
    """The store does not match Forge's seal. Carries the sealed snapshot so a
    caller may restore the trusted state, and the problems so the finding is
    legible.

    WHAT IT SAYS IS WHAT IT MEASURED. This message used to read "it was
    written outside this adapter and is not trusted", which is a CLAIM ABOUT
    AN ACTOR and is not what the seal check observes. The seal compares a
    revision, a working tree and file bytes; the difference is the finding,
    and the difference has an innocent cause this adapter can produce
    ITSELF -- `save` commits and then seals, so a process that dies between
    the two leaves Forge's own newest commit failing its own seal. Measured:
    the refusal named an external writer for a Forge crash, and the human
    restore route wrote that attribution into permanent lifecycle history.
    Untrusted is correct and the refusal stands; the author is not measured
    and is no longer named. Nothing here reads git metadata to soften the
    verdict either -- author, committer and parentage are all forgeable by a
    writer inside the store, so they may describe and may never license.
    """

    def __init__(self, problems: list[str], snapshot: AuthoritySnapshot) -> None:
        super().__init__(
            "the authority store does not match Forge's seal and is not trusted; "
            "what Forge measured: " + "; ".join(problems)
        )
        self.problems = problems
        self.snapshot = snapshot


def _is_junction(path: Path) -> bool:
    """A directory-shaped NTFS reparse point that `is_symlink()` reports False.

    `os.path.isjunction` is 3.12+ and `requires-python` allows 3.10, so the
    older interpreters read the reparse tag directly. Non-Windows has no
    `st_reparse_tag` and no junctions: False.
    """
    checker = getattr(os.path, "isjunction", None)
    if checker is not None:
        return bool(checker(path))
    try:
        return os.lstat(path).st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
    except (AttributeError, OSError, ValueError):
        return False


def _remove_tree(path: Path) -> None:
    """Remove a directory git owns. Git marks its object files read-only, and
    on Windows `rmtree` refuses those unless the bit is cleared first.

    A JUNCTION IS NOT A TREE TO WALK, and this used to remove NOTHING while
    reporting success. Measured on 3.12.10: `rmtree` refuses a junction with
    `OSError: Cannot call rmtree on a symbolic link`, and it reports that
    refusal by calling the handler with its own CHECK, `os.path.islink` --
    not a removal. `_clear_and_retry` re-ran the check, the check answered
    False, and `rmtree` returned having deleted nothing and raised nothing.
    So `_rebuild`'s wipe, whose docstring names a junction among the shapes
    it removes, silently left one standing; and `_write_fresh` inherited a
    removal that no-ops. `os.rmdir` removes the LINK and leaves the target
    untouched -- measured, target contents intact -- which is what removing a
    junction by shape means. Handled first, before `rmtree` is reached.
    """
    if _is_junction(path):
        os.rmdir(path)
        return

    def _clear_and_retry(function, target, _exc):
        os.chmod(target, 0o600)
        function(target)

    # `onerror` is deprecated in 3.12 and removed in 3.14; `onexc` arrived in
    # 3.12 and takes the exception rather than an `exc_info` triple. The
    # handler ignores that argument, so one body serves both spellings.
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_clear_and_retry)
    else:
        shutil.rmtree(path, onerror=_clear_and_retry)


def _replace_fresh(tmp: Path, path: Path) -> None:
    """`os.replace(tmp, path)`, retried once with the read-only bit cleared.

    Measured on Windows: a destination carrying `attrib +R` denies the rename
    with `PermissionError [WinError 5]`, exactly as it denied the unlink this
    replaced. One `attrib +R` on `.forge-seal` -- a command the same-user
    writer A-015 concedes can run -- would otherwise disable the product's
    human recovery route permanently. Clearing the bit is the remedy
    `_remove_tree` already applies to git's read-only objects.

    GUARDED ON `st_nlink`, because `os.chmod` through one name of a hardlink
    clears the bit on EVERY name -- measured: a read-only file outside the
    store became writable through a link planted inside it. A name the store
    does not solely own is left alone and the refusal stands. A held handle
    raises the same WinError 5 and no chmod can help it; A-022 records that
    residue, which lasts only as long as the handle.
    """
    try:
        os.replace(tmp, path)
        return
    except PermissionError:
        try:
            sole_owner = path.is_file() and not path.is_symlink() \
                and os.stat(path).st_nlink == 1
        except OSError:
            sole_owner = False
        if not sole_owner:
            raise
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        os.replace(tmp, path)


#: How many random bytes `_write_fresh` puts in the temp name it writes before
#: moving it onto its destination. ONE constant, because `_tree_changes` below
#: has to recognise the names this writer actually produces and the two must
#: not drift apart in silence. Pinned in both directions by
#: `test_the_cleanliness_exemption_matches_a_name_the_writer_really_produces`,
#: which builds a name with `_fresh_tmp_path` and asserts the matcher takes it.
_FRESH_TMP_RANDOM_BYTES = 8
_FRESH_TMP_NAME = re.compile(
    r"\.[0-9a-f]{" + str(_FRESH_TMP_RANDOM_BYTES * 2) + r"}\.tmp\Z"
)


def _fresh_tmp_path(path: Path) -> Path:
    """The sibling `_write_fresh` writes whole before moving it onto `path`."""
    return path.with_name(f"{path.name}.{os.urandom(_FRESH_TMP_RANDOM_BYTES).hex()}.tmp")


def _tree_changes(porcelain: str) -> list[str]:
    """The `git status --porcelain` lines that are a finding about the store.

    ONE NAME SHAPE IS EXEMPT, and only when UNTRACKED: a sibling in the store
    root whose name ends in Forge's own temp suffix. `_write_fresh` writes a
    finished file to that name and renames it, and a death between those two
    statements leaves the name behind -- a survivor no `finally` can take,
    exactly as `seal()`'s `.json.tmp` cannot be taken. Measured: one such
    stray made EVERY later load fail, `seal_problems` reporting "the working
    tree is not clean: ?? .forge-seal.<hex>.tmp" and the surface reporting
    TAMPERED, against a store nobody had touched, because of Forge's own
    crash. Fail-closed and repairable, but a tamper finding manufactured by
    the product about itself, and the human restore it invites costs the
    lifecycle a transition.

    THE EXEMPTION IS NOT A CLAIM THAT THE FILE IS FORGE'S. The name is the
    only evidence and any writer in the store can forge a name, so what this
    says is narrower and is all that is needed: an UNTRACKED file bearing that
    suffix is not BY ITSELF a tamper finding. It can smuggle no authority,
    because nothing in this module ever reads the store by pattern -- the
    authority files, the store marker and the seal marker are each read by
    exact name, and their bytes are compared to the seal regardless of what
    else is in the directory. A tracked file of that name that was modified or
    deleted is still a finding; so is an untracked file of any other name, and
    so is one in a subdirectory. A-022 records the widening.
    """
    kept: list[str] = []
    for line in porcelain.splitlines():
        if line.startswith("?? "):
            name = line[3:]
            if "/" not in name and "\\" not in name and _FRESH_TMP_NAME.search(name):
                continue
        kept.append(line)
    return "\n".join(kept).strip().splitlines()


def _write_fresh(path: Path, text: str) -> None:
    """Put these bytes at `path` as a NEW file, whatever shape is there now.

    `write_text` alone writes THROUGH what it finds. A directory raises; a
    symlink follows to its target; and a HARDLINK -- which needs no privilege
    on NTFS -- writes the bytes into every other name for the same inode.
    Measured under review at the parent of this commit: a hardlink planted at
    an authority path made a restoration overwrite a file OUTSIDE the store
    with the sealed capsule bytes. The wipe cannot help, because it preserves
    the authority files and the seal marker BY NAME regardless of shape.

    WRITTEN WHOLE AND MOVED INTO PLACE, which is `seal`'s idiom eighty lines
    down and for the same reason. Removing the entry and THEN writing it --
    what this did first -- left the destination ABSENT for the width of a
    write, and `_rebuild` calls this on the seal marker before anything else:
    so a death or an ordinary `OSError` in that instant left the worker's
    forged authority on disk under no marker, `protected()` False, and a
    sealless load returning the forged `READY`. Precisely the fall-open the
    marker-first ordering exists to close, reopened by the removal that
    closed a different one. The `OSError` form is the worse of the two: it
    is PERMANENT and the surface reports a clean refusal, whose exception
    promises in its own docstring that nothing was partially written.

    `os.replace` keeps everything the removal bought. It swaps the directory
    ENTRY, so a planted hardlink's other name keeps the old inode and the
    bytes land in the new one (measured: the outside file was untouched); it
    replaces a symlink rather than following it; and for a FILE destination
    it is never absent at any instant.

    A DIRECTORY AND A JUNCTION STILL NEED REMOVING, because a rename cannot
    replace either -- and the first version of this repair removed them where
    the old code did, BEFORE the temp existed, which left for those two shapes
    exactly the fall-open it had just closed for a file. Measured at that
    commit with nothing patched but `Path.write_text`: with a directory or a
    junction at `.forge-seal`, a handled `OSError` AND a crash inside the
    marker's own write each left `['.forge-capsule', 'capsule.json',
    'experience.json']` -- `protected()` False, and a sealless load returning
    the worker's forged `READY`. The `OSError` form is durable and needs no
    crash, and it is reported behind a refusal whose own docstring promises
    nothing was partially written. It is also a DEGRADATION Forge itself
    causes: before the call the directory made `protected()` True and a
    sealless load refuse. A concurrent observer counting absence strictly
    inside this function measured file 0/2518, directory 1706/4204, junction
    1475/2544.

    THE REMOVAL THEREFORE HAPPENS INSIDE THE `try`, AFTER THE FINISHED TEMP
    EXISTS. Every way the write itself can fail -- the full disk, the scanner
    holding the create, a death during the bytes -- now fails with the old
    entry still standing, and the durable `OSError` form disappears entirely
    for both shapes (measured after the reorder: `protected()` True and a
    sealless load `REFUSED CapsuleSealMissing`, in both shapes and both forms).

    WHAT REMAINS IS A CRASH-ONLY MICRO-WINDOW, INHERENT RATHER THAN CLOSED.
    For a directory or a junction the removal and the rename are two adjacent
    syscalls with no I/O between them, and a death in that gap still leaves
    the name absent. `os.replace` cannot replace a directory, so no ordering
    of those two calls removes the gap; only a shape the destination does not
    have would. It is narrowed, not eliminated, and A-022 records it as
    residue rather than as a closed hole.

    The temp name carries 64 random bits. It is a name in the STORE, which is
    the hostile directory -- unlike `seal`'s fixed sibling, which lives in the
    seal directory outside it -- so a predictable one could be pre-planted as
    a link and turned back into the write primitive this closes. Scope is
    this path: `_write_document` and `_write_experience` on the ordinary save
    path still write through, unchanged, and ASSUMPTIONS A-022 records that.
    """
    tmp = _fresh_tmp_path(path)
    try:
        tmp.write_text(text, encoding="utf-8", newline="")
        if path.is_dir() and not path.is_symlink():
            _remove_tree(path)
        _replace_fresh(tmp, path)
    except OSError:
        # Never mask the failure with a cleanup failure; `_rebuild`'s wipe
        # takes any survivor, since the temp name is in no keep set.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


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
        self._mark_sealed()
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
        self._mark_sealed()
        _run_git(self.root, "add", "-A")
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
        self._mark_sealed()
        _run_git(self.root, "add", "-A")
        _run_git(self.root, "commit", "--quiet", "-m", f"experience: {message.strip()}")
        self.seal()
        return self.revision()

    # -- the seal ------------------------------------------------------------
    def seal_ident(self) -> str:
        return hashlib.sha256(str(self.root.resolve()).encode("utf-8")).hexdigest()[:24]

    def seal_path(self) -> Path | None:
        if self.seal_dir is None:
            return None
        return self.seal_dir / f"{self.seal_ident()}.json"

    def protected(self) -> bool:
        """Was this store ever sealed by Forge? The committed marker says so,
        independently of whether the seal itself is still there."""
        return (self.root / _SEAL_MARKER_FILE).exists()

    def protect(self) -> str | None:
        """Begin protection of a store that predates sealing: commit the seal
        marker as Forge's own revision and seal it. A no-op for a store that
        already carries the marker. Returns the new revision, or None when
        nothing needed doing."""
        if self.seal_dir is None or self.protected():
            return None
        self._mark_sealed()
        _run_git(self.root, "add", "-A")
        _run_git(self.root, "commit", "--quiet", "-m", "capsule: protection begins")
        self.seal()
        return self.revision()

    def _mark_sealed(self) -> None:
        """Write the seal marker into the store when sealing is in force and
        the store does not carry one yet. Called before the commit it joins.

        Conditional on `protected()` because a store already carrying a marker
        needs nothing on the ordinary save path, and rewriting it there would
        dirty the tree for no reason. The RESTORATION path wants the
        unconditional form and calls `_write_seal_marker` directly.
        """
        if self.seal_dir is None or self.protected():
            return
        self._write_seal_marker()

    def _write_seal_marker(self) -> None:
        """Put the marker naming THIS store's seal on disk, whatever is there.

        Deliberately not conditioned on `protected()`. `protected()` only asks
        whether a file of that name exists, so a marker a worker deleted, or
        replaced with one naming another store's seal, is exactly the state a
        restoration has to correct -- and the conditional form would leave it
        standing. No-op only when sealing is not in force at all.

        Writes through `_write_fresh`: a worker may have left a directory, a
        link or a hardlink where the marker belongs, and `write_text` would
        raise on the first and write through the other two. Before this method
        existed the wipe ran first and happened to clear a directory there; the
        order that closes the fall-open would otherwise have lost the recovery
        with it.

        `_rebuild` LEANS ON HOW LITTLE OF THIS WRITE THE MARKER IS ABSENT FOR.
        It runs first there, so for the width of its write the store holds the
        worker's forged authority and nothing else: if the marker were absent
        during it, the fall-open would be open exactly then. `_write_fresh`
        therefore writes a finished file to a sibling and moves it onto the
        name, and removes a directory or a junction standing there only AFTER
        that sibling exists.

        WHAT THAT BUYS, STATED EXACTLY, because a stronger sentence stood here
        and was false. Against a FILE destination, or none, the marker on disk
        is the old one or the new one at every instant -- never neither; the
        rename is the only mutation. Against a DIRECTORY or a JUNCTION it is
        weaker: no ordinary failure of the write can strip the marker, since
        everything that can raise has already happened when the removal runs,
        but a process death BETWEEN the removal and the rename -- two adjacent
        syscalls, no I/O between them -- still leaves the name absent. That
        residue is inherent to `os.replace`, which cannot replace a directory,
        and A-022 records it as residue rather than as a closed hole.

        Pinned by the `inside-the-marker-write` rows: one crash and one
        ordinary `OSError` at a file destination, and the same two forms again
        at a directory and at a junction.
        """
        if self.seal_dir is None:
            return
        _write_fresh(
            self.root / _SEAL_MARKER_FILE,
            canonical_json({"schema": _SEAL_MARKER_SCHEMA, "seal": self.seal_ident()}) + "\n",
        )

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
            else:
                # Everything except a stray of Forge's own temp shape; see
                # `_tree_changes` for why that one name is not a finding.
                changes = _tree_changes(status.stdout)
                if changes:
                    problems.append(
                        "the working tree is not clean: " + "\n".join(changes)[:120])
        if not (self.root / _MARKER_FILE).exists():
            problems.append("the store marker is missing")
        marker = self.root / _SEAL_MARKER_FILE
        if not marker.exists():
            problems.append("the seal marker is missing")
        else:
            try:
                named = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                named = None
            if not isinstance(named, dict) or named.get("seal") != self.seal_ident():
                problems.append("the seal marker does not name this store's seal")
        for name, sealed_text in snapshot.files.items():
            path = self.root / name
            current = path.read_text(encoding="utf-8") if path.exists() else None
            if current != sealed_text:
                problems.append(f"{name} differs from the sealed bytes")
        return problems

    def assert_sealed(self) -> None:
        """Refuse a store that does not match its seal, and a protected store
        whose seal is gone. Three states, kept apart on purpose: sealed and
        matching (trusted), never sealed (legacy -- `sealed()` is None and
        `protected()` is False, and the caller reports it unsealed), and
        protected-but-unsealed (the marker is there, the seal is not), which
        is a refusal because a store known to need its anchor cannot be
        trusted without one, and no authority is inferred from its files."""
        snapshot = self.sealed()
        if snapshot is None:
            if self.seal_dir is not None and self.protected():
                raise CapsuleSealMissing(
                    f"the store at {self.root} was sealed by Forge and its seal is missing "
                    f"from {self.seal_dir}; nothing on disk is trusted and no authority is "
                    "inferred from it. Recovery is outside this surface."
                )
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
            restored = False
            if (self.root / ".git").is_dir():
                reset = subprocess.run(
                    ["git", *_GIT_IDENTITY, "reset", "--hard", "--quiet", snapshot.revision],
                    cwd=str(self.root), capture_output=True, text=True, check=False,
                )
                if reset.returncode == 0:
                    subprocess.run(
                        ["git", "clean", "-fdxq"], cwd=str(self.root),
                        capture_output=True, text=True, check=False,
                    )
                    restored = not self.seal_problems(snapshot)
            if not restored:
                # No repository to reset -- the worker removed or replaced it,
                # or the store directory itself -- or a reset that did not land.
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
        stray files -- is removed by shape, not by assumption.

        The junction in that list was a CLAIM rather than a behaviour until
        this commit: `_remove_tree` walked into `rmtree`, which refuses a
        junction, and the read-only retry handler swallowed the refusal, so
        the wipe returned success having left the junction standing. Measured,
        and now removed by `os.rmdir` with the target untouched. See
        `_remove_tree`.

        THE ORDER IS THE PROPERTY. Every step here can die -- a crash, a kill,
        a full disk -- and what matters is what a LATER process would then read
        off the directory. The wipe used to come first, and it kept only the
        store marker and the two authority files: so it deleted the seal marker
        while the worker's forged bytes were still on disk, and a death before
        the rewrite a few lines down left forged authority with `protected()`
        False -- permanently readable as a legacy store by anyone who also
        removed the seal, which is one same-user file deletion. Two-of-two had
        become one-of-one, and Forge's own recovery path is what degraded it.
        Measured before the repair: a `SystemExit` at the `git init` call left
        `['.forge-capsule', 'capsule.json', 'experience.json']`, `protected()`
        False, and a seal-less load returning the forged `stage == "READY"`.

        So: the seal marker FIRST and unconditionally, then the sealed bytes,
        then the store marker, and only then the wipe and a fresh repository.
        No instant of it holds forged authority under an absent marker.

        THE MARKER GOES FIRST, and the first ordering that closed the
        permanent fall-open did not. It wrote the sealed bytes and only then
        the marker, which leaves a window two statements wide: `snapshot.files`
        is `capsule.json` then `experience.json`, so a death BETWEEN THE TWO
        left the worker's forged `experience.json` -- an authority file by this
        module's own definition -- on disk with the marker still gone.
        Measured under review at the parent: `protected()` False, and a load
        whose seal file had also gone returned the forged `stage == "READY"`.
        A window rather than a permanent state, but the same fall-open, and
        the marker names the STORE rather than the bytes, so writing it before
        them costs nothing and is true at every instant after it. Pinned by
        the fourth crash instant in
        `test_a_crash_inside_the_rebuild_never_leaves_the_store_readable_as_legacy`.

        Between the marker and the last byte write the store therefore holds
        forged authority under a marker that DEMANDS a seal -- refused, not
        read: that is the property, not that the bytes are correct at every
        instant. The commit is last because a commit is not what makes the
        bytes trustworthy -- the seal is.
        """
        self.root.mkdir(parents=True, exist_ok=True)
        self._write_seal_marker()
        for name, text in snapshot.files.items():
            path = self.root / name
            if text is None:
                path.unlink(missing_ok=True)
            else:
                _write_fresh(path, text)
        _write_fresh(
            self.root / _MARKER_FILE,
            "Forge capsule store. Managed by nornyx_forge.capsule_store; "
            "not a user-facing repository.\n",
        )
        # The seal marker joins the keep set only where sealing is in force.
        # With no seal directory there is no seal for a marker to name, and one
        # found on disk is a worker's leftover the wipe should take, exactly as
        # it did before.
        keep = {_MARKER_FILE, *_AUTHORITY_FILES}
        if self.seal_dir is not None:
            keep.add(_SEAL_MARKER_FILE)
        for entry in list(self.root.iterdir()):
            if entry.name in keep:
                continue
            if entry.is_dir() and not entry.is_symlink():
                _remove_tree(entry)
            else:
                entry.unlink(missing_ok=True)
        _run_git(self.root, "init", "--quiet", "--initial-branch=main")
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
    "MARKER_TRUST_BASIS",
    "AuthoritySnapshot",
    "CapsuleSealError",
    "CapsuleSealMissing",
    "CapsuleSealUnreadable",
    "CapsuleStore",
    "CapsuleStoreError",
    "CapsuleTamperError",
    "CapsuleValidationError",
]
