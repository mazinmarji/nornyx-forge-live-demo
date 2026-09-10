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

THE PROCESS WITNESS, and the exact width of what it buys. `ProcessWitness`
remembers, in memory and nowhere else, the snapshot ONE FORGE APPLICATION
INSTANCE last sealed or last verified clean for each store, so a seal that
arrives on disk in place of that one is `CapsuleSealReplaced` at the next load
rather than a clean read. That closes the rollback above ONLY for the interval
a single instance is alive: the witness is not written down, and it may not be,
because
every place it could be written is the same-operating-system-user filesystem
the rollback already commands (a counter beside the seal, a mirror in a second
Forge-owned directory, an append-only log in a third place, and a DENY ACE on
the seal file -- four candidates, each built, and each rolled back with the set
it was
meant to anchor or undone by the same user; A-029 states each result). So the
currency word does NOT move.
What resets the witness is a fresh `create_app`, which on the shipped path
means restarting Forge, itself a same-user act; the new instance holds
whatever is
on disk; that is the disclosed limit, stated in A-029 and pinned in the
affirmative by `test_a_rollback_across_a_restart_is_the_disclosed_limit`. The
witness RAISES THE COST of a silent rollback -- it now requires terminating
Forge -- and is not a guarantee. An anchor that survives a restart needs an
authority outside the restoration domain (a second operating-system
principal, or hardware), which is external authority this repository does not
synthesize.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

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


class ProcessWitness:
    """What ONE FORGE APPLICATION INSTANCE last sealed, or last verified clean,
    for each store it has touched. In memory, for the life of that instance,
    and NOWHERE ELSE ON PURPOSE.

    WHAT IT ESTABLISHES, in one sentence that is the whole of the claim:
    since `held_since(ident)`, no load THROUGH THE INSTANCE HOLDING THIS
    WITNESS has found a seal for that store other than the one that instance
    last wrote or verified. Not
    that the store is the newest thing Forge ever wrote; not that a restart
    would find the same one. The surface reports it as `continuity` beside
    the unchanged `currency`, as a SEPARATE field, because it is a separate
    and much smaller fact.

    THE NAME SAYS PROCESS AND THE BOUND IS THE INSTANCE, which is narrower,
    and the narrower one is the claim. `create_app` builds one of these and
    hands it to every store handle it makes, so a SECOND `create_app` in the
    same operating-system process holds nothing and begins its own interval
    from disk -- measured in one pid, with the first instance refusing a
    rolled-back store `409` while the second answered `200` at the earlier
    stage under `continuity` `"process"`. The shipped composition makes one
    instance per process, so the two coincide there; the guarantee is still
    the instance's, and A-029 discloses it in those terms. The reported word
    is left as `"process"` deliberately: widening the witness to the process
    is a BEHAVIOUR change that reddens
    `test_a_rollback_across_a_restart_is_the_disclosed_limit`, and no wording
    is worth buying with one.

    WHY IT IS NOT PERSISTED, which is a measured result and not an omission.
    The rollback it detects replaces the store, its committed marker and its
    seal with an earlier consistent set, and every durable place a witness
    could live is inside the same one same-operating-system-user filesystem:
    a counter beside the seal, a mirror in a second Forge-owned directory, an
    append-only log in a third place (NTFS has no append-only attribute, so
    `open(log, "w")` truncates its last line) -- each was built as a subclass
    of this store and each was UNDETECTED once the actor copied its location
    back too. A DENY ACE on the seal does not even stop replacement:
    `os.replace` and `os.remove` both succeeded through one, because the parent
    directory grants the owner `FILE_DELETE_CHILD`, and `icacls /remove:d` then
    removed the ACE under the owner's implicit `WRITE_DAC`. A-029 states each
    of those results per candidate.
    An anchor that survives the restoration of the whole set has to sit outside
    it -- a second operating-system principal, or hardware -- which is external
    authority, and this repository neither synthesizes nor adopts one here.

    SO THE BOUND IS AN APPLICATION-INSTANCE LIFETIME, and on the shipped path
    reaching a fresh instance means terminating Forge, a same-user
    act. Against the A-015 actor this RAISES THE COST -- a silent rollback now
    needs Forge stopped and restarted, which is a visible side effect -- and it
    is not a guarantee. It is exactly as strong, and exactly as weak, as the
    in-memory hold the build window already relies on.

    NO CALLER OUTSIDE `create_app` PASSES A WITNESS. `cli.py`'s
    `build --project-dir` builds its store with a `seal_dir` and no witness, so
    it gets the seal's checks and not this one, and reads a wholesale
    rolled-back store as honest while the surface refuses the same store.
    A short-lived process that does one `load()` establishes no interval, so a
    witness there would report a fact about nothing; A-029 residue (3) states
    the gap and that the decision is unchanged.

    Held under a lock because the witness is shared between the request
    threads and the build thread. The shipped composition already serialises
    every store access under the application's own store lock, so the lock
    here is redundant there and cheap; a caller that does not serialise still
    cannot interleave a read of the snapshot with a write of it.
    """

    def __init__(self, clock: Callable[[], str]) -> None:
        #: The application's clock, so `held_since` is the same time source
        #: the lifecycle records and is deterministic under an injected one.
        self._clock = clock
        #: ident -> (snapshot, held_since). `held_since` is None for exactly
        #: one state: a replacement was detected and nothing has re-sealed
        #: since, so there is no interval to claim continuity over.
        self._held: dict[str, tuple[AuthoritySnapshot, str | None]] = {}
        self._lock = threading.Lock()

    def record(self, ident: str, snapshot: AuthoritySnapshot) -> None:
        """This process just wrote or verified `snapshot` for `ident`.

        `held_since` is stamped on the FIRST record and on the first record
        after a detected replacement, and is otherwise left alone: an ordinary
        save moves the snapshot and must not move the interval, or the field
        would read "held since a moment ago" after every write and would say
        nothing at all.
        """
        with self._lock:
            held = self._held.get(ident)
            since = held[1] if held is not None and held[1] is not None else self._clock()
            self._held[ident] = (snapshot, since)

    def expected(self, ident: str) -> AuthoritySnapshot | None:
        """The seal this process last wrote or verified for `ident`, or None
        when this process has never held one. Survives `interrupted`, so a
        detected replacement goes on being detected until it is restored."""
        with self._lock:
            held = self._held.get(ident)
        return None if held is None else held[0]

    def held_since(self, ident: str) -> str | None:
        with self._lock:
            held = self._held.get(ident)
        return None if held is None else held[1]

    def continuity(self, ident: str) -> str | None:
        """`"process"` while this process holds an unbroken interval for the
        store, else None. A closed vocabulary of one value and an absence:
        there is no third thing this can establish."""
        return "process" if self.held_since(ident) is not None else None

    def interrupted(self, ident: str) -> None:
        """A seal other than the held one was found: the interval ends here.

        The snapshot is KEPT -- it is what a restoration puts back and what
        every later load goes on being measured against -- and only the
        interval is dropped, so nothing claims continuity across the
        replacement. The next `record` starts a new interval.
        """
        with self._lock:
            held = self._held.get(ident)
            if held is not None:
                self._held[ident] = (held[0], None)


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

    #: The headline of the refusal, split out so a subclass whose finding is a
    #: DIFFERENT measurement can state its own. The body stays the measured
    #: problems either way, and no subclass may say more than it measured.
    _HEADLINE = (
        "the authority store does not match Forge's seal and is not trusted; "
        "what Forge measured: "
    )

    def __init__(self, problems: list[str], snapshot: AuthoritySnapshot) -> None:
        super().__init__(self._HEADLINE + "; ".join(problems))
        self.problems = problems
        self.snapshot = snapshot


class CapsuleSealReplaced(CapsuleSealError):
    """The store matches the seal on disk, and that seal is not the one this
    process last wrote or verified: store and seal were replaced together.

    A DIFFERENT MEASUREMENT FROM ITS PARENT, which is why it has its own
    headline. `CapsuleSealError` compares the store against the seal; this
    compares the SEAL against the process witness, and the store may agree
    with the disk seal perfectly -- that agreement is exactly what a wholesale
    rollback produces and what nothing on disk can tell apart from an honest
    state.

    `snapshot` is the WITNESS's snapshot, not the disk seal's, so a caller
    restoring from it puts back what this process last wrote. It is a
    `CapsuleSealError`, so every caller that already handles a tamper finding
    with something to restore handles this one unchanged.

    WHAT IT DOES NOT SAY. Not that the store is stale in any absolute sense --
    only that it is not what this process last held. A restart makes the same
    rollback invisible again, and the message says "while Forge was running"
    for that reason: it names the interval it is true over.
    """

    _HEADLINE = (
        "the authority seal is not the one this process last wrote or verified; "
        "the store and its seal were replaced while Forge was running; "
        "what Forge measured: "
    )

    @classmethod
    def between(
        cls, found: AuthoritySnapshot, expected: AuthoritySnapshot
    ) -> "CapsuleSealReplaced":
        """The finding for a seal `found` on disk where `expected` was held.

        An alternative constructor rather than a second spelling of the
        comparison at each call site: the load path and the human restore
        route both raise this, and a difference stated two ways is a
        difference that can drift.
        """
        return cls(_replacement_problems(found, expected), expected)


def _replacement_problems(
    found: AuthoritySnapshot, expected: AuthoritySnapshot
) -> list[str]:
    """Every way the seal on disk differs from the one this process holds.

    Shaped like `seal_problems`, and for the same reason: the finding is the
    DIFFERENCE, stated in the units it was measured in, so a reader can see
    what moved without being told a story about who moved it. Both the
    revision and the recorded bytes are compared, because a seal naming the
    held revision with different bytes is a difference too and is not caught
    anywhere else -- `seal_problems` would then be comparing the store against
    the substituted seal and finding them in agreement.
    """
    problems: list[str] = []
    if found.revision != expected.revision:
        problems.append(
            f"the seal names {found.revision[:12]} and this process last sealed "
            f"{expected.revision[:12]}"
        )
    differing = sorted(
        name for name in expected.files
        if found.files.get(name) != expected.files[name]
    )
    for name in differing:
        problems.append(f"the seal's recorded bytes for {name} are not the ones this "
                        "process sealed")
    if not problems:  # pragma: no cover - unequal snapshots always differ somewhere
        problems.append("the seal is not the one this process last wrote or verified")
    return problems


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


def _is_directory_entry(path: Path) -> bool:
    """Is the ENTRY at `path` directory-shaped, judged WITHOUT following it?

    THE PREDICATE THAT WAS WRONG THREE ROUNDS RUNNING was `path.is_dir() and
    not path.is_symlink()`, and it was wrong because `is_dir()` STATS THROUGH
    a reparse point. A junction whose target is gone therefore answers False
    while the entry on disk is still a directory to Win32 -- so the removal
    branch was skipped and `os.replace` was handed a destination it can never
    replace. One unprivileged `mklink /J .forge-seal <nonexistent>` reached it.

    `os.lstat` reads the LINK, so a broken target changes nothing. Measured on
    this host, and the last column is why this is a predicate rather than a
    list of shapes -- it is exactly the set `os.replace` refuses:

        shape              is_dir&!islink   lstat dir-attr   os.replace
        non-existent       False            (ENOENT)         SUCCEEDED
        regular file       False            False            SUCCEEDED
        read-only file     False            False            WinError 5 *
        hardlink           False            False            SUCCEEDED
        directory          True             True             WinError 5
        live junction      True             True             WinError 5
        DANGLING junction  False  <-- bug   True             WinError 5

    (* the read-only file is the one refusal that is not about shape;
    `_replace_fresh` clears the bit and retries, and must go on being the
    thing that handles it, which is why this predicate answers False there.)

    Symlinks could not be built on this host at all -- `os.symlink` raises
    `[WinError 1314] A required privilege is not held by the client` -- so the
    three symlink rows are UNMEASURED here and are declared as such rather
    than assumed. What is measured for them is this predicate alone, against
    synthesised attributes: a Windows directory symlink carries
    `FILE_ATTRIBUTE_DIRECTORY` on the link itself, so it lands in the removal
    branch, and a file symlink does not, so `os.replace` swaps the link. On
    POSIX `lstat` reports `S_IFLNK` for both, so neither is removed and
    `os.rename` replaces the link, which is the POSIX behaviour anyway.
    """
    try:
        info = os.lstat(path)
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", None)
    if attributes is not None:
        return bool(attributes & stat.FILE_ATTRIBUTE_DIRECTORY)
    return stat.S_ISDIR(info.st_mode)


def _remove_entry(path: Path) -> None:
    """Remove whatever is at `path` BY THE SHAPE OF THE ENTRY, following
    nothing. A no-op when the name is already free.

    ONE REMOVAL FOR EVERY SITE THAT REMOVES. `_write_fresh` and `_rebuild`'s
    wipe each carried their own spelling of "is this a directory", and both
    were the stat-following one. THE DEFECT HAD ONE HOME, NOT TWO, and the
    sentence that said two counted the sites rather than the failures: at
    `_write_fresh` the predicate handed `os.replace` a destination Win32
    forbids it to replace, which is P1-A and permanent; at the wipe the
    else-branch was `unlink`, which removes a junction rather than refusing
    it, so every shape still went. Measured both ways -- see the wipe.

    Sharing is worth having on its own terms: the NEXT shape is answered once
    instead of in each site separately. It does not need a defect it did not
    prevent, and claiming one made a green mutation row look like a hole.

    A reparse point is taken by its own shape and is NEVER walked: `rmdir`
    removes a directory-attributed link (a junction, a Windows directory
    symlink) and `unlink` a file-attributed one, and in both cases the TARGET
    is untouched -- measured for a junction, whose target kept its contents.
    A real directory goes to `_remove_tree`, which clears git's read-only
    bits. Everything else goes to `_unlink_clearing_read_only`.

    THE PLAIN-FILE BRANCH WAS THE ONE PRIMITIVE HERE THAT DID NOT CLEAR THE
    READ-ONLY BIT, and it was a bare `os.unlink` for as long as it has
    existed. Both its siblings do clear it: `_replace_fresh` chmods and
    retries, `_remove_tree` clears git's read-only objects. The asymmetry cost
    nothing while this function only removed a destination something was about
    to be written over -- the WRITE's failure was then the refusal, and the
    entry it could not take was still standing. `_neutralise_untrusted_
    authority` made it a removal in its own right, and the FIRST one that runs
    while `protected()` is still False, so its refusal became a fall-open:
    measured through the shipped `restore()`, one `attrib +R experience.json`
    left `capsule.json` removed, the seal marker never written and the
    worker's forged `experience.json` readable -- on the third call as on the
    first. See `_rebuild` and A-022.
    """
    if not os.path.lexists(path):
        return
    try:
        if _is_junction(path) or os.path.islink(path):
            (os.rmdir if _is_directory_entry(path) else os.unlink)(path)
        elif _is_directory_entry(path):
            _remove_tree(path)
        else:
            _unlink_clearing_read_only(path)
    except FileNotFoundError:
        return


def _unlink_clearing_read_only(path: Path) -> None:
    """`os.unlink(path)`, retried once with the read-only bit cleared.

    The removal half of what `_replace_fresh` does for a rename, under the
    same guard and for the same measured reason: `attrib +R` is a command
    A-015 concedes the same-operating-system-user writer can run, and Win32
    denies BOTH the rename and the unlink with `PermissionError [WinError 5]`.

    NOT EVERY DENIAL IS A READ-ONLY BIT, and this deliberately does not try to
    tell them apart before retrying. A held handle raises `PermissionError
    [WinError 32]`, no chmod can help it, and the retry fails exactly as the
    first attempt did. That is correct here and is precisely why `_rebuild`
    does not rely on this succeeding: no list of shapes closes the invariant,
    so `_rebuild` closes it on the FAILURE instead. Measured on this host at
    an authority path, the plant asserted to have landed in every row:

        shape               os.unlink        st_nlink   this function
        regular file        SUCCEEDED        1          removed
        read-only file      WinError 5       1          removed after chmod
        hardlink            SUCCEEDED        2          removed (one name)
        read-only hardlink  WinError 5       2          REFUSED, bit intact
        held handle         WinError 32      1          REFUSED, retry fails
    """
    try:
        os.unlink(path)
    except PermissionError:
        if not _solely_owned_file(path):
            raise
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        os.unlink(path)


def _solely_owned_file(path: Path) -> bool:
    """Is `path` a plain file the store holds the ONLY name for?

    THE GUARD ON EVERY `os.chmod` THIS MODULE MAKES AT A HOSTILE PATH.
    `os.chmod` acts on the FILE and not on the name, so clearing the read-only
    bit through one name of a hardlink clears it on EVERY name -- measured
    directly against this predicate's absence: a read-only file outside the
    store, planted as a link inside it, came back writable after one unguarded
    chmod through the inside name. A name the store does not solely own is
    left alone and the refusal stands.

    ONE SPELLING, TWO SITES, AND THE HOIST IS THE POINT. It lived inside
    `_replace_fresh` as an inline expression, so when the removal grew a chmod
    of its own there was nothing to reuse -- and the removal had shipped with
    no read-only handling at all, which is the defect above. Answered once,
    the next site that clears a bit cannot ship without it either.

    False rather than an exception when the path cannot be stat'ed: a name
    that vanished under the retry is not a name this may chmod.
    """
    try:
        return path.is_file() and not path.is_symlink() and os.stat(path).st_nlink == 1
    except OSError:
        return False


#: How many times `_remove_tree` re-lists and re-removes when an entry APPEARS
#: beneath the path, and how long it waits before the second attempt. The pause
#: doubles each time, so eight attempts SPEND AT MOST 6.35 SECONDS WAITING
#: (0.05 + 0.1 + ... + 3.2) -- a bound on the sleeping and not on the call,
#: which also does the removing, and none of it at all when the first attempt
#: succeeds, which is every removal that is not being written into.
#:
#: THE BOUND IS MEASURED, NOT PICKED. The writer this outlasts is git's own
#: auto-maintenance (see `_remove_tree`), and the longest run of it observed
#: here took 5.657 s -- `git maintenance run --auto --quiet --detach` repacking
#: 900 loose objects, timed from the call to its return. 6.35 s covers that
#: with margin. A writer that outlasts the budget is not waited out: attempt
#: eight raises, which is the refusal `_remove_tree` documents.
_APPEARED_ATTEMPTS = 8
_APPEARED_FIRST_PAUSE_SECONDS = 0.05


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

    AN ENTRY THAT IS ALREADY GONE IS THE STATE THIS FUNCTION WANTED, and the
    handler used to turn it into a crash. `rmtree` LISTS a directory and then
    VISITS its entries one at a time; an entry removed in that window is
    reported to the handler like any other failure, and the handler's first
    act was `os.chmod` on a path that no longer exists -- raising a SECOND
    `FileNotFoundError`, from the handler, which escapes `rmtree` entirely.
    Observed in CI as `.git/objects/7f` vanishing under the removal of a
    capsule store, on Python 3.11: `capsule_store.py` at the `chmod`, chained
    to shutil's own `entry.stat()` reporting the bare name `7f`.

    Measured against a concurrent remover, which is not a coin toss: BEFORE
    this `except`, 40 of 40 trials failed on 3.12 and 20 of 20 on 3.11; AFTER
    it, 0 of 200 and 0 of 100. 3.11 WAS NOT SINGLED OUT BY ITS HANDLER
    CONTRACT. The intolerance is in this body, which the `onerror` and `onexc`
    spellings share, so the version in the report says which interpreter lost
    the toss, not why there was one to lose.

    Only `FileNotFoundError` is absorbed. A target that is still there and
    still refuses to go -- a held handle, a permission that clearing did not
    fix -- must still raise, or this becomes the silent no-op the paragraph
    above records.

    AN ENTRY THAT APPEARS IS THE OPPOSITE CASE, AND IS NOT ABSORBED. The same
    listing window runs the other way: an entry CREATED between the listing and
    the final `rmdir` leaves the directory non-empty, and `os.rmdir` refuses it
    with `ENOTEMPTY`. The handler chmods the directory, calls `os.rmdir` again,
    gets `ENOTEMPTY` again, and that second one escapes the handler and
    `rmtree` both. Observed in CI, Python 3.12, this module under this module's
    own rollback helper:
    `OSError: [Errno 39] Directory not empty: '.../capsule/.git'`.

    ABSORBING IT WOULD BE A FAIL-OPEN, which is why this is a retry instead.
    `FileNotFoundError` means the goal is ALREADY REACHED -- the name this
    wanted gone is gone. `ENOTEMPTY` means the goal is NOT reached and someone
    is actively writing; returning on it would report success over a store that
    is still on disk, and this function's callers (`_rebuild`s wipe, and
    `_write_fresh` at a directory-attributed destination) remove untrusted
    content for a living. So the removal is ATTEMPTED AGAIN, up to
    `_APPEARED_ATTEMPTS` times: each attempt re-lists, so entries that appeared
    since the last one are seen and removed. Exhaustion RAISES the last
    `ENOTEMPTY` -- loudly, with the offending path -- and every error that is
    not `ENOTEMPTY` is re-raised on the FIRST attempt, so a held handle still
    refuses at once instead of stalling for the budget.

    THE MODE THE HANDLER CLEARS TO DEPENDS ON THE ENTRY, and getting that
    wrong is how the retry above arrived RED ON ALL FOUR LINUX JOBS while
    passing 300 Windows trials. `rmtree` routes a failed `rmdir` to the
    handler exactly as it routes a failed `unlink`, so `target` is a DIRECTORY
    as often as it is a file -- and the handler's `os.chmod(target, 0o600)`
    was written for the Windows read-only attribute, where a mode is a bit and
    traversal is not a permission at all. On POSIX `0o600` on a directory
    STRIPS THE SEARCH BIT: the directory stays listable and every entry inside
    it becomes unreachable. The retry then re-lists the directory it has just
    made untraversable and gets `EACCES` on the first name it tries to remove
    -- which is not `ENOTEMPTY`, so the loop below re-raises on the first
    attempt, correctly, at an error the handler manufactured. Measured in CI:
    `PermissionError: [Errno 13] Permission denied:
    '.../capsule/.git/maintenance.lock'` in the appearing-entry pin, and the
    same `EACCES` reaching the refusal pin where it demanded the real
    `ENOTEMPTY`. A directory therefore gets `stat.S_IRWXU` and a file keeps
    `0o600`; no entry is widened that was not already being chmod'd.

    THE TYPE IS TAKEN FROM `os.lstat` AND NOT FROM `_is_directory_entry`,
    which is this module's predicate for "does this entry need `rmdir`" and
    deliberately answers True for a directory-attributed REPARSE POINT. That
    is the right answer for choosing a removal primitive, which follows
    nothing, and the wrong one for choosing a mode, because `os.chmod` DOES
    follow. This handler runs at hostile paths, so the one shape the two
    predicates disagree about is the shape that decides which is used here: a
    symlink to a directory planted in a store must not have a directory's
    mode applied through it. `S_ISDIR` on an `lstat` is False for a link, so
    a link takes the file mode and whatever it points at keeps its own.

    THE WRITER IS GIT ITSELF, and it is not the product calling it. Measured
    with `GIT_TRACE2_EVENT` at stock configuration -- nothing in this product,
    its tests or its CI sets `gc.auto`, `gc.autoDetach` or `maintenance.*` --
    EVERY `git commit` spawns the child `git maintenance run --auto --quiet
    --detach`. When its auto-condition is met that child writes a pack, its
    `.idx`, its `.rev` and an `objects/pack/multi-pack-index`, and collapses
    the loose objects (744 to 186 over identical work); with
    `maintenance.auto=false` the same work leaves 744 loose objects and no pack
    at all. That is the whole fingerprint an earlier investigation saw appear
    inside a store mid-run and could not attribute.

    WHAT THAT MEASUREMENT DOES NOT SETTLE, kept separate from what it does. It
    was taken on Windows, where `--detach` does not detach: the parent `git
    commit` waits for the child (`child_exit` after 0.16 s, in the same trace),
    so the write finishing after the synchronous call returns is git's
    documented `--detach` behaviour on the platform CI failed on, not something
    observed here. And at stock `gc.auto` a store of 48 loose objects does NOT
    repack (measured), so the earlier sighting's threshold crossing is still
    unexplained. The repair does not depend on either: it survives a concurrent
    writer whatever the writer turns out to be.
    """
    if _is_junction(path):
        os.rmdir(path)
        return

    def _clear_and_retry(function, target, _exc):
        try:
            # A DIRECTORY NEEDS ITS SEARCH BIT BACK, a file does not have one
            # to lose, and a link must not be widened through. See above.
            os.chmod(target, stat.S_IRWXU if stat.S_ISDIR(os.lstat(target).st_mode) else 0o600)
            function(target)
        except FileNotFoundError:
            return

    for attempt in range(_APPEARED_ATTEMPTS):
        if attempt:
            time.sleep(_APPEARED_FIRST_PAUSE_SECONDS * 2 ** (attempt - 1))
        try:
            # `onerror` is deprecated in 3.12 and removed in 3.14; `onexc`
            # arrived in 3.12 and takes the exception rather than an `exc_info`
            # triple. The handler ignores that argument, so one body serves
            # both spellings.
            if sys.version_info >= (3, 12):
                shutil.rmtree(path, onexc=_clear_and_retry)
            else:
                shutil.rmtree(path, onerror=_clear_and_retry)
            return
        except OSError as exc:
            # The last attempt re-raises too: exhaustion is a failure, and the
            # exception it fails with is the real one, at the real path.
            if exc.errno != errno.ENOTEMPTY or attempt == _APPEARED_ATTEMPTS - 1:
                raise


def _replace_fresh(tmp: Path, path: Path) -> None:
    """`os.replace(tmp, path)`, retried once with the read-only bit cleared.

    Measured on Windows: a destination carrying `attrib +R` denies the rename
    with `PermissionError [WinError 5]`, exactly as it denied the unlink this
    replaced. One `attrib +R` on `.forge-seal` -- a command the same-user
    writer A-015 concedes can run -- would otherwise disable the product's
    human recovery route permanently. Clearing the bit is the remedy
    `_remove_tree` already applies to git's read-only objects.

    GUARDED BY `_solely_owned_file`, because `os.chmod` through one name of a
    hardlink clears the bit on EVERY name -- measured: a read-only file
    outside the store became writable through a link planted inside it. A name
    the store does not solely own is left alone and the refusal stands. That
    guard was an inline expression here until `_unlink_clearing_read_only`
    needed the same one; it is now a named predicate both sites call, so
    neither can drift. A held handle raises the same WinError 5 and no chmod
    can help it; A-022 records that residue, which lasts only as long as the
    handle.
    """
    try:
        os.replace(tmp, path)
        return
    except PermissionError:
        if not _solely_owned_file(path):
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

    WHAT HAPPENS TO A STRAY THAT IS NOT SWEPT UP, corrected: `git clean` on
    the honest restore route takes it, and `_rebuild`'s wipe takes it, but
    only until the NEXT SAVE. `save` runs `git add -A` and commits, so a
    stray still present then is absorbed into the store's own history and
    becomes TRACKED AND CLEAN -- measured: after one save the porcelain
    reports nothing at all about it, `git clean -fdx` leaves it standing,
    `seal_problems` is empty, and it is in `git ls-files`. From then on it is
    permanent and invisible rather than exempt, and only the wipe removes it.
    It still carries no authority, for the reason above; what changes is that
    the two routes named as taking it no longer do.

    EACH LINE IS TRIMMED, NOT THE JOINED BLOCK. `"\\n".join(kept).strip()`
    stripped the leading status padding off the FIRST line only, so one
    finding read `M capsule.json` and two read `M capsule.json` and
    ` D experience.json` -- the same status in two spellings depending on
    where it landed in the list.
    """
    kept: list[str] = []
    for line in porcelain.splitlines():
        if line.startswith("?? "):
            name = line[3:]
            if "/" not in name and "\\" not in name and _FRESH_TMP_NAME.search(name):
                continue
        trimmed = line.lstrip()
        if trimmed:
            kept.append(trimmed)
    return kept


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
    bytes land in the new one (measured: the outside file was untouched), and
    for a FILE destination it is never absent at any instant. It is also
    stated to replace a symlink rather than following it; that is POSIX
    `rename` semantics and the documented Windows behaviour for a file
    symlink, and it is UNVERIFIED HERE, because `os.symlink` on this host
    raises `[WinError 1314] A required privilege is not held by the client`.
    The claim used to stand unqualified.

    A DIRECTORY-ATTRIBUTED DESTINATION STILL NEEDS REMOVING, because a rename
    cannot replace one. "Only a directory and a junction" was the old wording
    and it was a LIST rather than a property, so it missed the shape that is
    neither: a DANGLING junction, which `is_dir()` answers False for while
    Win32 still refuses the rename. `_is_directory_entry` is the property, and
    the removal is keyed on it.

    THE REMOVAL HAPPENS INSIDE THE `try`, AFTER THE FINISHED TEMP EXISTS.
    Round 3 removed the entry where the old code did, before the temp existed,
    which left for those shapes exactly the fall-open it had just closed for a
    file; the reorder means every way the WRITE can fail -- the full disk, the
    scanner holding the create, a death during the bytes -- fails with the old
    entry still standing.

    WHAT IT DOES NOT BUY, and one round said it did. "The durable `OSError`
    form disappears entirely for both shapes" was FALSE: `_replace_fresh` runs
    AFTER the removal and can raise on its own. An ordinary concurrent reader
    -- an indexer, a backup agent, Defender: no privilege, no patching, no
    crash -- opens the finished temp, and a handle on the SOURCE denies the
    rename with a sharing violation. Measured on this host, one observer thread
    doing nothing but enumerate the directory and read what it finds, 400
    rounds per shape:

        destination   succeeded   raised          durably ABSENT after
        regular file  390         10 (32 x8, 5 x2)   0 / 10
        directory     305         95 (WinError 32)  95 / 95
        junction      399          1 (WinError 32)   1 / 1

    The file column is why the claim survived a round: at a file destination
    there is no removal, so the failure leaves the old marker standing and it
    really does fail closed. At a directory-attributed one the removal has
    already happened, and the failure is durable. A-022's "no OSError, no full
    disk, no scanner can reach it" is corrected there; a scanner is precisely
    what reached it. "Crash-only micro-window" was wrong for the same reason,
    and it was wrong about the width too: the marker's absence occupies 16.5%
    of the call at a directory and 29.1% at a junction (662/4023 and 640/2202,
    measured by a concurrent observer inside this function).

    THAT RESIDUE IS NOT CLOSED HERE AND IS NO LONGER A FALL-OPEN. `os.replace`
    cannot replace a directory, so no ordering of these two calls removes the
    gap and no guard patch will; three rounds tried. `_rebuild` instead
    neutralises the untrusted authority BEFORE it reaches this function, so a
    destination this leaves absent -- durably or in the gap -- is absent over
    a store that has no readable authority to fall open with. See `_rebuild`.

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
        if _is_directory_entry(path):
            _remove_entry(path)
        # AND THIS STATEMENT CAN RAISE. It is the one after the removal, so at
        # a directory-attributed destination its failure is what leaves the
        # name absent; it is written on its own line and named in the docstring
        # rather than read as the tail of an operation that already succeeded.
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

    def __init__(self, root: Path, seal_dir: Path | None = None,
                 witness: ProcessWitness | None = None):
        self.root = Path(root)
        #: Where Forge keeps this store's seal: OUTSIDE the project directory,
        #: named by the store's resolved path. `None` means an unsealed store,
        #: which the domain tests use; the application always passes one.
        self.seal_dir = Path(seal_dir) if seal_dir is not None else None
        #: The running process's memory of what it last sealed here. `None`
        #: means this store keeps no witness and behaves exactly as it did
        #: before the witness existed -- which is what every store constructed
        #: without one gets, so nothing that does not ask for it is changed.
        self.witness = witness

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

        `_rebuild` NO LONGER LEANS ON HOW LITTLE OF THIS WRITE THE MARKER IS
        ABSENT FOR, and three rounds of trying to make it lean less is why.
        It used to run first there, so the width of this write was the width
        of a fall-open; each round narrowed that width for the shapes it had
        enumerated and left another shape holding it. `_rebuild` now removes
        the untrusted authority BEFORE calling this, so an absent marker here
        stands over a store with nothing readable to fall open with.

        WHAT THIS WRITE BUYS, STATED EXACTLY, because two successively weaker
        sentences have stood here and both were false. Against a FILE
        destination, or none, the marker on disk is the old one or the new one
        at every instant -- never neither; the rename is the only mutation.
        Against a DIRECTORY-ATTRIBUTED one it is weaker in BOTH the ways the
        previous sentence denied. "No ordinary failure of the write can strip
        the marker, since everything that can raise has already happened when
        the removal runs" was wrong: `_replace_fresh` runs after the removal,
        and an ordinary concurrent reader holding the finished temp denied it
        95 times in 400 -- durably, no crash. A process death in the same gap
        does it too. `os.replace` cannot replace a directory, so neither is
        closed here; what closes the FALL-OPEN is the ordering in `_rebuild`,
        which does not depend on this write being atomic for any shape.

        THIS IS THE SUCCESS-PATH WRITE AND IT STAYS UNCONDITIONAL. There is a
        second caller now -- `_write_seal_marker_best_effort`, on the path
        where the neutralisation failed -- and it is conditional on
        `protected()` for a reason that does NOT apply here: it is not
        restoring anything, so the marker's content buys it nothing, while
        writing through an occupant can leave the name empty and cost the
        store its protection. Here the restoration IS happening, a marker
        naming another store's seal is exactly the state to correct, and the
        untrusted authority is already gone by the time this runs.

        Pinned by the `inside-the-marker-write` rows, by the shape matrix in
        `test_the_marker_write_is_shape_correct_at_every_interior_instant`,
        and by the ordinary-reader row, which asserts the fail-closed property
        rather than a rate.
        """
        if self.seal_dir is None:
            return
        _write_fresh(
            self.root / _SEAL_MARKER_FILE,
            canonical_json({"schema": _SEAL_MARKER_SCHEMA, "seal": self.seal_ident()}) + "\n",
        )

    def _write_seal_marker_best_effort(self) -> None:
        """`_write_seal_marker`, on a path that is already failing. NEVER
        raises, and never becomes the error the caller sees.

        THE POINT OF ROUND 6, AND WHY IT IS NOT A SIXTH SHAPE. Four rounds
        enumerated shapes at the marker's destination, and each closed the
        cells it had listed. This one runs where the RECOVERY is already lost,
        and its only job is to make sure the store is left demanding a seal.
        `protected()` True over a store whose seal is gone is
        `CapsuleSealMissing` on both authority routes, so a residue Forge
        cannot clean becomes a refusal instead of a legacy read. It is
        therefore attempted even when the untrusted authority is still there.

        `BaseException`, deliberately, on both sides. `SystemExit` is how a
        supervised death arrives in-process and is exactly the case that most
        needs the marker; and a failure of THIS write must not replace the
        real diagnosis with a secondary one, which is the mistake
        `_write_fresh`'s own cleanup already avoids. Swallowing costs the
        caller nothing: the original exception is re-raised by `_rebuild`, and
        `restore()` turns an `OSError` into `CapsuleStoreError` as before. A
        `KeyboardInterrupt` that lands inside this write is lost in favour of
        the error that brought us here -- accepted, and stated rather than
        hidden, because the alternative is leaving the store open.

        IT DOES NOTHING AT ALL WHEN THE STORE IS ALREADY PROTECTED, AND THE
        FIRST VERSION OF THIS METHOD DID NOT -- WHICH MADE THINGS WORSE.
        `_write_seal_marker` writes THROUGH whatever is at the name, so at a
        directory-attributed occupant it removes first and renames second, and
        a denied rename leaves the name EMPTY. Measured, neutralisation failed
        and the marker's rename denied by an ordinary sharing violation:

            marker occupant   rename denied   marker after   protected()
            absent            no              file           True
            absent            YES             absent         False
            directory         no              file           True
            directory         YES             absent         False   <-- was True
            live junction     YES             absent         False   <-- was True
            dangling junction YES             absent         False

        The two marked rows are a store that DEMANDED A SEAL before the call
        and did not after: Forge's own fail-closed step spending the very
        property it exists to protect. On this path the marker's CONTENT does
        not matter -- one naming another store's seal is `seal_problems`'
        "does not name this store's seal", a refusal either way -- so there is
        nothing to buy by rewriting an occupant and a fall-open to lose. The
        unconditional form stays where restoration really is happening, in
        `_write_seal_marker` on the success path, and its docstring says why.

        THE LAST RESORT IS ONE EXCLUSIVE CREATE. Where `_write_fresh` has been
        denied and left the name free, a single `O_CREAT | O_EXCL` write puts
        the marker there with no removal and no rename, so it has no window of
        its own. `O_EXCL` is what makes it safe rather than merely simple: it
        REFUSES an existing name, so it does not follow a link a worker plants
        in the gap after `protected()` answered False -- the write-through this
        module built `_write_fresh` to prevent.

        THAT REFUSAL IS QUALIFIED, exactly as `_write_fresh` qualifies its own
        `os.replace` claim. Against a SYMLINK it is POSIX `open` semantics and
        the documented Win32 `CREATE_NEW` behaviour, and it is UNVERIFIED HERE,
        because `os.symlink` on this host raises `[WinError 1314] A required
        privilege is not held by the client`. What IS measured here is the
        shape this host can build -- and it is closed by construction rather
        than by `O_EXCL` alone, so the two are not one fact:

            occupant at the marker name    os.open(O_CREAT|O_EXCL|O_WRONLY)
            live junction                  FileExistsError  errno 17
            dangling junction              PermissionError  errno 13
            ordinary existing file         FileExistsError  errno 17

        Neither junction is followed. Note the errno rather than a `winerror`:
        CPython reaches this through the CRT, so the Win32 code never surfaces
        and a row phrased on `.winerror` would assert `None`. The symlink claim
        used to stand unqualified.

        A torn or truncated marker is still a refusal, so even a partial one
        fails closed.

        BYTE-EXACT, AND IT WAS NOT. `os.open` defaults to TEXT mode on Windows,
        so `os.write` of bytes ending `}\\n` landed on disk as `}\\r\\n` --
        measured on this host, `b'{"a": 1}\\n'` in and `b'{"a": 1}\\r\\n'` out,
        one CR without `os.O_BINARY` and none with it. Nothing broke:
        `json.loads` tolerates the extra byte and a marker of any content still
        refuses. But this is the module whose entire idiom -- `_write_fresh`,
        `newline=""`, `canonical_json` -- exists to put exact bytes on disk,
        and NO ROW ASSERTED THIS WRITE'S BYTES, so the one write that escaped
        the idiom was the one nothing was watching. `O_BINARY` under `getattr`
        because POSIX does not define it, and the write is LOOPED because
        `os.write` may write short and a single unlooped call would leave a
        torn marker where a whole one was available. Pinned by
        `test_the_exclusive_create_fallback_writes_the_markers_exact_bytes`.

        IT IS BEST EFFORT AND THE NAME SAYS SO. Both writes can be denied, so
        this is not a guarantee the marker exists afterwards -- only that
        nothing was left unattempted and that nothing was made worse. The
        residue that remains is disclosed in A-022 rather than claimed closed.
        """
        if self.seal_dir is None or self.protected():
            return
        try:
            self._write_seal_marker()
        except BaseException:
            pass
        if self.protected():
            return
        try:
            marker = os.open(self.root / _SEAL_MARKER_FILE,
                             os.O_CREAT | os.O_EXCL | os.O_WRONLY
                             | getattr(os, "O_BINARY", 0), 0o600)
            try:
                payload = (canonical_json(
                    {"schema": _SEAL_MARKER_SCHEMA, "seal": self.seal_ident()}
                ) + "\n").encode("utf-8")
                written = 0
                while written < len(payload):
                    written += os.write(marker, payload[written:])
            finally:
                os.close(marker)
        except BaseException:
            return

    def snapshot(self) -> AuthoritySnapshot:
        """The authority as it stands on disk right now: HEAD and file bytes."""
        files: dict[str, str | None] = {}
        for name in _AUTHORITY_FILES:
            path = self.root / name
            files[name] = path.read_text(encoding="utf-8") if path.exists() else None
        return AuthoritySnapshot(revision=self.revision(), files=files)

    def seal(self) -> AuthoritySnapshot | None:
        """Record the store's authority as Forge just wrote it. Called after
        every commit this adapter makes, and nowhere else.

        THE WITNESS MOVES HERE AND ONLY HERE, which is why the one method
        every write path ends in is the right place for it: `initialize`,
        `save`, `save_experience`, `protect` and `restore` all finish by
        sealing, so a write route that forgot to tell the witness would have
        had to forget to seal, which the next load would refuse anyway. It is
        recorded AFTER the seal file has landed -- a witness to a seal that
        failed to be written would be a claim about a file that is not there.
        """
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
        if self.witness is not None:
            self.witness.record(self.seal_ident(), snapshot)
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
        trusted without one, and no authority is inferred from its files.

        THEN, AND ONLY THEN, THE WITNESS. The three states above are decided
        exactly as they were; the fourth question -- is this seal the one this
        process last held? -- is asked last, of a store that has just passed
        every check the seal itself can make. That ordering is deliberate:
        a store that fails its own seal has a finding of its own, with its own
        `problems` and its own snapshot to restore from, and the witness must
        not take that finding's place. It follows that a rollback which ALSO
        leaves the store disagreeing with the rolled-back seal is reported as
        the ordinary breach and restored to the DISK seal rather than to the
        witness -- a lesser recovery, not a fall-open, and disclosed in A-029.
        The human restore route consults the witness first for that reason.

        A store the witness has never held ADOPTS the disk seal here, once it
        has verified clean. A process that only ever reads must be able to
        establish an interval too, or continuity would begin at the first
        WRITE and a rollback before that write would pass unnoticed inside a
        process that had already read the store.
        """
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
        if self.witness is None:
            return
        ident = self.seal_ident()
        expected = self.witness.expected(ident)
        if expected is None:
            self.witness.record(ident, snapshot)
            return
        if snapshot != expected:
            self.witness.interrupted(ident)
            raise CapsuleSealReplaced.between(snapshot, expected)

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

        THE FALL-OPEN IS A CONJUNCTION, AND THIS BREAKS THE OTHER HALF OF IT.
        Reading a store as legacy needs TWO things at once: the marker absent
        AND the worker's forged authority readable on disk. Three rounds
        attacked the first half -- write the marker before the bytes, make its
        write atomic, remove a directory before renaming onto it -- and each
        one closed the shapes it had enumerated and left a cell out, because
        `os.replace` CANNOT replace a directory and so a remove-then-create
        window is irreducible for a directory-shaped entry. There is no fourth
        guard patch that closes it.

        So the untrusted authority is NEUTRALISED FIRST, and the marker's
        write stops being load-bearing. `_neutralise_untrusted_authority`
        removes the authority files by shape; only then the seal marker,
        then the sealed bytes, then the store marker, then the wipe and a
        fresh repository. At every instant the store therefore holds either
        NO READABLE AUTHORITY -- both routes fail closed on the absent file --
        or authority under a marker that demands a seal. Neither leg needs an
        atomic directory replacement, so the shape space stops being
        load-bearing for this invariant.

        BOTH FILES, AND THAT IS MEASURED RATHER THAN ASSUMED. With the seal
        deleted and the marker absent, removing only one of them leaves the
        other route open:

            marker    authority              load_experience()   load()
            absent    both gone              REFUSED             REFUSED
            absent    capsule.json gone      RETURNED 'READY'    REFUSED
            absent    experience.json gone   REFUSED             RETURNED
            absent    neither gone           RETURNED 'READY'    RETURNED

        REMOVED, NOT TRUNCATED. Truncation follows what it finds: measured, a
        hardlink planted at `capsule.json` and truncated left a file OUTSIDE
        the store holding `''` with its link count still 2 -- the same write
        primitive `_write_fresh` exists to close, pointed at destruction
        instead. `_remove_entry` takes the NAME by shape; on the same specimen
        the outside file kept its bytes and its count dropped to 1.

        THIS CANNOT STRAND THE STORE WORSE THAN NOT CALLING IT. The files it
        removes are exactly the ones the next few statements overwrite from
        the seal, and `_rebuild` is reached only from `restore()`, only after
        the honest `git reset --hard` route has failed, and only with the
        sealed snapshot already in the caller's hands -- so nothing removed
        here was going to survive the call anyway, and the trusted copy is
        outside the store. A death or an `OSError` between the neutralisation
        and the sealed write leaves the authority absent: both routes refuse,
        and re-running `restore()` with the same seal repairs it.

        AND THE NEUTRALISATION ITSELF CAN RAISE PART-DONE, which two shipped
        sentences denied. "If the neutralisation itself raises, it raises
        BEFORE anything else has been touched" is FALSE the moment the SECOND
        removal is the one that fails: `_AUTHORITY_FILES` is ordered
        `(capsule.json, experience.json)`, so `capsule.json` is already gone.
        Measured through the shipped `restore()` with `.git` destroyed, the
        marker deleted and one `attrib +R experience.json` -- no crash, no
        patching, no privilege:

            BEFORE   ['.forge-capsule', 'capsule.json', 'experience.json']
            restore  CapsuleStoreError: PermissionError [WinError 5]
            AFTER    ['.forge-capsule', 'experience.json']
            marker absent   protected() False   forged READY readable

        And "re-running `restore()` with the same seal repairs it" was FALSE
        for that shape in particular: attempts two and three raised the same
        way and the forged stage stayed readable. The bit is still set, so the
        remedy is defeated for as long as it is -- permanently, by one
        unprivileged command. `_unlink_clearing_read_only` now clears it, and
        that closes THIS shape.

        BUT NO LIST OF SHAPES CLOSES THE INVARIANT, which is the lesson four
        rounds paid for. A held handle raises `WinError 32` and no chmod
        reaches it; the next shape will be some third thing. So the ordering
        is backed by a STRUCTURAL fail-closed step rather than by enumeration:
        ANY failure of the neutralisation writes the seal marker, best effort,
        BEFORE the error propagates. The marker turns every residue from a
        FALL-OPEN into a REFUSAL -- `protected()` True with no seal on disk is
        `CapsuleSealMissing` on both routes -- and it is written even where the
        untrusted authority could not be removed at all, because the marker is
        the half of the conjunction Forge can always reach for. What survives
        is a restoration that did not happen, not a store Forge opened.

        The best-effort write cannot itself raise past the original error, and
        the ORIGINAL error is the one the caller sees; see
        `_write_seal_marker_best_effort`. What it does NOT cover is a real
        process death inside the neutralisation, where no Python runs at all:
        there the guarantee is the weaker one this design already carried --
        the restoration OPENED nothing, the readable set is a subset of what
        the call found. Both are pinned, and the residue is disclosed in
        A-022 rather than claimed closed.

        THE MARKER GOES BEFORE THE BYTES, and the first ordering that closed the
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
        try:
            self._neutralise_untrusted_authority()
        except BaseException:
            # THE STRUCTURAL HALF. Whatever defeated the removal -- a
            # read-only bit, a held handle, a shape nobody has met -- the
            # store still ends PROTECTED, so the residue is a refusal and not
            # a fall-open. The original failure is re-raised below, unchanged.
            self._write_seal_marker_best_effort()
            raise
        self._write_seal_marker()
        for name, text in snapshot.files.items():
            path = self.root / name
            if text is None:
                _remove_entry(path)
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
            # `entry.is_dir() and not entry.is_symlink()` stood here, the same
            # stat-following predicate that let a dangling junction past
            # `_write_fresh`. AT THIS SITE IT WAS NOT A DEFECT, and the claim
            # that it was is withdrawn. It read: "here it sent one to `unlink`,
            # which Win32 denies for a directory-attributed entry, so the wipe
            # raised and the rebuild stopped before `git init`". Measured at
            # 719c744, which carries the old predicate, with a dangling AND a
            # live junction planted at non-kept names and `.git` removed:
            # `restore()` RETURNED, `git init` was reached, both entries were
            # gone, the live target kept its bytes. `os.unlink` does not refuse
            # a junction -- CPython's `Py_DeleteFileW` sees a directory reparse
            # point and calls `RemoveDirectoryW` -- and a live junction never
            # reached that branch anyway, since `is_dir()` is True through it
            # and `_remove_tree` has taken junctions by link since 889542a.
            # The refusal that is real belongs to `os.replace`, at the OTHER
            # site. Two call sites shared one predicate; ONE was a defect.
            #
            # `_remove_entry` stands here as UNIFICATION, not repair: the next
            # shape gets answered once instead of per site. A faithful mutation
            # back to the old predicate is therefore an EQUIVALENT MUTANT and
            # nothing can kill it -- round 5's row M6 restored it exactly and
            # the module stayed green over a full run. Recorded so a later
            # round does not read that green as a missing assertion. Walking a
            # reparse point instead of taking it IS caught: row M9 removed both
            # guards and reddened five rows, including the wipe's own.
            _remove_entry(entry)
        _run_git(self.root, "init", "--quiet", "--initial-branch=main")
        _run_git(self.root, "add", "-A")
        _run_git(self.root, "commit", "--quiet", "-m", "capsule: authority restored from seal")

    def _neutralise_untrusted_authority(self) -> None:
        """Remove the store's authority files, by shape, before the rebuild
        touches anything else. The FIRST statement of `_rebuild` that can
        change the store, and deliberately so; see `_rebuild` for why.

        BY SHAPE AND NEVER THROUGH: `_remove_entry` takes the NAME, so a
        hardlink the worker planted loses one of its names and the file
        outside the store keeps its bytes. Truncating instead would zero that
        outside file -- measured.

        Both names, because either one left readable answers one of the two
        authority routes; the table is in `_rebuild`. `_AUTHORITY_FILES` is
        the module's own definition of what authority is, so a file promoted
        into it is neutralised here without a second edit.

        IT CAN RAISE PART-DONE, AND THE CALLER IS BUILT FOR THAT. The names
        are removed IN ORDER, so a failure at `experience.json` leaves
        `capsule.json` already gone -- a state `_rebuild`'s own docstring once
        denied could exist. Nothing is attempted here to make the removals
        atomic, because they cannot be; `_rebuild` catches the failure and
        writes the seal marker before propagating it, which turns whatever is
        left into a refusal rather than a fall-open.
        """
        for name in _AUTHORITY_FILES:
            _remove_entry(self.root / name)

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
    "CapsuleSealReplaced",
    "CapsuleSealUnreadable",
    "CapsuleStore",
    "CapsuleStoreError",
    "CapsuleTamperError",
    "CapsuleValidationError",
    "ProcessWitness",
]
