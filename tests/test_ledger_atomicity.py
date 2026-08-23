"""The consumption row and the continuity witness commit as one unit.

A7-P1-2. The two stores are separate files -- deliberately, because the witness
has to survive a restore of the ledger, which is the whole reason it exists.
They were committed SEPARATELY, and a review measured what that costs:
terminating a consumption between the two writes left the row durable and the
witness stale, after which a ledger-only restore released the already-spent
grant.

Reproduced here as a sweep rather than a single point: killing the child at each
SQL statement in turn, 8 of 45 kill points left the stores disagreeing.

THE FIX IS NOT AN ORDERING TRICK. Advancing the witness FIRST was implemented
and measured worse -- it refused legitimate concurrent grants in 1 of 12 trials,
because a witness legitimately ahead of the rows is indistinguishable from
history that vanished. That design was reverted.

What closes it is SQLite's own multi-database commit: a transaction spanning
ATTACHed databases commits or rolls back as one unit, PROVIDED none of them is
in WAL. So both stores are provisioned in a rollback-journal mode, the mode is
verified rather than assumed, and the row and the witness are written in one
transaction under `BEGIN IMMEDIATE`.

    BEGIN IMMEDIATE   solves the CONCURRENCY half
    the attached txn  solves the CRASH half

Neither substitutes for the other.

WHAT THESE TESTS DO NOT PROVE, stated plainly: that SQLite's commit protocol is
itself crash-atomic. That is SQLite's documented guarantee about its own
internals, and a Python test cannot demonstrate it. What is measured here is
that this code establishes the required configuration, verifies it, refuses when
it is absent, and puts both writes in a single transaction -- and that no kill
point reachable from Python leaves the stores disagreeing.

BOUND ON THE CLAIM: if BOTH files are restored together to a mutually
consistent older snapshot, no purely local witness can detect it. Doing so needs
an authority outside the restoration domain -- a remote monotonic counter, a
hardware counter, or an append-only external log. That is a different property
from A7-P1-2 and is not claimed here.
"""

from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest
from signing import GRANT_ISSUED, LEDGER_ESTABLISHED  # noqa: E402

from nornyx_forge.nornyx_runtime import (
    LEDGER_BUSY,
    LEDGER_CONTINUITY_MIGRATION_REQUIRED,
    LEDGER_CONTINUITY_UNKNOWN,
    LEDGER_ROLLED_BACK,
    ROLLBACK_JOURNAL_MODES,
    ApprovalLedger,
)

NOW = "2026-08-03T00:00:00Z"
ROOT = Path(__file__).resolve().parents[1]

#: The kill sweep. 60 covers the whole consumption comfortably; the pre-C-4
#: design failed at points 27-34 of 45.
KILL_POINTS = 60

_CHILD = '''
import os, sqlite3, sys
sys.path.insert(0, {src!r})
KILL_AT = {kill_at}
_real = sqlite3.connect
_seen = [0]
def _traced(*a, **k):
    conn = _real(*a, **k)
    def _trace(_s):
        _seen[0] += 1
        if _seen[0] == KILL_AT:
            os._exit(70)
    conn.set_trace_callback(_trace)
    return conn
sqlite3.connect = _traced
from nornyx_forge.nornyx_runtime import ApprovalLedger
claimed, reason = ApprovalLedger({path!r}).consume(
    "fp-kill", "rd-kill", at={now!r}, grant_issued_at={gi!r},
    approval_id="ACT-KILL")
print("CLAIMED", claimed)
'''


def _rows(path: Path) -> int:
    with closing(sqlite3.connect(path)) as conn:
        return int(conn.execute("SELECT count(*) FROM consumed_approvals").fetchone()[0])


def _witness(side: Path):
    if not side.exists():
        return "ABSENT"
    try:
        with closing(sqlite3.connect(side)) as conn:
            got = conn.execute("SELECT value FROM high_water").fetchall()
    except sqlite3.Error as exc:
        return f"ERR:{type(exc).__name__}"
    return got[0][0] if len(got) == 1 else f"ROWS={len(got)}"


def _ledger(tmp_path: Path, spends: int = 0) -> tuple[Path, Path]:
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    led = ApprovalLedger(path)
    for index in range(spends):
        claimed, reason = led.consume(
            f"fp-{index}", f"rd-{index}", at=NOW,
            grant_issued_at=GRANT_ISSUED, approval_id=f"ACT-{index}")
        assert claimed, f"setup spend {index} was refused: {reason}"
    return path, path.with_name(path.name + ".highwater")


# --------------------------------------------------------------------------
# The configuration the guarantee rests on
# --------------------------------------------------------------------------


@pytest.mark.parametrize("store", ["ledger", "witness"])
def test_both_stores_are_provisioned_where_one_commit_covers_both(
    store: str, tmp_path: Path
) -> None:
    """WAL is the reason A7-P1-2 existed, so its absence is asserted."""
    path, side = _ledger(tmp_path, spends=1)
    target = path if store == "ledger" else side
    with closing(sqlite3.connect(target)) as conn:
        mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
    assert mode in ROLLBACK_JOURNAL_MODES, (
        f"the {store} is in {mode!r}. SQLite commits a multi-database "
        "transaction as one unit only when no attached database is in WAL, and "
        "that guarantee is what keeps the consumption row and the witness from "
        "diverging."
    )


@pytest.mark.parametrize("store", ["ledger", "witness"])
def test_wal_on_either_store_refuses_rather_than_converting(
    store: str, tmp_path: Path
) -> None:
    """A silent conversion inside `consume` would be a schema migration
    performed by an authorization decision. It refuses and names the command."""
    path, side = _ledger(tmp_path, spends=1)
    target = path if store == "ledger" else side
    with closing(sqlite3.connect(target)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")

    claimed, reason = ApprovalLedger(path).consume(
        "fp-wal", "rd-wal", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-WAL")
    assert claimed is False, f"a store in WAL released an effect: {reason!r}"
    assert LEDGER_CONTINUITY_MIGRATION_REQUIRED in reason, reason
    assert "--migrate-continuity" in reason, (
        "the refusal must name the command that fixes it; a remedy nobody can "
        "run costs the reader the time to discover it does not exist"
    )


# --------------------------------------------------------------------------
# The crash boundary
# --------------------------------------------------------------------------


@pytest.mark.false_green("FG39")
def test_no_kill_point_during_a_consumption_leaves_the_stores_disagreeing(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The sweep that reproduced A7-P1-2, run as a regression.
    FG39: single use, with two durable stores committed separately.

    Design-independent by construction: the kill is injected by wrapping
    `sqlite3.connect` in the child and installing a trace callback, so it fires
    for every connection the runtime opens and depends on no internal method
    name. The same probe was valid before and after this change.
    """
    disagreed = []
    for kill_at in range(1, KILL_POINTS + 1):
        work = tmp_path_factory.mktemp("kill")
        path, side = _ledger(work, spends=2)
        child = _CHILD.format(src=str(ROOT / "src"), kill_at=kill_at,
                              path=str(path), now=NOW, gi=GRANT_ISSUED)
        subprocess.run(  # noqa: S603
            [sys.executable, "-c", child], capture_output=True, text=True,
            timeout=300, check=False)
        rows, witness = _rows(path), _witness(side)
        if rows != witness:
            disagreed.append((kill_at, rows, witness))

    assert disagreed == [], (
        "these kill points left the consumption row and the continuity witness "
        "disagreeing, which is the state a ledger-only restore then hides: "
        f"{disagreed[:8]}"
    )


def test_the_kill_sweep_actually_kills_children(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The control, corrected. It used to be satisfied by children never killed.

    It asserted `reached > 0` -- "at least one kill point left a committed
    consumption" -- and a review measured what actually satisfies that:

        kill points declared             60
        points that actually killed      38   (1..38)
        points where NOTHING was killed  22   (39..60)
        points leaving a committed row   22   -- EXACTLY the no-kill tail
        of the 38 children actually killed, ZERO left a committed row

    So the control could not distinguish "a kill landed after the write" from
    "no kill landed at all", and the 22 trials passing it were the 22 where the
    child ran to completion.

    WHY NO KILLED CHILD LEAVES A COMMITTED ROW, which is the fact the old
    assertion was groping for and getting backwards: a consumption is a fixed
    number of statements ending in `COMMIT`, and `set_trace_callback` fires
    BEFORE a statement executes. No kill point can therefore land INSIDE
    SQLite's multi-file commit -- the only window in which the single-
    transaction design could fail. That is a property of the design, not a
    deficiency of the sweep, and stating it is more honest than asserting a
    number the tail satisfies.

    What this control now measures is that the sweep REACHES the work at all:
    children must actually die, and they must die across the consumption rather
    than all at import time.
    """
    killed = []
    for kill_at in range(1, KILL_POINTS + 1):
        work = tmp_path_factory.mktemp("reach")
        path, _side = _ledger(work, spends=2)
        child = _CHILD.format(src=str(ROOT / "src"), kill_at=kill_at,
                              path=str(path), now=NOW, gi=GRANT_ISSUED)
        done = subprocess.run(  # noqa: S603
            [sys.executable, "-c", child], capture_output=True, text=True,
            timeout=300, check=False)
        if done.returncode == 70:
            killed.append(kill_at)

    assert killed, (
        "no child in the sweep was killed at all, so every trial ran to "
        "completion and the sweep above measures nothing about crash behaviour"
    )
    assert len(killed) >= 10, (
        f"only {len(killed)} of {KILL_POINTS} kill points actually terminated a "
        "child; the sweep is barely reaching the consumption"
    )
    assert max(killed) - min(killed) >= 5, (
        f"every kill landed in a narrow band ({min(killed)}..{max(killed)}), so "
        "the sweep is exercising one moment rather than the consumption"
    )


# --------------------------------------------------------------------------
# Restore, in both directions
# --------------------------------------------------------------------------


def test_a_ledger_only_restore_is_refused(tmp_path: Path) -> None:
    """The witness ends up AHEAD, which is what a lost ledger looks like."""
    path, side = _ledger(tmp_path, spends=2)
    backup = tmp_path / "ledger.backup"
    shutil.copy2(path, backup)
    assert ApprovalLedger(path).consume(
        "fp-9", "rd-9", at=NOW, grant_issued_at=GRANT_ISSUED,
        approval_id="ACT-9")[0]
    shutil.copy2(backup, path)

    claimed, reason = ApprovalLedger(path).consume(
        "fp-9", "rd-9", at=NOW, grant_issued_at=GRANT_ISSUED,
        approval_id="ACT-9")
    assert claimed is False, "the spent grant released again after a restore"
    assert LEDGER_ROLLED_BACK in reason, reason
    assert "LEDGER holds fewer" in reason, (
        f"the refusal must name WHICH store moved: {reason!r}"
    )


def test_a_witness_only_restore_is_refused(tmp_path: Path) -> None:
    """The witness ends up BEHIND. The old monotone check read that as healthy,
    which is exactly how the crash window stayed invisible."""
    path, side = _ledger(tmp_path, spends=2)
    backup = tmp_path / "witness.backup"
    shutil.copy2(side, backup)
    assert ApprovalLedger(path).consume(
        "fp-9", "rd-9", at=NOW, grant_issued_at=GRANT_ISSUED,
        approval_id="ACT-9")[0]
    shutil.copy2(backup, side)

    claimed, reason = ApprovalLedger(path).consume(
        "fp-8", "rd-8", at=NOW, grant_issued_at=GRANT_ISSUED,
        approval_id="ACT-8")
    assert claimed is False, f"a rolled-back witness released an effect: {reason!r}"
    assert LEDGER_ROLLED_BACK in reason, reason
    assert "WITNESS records fewer" in reason, (
        f"the refusal must name WHICH store moved: {reason!r}"
    )


@pytest.mark.parametrize(
    ("label", "damage"),
    [
        ("absent", lambda side: side.unlink()),
        ("zero length", lambda side: side.write_bytes(b"")),
        ("not a database", lambda side: side.write_bytes(b"not a database")),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_a_witness_that_cannot_be_read_refuses_and_names_the_witness(
    label: str, damage, tmp_path: Path
) -> None:
    """And the refusal must blame the WITNESS, not the ledger.

    Left to the generic handler, an unattachable witness surfaced as "action
    approval ledger is unusable ... file is not a database", which names the
    wrong store for a fault entirely in the other one.
    """
    path, side = _ledger(tmp_path, spends=1)
    damage(side)

    claimed, reason = ApprovalLedger(path).consume(
        "fp-7", "rd-7", at=NOW, grant_issued_at=GRANT_ISSUED,
        approval_id="ACT-7")
    assert claimed is False, f"witness {label!r} released an effect: {reason!r}"
    assert LEDGER_CONTINUITY_UNKNOWN in reason, reason
    assert ".highwater" in reason, (
        f"the refusal does not name the witness it is about: {reason!r}"
    )


# --------------------------------------------------------------------------
# Concurrency. These are the controls that keep the refusals above honest.
# --------------------------------------------------------------------------


def test_one_grant_across_many_processes_releases_exactly_once(
    tmp_path: Path,
) -> None:
    path, side = _ledger(tmp_path)
    child = (
        "import sys; sys.path.insert(0, {src!r});"
        "from nornyx_forge.nornyx_runtime import ApprovalLedger;"
        "c, r = ApprovalLedger({path!r}).consume("
        "'fp-one', 'rd-one', at={now!r}, grant_issued_at={gi!r},"
        " approval_id='ACT-ONE'); print('CLAIMED', c)"
    ).format(src=str(ROOT / "src"), path=str(path), now=NOW, gi=GRANT_ISSUED)

    import concurrent.futures as futures

    def run(_index: int) -> str:
        done = subprocess.run(  # noqa: S603
            [sys.executable, "-c", child], capture_output=True, text=True,
            timeout=300, check=False)
        return done.stdout
    with futures.ThreadPoolExecutor(max_workers=8) as pool:
        out = list(pool.map(run, range(8)))

    winners = sum(1 for line in out if "CLAIMED True" in line)
    assert winners == 1, f"{winners} processes released the same grant"
    assert _rows(path) == 1
    assert _witness(side) == 1


def test_distinct_grants_are_never_refused_under_concurrency(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Repeated, because one clean run is not concurrency evidence.

    The rejected reserve-before-insert design failed this in 1 of 12 trials
    with `LEDGER_ROLLED_BACK` on a ledger nothing had rolled back. That count is
    the bar this has to beat, so the trial count matches it.
    """
    import threading

    refused: list = []
    for _trial in range(12):
        work = tmp_path_factory.mktemp("race")
        path, _side = _ledger(work)
        barrier = threading.Barrier(6)
        lock = threading.Lock()

        def consume(index: int, path: Path = path) -> None:
            led = ApprovalLedger(path)
            barrier.wait()
            claimed, reason = led.consume(
                f"fp-r{index}", f"rd-r{index}", at=NOW,
                grant_issued_at=GRANT_ISSUED, approval_id=f"ACT-R{index}")
            if not claimed:
                with lock:
                    refused.append(reason)

        threads = [threading.Thread(target=consume, args=(i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert refused == [], (
        "distinct, legitimate, never-before-seen grants were refused under "
        f"concurrency: {refused[:3]}"
    )


def test_a_spent_grant_is_refused_without_moving_the_witness(
    tmp_path: Path,
) -> None:
    """Replay is an ordinary adversarial event and must cost nothing.

    The rejected design failed here too: re-presenting four spent grants drove
    the witness to 8 against 4 rows, which then refused every legitimate grant
    after it -- a replayed grant bricking the ledger.
    """
    path, side = _ledger(tmp_path, spends=2)
    before = _witness(side)
    for _attempt in range(4):
        claimed, _reason = ApprovalLedger(path).consume(
            "fp-0", "rd-0", at=NOW, grant_issued_at=GRANT_ISSUED,
            approval_id="ACT-0")
        assert claimed is False
    assert _witness(side) == before, (
        f"replaying a spent grant moved the witness {before} -> "
        f"{_witness(side)}, which would refuse every legitimate grant after it"
    )
    assert ApprovalLedger(path).consume(
        "fp-fresh", "rd-fresh", at=NOW, grant_issued_at=GRANT_ISSUED,
        approval_id="ACT-FRESH")[0] is True


def _witness_conn(side: Path):
    return closing(sqlite3.connect(side))


@pytest.mark.parametrize(
    ("label", "sabotage"),
    [
        ("trigger in the sqlite_% shadow", "shadow"),
        ("trigger via writable_schema", "writable"),
        ("witness row keyed 7", "rekey"),
        ("witness row keyed 0", "rekey0"),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_a_witness_that_cannot_record_the_advance_refuses(
    label: str, sabotage: str, tmp_path: Path
) -> None:
    """The witness write is VERIFIED, exactly as the ledger insert is.

    Two routes reached a COMMITTED state where witness != rows, and each let one
    signed human approval run a consequential effect twice through the real
    boundary, with 123 tests green:

      the closure query filtered candidates on the way IN with
      `WHERE name NOT LIKE 'sqlite_%'` -- `_` is a single-character LIKE
      wildcard, so an ordinary `CREATE TRIGGER sqliteXz` was discarded before it
      could be judged, and `PRAGMA writable_schema` reached the literal prefix.
      That inversion is documented at length by the sibling ledger check as
      having already produced two live bypasses; it was copied here unrepaired.

      the `UPDATE ... WHERE id = 1` matched zero rows when the witness was
      rebuilt under another id, and nothing checked either the key or the
      result. Atomicity of a no-op is still a no-op.

    Both are closed by re-reading the VALUE inside the transaction. `changes()`
    would catch the second and not the first -- a RAISE(IGNORE) trigger reports
    a row as changed -- which is why the value is what is read.
    """
    path, side = _ledger(tmp_path, spends=2)
    with _witness_conn(side) as conn:
        if sabotage == "shadow":
            conn.execute("CREATE TRIGGER sqliteXz BEFORE UPDATE ON high_water"
                         " BEGIN SELECT RAISE(IGNORE); END")
        elif sabotage == "writable":
            conn.execute("PRAGMA writable_schema=ON")
            conn.execute("CREATE TRIGGER sqlite_guard BEFORE UPDATE ON high_water"
                         " BEGIN SELECT RAISE(IGNORE); END")
            conn.execute("PRAGMA writable_schema=OFF")
        else:
            conn.execute("DROP TABLE high_water")
            conn.execute("CREATE TABLE high_water"
                         " (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)")
            conn.execute("INSERT INTO high_water (id, value) VALUES (?, 2)",
                         (7 if sabotage == "rekey" else 0,))
        conn.commit()

    before = _rows(path)
    claimed, reason = ApprovalLedger(path).consume(
        "fp-sab", "rd-sab", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-SAB",
    )
    assert claimed is False, (
        f"{label}: the grant released while the witness could not record it, so "
        "a later ledger-only restore would release it again"
    )
    assert LEDGER_CONTINUITY_UNKNOWN in reason, reason
    assert _rows(path) == before, (
        f"{label}: the consumption row committed even though the refusal "
        f"rolled back -- rows {before} -> {_rows(path)}"
    )


def test_analyze_on_the_witness_does_not_brick_the_ledger(tmp_path: Path) -> None:
    """The control for the closure repair, and it is load-bearing.

    Dropping the `WHERE` alone -- the obvious fix -- makes an ordinary `ANALYZE`
    fatal, because it creates `sqlite_stat1`. That is the availability defect
    `PERMITTED_LEDGER_STATISTICS` exists to prevent on the ledger, reintroduced
    on the witness by the repair. Measured before the allowance was carried
    across: a permanent LEDGER_CONTINUITY_UNKNOWN.
    """
    path, side = _ledger(tmp_path, spends=1)
    with _witness_conn(side) as conn:
        conn.execute("ANALYZE")
        conn.commit()

    claimed, reason = ApprovalLedger(path).consume(
        "fp-an", "rd-an", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-AN",
    )
    assert claimed is True, (
        f"an ANALYZE on the witness bricked a healthy ledger: {reason!r}"
    )


def _roll_back_to_one_row(path: Path) -> None:
    """Leave the ledger holding exactly one consumption row.

    The rollback signature the continuity witness exists to detect: rows only
    ever accumulate, so a ledger holding fewer than were recorded against it
    has lost history.
    """
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "DELETE FROM consumed_approvals WHERE rowid NOT IN"
            " (SELECT rowid FROM consumed_approvals LIMIT 1)"
        )
        conn.commit()


def test_a_legacy_plain_text_mark_refuses_and_names_the_non_destructive_remedy(
    tmp_path: Path,
) -> None:
    """AUTHORIZATION DOES NOT MIGRATE. This test used to require that it did.

    The withdrawn expectation was `claimed is True` -- a healthy ledger with a
    pre-database mark had to release, converting the mark from the ATTACH path.
    It was written to fix a real problem: the upgrade refused every release and
    the only documented escape was `--reset-replay-history`, which mints a new
    epoch and invalidates every outstanding approval.

    THE CURE WAS WORSE, and a review measured it. The plain-text mark is an
    unauthenticated integer in a directory the governed process writes to, so
    adopting it at authorization time lets whoever can write one byte choose
    the replay high-water mark. On this repository's own rollback fixture --
    six grants spent, ledger restored to one row:

        sidecar b"6" (the true count)   claimed False   LEDGER_ROLLED_BACK
        sidecar b"1"                    claimed True    RELEASED
          then five already-spent grants released in turn,
          the witness re-anchoring at each step

    No check repairs this. Requiring the mark to agree with the row count does
    not, because the adversary writes the row count. The value carries no
    authentication, so it cannot decide anything at authorization time.

    This is not a test weakened to let an implementation pass. It is a test
    whose pinned behaviour a hostile specimen proved unsafe, rewritten to pin
    the property that replaces it: the authorization REFUSES, and names the
    non-destructive remedy that the earlier round actually needed --
    `--migrate-continuity`, an explicit operator act that checks agreement,
    rather than `--reset-replay-history`, which discards approvals.
    """
    path, side = _ledger(tmp_path, spends=2)
    side.unlink()
    side.write_bytes(b"2")

    claimed, reason = ApprovalLedger(path).consume(
        "fp-legacy", "rd-legacy", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-LEGACY",
    )
    assert claimed is False, (
        "an authorization converted an unauthenticated plain-text mark and "
        "released against it"
    )
    assert reason.startswith(LEDGER_CONTINUITY_MIGRATION_REQUIRED), reason
    assert "--migrate-continuity" in reason, (
        "the refusal does not name the non-destructive remedy, which is the "
        f"whole reason the migration was wired into consume once: {reason}"
    )
    assert "--reset-replay-history" not in reason, (
        "the refusal sends the operator to the remedy that discards every "
        "outstanding approval, for an upgrade that costs nothing"
    )
    assert side.read_bytes() == b"2", (
        "the refusal MUTATED the store it refused over; a decision that "
        "declines must leave the evidence as it found it"
    )


def test_a_one_byte_sidecar_cannot_re_anchor_the_continuity_witness(
    tmp_path: Path,
) -> None:
    """The hostile specimen, on this repository's own rollback fixture.

    Six grants spent, the ledger restored to one row -- the exact state the
    witness exists to detect. Replacing the sidecar with the single byte `1`
    made the rolled-back ledger agree with itself, and five already-spent human
    approvals released five more effects.

    The cost of the attack is one ASCII digit, which is strictly weaker than
    the capability `RUNTIME_INPUT_AUDIT.md` discloses ("an adversary who can
    restore the directory") and the OPPOSITE outcome from deleting the same
    file, which fails closed.
    """
    # `_ledger(spends=n)` consumes fp-0..fp-(n-1) itself, so the fingerprints
    # replayed below must be its own -- presenting new ones would measure
    # nothing about replay.
    path, side = _ledger(tmp_path, spends=6)
    assert _rows(path) == 6, _rows(path)

    _roll_back_to_one_row(path)
    side.unlink()
    side.write_bytes(b"1")  # the whole attack

    released = []
    for index in range(1, 6):
        claimed, reason = ApprovalLedger(path).consume(
            f"fp-{index}", f"rd-{index}", at=NOW,
            grant_issued_at=GRANT_ISSUED, approval_id=f"ACT-{index}",
        )
        released.append((index, claimed, reason[:60]))
    assert not any(claimed for _, claimed, _ in released), (
        "an already-spent approval released again after a one-byte sidecar "
        f"re-anchored the witness: {released}"
    )


def test_a_plain_text_mark_that_is_not_a_number_still_refuses(
    tmp_path: Path,
) -> None:
    """The control. Without it the migration above is satisfied by converting
    anything, including a witness whose contents mean nothing."""
    path, side = _ledger(tmp_path, spends=1)
    side.unlink()
    side.write_bytes(b"not a number at all")

    claimed, reason = ApprovalLedger(path).consume(
        "fp-junk", "rd-junk", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-JUNK",
    )
    assert claimed is False, "an unreadable witness released an effect"
    assert LEDGER_CONTINUITY_UNKNOWN in reason, reason


@pytest.mark.parametrize("held", ["ledger", "witness"])
def test_lock_contention_is_not_diagnosed_as_lost_history(held: str, tmp_path: Path):
    """A busy database is a database. It was reported as a damaged one.

    MEASURED on both live paths, each with a legitimate, first-ever,
    never-spent grant and another connection holding the lock:

        witness held    DENY LEDGER_CONTINUITY_UNKNOWN
                        "TO RECOVER: run `provision-ledger
                         --reset-replay-history`"
        ledger held     DENY APPROVAL_LEDGER_UNREADABLE
                        "action approval ledger is unusable, so single use
                         cannot be guaranteed"

    Neither ledger was unusable. Neither had lost history. Both remedies are
    wrong, and the first is destructive: `--reset-replay-history` discards the
    replay history and mints a later epoch, invalidating EVERY outstanding
    human approval — to cure a lock that would have cleared on its own.

    This is reachable without an adversary. `provision-ledger
    --migrate-continuity` run while traffic is served does it; so does a
    backup, an antivirus scan, or simply two consequential requests in flight.

    Asserted on both directions: the code says BUSY, and the refusal does not
    carry the destructive remedy.
    """
    path, side = _ledger(tmp_path, spends=0)
    target = path if held == "ledger" else side

    blocker = sqlite3.connect(target, timeout=1, isolation_level=None)
    try:
        blocker.execute("BEGIN EXCLUSIVE")
        claimed, reason = ApprovalLedger(path).consume(
            "fp-busy", "rd-busy", at=NOW,
            grant_issued_at=GRANT_ISSUED, approval_id="ACT-BUSY",
        )
    finally:
        blocker.close()

    assert claimed is False, "a consumption was recorded against a locked store"
    assert reason.startswith(LEDGER_BUSY), (
        "contention was diagnosed as " + reason.split(":")[0] + ", which is a "
        "damage or lost-history code. The operator response differs: one is "
        "'retry', the others are 'investigate' and 'discard every approval'"
    )
    # THE PRESCRIPTION, not the mention. The refusal names
    # `--reset-replay-history` in order to warn AGAINST it, which is exactly
    # what an operator who has seen the old message needs to read. What must
    # not appear is that command presented as the recovery.
    assert "TO RECOVER: run `nornyx-forge provision-ledger " not in reason or (
        "--reset-replay-history" not in reason.split("TO RECOVER:")[1].split(".")[0]
    ), (
        "the refusal for a transient lock prescribes the remedy that discards "
        "the replay history and invalidates every outstanding approval"
    )
    assert "Do NOT run" in reason, (
        "the refusal does not warn against the destructive remedy, which is "
        "what the previous message sent operators to"
    )
    assert "retry" in reason.lower(), (
        "the refusal does not tell the operator the one thing that works"
    )


def test_a_busy_ledger_does_not_spend_the_grant(tmp_path: Path):
    """Refusing for contention must leave the approval usable.

    The whole argument for 'retry' as the remedy is that nothing was consumed.
    If a contention refusal spent the grant, retrying would fail as
    APPROVAL_ALREADY_CONSUMED and the advice would be worse than useless.
    """
    path, _side = _ledger(tmp_path, spends=0)

    blocker = sqlite3.connect(path, timeout=1, isolation_level=None)
    try:
        blocker.execute("BEGIN EXCLUSIVE")
        refused, reason = ApprovalLedger(path).consume(
            "fp-retry", "rd-retry", at=NOW,
            grant_issued_at=GRANT_ISSUED, approval_id="ACT-RETRY",
        )
        assert refused is False, reason
    finally:
        blocker.close()

    claimed, reason = ApprovalLedger(path).consume(
        "fp-retry", "rd-retry", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-RETRY",
    )
    assert claimed is True, (
        "the retry the refusal recommends does not work: the grant was spent "
        f"by a refusal that released nothing: {reason}"
    )
