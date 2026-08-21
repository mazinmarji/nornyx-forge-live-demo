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


def test_no_kill_point_during_a_consumption_leaves_the_stores_disagreeing(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The sweep that reproduced A7-P1-2, run as a regression.

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


def test_the_kill_sweep_actually_reaches_the_write(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """The control. If every child died before touching anything, the sweep
    above would pass while measuring nothing at all."""
    reached = 0
    for kill_at in range(1, KILL_POINTS + 1):
        work = tmp_path_factory.mktemp("reach")
        path, side = _ledger(work, spends=2)
        child = _CHILD.format(src=str(ROOT / "src"), kill_at=kill_at,
                              path=str(path), now=NOW, gi=GRANT_ISSUED)
        subprocess.run(  # noqa: S603
            [sys.executable, "-c", child], capture_output=True, text=True,
            timeout=300, check=False)
        if _rows(path) == 3:
            reached += 1
    assert reached > 0, (
        "no kill point in the sweep left a committed consumption, so every "
        "child died before the write and the sweep proves nothing"
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
