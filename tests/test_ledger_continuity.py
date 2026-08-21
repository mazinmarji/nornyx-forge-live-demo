"""A spent grant is never released again, whatever the sidecar holds.

WHY THIS MODULE EXISTS, and it is not a pleasant reason.

The high-water sidecar was repaired twice. After the second repair a review
measured:

    grep -rn "LedgerContinuityUnknown" tests/ scripts/   ->  0
    grep -rn "LedgerContinuityUnknown" src/              ->  4

and coverage showed the `except LedgerContinuityUnknown` handler, BOTH `raise`
sites, the whole of `_adopt_plaintext_mark`, and the writer's failure path all
unexecuted -- under a fully green suite, with 123 tests covering this exact
subject passing. The remediation for a P1 shipped with no proof it worked and
no proof it would keep working.

Which is why the P1 survived it. A zero-byte sidecar -- the state
`sqlite3.connect()` leaves before writing a single page, i.e. what a crash
during the sidecar's own first write produces -- took the "unmarked, therefore
bootstrap" branch and returned None. None means compare nothing. Measured end
to end through the real boundary: one human approval, the ledger restored from
a backup, and the spent grant RELEASED THE EFFECT AGAIN -- then every other
forgotten grant in turn, because the mark re-bootstraps at the rolled-back
count.

So this module drives the SIDECAR STATE SPACE through `consume`, which is the
production path, and asserts the property rather than the diagnostic: after
history is lost, a grant that was already spent must not release, whatever the
sidecar happens to contain. The states are enumerated because the file system
offers finitely many shapes here; the CONTROLS are the load-bearing part,
because every assertion below is satisfiable by a ledger that refuses
everything.
"""

from __future__ import annotations

import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from signing import GRANT_ISSUED, LEDGER_ESTABLISHED  # noqa: E402

from nornyx_forge.nornyx_runtime import (
    LEDGER_CONTINUITY_UNKNOWN,
    LEDGER_ROLLED_BACK,
    ApprovalLedger,
)

NOW = "2026-08-03T00:00:00Z"


def _spend(ledger: ApprovalLedger, index: int) -> bool:
    claimed, _reason = ledger.consume(
        f"fp-{index}", f"rd-{index}", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id=f"ACT-{index}",
    )
    return claimed


def _rows(path: Path) -> int:
    with closing(sqlite3.connect(path)) as conn:
        return int(
            conn.execute("SELECT count(*) FROM consumed_approvals").fetchone()[0]
        )


def _checkpoint(path: Path) -> None:
    """Fold the WAL in, so copying the main file really is a restore.

    Without this, SQLite replays the `-wal` and the backup silently keeps the
    history it was supposed to have lost -- the test would then pass while
    measuring nothing at all.
    """
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for suffix in ("-wal", "-shm"):
        sibling = path.with_name(path.name + suffix)
        if sibling.exists():
            sibling.unlink()


def _rolled_back_ledger(tmp_path: Path) -> tuple[Path, Path]:
    """Six grants spent, history restored to one. Returns (ledger, sidecar)."""
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    ledger = ApprovalLedger(path)
    assert _spend(ledger, 0), "the first grant did not release; setup is broken"

    _checkpoint(path)
    backup = tmp_path / "backup.sqlite3"
    shutil.copy2(path, backup)

    for index in range(1, 6):
        assert _spend(ledger, index), f"grant {index} did not release"
    assert _rows(path) == 6

    _checkpoint(path)
    shutil.copy2(backup, path)
    assert _rows(path) == 1, "the restore did not actually lose history"
    return path, path.with_name(path.name + ".highwater")


# --------------------------------------------------------------------------
# The sidecar state space. Each entry installs one on-disk shape.
# --------------------------------------------------------------------------

def _absent(side: Path) -> None:
    if side.exists():
        side.unlink()


def _zero_length(side: Path) -> None:
    side.write_bytes(b"")


def _valid_db_no_table(side: Path) -> None:
    side.unlink(missing_ok=True)
    sqlite3.connect(side).close()


def _valid_db_no_row(side: Path) -> None:
    side.unlink(missing_ok=True)
    with closing(sqlite3.connect(side)) as conn:
        conn.execute(
            "CREATE TABLE high_water (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)"
        )


def _text_value(side: Path) -> None:
    side.unlink(missing_ok=True)
    with closing(sqlite3.connect(side)) as conn:
        conn.execute("CREATE TABLE high_water (id INTEGER PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO high_water (id, value) VALUES (1, 'lots')")
        conn.commit()


def _null_value(side: Path) -> None:
    side.unlink(missing_ok=True)
    with closing(sqlite3.connect(side)) as conn:
        conn.execute("CREATE TABLE high_water (id INTEGER PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO high_water (id, value) VALUES (1, NULL)")
        conn.commit()


def _plaintext(side: Path) -> None:
    side.unlink(missing_ok=True)
    side.write_bytes(b"6")


def _plaintext_garbage(side: Path) -> None:
    side.unlink(missing_ok=True)
    side.write_bytes(b"not a number at all")


def _torn_bytes(side: Path) -> None:
    side.unlink(missing_ok=True)
    side.write_bytes(b"SQLite format 3\x00" + b"\x00" * 4)


def _directory(side: Path) -> None:
    if side.exists() and side.is_file():
        side.unlink()
    side.mkdir(exist_ok=True)


def _hostile_trigger(side: Path) -> None:
    """A trigger that silently discards every advance of the mark.

    The LEDGER's object set is closed by `_assert_ledger_structure` and re-run
    at claim time, because "the next hostile object is the one nobody
    enumerated". None of that applied to the sidecar, which carries exactly as
    much weight for the replay decision. A review froze the mark at 0 across six
    consumptions this way and then released a spent grant from a restore.
    """
    with closing(sqlite3.connect(side)) as conn:
        conn.execute(
            "CREATE TRIGGER freeze BEFORE UPDATE ON high_water"
            " BEGIN SELECT RAISE(IGNORE); END"
        )
        conn.commit()


def _two_marks(side: Path) -> None:
    """A `high_water` table rebuilt WITHOUT `CHECK (id = 1)`, holding two rows.

    `fetchone()` answers the first, so `(1, 0)` beside `(2, 6)` reads as 0 --
    the exact defect `_read_established_at` was repaired for, un-repaired one
    file over.
    """
    with closing(sqlite3.connect(side)) as conn:
        conn.execute("DROP TABLE IF EXISTS high_water")
        conn.execute("CREATE TABLE high_water (id INTEGER, value INTEGER)")
        conn.execute("INSERT INTO high_water (id, value) VALUES (1, 0)")
        conn.execute("INSERT INTO high_water (id, value) VALUES (2, 6)")
        conn.commit()


SIDECAR_STATES = [
    ("absent", _absent),
    ("zero length", _zero_length),
    ("valid db, no high_water table", _valid_db_no_table),
    ("valid db, table but no row", _valid_db_no_row),
    ("value is TEXT", _text_value),
    ("value is NULL", _null_value),
    ("legacy plain-text mark", _plaintext),
    ("plain text that is not a number", _plaintext_garbage),
    ("torn SQLite header", _torn_bytes),
    ("sidecar is a directory", _directory),
    ("a trigger freezing the mark", _hostile_trigger),
    ("two high_water rows", _two_marks),
]


@pytest.mark.parametrize(("label", "install"), SIDECAR_STATES, ids=lambda v: v)
def test_a_spent_grant_is_never_released_again_whatever_the_sidecar_holds(
    label: str, install, tmp_path: Path
) -> None:
    """The property, not the diagnostic.

    WHICH refusal arrives is an operator-facing detail and differs by state:
    a readable mark above the row count gives LEDGER_ROLLED_BACK, an unreadable
    one gives LEDGER_CONTINUITY_UNKNOWN, and a grant older than a re-anchored
    ledger gives GRANT_PREDATES_LEDGER. Asserting a particular code here would
    make this a test of wording. What may never happen is a release.
    """
    path, side = _rolled_back_ledger(tmp_path)
    install(side)

    claimed, reason = ApprovalLedger(path).consume(
        "fp-3", "rd-3", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-3",
    )
    assert claimed is False, (
        f"sidecar state {label!r}: a grant that was already spent RELEASED THE "
        "EFFECT AGAIN after replay history was rolled back. One human approval, "
        f"two effects. Reason given: {reason!r}"
    )


@pytest.mark.parametrize(("label", "install"), SIDECAR_STATES, ids=lambda v: v)
def test_no_sidecar_state_permanently_bricks_a_healthy_ledger(
    label: str, install, tmp_path: Path
) -> None:
    """Failing closed must not mean failing forever.

    A refusal that cannot be cleared is an availability defect, and this
    repository has already shipped one: a sidecar shape that could never be
    written again silently disabled the check it fed. `provision-ledger
    --reset-replay-history` is the documented route out, so it must actually
    work from every state -- which is also the only thing that keeps the
    refusals above from being free.
    """
    from nornyx_forge.nornyx_runtime import approval_ledger_path  # noqa: PLC0415

    path = approval_ledger_path(tmp_path.resolve())
    path.parent.mkdir(parents=True, exist_ok=True)
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    side = path.with_name(path.name + ".highwater")
    assert _spend(ApprovalLedger(path), 0)
    install(side)

    # THE SHIPPED COMMAND, NOT A COPY OF IT.
    #
    # This reimplemented the reset inline, under a docstring saying the reset
    # "must actually work from every state -- which is also the only thing that
    # keeps the refusals above from being free". A review mutated the real
    # command three ways -- `rmtree` back to `unlink` only, the `finally`
    # removed, and the entire body replaced by `pass` -- and this module stayed
    # at 25 passed for all three. A control that reimplements what it controls
    # is FG26, and it was committed in the module written to answer "no
    # executing proof".
    from typer.testing import CliRunner  # noqa: PLC0415

    from nornyx_forge.cli import app  # noqa: PLC0415

    result = CliRunner().invoke(
        app, ["provision-ledger", "--root", str(tmp_path),
              "--reset-replay-history"],
    )
    assert result.exit_code == 0, (
        f"sidecar state {label!r}: the documented reset command failed: "
        + str(result.exit_code) + " " + str(result.output)
    )

    # A GRANT ISSUED AFTER THE RESET, because the reset mints a NEW EPOCH and
    # every outstanding grant is supposed to predate it. The previous version
    # of this test re-provisioned inline with the fixture's pinned
    # `established_at`, which kept the epoch still and hid that entirely -- the
    # first thing driving the real command surfaced.
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415

    later = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    claimed, reason = ApprovalLedger(path).consume(
        "fp-fresh", "rd-fresh", at=later,
        grant_issued_at=later, approval_id="ACT-FRESH",
    )
    assert claimed is True, (
        f"sidecar state {label!r}: after the documented reset a FRESH grant "
        f"still could not release, so the ledger is permanently bricked: {reason!r}"
    )


# --------------------------------------------------------------------------
# CONTROLS. Without these, every assertion above is satisfied by a ledger that
# refuses everything, and the module would prove nothing at all.
# --------------------------------------------------------------------------


def test_the_control_a_healthy_ledger_releases_a_fresh_grant(tmp_path: Path) -> None:
    """If this fails, the refusals above are not evidence of anything."""
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    assert _spend(ApprovalLedger(path), 0) is True


def test_the_control_the_rollback_is_detected_when_the_sidecar_is_intact(
    tmp_path: Path,
) -> None:
    """The setup genuinely loses history AND is genuinely noticed.

    This is the arm that proves `_rolled_back_ledger` builds the state the
    parametrised tests think it builds. If the WAL checkpoint were wrong the
    restore would keep its history, every refusal above would arrive for the
    ordinary already-consumed reason, and the module would be green over a
    setup that never rolled anything back.
    """
    path, _side = _rolled_back_ledger(tmp_path)
    claimed, reason = ApprovalLedger(path).consume(
        "fp-3", "rd-3", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-3",
    )
    assert claimed is False
    assert LEDGER_ROLLED_BACK in reason, (
        "with an intact sidecar the rollback must be detected as a rollback, "
        f"not as something else: {reason!r}"
    )


def test_an_unreadable_sidecar_refuses_with_its_own_code(tmp_path: Path) -> None:
    """The coded refusal exists and is reachable through `consume`.

    Named separately from the property test because an operator acts on the
    code: LEDGER_CONTINUITY_UNKNOWN says the mark cannot be read, which is a
    different remedy from LEDGER_ROLLED_BACK. A review found this code had no
    executing test of any kind -- four assertions elsewhere name the constant,
    all of them about a missing `established_at`, a different cause entirely.
    """
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    assert _spend(ApprovalLedger(path), 0)
    side = path.with_name(path.name + ".highwater")
    side.unlink(missing_ok=True)
    side.write_bytes(b"not a database and not a number")

    claimed, reason = ApprovalLedger(path).consume(
        "fp-1", "rd-1", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-1",
    )
    assert claimed is False
    assert LEDGER_CONTINUITY_UNKNOWN in reason, reason
    assert "--reset-replay-history" in reason, (
        "the refusal does not name a remedy, and a refusal an operator cannot "
        "act on is how the previous wording sent people to re-provision, which "
        "measurably did not clear it"
    )


def test_provisioning_writes_the_mark_so_there_is_no_unmarked_window(
    tmp_path: Path,
) -> None:
    """The invariant, made true by construction instead of by argument.

    The first version of this repair reasoned: "a ledger holding rows
    necessarily had a mark written, so unmarked-over-non-empty is a
    contradiction". Running it showed the reasoning has a hole --
    `_record_consumptions` writes the mark AFTER the insert commits, so between
    those two moments a used ledger legitimately has none. Six concurrent
    first-time consumers measured five legitimate grants refused through that
    window.

    `provision` writing the mark closes it: the mark exists whenever the ledger
    does, so absence and emptiness stop being ambiguous and become what they
    look like. This test pins the property the repair now rests on.
    """
    path = tmp_path / "ledger.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    side = path.with_name(path.name + ".highwater")

    assert side.exists(), "provisioning did not create the mark"
    assert ApprovalLedger(path)._recorded_consumptions() == 0, (
        "a freshly provisioned ledger must record zero consumptions, not None; "
        "None is the ambiguous state this change exists to remove"
    )

    # And a truncated mark is now tampering even over an empty ledger, because
    # provisioning already wrote one.
    side.unlink()
    sqlite3.connect(side).close()
    assert side.stat().st_size == 0
    claimed, reason = ApprovalLedger(path).consume(
        "fp-first", "rd-first", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-FIRST",
    )
    assert claimed is False
    assert LEDGER_CONTINUITY_UNKNOWN in reason, reason


def test_concurrent_first_time_consumers_are_not_refused(tmp_path: Path) -> None:
    """The regression that forced the design, driven directly.

    Every one of these is a distinct, legitimate, never-before-seen grant on a
    freshly provisioned ledger. If the mark is not present from provisioning,
    the ones that reach `_recorded_consumptions` before the first mark write
    are refused -- measured as `1 == 6` before this was fixed.
    """
    import threading

    path = tmp_path / "race.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)

    barrier = threading.Barrier(6)
    granted: list = []
    lock = threading.Lock()

    def run(index: int) -> None:
        ledger = ApprovalLedger(path)
        barrier.wait()
        claimed, reason = ledger.consume(
            f"fp-race-{index}", f"rd-race-{index}", at=NOW,
            grant_issued_at=GRANT_ISSUED, approval_id=f"ACT-RACE-{index}",
        )
        with lock:
            granted.append((claimed, reason))

    threads = [threading.Thread(target=run, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    refused = [reason for claimed, reason in granted if not claimed]
    assert refused == [], (
        "distinct first-time grants were refused on a freshly provisioned "
        f"ledger: {refused}"
    )
    assert _rows(path) == 6


def test_provisioning_an_existing_ledger_does_not_mint_a_mark(tmp_path: Path) -> None:
    """The writer must not undo what the reader was taught.

    `_recorded_consumptions` treats an absent mark as REMOVAL. `provision`
    minted an absent mark at 0 whatever the ledger beside it held, so the state
    the reader calls tampering was the state the writer called first-time
    setup -- and the writer runs first.

    A review drove it with no adversary and no deletion, on the legacy-upgrade
    path the source itself names: a ledger with rows and no mark correctly
    refused; the DOCUMENTED `provision-ledger` command then reported
    `"action": "left_unchanged"` and wrote a mark of 0; the next restore
    released an already-spent grant, and then every other forgotten grant in
    turn.

    The refusal text warns that deleting the mark by hand would disable the
    check. The command one flag away did the same thing and reported `pass`.
    """
    path = tmp_path / "legacy.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    assert _spend(ApprovalLedger(path), 0)
    side = path.with_name(path.name + ".highwater")
    side.unlink()

    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)

    assert not side.exists(), (
        "re-provisioning an EXISTING ledger created a replay high-water mark. "
        "This call knows nothing about the history that ledger holds, so a "
        "mark it writes asserts a history it cannot have measured -- and a "
        "mark of 0 over a used ledger disables rollback detection entirely."
    )
    claimed, reason = ApprovalLedger(path).consume(
        "fp-0", "rd-0", at=NOW,
        grant_issued_at=GRANT_ISSUED, approval_id="ACT-0",
    )
    assert claimed is False, (
        "the already-spent grant released after the documented provisioning "
        f"command: {reason!r}"
    )
    assert LEDGER_CONTINUITY_UNKNOWN in reason, reason


def test_provisioning_a_new_ledger_still_mints_its_mark(tmp_path: Path) -> None:
    """The control. Without it the assertion above is satisfied by never
    minting at all, which would reopen the concurrent-first-consumer window
    that minting at provision time exists to close."""
    path = tmp_path / "fresh.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    side = path.with_name(path.name + ".highwater")
    assert side.exists(), "a NEW ledger was provisioned without its mark"
    assert ApprovalLedger(path)._recorded_consumptions() == 0
    assert _spend(ApprovalLedger(path), 0) is True


def test_the_mark_cannot_be_lowered_deterministically(tmp_path: Path) -> None:
    """The monotonicity guard, proved without a race.

    `test_a21_the_mark_keeps_up_with_overlapping_consumptions` is the only
    proof this guard had, and a review measured that removing the guard
    (`UPDATE ... WHERE value < ?` -> `UPDATE ...`) is detected in 3 RUNS OF 10.
    A security guard whose regression ships green seven times in ten is not
    proved.

    The concurrent test measures "the mark KEEPS UP", which needs a race. This
    measures "the mark is NEVER LOWERED", which does not: set it high, ask for
    lower, require it to refuse. Both are worth having; only one of them has to
    be nondeterministic.
    """
    path = tmp_path / "monotone.sqlite3"
    ApprovalLedger.provision(path, established_at=LEDGER_ESTABLISHED)
    ledger = ApprovalLedger(path)

    ledger._record_consumptions(9)
    assert ledger._recorded_consumptions() == 9

    ledger._record_consumptions(3)
    assert ledger._recorded_consumptions() == 9, (
        "the recorded consumption count was LOWERED. A mark that can go down "
        "is a mark a restore can rewrite, and the rollback check compares "
        "against it."
    )
    ledger._record_consumptions(12)
    assert ledger._recorded_consumptions() == 12, (
        "the mark refused to RISE, so the guard above is satisfied by a setter "
        "that never writes at all"
    )
