from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .app_launcher import launch_application, launch_onboarding
from .development_flow import DevelopmentFlow
from .governed_subject import RuntimeAuthorityConfig
from .repo_qualifier import qualify_deep_remote, qualify_local, qualify_remote
from .repo_scout import scout as scout_repositories
from .requirements import parse_brd, profile_from_brd
from .runtime_preparation import prepare_runtime_contract
from .util import write_json


def _make_output_encoding_safe() -> None:
    """Stop the console's encoding from being able to crash a governed run.

    Reproduced on a Windows workstation: `sys.stdout.encoding` is `cp1252`, and
    writing `\\u2713` raises `UnicodeEncodeError: 'charmap' codec can't encode
    character`. CrewAI's event bus prints progress marks like that one, so
    selecting the CrewAI backend on a legacy console could abort the run partway
    through — after side effects, with a traceback about a checkmark rather than
    about anything that went wrong.

    Applied once at the interface boundary and process-wide, because the writer
    is a third-party library, not this code. `backslashreplace` rather than
    `replace`: a mangled character should still be legible as what it was, and
    evidence should never silently lose content to a display concern.

    Presentation only. Nothing here reaches an authorization decision, and every
    governed artifact is written as UTF-8 bytes through its own path regardless
    of what the terminal can render.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # a redirected or wrapped stream
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (OSError, ValueError):  # pragma: no cover - stream cannot be retuned
            pass


_make_output_encoding_safe()

app = typer.Typer(no_args_is_help=True, help="Nornyx Forge live-demo CLI")
console = Console()


@app.command()
def doctor() -> None:
    """Check local prerequisites and execution modes."""
    commands = ["git", "python", "docker", "claude", "nornyx"]
    table = Table("Tool", "Available", "Purpose")
    purposes = {
        "git": "repository revision binding",
        "python": "Forge and application runtime",
        "docker": "container launch",
        "claude": "Claude Code workers",
        "nornyx": "contract, lock, authorization, and evidence",
    }
    for command in commands:
        table.add_row(command, "yes" if shutil.which(command) else "no", purposes[command])
    console.print(table)


@app.command()
def qualify(
    repository: str = typer.Argument("."),
    brd: Path = typer.Option(Path("BRD.md"), exists=True, readable=True),
    deep: bool = typer.Option(False, help="Safely clone for structural inspection; never run its code."),
    output: Path = Path(".nornyx/qualification.json"),
) -> None:
    """Qualify one public or local repository against BRD-derived criteria."""
    profile = profile_from_brd(parse_brd(brd))
    path = Path(repository)
    if path.exists():
        report = qualify_local(path.resolve(), profile)
    elif deep:
        report = qualify_deep_remote(repository, profile)
    else:
        report = qualify_remote(repository, profile)
    write_json(output, report.to_dict())
    console.print_json(json.dumps(report.to_dict()))
    raise typer.Exit(0 if report.verdict in {"GO", "CONDITIONAL_GO"} else 2)


@app.command()
def scout(
    brd: Path = typer.Option(Path("BRD.md"), exists=True, readable=True),
    limit: int = 5,
    output: Path = Path(".nornyx/scout-results.json"),
) -> None:
    """Search GitHub and rank public foundations against the BRD."""
    profile = profile_from_brd(parse_brd(brd))
    reports = scout_repositories(profile=profile, limit=limit)
    write_json(output, reports)
    console.print_json(json.dumps(reports))
    raise typer.Exit(0 if reports else 2)


@app.command("prepare-runtime")
def prepare_runtime() -> None:
    """Generate and verify the Nornyx runtime lock and controls."""
    results = prepare_runtime_contract(Path.cwd())
    console.print_json(json.dumps([item.__dict__ for item in results], default=list))
    raise typer.Exit(0 if results and all(item.passed for item in results) else 2)


@app.command()
def onboard(
    port: int = typer.Option(8710, help="Loopback port for the onboarding page."),
    project_dir: Path = typer.Option(
        Path("forge-project"),
        help="Where this project's capsule lives. Resolved here, at your "
        "console, so the choice is yours and never the environment's.",
    ),
) -> None:
    """Open the Forge onboarding surface for one project. Never returns.

    The resolution below is the one place a relative path becomes absolute:
    an explicit decision at the human's console, per the FORGE_ROOT closure.
    Everything downstream refuses relative project directories outright.
    """
    launch_onboarding(port=port, project_dir=str(project_dir.resolve()))


@app.command("build")
def build_app(
    worker_mode: str = typer.Option(
        "deterministic",
        help="deterministic, in-session, or claude-code",
    ),
    repo_mode: str = typer.Option(
        "certified",
        help="certified, target, scout, or greenfield",
    ),
    target_repo: str | None = typer.Option(None),
    provider: str | None = typer.Option(
        None,
        help="Route engineering workers through a declared provider "
        "(codex or claude); requires --worker-mode claude-code.",
    ),
) -> None:
    """Execute the governed development flow."""
    root = Path.cwd()
    flow = DevelopmentFlow(
        root,
        worker_mode=worker_mode,
        repo_mode=repo_mode,
        target_repo=target_repo,
        provider=provider,
    )
    result = flow.run()
    console.print_json(json.dumps(result, default=list))
    raise typer.Exit(0 if result.get("accepted") else 2)


@app.command()
def demo(
    offline: bool = typer.Option(False),
    strict_nornyx: bool = typer.Option(False, help="Refuse deterministic policy fallback."),
    worker_mode: str = typer.Option("deterministic"),
    port: int = 8000,
) -> None:
    """Run demo scenarios or launch the application."""
    if offline:
        from demo_app.agentic import run_demo_scenarios

        from .nornyx_runtime import NornyxRuntimeUnavailable

        # Mode is parsed here, at the command boundary, into the typed config
        # that gets bound into the subject. `--strict-nornyx` selects the
        # governed backend, which refuses when Nornyx cannot authorize —
        # including when no human approval exists, as on this branch. The
        # default names the deterministic demo backend rather than relying on an
        # ambient fallback, so the run cannot claim Nornyx governance while
        # executing something else.
        config = RuntimeAuthorityConfig(
            policy_backend="nornyx" if strict_nornyx else "deterministic_demo",
            execution_backend="sequential",
        )
        try:
            result = run_demo_scenarios(
                Path.cwd(),
                worker_mode=worker_mode,
                config=config,
            )
        except NornyxRuntimeUnavailable as exc:
            # Fail closed and legibly: no capability was authorized, so nothing ran.
            console.print_json(
                json.dumps(
                    {
                        "status": "blocked",
                        "reason": "nornyx_runtime_unavailable",
                        "message": (
                            "Strict mode refused the deterministic fallback and the "
                            "Nornyx authorization path could not be established. "
                            "No case was processed and no action executed."
                        ),
                        "detail": exc.detail,
                        "assurance_mode": "autonomous_demonstration",
                        "human_review": "not_performed",
                        "production_approval": "not_granted",
                    }
                )
            )
            raise typer.Exit(2) from exc
        console.print_json(json.dumps(result))
        raise typer.Exit(0 if result["status"] == "pass" else 2)
    launch_application(port=port, worker_mode=worker_mode)


@app.command("provision-ledger")
def provision_ledger(
    root: Path = typer.Option(Path("."), help="Repository root the ledger serves."),
    migrate_continuity: bool = typer.Option(
        False,
        "--migrate-continuity",
        help=(
            "Convert the ledger and its continuity witness to the journal mode "
            "under which SQLite commits them as one unit. Preserves all "
            "history. Refuses if the two stores disagree, because a "
            "disagreement is the thing continuity exists to detect."
        ),
    ),
    reset_replay_history: bool = typer.Option(
        False,
        "--reset-replay-history",
        help=(
            "Discard the replay history AND its high-water mark, and establish "
            "a fresh epoch. Every outstanding grant then predates the new epoch "
            "and is refused; a NEW human approval is required."
        ),
    ),
) -> None:
    """Create the action-approval ledger. A deliberate operator step.

    Creation used to happen wherever the ledger was first touched, which meant
    deleting the file produced an empty one in which nothing had been spent —
    every previously consumed grant replayable again. Deleting a file is not an
    authorization decision. Provisioning is now separate and explicit, and the
    boundary refuses rather than creating what it is missing.

    Safe to re-run: an existing ledger is left exactly as it is, contents
    included.
    """
    from .nornyx_runtime import (
        LEDGER_WATERMARK_SUFFIX,
        ApprovalLedger,
        NornyxRuntimeUnavailable,
        approval_ledger_path,
    )

    location = approval_ledger_path(root.resolve())
    existed = location.is_file()
    if migrate_continuity:
        import sqlite3
        from contextlib import closing

        from .nornyx_runtime import (
            LEDGER_WATERMARK_SUFFIX,
            REQUIRED_JOURNAL_MODE,
            ROLLBACK_JOURNAL_MODES,
        )

        witness = location.with_name(location.name + LEDGER_WATERMARK_SUFFIX)
        if not location.is_file() or not witness.is_file():
            raise typer.BadParameter(
                f"both stores must exist to migrate: ledger "
                f"{'present' if location.is_file() else 'ABSENT'}, witness "
                f"{'present' if witness.is_file() else 'ABSENT'}. Use "
                "--reset-replay-history to establish a fresh epoch instead."
            )

        def _rows(path: Path, sql: str) -> int:
            with closing(sqlite3.connect(path)) as conn:
                return int(conn.execute(sql).fetchone()[0])

        # VERIFY BEFORE. A migration is not a repair: if the two stores already
        # disagree, converting them preserves the disagreement and hands back a
        # store that looks migrated and is still broken.
        before_rows = _rows(location, "SELECT count(*) FROM consumed_approvals")
        # EXACTLY ONE WITNESS ROW, READ IN FULL.
        #
        # This was `fetchone()[0]`, which returns whichever row SQLite yields
        # first and never looks at the rest. A witness holding two rows -- one
        # agreeing with the ledger and one not -- therefore migrated or refused
        # DEPENDING ON THE ORDER SQLITE HAPPENED TO RETURN. Measured on the
        # same two rows against a 2-row ledger:
        #
        #     (1, 99) then (2, 2)   fetchone -> 99   REFUSED
        #     (1, 2)  then (2, 99)  fetchone -> 2    status pass,
        #                                            action migrated_continuity
        #
        # The second left a witness still holding 99 in a store the command had
        # just called migrated. Which row comes first is not a property of the
        # data, so a verdict that turns on it is not a verdict.
        #
        # This is the ordering-dependent read that `_assert_witness_structure`
        # and the consumption re-read were each repaired for; the migration
        # path kept the original shape.
        # A PLAIN-TEXT WITNESS IS CONVERTED FIRST, because it is not a
        # database and the read below cannot ask it anything. This command
        # is what `LEDGER_CONTINUITY_MIGRATION_REQUIRED` tells the operator
        # to run, and on exactly that artifact it raised
        # `DatabaseError: file is not a database` and converted nothing --
        # leaving `--reset-replay-history`, which DISCARDS APPROVALS, as the
        # only command that cleared the state. The refusal named a remedy
        # that did not run, so the destructive one was the real advice.
        #
        # Agreement is checked BEFORE the conversion, against the same rule
        # the database path uses below: a mark that disagrees with the rows
        # is what continuity exists to detect, and converting it would
        # launder the disagreement into a store that looks migrated.
        # CONSTRUCTED BEHIND A GUARD. `ApprovalLedger(...)` runs the witness
        # structure check, which RAISES on a hostile witness -- so this line
        # reintroduced, in the sibling branch, exactly the traceback-instead-
        # of-status defect that `--reset-replay-history` below documents as
        # repaired. A review measured it: a witness carrying a trigger gave
        # exit 1 and a Python stack trace where this surface's stated
        # property is A GOVERNED REFUSAL, NOT A TRACEBACK.
        #
        # The plain-text reader is asked FIRST, because it needs no
        # structural check to answer: it reads bytes. A witness that is
        # neither a mark nor a usable database then falls through to the
        # database path below, which reports rather than raises.
        try:
            ledger = ApprovalLedger(location)
            legacy_mark = ledger.plaintext_witness_value()
        except NornyxRuntimeUnavailable as exc:
            raise typer.BadParameter(
                f"the continuity witness at {witness} cannot be read as a "
                f"store this command can convert: {exc}. Nothing was "
                "changed. Use --reset-replay-history to establish a fresh "
                "epoch."
            ) from exc
        if legacy_mark is not None:
            if before_rows != legacy_mark:
                raise typer.BadParameter(
                    f"the ledger holds {before_rows} consumptions and the "
                    f"pre-database mark records {legacy_mark}. They must "
                    "agree before they can be migrated; a disagreement is "
                    "what continuity exists to detect, and this command must "
                    "not paper over it. Use --reset-replay-history to "
                    "establish a fresh epoch."
                )
            if ledger.adopt_plaintext_witness() is None:
                raise typer.BadParameter(
                    f"the pre-database mark at {witness} could not be "
                    "converted to a continuity witness. Nothing was changed. "
                    "Use --reset-replay-history to establish a fresh epoch."
                )
        # The result is verified by the same read either way, which is what
        # the refusal promises: "converts it after checking that it agrees".
        with closing(sqlite3.connect(witness)) as conn:
            marks = conn.execute("SELECT id, value FROM high_water").fetchall()
        if len(marks) != 1:
            raise typer.BadParameter(
                f"the continuity witness holds {len(marks)} rows where exactly "
                f"one is required: {marks}. Which of them is the mark would "
                "depend on the order SQLite returned it, so this store cannot "
                "be migrated. Use --reset-replay-history to establish a fresh "
                "epoch."
            )
        before_mark = int(marks[0][1])
        if before_rows != before_mark:
            raise typer.BadParameter(
                f"the ledger holds {before_rows} consumptions and the witness "
                f"records {before_mark}. They must agree before they can be "
                "migrated; a disagreement is what continuity exists to detect, "
                "and this command must not paper over it. Use "
                "--reset-replay-history to establish a fresh epoch."
            )

        # NEITHER STORE IS LEFT CONVERTED IF BOTH CANNOT BE.
        #
        # The loop below took the ledger first and the witness second with no
        # guard. A review held ONE ordinary reader on the witness and ran the
        # remedy that LEDGER_CONTINUITY_MIGRATION_REQUIRED names: the ledger
        # converted, the witness raised `OperationalError: database is
        # locked` out of this function, the verify-after never ran, and the
        # command emitted no status at all -- exit 1, empty stdout, modes left
        # ['delete', 'wal'].
        #
        # A LOCK PRE-CHECK DOES NOT WORK HERE, and two versions of one were
        # written before this. `BEGIN IMMEDIATE` takes RESERVED, which a
        # reader does not block; `BEGIN EXCLUSIVE` does not conflict with a
        # reader in WAL at all. Both passed while the journal-mode change --
        # which must checkpoint and take the database file exclusively --
        # still failed. Probing at a different lock level than the operation
        # uses answers a different question, which is the same mistake as
        # measuring a property by a proxy for it.
        #
        # So the modes are RECORDED and RESTORED instead. That needs no
        # prediction about locks: whatever the first conversion did, the
        # second's failure undoes it, and the operator is told the state the
        # stores are actually in rather than left to infer it.
        stores = (("ledger", location), ("witness", witness))
        original_modes = {}
        for label, target in stores:
            with closing(sqlite3.connect(target, timeout=30)) as conn:
                original_modes[label] = str(
                    conn.execute("PRAGMA journal_mode").fetchone()[0]
                ).lower()
        converted = {}
        for label, target in stores:
            # GUARDED TOO, not only pre-checked. The pre-check and the
            # conversion are separate moments and a connection can arrive
            # between them; reporting both ways costs one handler and means
            # no interleaving turns this command into a stack trace.
            try:
                with closing(sqlite3.connect(target, timeout=30)) as conn:
                    conn.execute("PRAGMA busy_timeout=30000")
                    conn.execute(f"PRAGMA journal_mode={REQUIRED_JOURNAL_MODE}")
                    conn.execute("PRAGMA synchronous=FULL")
                    conn.commit()
                    converted[label] = str(
                        conn.execute("PRAGMA journal_mode").fetchone()[0]
                    ).lower()
            except sqlite3.Error as exc:
                restored, stranded = [], []
                for done in sorted(converted):
                    was = original_modes[done]
                    where = dict(stores)[done]
                    try:
                        with closing(
                            sqlite3.connect(where, timeout=30)
                        ) as undo:
                            undo.execute("PRAGMA busy_timeout=30000")
                            undo.execute(f"PRAGMA journal_mode={was}")
                            undo.commit()
                        restored.append(done)
                    except sqlite3.Error:  # pragma: no cover - rare
                        stranded.append(done)
                detail = (
                    " Restored: " + ", ".join(restored) + "."
                    if restored
                    else " Nothing had been converted yet."
                )
                if stranded:
                    detail += (
                        " COULD NOT RESTORE: " + ", ".join(stranded)
                        + " -- these are left converted and the pair is not"
                        " consistent. Run this command again."
                    )
                raise typer.BadParameter(
                    f"the {label} at {target} could not be converted: {exc}."
                    + detail
                    + " Run this command again once nothing else holds these"
                    " files open; the ledger keeps refusing until it"
                    " succeeds, and no approval is discarded by waiting."
                ) from exc

        # VERIFY AFTER, and by reading the file back rather than trusting the
        # statement that was just issued.
        wrong = {
            label: mode for label, mode in converted.items()
            if mode not in ROLLBACK_JOURNAL_MODES
        }
        if wrong:
            raise typer.BadParameter(
                "the journal mode could not be converted: "
                + ", ".join(f"{k}={v}" for k, v in sorted(wrong.items()))
                + ". A store still in WAL cannot commit with its sibling, so "
                "nothing has been made safe by this run."
            )
        after_rows = _rows(location, "SELECT count(*) FROM consumed_approvals")
        after_mark = _rows(witness, "SELECT value FROM high_water")
        if (after_rows, after_mark) != (before_rows, before_mark):
            raise typer.BadParameter(
                f"history changed during migration: rows {before_rows}->"
                f"{after_rows}, witness {before_mark}->{after_mark}. The "
                "migration must preserve history exactly."
            )
        typer.echo(json.dumps({
            "status": "pass",
            "action": "migrated_continuity",
            "journal_modes": converted,
            "consumptions_preserved": after_rows,
        }, indent=2))
        return

    if reset_replay_history:
        # THE REMEDY THE REFUSAL NAMES, made real. `LEDGER_ROLLED_BACK` used to
        # say "re-provision the ledger and obtain a fresh approval", and a
        # review measured that doing exactly that left the refusal standing --
        # `provision` never touched the mark, so the ledger stayed bricked. The
        # only action that cleared it was deleting the mark by hand, which
        # DISABLES the check and makes every forgotten grant replayable.
        #
        # A refusal that names an ineffective remedy is a governance record
        # stating a falsehood, which this runtime already refuses elsewhere. So
        # the remedy exists, it is explicit, and it is destructive on purpose:
        # it discards the history AND the mark together, then mints a later
        # epoch so nothing outstanding survives it.
        # THE PATH IS COMPUTED FROM THE STRING, NOT FROM A LEDGER OBJECT.
        # This read `ApprovalLedger(location).watermark_path`, and constructing
        # an `ApprovalLedger` runs the full structure check -- so on a ledger
        # carrying a hostile object the constructor raised
        # APPROVAL_LEDGER_UNREADABLE and this recovery died with an unhandled
        # traceback, having deleted nothing. A review measured exit 1 with the
        # ledger still in place.
        #
        # That is precisely backwards: the more broken the ledger, the more
        # certainly the destructive repair refused to run, leaving an operator
        # with no route but deleting files by hand -- and deleting the mark by
        # hand DISABLES the rollback check. The path is a string operation and
        # never needed to open anything.
        #
        # `.migrating` is the staging file `_adopt_plaintext_mark` moves into
        # place; a crash mid-migration can leave one, and a reset that left it
        # behind would hand the fresh epoch a stale artifact.
        # BY SHAPE, AND NEVER HALF-DONE.
        #
        # This called `unlink()` on each artifact in turn. A review left
        # `<ledger>.highwater.migrating` as a DIRECTORY -- a state that by
        # itself bricks the ledger, because `_adopt_plaintext_mark`'s
        # `staging.unlink()` then raises and every release refuses -- and
        # measured: exit 1, PermissionError, ledger GONE, mark GONE, nothing
        # re-provisioned. The old defect was "exit 1, nothing deleted"; the
        # repair turned it into "exit 1, everything deleted".
        #
        # A directory is a shape `unlink` cannot remove, and it is precisely
        # the shape that made the repair necessary. So removal handles both,
        # and provisioning happens in a `finally` -- a destructive recovery
        # that can leave the ledger absent is not a recovery.
        watermark = location.with_name(location.name + LEDGER_WATERMARK_SUFFIX)
        failures: list[str] = []
        try:
            for path in (location, watermark,
                         watermark.with_name(watermark.name + ".migrating")):
                for suffix in ("", "-wal", "-shm"):
                    sibling = path.with_name(path.name + suffix)
                    try:
                        if sibling.is_dir():
                            shutil.rmtree(sibling)
                        elif sibling.exists():
                            sibling.unlink()
                    except OSError as exc:
                        failures.append(f"{sibling}: {exc}")
        finally:
            ApprovalLedger.provision(location)
        if failures:
            raise typer.BadParameter(
                "the replay history was reset and the ledger re-provisioned, "
                "but these artifacts could not be removed and may still hold "
                "stale state: " + "; ".join(failures)
            )
        existed = False
    # A GOVERNED REFUSAL, NOT A TRACEBACK.
    #
    # `provision` refuses an existing ledger whose journal mode cannot commit
    # as one unit with its witness -- correctly, because converting it would
    # change replay-safety semantics for a caller who asked only to provision.
    # That refusal reached the operator as an UNHANDLED EXCEPTION: measured,
    # exit 1 with a Python traceback in stderr wrapping the message.
    #
    # The message itself is good and names the recovery command. Delivering it
    # as a crash is the defect: every other refusal on this surface is a JSON
    # report and a chosen exit code, and an operator parsing this output gets
    # a stack trace instead of a status.
    try:
        ledger = ApprovalLedger.provision(location)
    except NornyxRuntimeUnavailable as exc:
        console.print_json(
            json.dumps(
                {
                    "status": "fail",
                    "ledger": str(location),
                    "action": "refused",
                    "reason": str(exc),
                }
            )
        )
        raise typer.Exit(2) from exc
    console.print_json(
        json.dumps(
            {
                "status": "pass",
                "ledger": str(ledger.path),
                "action": (
                    "reset" if reset_replay_history
                    else ("left_unchanged" if existed else "created")
                ),
                "available": ledger.available,
            }
        )
    )


if __name__ == "__main__":
    app()
