from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .app_launcher import launch_application
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
) -> None:
    """Execute the governed development flow."""
    root = Path.cwd()
    flow = DevelopmentFlow(
        root,
        worker_mode=worker_mode,
        repo_mode=repo_mode,
        target_repo=target_repo,
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
    from .nornyx_runtime import ApprovalLedger, approval_ledger_path

    location = approval_ledger_path(root.resolve())
    existed = location.is_file()
    ledger = ApprovalLedger.provision(location)
    console.print_json(
        json.dumps(
            {
                "status": "pass",
                "ledger": str(ledger.path),
                "action": "left_unchanged" if existed else "created",
                "available": ledger.available,
            }
        )
    )


if __name__ == "__main__":
    app()
