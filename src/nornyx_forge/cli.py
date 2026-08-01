from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .development_flow import DevelopmentFlow
from .nornyx_runtime import prepare_runtime_contract
from .repo_qualifier import qualify_deep_remote, qualify_local, qualify_remote
from .repo_scout import scout as scout_repositories
from .requirements import parse_brd, profile_from_brd
from .util import write_json

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

        result = run_demo_scenarios(
            Path.cwd(),
            worker_mode=worker_mode,
            allow_policy_fallback=not strict_nornyx,
        )
        console.print_json(json.dumps(result))
        raise typer.Exit(0 if result["status"] == "pass" else 2)
    os.environ["FORGE_WORKER_MODE"] = worker_mode
    os.environ["FORGE_ALLOW_POLICY_FALLBACK"] = "false" if strict_nornyx else "true"
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "demo_app.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        str(port),
    ]
    os.execvp(command[0], command)


if __name__ == "__main__":
    app()
