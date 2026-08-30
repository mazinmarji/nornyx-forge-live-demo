"""Assemble and serve the onboarding surface. One command, no ambience.

THE SELECTION RULE, inherited from the FORGE_ROOT closure and applied
unchanged: the project directory an onboarding server operates on is
project AUTHORITY — the capsule's authoritative region lives under it —
so nothing ambient may select it. No environment variable, and no current
working directory either: `resolve_packaged_root`'s own doctrine calls the
launch directory "the same defect wearing different clothes", so a
RELATIVE project directory is refused here rather than resolved. The path
arrives as an explicit absolute argument — a decision a person made at
their console — and the contracts directory is derived structurally from
where the package is installed, exactly as the governed subject's root is.

THE BINDING RULE: the onboarding surface is a local, single-person,
unauthenticated surface (its module says so), so it listens on loopback
and nowhere else. Serving an unauthenticated authority surface on the LAN
would turn a disclosed local trust boundary into an undisclosed remote
one; the loopback constant is pinned by test.

`layer.application`: this module composes the app and runs the server
loop in the CURRENT process — uvicorn.run is an event loop, not a process
start. Starting the PROCESS that runs this module is the launcher
adapter's job, through the one declared exec site.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from .onboarding_app import create_app
from .subject_bootstrap import resolve_packaged_root

#: The one address the onboarding surface may bind. Loopback, by doctrine.
ONBOARDING_HOST = "127.0.0.1"


def assemble(project_dir: Path) -> FastAPI:
    """The onboarding app over an explicitly chosen project directory."""
    chosen = Path(project_dir)
    if not chosen.is_absolute():
        raise ValueError(
            "the project directory must be absolute: a relative path would "
            "let the launch directory select project authority, which is the "
            "FORGE_ROOT defect wearing different clothes"
        )
    application = create_app(
        chosen / "capsule",
        resolve_packaged_root() / ".nornyx" / "contracts",
    )
    application.state.project_dir = str(chosen)
    return application


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Serve the Forge onboarding surface")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--project-dir", required=True)
    arguments = parser.parse_args(argv)
    uvicorn.run(
        assemble(Path(arguments.project_dir)),
        host=ONBOARDING_HOST,
        port=arguments.port,
    )


if __name__ == "__main__":  # pragma: no cover - the child process entry
    main(sys.argv[1:])
