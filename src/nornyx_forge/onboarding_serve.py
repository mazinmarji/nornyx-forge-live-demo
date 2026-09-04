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

THE HOST RULE: the composition answers only to a loopback Host header --
`127.0.0.1` or `localhost` -- and refuses any other with 400 before a route
runs. A page the person is looking at could otherwise rebind a name it
controls to 127.0.0.1 and reach this surface from their browser as if it
were them (measured under the PR-18 review). The rule lives HERE, at the one
composition every production launch path serves: the console `onboard` path
runs this module's `main`, and the Windows runtime receives `assemble`
through its default seam, so neither launcher has to remember the policy on
its own. It is a Host-header check and nothing more: the surface remains the
single-person, loopback, unauthenticated surface A-015 describes, and
nothing here authenticates the person at the browser.

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
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from .capsule_store import DEFAULT_SEAL_DIR
from .onboarding_app import create_app
from .subject_bootstrap import resolve_packaged_root

#: The one address the onboarding surface may bind. Loopback, by doctrine.
ONBOARDING_HOST = "127.0.0.1"

#: The Host identities the composition answers to, and no other: the bound
#: address and the name that resolves to it. Not `*`, not a LAN address, and
#: not the test client's default `testserver` -- a production rule is not
#: widened for a test's convenience; the tests carry a loopback base URL.
ONBOARDING_HOSTS = ("127.0.0.1", "localhost")

#: Where Forge keeps each project's authority seal: outside every project
#: directory, in Forge's own place beside the reviewer trust store. A seal
#: inside the provider's workspace would seal nothing; this one is out of a
#: workspace-write sandbox's reach and inside the same operating-system user's
#: reach, which is the bound capsule_store states.
SEAL_DIR = DEFAULT_SEAL_DIR


def assemble(project_dir: Path) -> FastAPI:
    """The onboarding app over an explicitly chosen project directory."""
    chosen = Path(project_dir)
    if not chosen.is_absolute():
        raise ValueError(
            "the project directory must be absolute: a relative path would "
            "let the launch directory select project authority, which is the "
            "FORGE_ROOT defect wearing different clothes"
        )
    # No `eligibility` is passed: the served surface decides governed
    # eligibility by the Provider Contract's own function and nothing else.
    application = create_app(
        chosen / "capsule",
        resolve_packaged_root() / ".nornyx" / "contracts",
        seal_dir=SEAL_DIR,
    )
    application.state.project_dir = str(chosen)
    # THE HOST RULE (module docstring), installed once, here, on the
    # composition every production launch path serves.
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ONBOARDING_HOSTS))
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
