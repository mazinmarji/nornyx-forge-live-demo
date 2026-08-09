"""Bounded adapter for starting the application server process.

`constraint.bounded_external_adapter` exists so that the set of places this
system can start a process is a short, declared list a reviewer can read. The
Forge CLI held an `os.execvp` directly, which was invisible while the CLI was
undeclared; extending architecture coverage surfaced it.

It is moved here rather than exempted. The composition-root exemption the CLI
carries is about layer *direction* only, and stretching it to cover process
execution as well would have left the adapter list incomplete — which is the
one thing this constraint is for.
"""

from __future__ import annotations

import os
import sys

APPLICATION_TARGET = "demo_app.main:app"


def launch_application(*, port: int, worker_mode: str) -> None:
    """Replace this process with the application server. Never returns.

    The application is named as a string rather than imported: this adapter
    starts the server, it does not depend on the application it starts.
    """
    # Worker mode is operational and stays an environment value. Governance
    # mode deliberately does not: it is bound into the subject, so passing it
    # ambiently would let the child process run a governance backend the
    # subject never attested to.
    os.environ["FORGE_WORKER_MODE"] = worker_mode
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        APPLICATION_TARGET,
        "--host",
        "0.0.0.0",
        "--port",
        str(port),
    ]
    os.execvp(command[0], command)
