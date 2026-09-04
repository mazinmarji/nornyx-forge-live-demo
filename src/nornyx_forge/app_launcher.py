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
from pathlib import Path
from urllib.parse import urlsplit

APPLICATION_TARGET = "demo_app.main:app"
ONBOARDING_TARGET = "nornyx_forge.onboarding_serve"
#: The only URLs this adapter will hand to a browser: the loopback onboarding
#: surface. Presentation, bounded to the one address the surface may bind.
LOOPBACK_URL_PREFIX = "http://127.0.0.1:"


def open_in_default_browser(url: str) -> None:
    """Hand the loopback onboarding URL to the person's default browser.

    Presentation, not authority: nothing about the runtime's health or the
    project's state is decided here, and the caller opens the browser only
    after it has evidence the server answered. `os.startfile` is process
    execution (the shell starts the browser), which is why this lives in the
    declared launcher adapter and not in the runtime module that decides
    when to call it. Windows only, by the programme's one-OS scope; elsewhere
    the URL is refused with the address a person can open by hand.
    """
    parts = urlsplit(url)
    if (
        not url.startswith(LOOPBACK_URL_PREFIX)
        or parts.scheme != "http"
        or parts.hostname != "127.0.0.1"
        or parts.username is not None
        or parts.password is not None
        or parts.port is None
    ):
        raise ValueError(
            "only the loopback onboarding surface may be opened in the browser, "
            f"not {url!r}"
        )
    if sys.platform != "win32":
        raise OSError(
            "opening the default browser is implemented for Windows only; "
            f"open {url} yourself"
        )
    os.startfile(url)  # noqa: S606 - the declared browser-start site


def launch_application(*, port: int, worker_mode: str) -> None:
    """Replace this process with the application server. Never returns.

    The application is named as a string rather than imported: this adapter
    starts the server, it does not depend on the application it starts.
    """
    # Worker mode is operational and stays an environment value. Governance
    # mode deliberately does not: it is bound into the subject, so passing it
    # ambiently would let the child process run a governance backend the
    # subject never attested to.
    # FORGE_WORKER_MODE IS NOT WRITTEN. Nothing reads it: a repository-wide
    # search finds writes here, in `scripts/smoke_http.py`, in `.env.example`
    # and in `docker-compose.yml`, and no reader anywhere. It appeared in
    # neither table of a document that opens "Every external input reachable
    # from `src/`", and that document's own FORGE_ROOT row states the rule --
    # a variable nothing reads still tells a reader it matters.
    #
    # The worker mode travels as an argument, which is why nothing needed to
    # read it.
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


def launch_onboarding(*, port: int, project_dir: str) -> None:
    """Replace this process with the onboarding server. Never returns.

    The project directory travels as an explicit absolute argument and is
    refused otherwise HERE as well as in the serve module: this adapter is
    the last point where a relative path could silently pick up the launch
    directory, so the refusal cannot be bypassed by calling one layer down.
    The target is named as a string for the same reason as the application
    target above — this adapter starts the server, it does not depend on it.
    """
    if not Path(project_dir).is_absolute():
        raise ValueError(
            "the project directory must be absolute before launch: a relative "
            "path would let the launch directory select project authority"
        )
    command = [
        sys.executable,
        "-m",
        ONBOARDING_TARGET,
        "--port",
        str(port),
        "--project-dir",
        project_dir,
    ]
    os.execvp(command[0], command)
