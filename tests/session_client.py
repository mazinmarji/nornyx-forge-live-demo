"""A shared authenticated TestClient for the gated onboarding surface.

Tranche B installs a control-plane session gate in `create_app`, so every route
but the four allowlisted ones (`GET /`, `GET /api/runtime`,
`POST /api/session/redeem`, `POST /api/runtime/reopen`) refuses a request that
does not carry `Authorization: Bearer <token>`. The tests here compose the app
themselves -- they ARE Forge, holding the token in memory exactly as the server
does -- so they present the token rather than route through the nonce/redeem
bootstrap a browser uses.

This is AUTHENTICATING, not bypassing the gate. Not a test-only escape hatch in
the surface: the token is read from `app.state.session`, the same object the
gate verifies against, and a request without it is refused. That refusal is the
subject of `tests/test_control_plane_session.py`; this helper is for every other
suite whose subject is the capsule, the journey or the runtime rather than the
gate, so those tests exercise the real gated composition while asserting the
behaviour they were written for.

NOT a test module (its name is `session_client`, not `test_*`), so pytest never
collects it and the census does not require it.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient


def session_token(app: FastAPI) -> str:
    """This run's bearer, read from the app the test composed."""
    return app.state.session.token


def bearer_header(app: FastAPI) -> dict[str, str]:
    return {"Authorization": f"Bearer {session_token(app)}"}


def authed_client(app: FastAPI, **kwargs: Any) -> TestClient:
    """A TestClient over `app` that carries the run's bearer on every request.

    `kwargs` pass through to `TestClient` (e.g. `base_url`,
    `raise_server_exceptions`), so callers keep whatever they set before.
    """
    client = TestClient(app, **kwargs)
    client.headers.update(bearer_header(app))
    return client
