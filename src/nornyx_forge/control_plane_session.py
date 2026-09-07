"""The control-plane session: one per-run bearer, and the gate that enforces it.

WHAT THIS IS FOR. Tranche B closes the loopback half of A-024. Forge's
onboarding surface is local and unauthenticated, and PA-01 measured that a
Codex worker confined to the project workspace still reaches loopback and its
POST is accepted under the Host rule (`docs/governance/CODEX_CONFINEMENT_MEASUREMENT.md`).
The Host rule defends against a browser rebinding a name to 127.0.0.1; it does
not stop a local process. So a process that can open a socket to loopback --
the provider Forge starts during a build, or one that survived an earlier run
-- can drive `/api/journey/ready`, `/api/proposals/{id}/confirm`,
`/api/journey/restore`, `/api/build` and `/api/runtime/stop` as if it were the
person. This module makes loopback reachability irrelevant: the surface admits
a request only when it carries this run's bearer, and the bearer is minted at
server start, held in Forge's process memory and the human's page, and
deliberately excluded from everything the provider can read (A-027).

WHY IT LIVES IN THE DOMAIN, and imports no web framework. The gate is a pure
ASGI callable -- it reads `scope`, decides, and either passes the request
through untouched or sends a fixed refusal. It holds no I/O beyond `hmac`,
`secrets`, `time` and `threading`, so `scripts/check_architecture.py` places it
in `layer.domain` with no process-execution capability, and its `forbidden`
map names this file: an import of `fastapi`, `starlette`, `uvicorn` or
`subprocess` here is a gate violation, not a convention (measured under the
third review: before the entry existed, an injected `import fastapi` passed).
`create_app` installs it as the outermost user middleware
of the onboarding app, so it wraps every route -- the ones `create_app` defines
AND the operational routes `attach_runtime_routes` adds later -- and an app
composed without a session refuses everything by construction (INV-B7): there
is no session to verify against, so no non-allowlisted request can carry a
matching bearer.

THE TWO SECRETS, and the boundary against the provider (A-027, INV-B2).

  * The token (`secrets.token_urlsafe(32)`) is the bearer. It is presented as
    `Authorization: Bearer <token>` -- exactly one space, nothing else, and
    the SCHEME NAME compared case-insensitively, which `_bearer` does
    (`bearer` and `BEARER` are accepted; nothing else about the shape is lax).
    The case rule is RFC 7235 SS2.1's, for every auth scheme, and RFC 6750
    inherits it for Bearer rather than stating it; round 6 cited 6750 alone
    (round-6 security, informational). "Exactly `Bearer <credential>`" read as
    a case-sensitive rule and was not one (round-5 security P4). It is
    compared as BYTES with `hmac.compare_digest`. It exists only here, in
    `app.state.session`, and -- once redeemed -- in the page's JavaScript
    closure. Forge sets no cookie and writes it to no default path: the
    profile's ACLs grant `CodexSandboxUsers` read over the runtime dir, the
    seal dir and browser storage (A-027), so a secret on any of those is a
    secret the provider can read. The only file that ever carries the token is
    the explicit, fenced `--session-file` a smoke or a test asks for, on a
    path the shipped launchers never pass.

  * The nonces (`token_urlsafe(32)`, TTL-bounded, single-use, consumed under a
    lock) are the bootstrap. There are TWO independent slots: `launch`, minted
    once at readiness for the page the launcher opens, and `reopen`, minted by
    the reopen route for the page it opens. A launch mint replaces the previous
    launch nonce and nothing else, so a local process calling reopen cannot
    invalidate the human's pending launch bootstrap (measured under review: a
    single slot let it). A reopen mint replaces NOTHING: reopen nonces QUEUE,
    oldest first, up to `REOPEN_PENDING_BOUND`, because the reopen route is
    unauthenticated and any local caller may hit it once per interval, and a
    single reopen slot let such a caller invalidate the nonce the person's own
    Reconnect had just minted (measured under the third review: person
    Reconnect 200, local reopen at t+11 s 200, person's redeem 404). The bound
    is the most mints the route's rate limit admits within one nonce's
    lifetime, so under that limit no unexpired nonce is ever evicted; a direct
    `mint` past the bound evicts the oldest. The launcher opens
    `.../#<nonce>`; a URL fragment is never sent to the server, so it does not
    reach the access log that `windows_runtime._log_to` gives a FileHandler.
    The page reads `location.hash`, redeems the nonce for the token once, and
    replaces the URL.

CREDENTIALS ARE ASCII, COMPARED AS BYTES. Both secrets are drawn from the
URL-safe base64 alphabet, so a presented value outside that alphabet is not a
credential and is refused before any comparison. Review measured why this
matters: `hmac.compare_digest` raises `TypeError` on a non-ASCII `str`, and
headers arrive decoded as latin-1, so `Authorization: Bearer \\xff` produced a
500 and a traceback in the runtime log per request. Now nothing inside the
gate's own logic can raise: an exception there becomes the fixed 401.

THE ALLOWLIST is exact method+path. `GET /` serves the static shell that has no
token; `GET /api/runtime` is the operational identity a launcher probes;
`POST /api/session/redeem` trades a valid nonce for the token; and
`POST /api/runtime/reopen` lets a second launcher, or the page's Reconnect,
ask the OWNING process to mint a fresh nonce and open the browser -- the caller
never receives the token, only a browser window opens on the human's Forge.
Everything else, known path or not, any other method on these paths included,
needs the bearer. Non-HTTP scopes never reach the router: `lifespan` passes
through, a `websocket` handshake is closed before it is accepted, and any
other scope type is dropped.
"""

from __future__ import annotations

import hmac
import json
import secrets
import threading
import time
from collections import deque
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Mapping

#: The bootstrap nonce's time to live, in seconds. Short: the launcher opens
#: the page immediately, and a nonce that outlived the launch would be a second
#: standing credential for no reason. A nonce is valid through the instant
#: `mint + NONCE_TTL_S` inclusive and dead after it.
NONCE_TTL_S = 120.0

#: The two independent nonce slots. `launch` is minted once at readiness for
#: the page the launcher opens; `reopen` is minted by the reopen route. A
#: launch mint replaces the previous launch nonce; a reopen mint queues.
LAUNCH_SLOT = "launch"
REOPEN_SLOT = "reopen"
NONCE_SLOTS = frozenset({LAUNCH_SLOT, REOPEN_SLOT})

#: How many reopen nonces may be outstanding at once. The reopen route admits
#: one mint per `windows_runtime.REOPEN_INTERVAL_S` (10 s), and a nonce lives
#: `NONCE_TTL_S` (120 s) inclusive of its expiry instant, so within one nonce's
#: lifetime the limiter admits at most floor(120 / 10) + 1 = 13 mints (at
#: t = 0, 10, ..., 120): a queue this deep evicts nothing that the limiter
#: could still have left valid. Pinned against both constants by
#: `test_the_reopen_queue_bound_is_what_the_rate_limit_admits_in_one_ttl`.
REOPEN_PENDING_BOUND = 13

#: The depth of each slot's queue. The launch slot holds ONE nonce, so a
#: second launch mint replaces the first (INV-B6); the reopen slot holds the
#: bound above.
_SLOT_BOUNDS: Mapping[str, int] = MappingProxyType({LAUNCH_SLOT: 1, REOPEN_SLOT: REOPEN_PENDING_BOUND})

#: The alphabet `secrets.token_urlsafe` draws from. A presented credential
#: outside it is refused before comparison: it cannot be a secret this module
#: minted, and it is exactly the input that made the comparison primitive
#: raise (non-ASCII text) under review.
_CREDENTIAL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

#: The allowlisted paths, named once so the routes that serve them import the
#: same strings rather than restating them: a drift between the gate and a route
#: would either publish an authority route unguarded or make the redeem route
#: unreachable, so `onboarding_app` and `windows_runtime` take these constants.
PAGE_PATH = "/"
RUNTIME_PATH = "/api/runtime"
REDEEM_PATH = "/api/session/redeem"
REOPEN_PATH = "/api/runtime/reopen"

#: The routes reachable without the bearer, as exact (method, path) pairs.
#: Everything else -- every other method on these paths included -- is gated.
ALLOWLIST = frozenset({
    ("GET", PAGE_PATH),
    ("GET", RUNTIME_PATH),
    ("POST", REDEEM_PATH),
    ("POST", REOPEN_PATH),
})

#: The two unauthenticated POST routes carry browser-provenance checks, because
#: they are the only writes a page without the token may make.
ORIGIN_CHECKED = frozenset({REDEEM_PATH, REOPEN_PATH})

#: Fixed refusal bodies. Each echoes NOTHING of the request: a body that
#: reflected a header or the submitted value would hand an attacker a channel
#: and the surface an XSS vector. They are the whole vocabulary of the gate.
#: Read-only views, so no route or handler can grow one in place: a shared
#: module dict that a handler mutated would be served to every later caller.
NO_SESSION: Mapping[str, str] = MappingProxyType({"refused": "no session for this Forge instance"})
COOKIE_REFUSED: Mapping[str, str] = MappingProxyType(
    {"refused": "Forge sets no session cookie; this request carried one"})
CROSS_ORIGIN: Mapping[str, str] = MappingProxyType(
    {"refused": "this request did not come from this Forge instance's page"})

#: The nonce redemption failure body, returned by the redeem route (not the
#: gate) when a nonce is invalid, expired or already used.
NONCE_INVALID: Mapping[str, str] = MappingProxyType(
    {"refused": "this start link is no longer valid; start Forge again"})

#: The RequestValidationError body the app installs: no `input`, no `ctx`, so a
#: malformed body is never reflected.
BAD_SHAPE: Mapping[str, str] = MappingProxyType(
    {"refused": "the request did not have the shape this route accepts"})

#: The close code a websocket handshake receives: there is no session on a
#: websocket, so none is ever accepted. 4401 is in the application range.
WEBSOCKET_REFUSED_CODE = 4401

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


def _credential_bytes(value: Any) -> bytes | None:
    """`value` as ASCII bytes if it is a non-empty `str` drawn from the
    URL-safe base64 alphabet; otherwise None. This is the ONLY road into a
    comparison, so nothing that is not a well-formed credential is ever
    compared -- and nothing the comparison primitive rejects reaches it."""
    if not isinstance(value, str) or not value:
        return None
    if not all(character in _CREDENTIAL_ALPHABET for character in value):
        return None
    return value.encode("ascii")


class ControlPlaneSession:
    """One run's bearer token, and its single-use bootstrap nonces.

    Every secret is minted with `secrets.token_urlsafe(32)`; every comparison
    is constant-time over bytes. A nonce lives in one of two slots. The
    `launch` slot holds one nonce, replaced by the next launch mint; the
    `reopen` slot is a queue of up to `REOPEN_PENDING_BOUND`, oldest evicted
    first, so one caller's reopen does not invalidate another's pending
    nonce. Every nonce expires `ttl` seconds after its mint and is consumed
    only by a correct `redeem` -- a wrong guess neither matches nor
    invalidates any outstanding nonce, so a process that can spray guesses
    cannot lock the human out by exhausting one.

    `clock` defaults to `time.monotonic` as resolved WHEN the session is
    constructed, so a composition root that constructs one with no clock
    argument -- `create_app` -- runs on the clock in force at that moment,
    which is what lets a test prove the default TTL against an injected one.
    """

    def __init__(self, *, ttl: float = NONCE_TTL_S,
                 clock: Callable[[], float] | None = None) -> None:
        self._token = secrets.token_urlsafe(32)
        self._token_bytes = self._token.encode("ascii")
        self._ttl = ttl
        self._clock = time.monotonic if clock is None else clock
        self._lock = threading.Lock()
        #: slot -> its pending (nonce bytes, expiry) entries, oldest first,
        #: bounded by `_SLOT_BOUNDS`; an empty queue: nothing outstanding.
        self._nonces: dict[str, deque[tuple[bytes, float]]] = {
            slot: deque(maxlen=bound) for slot, bound in _SLOT_BOUNDS.items()}

    @property
    def token(self) -> str:
        return self._token

    def mint(self, slot: str = LAUNCH_SLOT) -> str:
        """A fresh single-use nonce in `slot`. In the launch slot it replaces
        the previous launch nonce and no other; in the reopen slot it joins the
        queue, evicting the oldest reopen nonce only past `REOPEN_PENDING_BOUND`.
        `slot` is `launch` or `reopen`; anything else is a programming error,
        refused loudly."""
        if slot not in NONCE_SLOTS:
            raise ValueError(f"unknown nonce slot {slot!r}; expected one of {sorted(NONCE_SLOTS)}")
        nonce = secrets.token_urlsafe(32)
        with self._lock:
            self._nonces[slot].append((nonce.encode("ascii"), self._clock() + self._ttl))
        return nonce

    def redeem(self, nonce: Any) -> str | None:
        """The token if `nonce` is an outstanding, unexpired nonce of either
        slot; else None.

        A correct redemption consumes exactly the nonce presented (it is
        single-use); an expired nonce is discarded; a wrong guess does neither,
        so it cannot be used to invalidate a real nonce. A value that is not a
        well-formed credential is refused before any comparison. Comparison
        is constant-time over bytes.

        WHAT IS PINNED, exactly (an AST test, because a lexical pin let a
        swapped-operand `==` through twice), in four rules:

          1. No `==`, `!=`, `in` or `not in` OPERATOR appears in this method
             or in `verify`.
          2. No REFERENCE to `__eq__`, `__ne__`, `__contains__` or their
             `operator` spellings appears in either -- as an attribute, as a
             bare name, as a dunder string literal at all, or as a LITERAL
             string handed to `getattr`/`attrgetter`/`methodcaller`. Those
             three carry a stricter rule of their own: a name handed to them
             that is not a string literal is refused OUTRIGHT, whatever it
             would evaluate to, because a computed name is unreadable and so
             could be any name (round-7 finding F-2(a):
             `methodcaller('__e' + 'q__', ...)` survived a reader that matched
             only the literal). `getattr(x, "spam")` -- a literal that is not
             a comparison -- is still allowed.
          3. This module BINDS no such comparison by import, at any scope.
             The rule is written on the `ast.alias`, so the imported object's
             own name is what is read and no rename escapes it (round-6 test
             T-P3-1: `from operator import eq as _same` at module scope, used
             inside `verify`, names nothing forbidden at the call site).
          4. `verify` and `redeem` reach EXACTLY ONE module-scope callable --
             `_credential_bytes` -- and its comparisons are enumerated too
             (round-7 finding F-2(b): a module-scope `def _same(a, b): return
             a == b` called from `verify` is neither an operator in the
             method nor an import). The comparison cannot be delegated
             outward, and it cannot be hidden inside the one helper that is
             reachable.

        "Reference", not "call": reading only calls let
        `checker = candidate.__eq__` followed by `checker(...)` through,
        because the call site names nothing (round-5 test P3-b), just as
        reading only `ast.Compare` let the call spellings through a round
        earlier (round-4 test P3). The pin is SPELLING-BASED and says so where
        it lives: it cannot prove constant time, it forbids the spellings that
        reintroduce a short-circuit. The ORDERING comparison `now > expires`
        below is deliberately outside rule 1 and is not covered by it: it
        reads the clock against a stored expiry, neither of which is a
        secret. An earlier draft of this docstring claimed "no equality,
        inequality or membership comparison at all", which reads as covering
        `>` and was false of the line three below it.
        """
        candidate = _credential_bytes(nonce)
        matched = False
        with self._lock:
            now = self._clock()
            for pending in self._nonces.values():
                kept: deque[tuple[bytes, float]] = deque(maxlen=pending.maxlen)
                for outstanding, expires in pending:
                    if now > expires:
                        continue  # expired: discarded, whatever was presented
                    if (not matched and candidate is not None
                            and hmac.compare_digest(candidate, outstanding)):
                        matched = True  # consumed: the one entry not kept
                        continue
                    kept.append((outstanding, expires))
                pending.clear()
                pending.extend(kept)
        return self._token if matched else None

    def verify(self, token: Any) -> bool:
        """True when `token` is this run's bearer. Constant-time over bytes; a
        value that is not a well-formed credential is False without comparison."""
        candidate = _credential_bytes(token)
        if candidate is None:
            return False
        return hmac.compare_digest(candidate, self._token_bytes)


def _headers(scope: Scope) -> dict[str, str]:
    """The request headers, lowercased, repeats joined with ', ' as HTTP does."""
    collected: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", []):
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        collected[name] = f"{collected[name]}, {value}" if name in collected else value
    return collected


def _bearer(authorization: str | None) -> str | None:
    """The credential in an `Authorization: Bearer <credential>` header, or None.

    Strict: exactly `<scheme> <credential>` -- one space, no leading or
    trailing whitespace, no further fields, no whitespace inside the
    credential -- with the scheme compared case-insensitively to `bearer`
    (RFC 7235 SS2.1 makes every auth scheme's name case-insensitive and RFC
    6750's Bearer inherits that; nothing else here is lax).
    A repeated Authorization header arrives joined with ', ' and is refused by
    the same rule. The credential's alphabet is checked at comparison time.
    """
    if not authorization or authorization != authorization.strip():
        return None
    scheme, separator, credential = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not credential:
        return None
    if any(character.isspace() for character in credential):
        return None
    return credential


def _names_a_forge_cookie(cookie: str | None) -> bool:
    """True when a Cookie header carries a `forge_session*` cookie. Forge sets
    none and reads none: consulted for GATED requests only, where its presence
    is a caller presenting an ambient credential this surface never issued.
    The allowlisted routes never call this."""
    if not cookie:
        return False
    for pair in cookie.split(";"):
        name = pair.split("=", 1)[0].strip().lower()
        if name.startswith("forge_session"):
            return True
    return False


class SessionGate:
    """A pure ASGI middleware admitting only requests that carry the bearer.

    Installed by `create_app` as the outermost user middleware, so it wraps
    every route including those attached after composition. It never reads the
    request body: it decides from the method, the path and a handful of
    headers, then either passes the request through unchanged or sends one of
    the fixed refusals above. Its own decision can never raise: any exception
    inside it is the fixed 401, never a traceback (measured under review: a
    non-ASCII bearer wrote a 2 KB traceback into the runtime log per request).
    """

    def __init__(self, app: Callable[[Scope, Receive, Send], Awaitable[None]],
                 session: ControlPlaneSession) -> None:
        self._app = app
        self._session = session

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope.get("type")
        if kind == "lifespan":
            await self._app(scope, receive, send)
            return
        if kind == "websocket":
            # No session can be presented on a handshake this surface never
            # accepts: closed before accept, so it never reaches the router.
            await send({"type": "websocket.close", "code": WEBSOCKET_REFUSED_CODE})
            return
        if kind != "http":
            # An ASGI scope type this module does not know is not admitted.
            return
        try:
            refusal = self._decide(scope)
        except Exception:  # noqa: BLE001 - the gate's own failure is a refusal
            refusal = (401, NO_SESSION)
        if refusal is None:
            await self._app(scope, receive, send)
            return
        status, payload = refusal
        await self._respond(send, status, payload)

    def _decide(self, scope: Scope) -> tuple[int, Mapping[str, str]] | None:
        """None to admit the request; otherwise the (status, body) refusal."""
        method = scope.get("method", "")
        path = scope.get("path", "")
        headers = _headers(scope)

        # A cross-site top-level navigation cannot carry the bearer (there is
        # no ambient credential), but a non-GET navigation is a form-POST from
        # another origin: refused structurally, before the allowlist.
        if method != "GET" and headers.get("sec-fetch-mode") == "navigate":
            return 403, CROSS_ORIGIN

        # The allowlisted routes IGNORE cookies. Forge reads no cookie, and
        # the page sends none (`credentials: "omit"`); a cookie is host-scoped,
        # not port-scoped, so a listener on another loopback port can set
        # `forge_session` for 127.0.0.1 -- and a rule that judged `GET /` by
        # it let such a listener deny the person their own page (measured
        # under the second review). The four pairs move no authority a
        # cookie could reach, so a cookie on them is simply not read.
        if (method, path) in ALLOWLIST:
            if path in ORIGIN_CHECKED and self._origin_refusal(path, headers):
                return 403, CROSS_ORIGIN
            return None

        # GATED requests only: a forge_session cookie beside (or instead of)
        # the bearer is a caller presenting an ambient credential this surface
        # never issued, refused before the bearer is looked at. The refusal
        # reveals nothing, and nothing legitimate arrives here with a cookie:
        # the page omits credentials and the smoke sends a bearer only.
        if _names_a_forge_cookie(headers.get("cookie")):
            return 400, COOKIE_REFUSED

        if self._session.verify(_bearer(headers.get("authorization"))):
            return None
        return 401, NO_SESSION

    def _origin_refusal(self, path: str, headers: dict[str, str]) -> bool:
        """Whether an allowlisted POST fails its browser-provenance checks.

        `Sec-Fetch-Site` present and not same-origin, or an `Origin` whose
        full serialization is not exactly `http://<Host>` (which catches
        `Origin: null`, a prefix of the port, and a suffix on the host), is
        refused. For redeem only, a request with neither header is refused as
        well: browsers always send `Origin` on a cross-content POST, so their
        absence is a non-browser caller, and only reopen admits one (the
        second launcher). True to refuse, False to admit.

        This is BROWSER PROVENANCE, not caller authentication: a browser sets
        `Origin` and `Host` itself and a page cannot forge them, which is what
        keeps another browser context from driving these two POSTs; a
        non-browser process sets both headers to whatever it likes and passes
        this check (measured under the third review). What a non-browser
        caller gains is what these two routes give anyone: redeem needs a
        nonce it does not have, and reopen opens a browser window on the
        owner's machine and returns no secret. Admission to everything else
        is the bearer, never this check.
        """
        sec_fetch_site = headers.get("sec-fetch-site")
        origin = headers.get("origin")
        if sec_fetch_site is not None and sec_fetch_site != "same-origin":
            return True
        if origin is not None:
            expected = "http://" + headers.get("host", "")
            if origin != expected:
                return True
        return path == REDEEM_PATH and origin is None and sec_fetch_site is None

    async def _respond(self, send: Send, status: int, payload: Mapping[str, str]) -> None:
        # `dict(...)`: the fixed bodies are read-only views, serialised per
        # response from a copy that nothing else holds.
        body = json.dumps(dict(payload)).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("latin-1")),
            ],
        })
        await send({"type": "http.response.body", "body": body})
