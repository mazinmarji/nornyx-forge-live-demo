"""Probe the onboarding control plane from THIS process, as a local stranger would.

WHAT THIS IS, AND IS NOT (Tranche C, slice C2). This is a MEASUREMENT HARNESS.
It changes no admission criterion, runs no provider, and reaches no verdict about
any provider principal. It takes a live Forge onboarding surface -- a real
loopback socket -- and records what an unauthenticated local caller running as
the surface's own OS principal can and cannot do to it, so a later slice can
compare that record against `CONFINEMENT_PROPERTIES`. The only caller it
classifies is itself.

WHY IT OBSERVES THE SURFACE AS A STRANGER. The probe never imports the app to
enumerate its routes: a stranger does not have the router, it has the wire. The
path list is `DOCUMENTED_PATHS`, a constant that
`tests/test_control_plane_authority.py` holds equal to the served composition's
route table (`assemble` + `attach_runtime_routes`, in-process) -- so a route
added to the surface without being added here is a red test, not a blind spot.
Liveness is confirmed by `GET /api/runtime`, the one operational identity the
surface discloses to any local caller (A-027); the probe reads the
instance/pid/port from it and probes the documented paths, it does not read a
route table from it.

THE STATES THIS HARNESS DERIVES, and `inconclusive`. Three, plus the bookkeeping
value: `reachable_unadmitted`, `admitted_nuisance`, `authority_reachable`, and
`inconclusive`. `unreachable` is NOT in this record's vocabulary: deriving it
needs a positive control from a SEPARATED principal proving the same instance
was up while this caller could not connect, which only C3 can supply
(`NOT_DERIVABLE_HERE`); the validator refuses a record that claims it. The
classification is derived from the unauthenticated request log alone -- never
from a caller's own account of itself, never from a row's stored flags
(allowlist membership is derived from `ALLOWLISTED_PAIRS` and a row whose
stored flag disagrees is refused), and never from the authenticated positive
control (which exists only to prove the surface was live). Three rules bound it:
a gated 2xx DOMINATES at any coverage (a credible counterexample is never
withheld as `inconclusive`); a state that would count as confinement --
`reachable_unadmitted` or `admitted_nuisance` -- requires EVERY cell of the
`DOCUMENTED_PATHS` x `PROBED_METHODS` matrix answered; and ANY EXPIRY OF THE
DEADLINE, at any point in the run, is `inconclusive`. A partial log, a surface
that stopped answering, or a probe cut short is the reason recorded, never a
state.

WHY ANY EXPIRY, AND NOT JUST A TRUNCATED MATRIX (round-2 architecture F-B).
`deadline_exceeded` used to be set only inside the matrix loop, so a deadline
expiring AFTER the matrix -- during the positive control or the artefact reads
-- left the flag false while the artefact rows said "not attempted: the
deadline was exceeded", and a confinement-shaped state was accepted over a run
whose artefact reads never happened. The flag is now set wherever the clock
expires, `artefacts_truncated` counts the reads the expiry cut off (the
validator recomputes it from the artefacts themselves), and the classification
of any cut-short run is `inconclusive`. A record cannot be short of the
evidence it claims and confident at the same time.

EACH FACT CARRIES ITS MECHANISM, kept apart on purpose (A-024's lesson): a fact
observed on the socket carries `observed_surface_record`; a filesystem or
OS-capability fact carries `inferred_acl`, which is an INFERENCE and not a
socket measurement.

AN ARTEFACT HAS THREE OUTCOMES, AND A REFUSAL IS NOT AN OBSERVATION (round-2
test F-3). `observed` is a capability this caller ACQUIRED; `refused` is a
facility that EXISTS and denied this caller; `not_applicable` is that there was
nothing to try. Before this, `OpenProcess` denied with ERROR_ACCESS_DENIED and
a present file this principal could not open both recorded `observed` -- the
same machine-readable word as a real capability, which is how the weakest fact
came to wear the strongest word. `capability_acquired()` is the only sanctioned
way to read an artefact as evidence of a capability, and the validator refuses
a record whose own detail records a denial under the acquired outcome.

THE RECORD IS A SELF-REPORT, and the validator says what it can and cannot
refuse. `transport: loopback_socket` is a DECLARATION the producer makes about
itself; the validator can refuse a record that declares a non-socket transport
or that labels a socket fact as an inference, and it CANNOT tell a log built in
process (a `TestClient`) and labelled as a socket log from one that opened a
socket -- there is nothing in a request row that only a socket could have put
there. What holds the label honest is the PRODUCER: `probe()` has exactly one
transport, `http.client` over a loopback address, and no in-process path exists
in this module. That is a property of this file, pinned by an AST test, not a
property the validator establishes.

SECRETS NEVER ENTER THE RECORD. The positive control reads this run's bearer from
an operator-supplied `--session-file` to prove the surface is live; it records
that a bearered `GET /api/state` was made and what it answered, never the token.
A nonce observed on a channel (the browser handler command line) is recorded as
a sha256 prefix, never in the clear. Acquiring the bearer from a file the
operator handed the probe is NOT acquiring authority THROUGH THE SURFACE, so it
never moves the classification: `authority_reachable` is recorded only when a
gated route answered 2xx, which does not happen from the network side.

THE HOST NAMES NO ONE. The record carries the subject-binding paths a subject
proof needs; on Windows those spell the profile folder, which is the login and
machine name (A-025 forbids either in committed text), and the interpreter path
may spell it in 8.3 short form (`DEVUSER~1.BOX`-shaped -- a PLACEHOLDER, which
is the only shape of it this file may carry; a round-2 security finding was
that the development host's own 8.3 spelling had been written into this
docstring as the example). `redact` folds every known spelling of home -- long,
resolved, and on Windows the `GetLongPathNameW` and `GetShortPathNameW` forms
-- to `~` and removes the login and machine name, matching each of them BOTH
raw and JSON-ESCAPED, because the whole-record backstop runs over a
`json.dumps` blob in which every separator is doubled and a single-separator
pattern walked straight past it (round-2 security P3-1). The validator refuses
a record that still names any of them, and a refusal message printed by the
CLI is put through the same fold before it reaches stderr.

WHAT B'S BEARER GATE IS NOT. `admitted_nuisance` -- the state the self-probe
reaches -- is confinement only for a principal SEPARATED from the surface's
owner. This probe runs as the owner, so `principal_separated` is
`not_separated` and the record says in one field why that is not confinement: a
same-user caller can read the browser handler's command line and Forge's
process memory (A-027). A bearer gate constrains the surface; it establishes
nothing about a provider.

WHAT RUNNING IT DOES TO THE HOST. The matrix's `POST /api/runtime/reopen` is
answered 200: the surface mints a fresh reopen nonce and opens the owner's
default browser on it -- one mint per run (the explicit pull that follows
answers 429 inside the rate-limit interval). Expect a browser tab to open on
every run against a browser-granted surface.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

#: The record schema. One measurement, one caller, one surface.
SCHEMA = "nornyx.forge.control_plane_probe.v1"

#: The one transport this producer has. A DECLARATION in the record; see the
#: module docstring for what the validator can and cannot do with it.
TRANSPORT = "loopback_socket"

#: Every method the unauthenticated matrix probes on every path, declared or
#: not -- held EQUAL to `tests/test_control_plane_session.py::PROBED_METHODS`
#: by `test_the_documented_paths_equal_the_served_compositions_route_table`,
#: so a method added to the session census and not here is a red test.
PROBED_METHODS = ("GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE")

#: The four (method, path) pairs the surface admits without the bearer
#: (`control_plane_session.ALLOWLIST`). Restated here, not imported, because the
#: probe is a stranger: the test above holds this equal to the surface's own
#: allowlist. Membership is DERIVED from this constant for every row; a row's
#: stored `allowlisted` flag is checked against it and never trusted.
ALLOWLISTED_PAIRS = frozenset({
    ("GET", "/"),
    ("GET", "/api/runtime"),
    ("POST", "/api/session/redeem"),
    ("POST", "/api/runtime/reopen"),
})

#: The composed route census, as CONCRETE paths (a proposal id filled in, the
#: way a stranger would spell one). HELD EQUAL to the served composition's route
#: table -- `assemble` plus `attach_runtime_routes` -- by
#: `test_the_documented_paths_equal_the_served_compositions_route_table`, so a
#: route added to the surface and not here is a red test. A path parameter is
#: rendered `P-1`, the value the census uses.
DOCUMENTED_PATHS = (
    "/",
    "/api/brd",
    "/api/build",
    "/api/governance",
    "/api/journey/confirm-scope",
    "/api/journey/ready",
    "/api/journey/restore",
    "/api/journey/retry",
    "/api/journey/start",
    "/api/project",
    "/api/proposals",
    "/api/proposals/P-1/confirm",
    "/api/proposals/P-1/reject",
    "/api/runtime",
    "/api/runtime/reopen",
    "/api/runtime/stop",
    "/api/session/redeem",
    "/api/sharing-preview",
    "/api/state",
)

#: Every cell the matrix must answer before a state that counts as confinement
#: may be derived.
MATRIX_CELLS = frozenset((method, path) for path in DOCUMENTED_PATHS for method in PROBED_METHODS)

#: The authority-MOVING routes A-027 and `control_plane_session` name: a 2xx on
#: any of these, unauthenticated, would be authority reached by the front door.
#: Used to DESCRIBE `reachable_unadmitted`; the classification does not privilege
#: them, because any gated 2xx is `authority_reachable`.
AUTHORITY_ROUTES = frozenset({
    "/api/journey/ready",
    "/api/proposals/P-1/confirm",
    "/api/journey/restore",
    "/api/build",
    "/api/runtime/stop",
})

#: Mechanism labels, kept apart. A socket-observed fact is a MEASUREMENT of the
#: surface; a filesystem/OS-capability fact is an INFERENCE from an ACL or a
#: process handle and cannot stand in for one.
MECH_SURFACE = "observed_surface_record"
MECH_ACL = "inferred_acl"

#: An artefact's three outcomes. `observed` is a capability this caller
#: ACQUIRED; `refused` is a facility that EXISTS and denied this caller;
#: `not_applicable` is that there was nothing to try. The three are kept apart
#: because a refusal wearing the word for an acquisition is a strong claim made
#: out of a weak fact (round-2 test F-3), and `capability_acquired()` is the
#: only sanctioned way to read one as evidence of a capability.
ARTEFACT_OBSERVED = "observed"
ARTEFACT_REFUSED = "refused"
ARTEFACT_NOT_APPLICABLE = "not_applicable"
ARTEFACT_OUTCOMES = (ARTEFACT_OBSERVED, ARTEFACT_REFUSED, ARTEFACT_NOT_APPLICABLE)

#: A detail that says the facility was there and this caller was DENIED it.
#: An artefact carrying `observed` may not say this about itself, and one
#: carrying `refused` must: the word and the sentence have to agree, or the
#: vocabulary buys nothing.
_DENIAL_DETAIL = re.compile(r"\b(refused|denied|not readable|not listable)\b", re.IGNORECASE)

#: What a read the deadline cut off says about itself. `artefacts_truncated`
#: counts these, and the validator recomputes the count from the artefacts.
_DEADLINE_TRUNCATED = "not attempted: the deadline was exceeded"

#: The states this harness derives, plus the bookkeeping value for "not
#: observed". No synonym is added: `inconclusive` already carries "the attempt
#: was not observed" and "the matrix was not completed".
STATE_REACHABLE_UNADMITTED = "reachable_unadmitted"
STATE_ADMITTED_NUISANCE = "admitted_nuisance"
STATE_AUTHORITY_REACHABLE = "authority_reachable"
STATE_INCONCLUSIVE = "inconclusive"
STATES = (
    STATE_REACHABLE_UNADMITTED,
    STATE_ADMITTED_NUISANCE,
    STATE_AUTHORITY_REACHABLE,
    STATE_INCONCLUSIVE,
)
#: A state the design names that THIS harness cannot derive: `unreachable`
#: needs a positive control from a separated principal proving the same
#: instance was up while this caller could not connect (C3). A record claiming
#: it is refused by name rather than as an unknown word.
NOT_DERIVABLE_HERE = ("unreachable",)

#: The `principal_separated` vocabulary: three words, none of which is a
#: Python truth value. `is_separated` turns a record's word into True / False /
#: None; a bare truth test on the field is what the old `"false"` string made
#: wrong (a non-empty string is truthy). C2 records `not_separated` for the
#: self-probe (it runs as the surface's owner) and `unknown` otherwise --
#: never `separated`, which only a measured separate principal (C3) may claim.
SEPARATION_SEPARATED = "separated"
SEPARATION_NOT_SEPARATED = "not_separated"
SEPARATION_UNKNOWN = "unknown"
SEPARATION_VOCABULARY = (SEPARATION_SEPARATED, SEPARATION_NOT_SEPARATED, SEPARATION_UNKNOWN)
#: What C2 may RECORD.
SEPARATION_VALUES = (SEPARATION_NOT_SEPARATED, SEPARATION_UNKNOWN)

#: The whole run is bounded by a wall-clock deadline checked between requests
#: and before every artefact read; per-request socket timeouts alone summed to
#: minutes against a black-holed surface (round-1 architecture F2).
DEFAULT_DEADLINE_S = 300.0

#: `main()` exit codes. 0 is "no authority reached by this caller" -- which is
#: NOT confinement of anything (see `not_confinement_reason`); 2 is a gated
#: route answering an unauthenticated caller; 3 is a record that could not
#: reach a state; 4 is a probe that refused to run or a record that failed its
#: own validation.
EXIT_NO_AUTHORITY = 0
EXIT_AUTHORITY_REACHABLE = 2
EXIT_INCONCLUSIVE = 3
EXIT_REFUSED = 4
EXIT_CODES = {
    STATE_REACHABLE_UNADMITTED: EXIT_NO_AUTHORITY,
    STATE_ADMITTED_NUISANCE: EXIT_NO_AUTHORITY,
    STATE_AUTHORITY_REACHABLE: EXIT_AUTHORITY_REACHABLE,
    STATE_INCONCLUSIVE: EXIT_INCONCLUSIVE,
}

_ONBOARDING_HOST = "127.0.0.1"

#: Windows error codes `OpenProcess` sets. 87 is what a pid that names no
#: process gets; 5 is a live process this principal may not open.
_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_PARAMETER = 87
_PROCESS_VM_READ = 0x0010

#: Where the two system executables the artefact reads use live, relative to
#: `%SystemRoot%`. Absolute on purpose: a bare `powershell` or `whoami` on
#: Windows is searched from the current directory first (round-1 security
#: P3-3), and the fallback walk below never looks there either.
_SYSTEM_LOCATIONS = {
    "powershell.exe": (("System32", "WindowsPowerShell", "v1.0"),),
    "whoami.exe": (("System32",),),
}


class ProbeRecordError(Exception):
    """A record that does not describe what it claims to have measured."""


class NonLoopbackHostError(ValueError):
    """The probe was pointed at a host that is not a loopback address."""


class _QueryUnavailable(Exception):
    """A host facility the artefact read needs could not be used; carries why."""


# ---------------------------------------------------------------------------
# Redaction (A-025): a record names no host identity in the clear.
# ---------------------------------------------------------------------------

def _windows_path_forms(path: str) -> set[str]:
    """The `GetLongPathNameW` and `GetShortPathNameW` spellings of `path`, on
    Windows and where the volume generates them; empty elsewhere."""
    if sys.platform != "win32" or not path:
        return set()
    try:
        import ctypes  # noqa: PLC0415
        from ctypes import wintypes  # noqa: PLC0415

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        forms: set[str] = set()
        for name in ("GetLongPathNameW", "GetShortPathNameW"):
            function = getattr(kernel32, name)
            function.restype = wintypes.DWORD
            function.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
            buffer = ctypes.create_unicode_buffer(32768)
            length = function(path, buffer, len(buffer))
            if 0 < length < len(buffer):
                forms.add(buffer.value)
        return forms
    except Exception:  # noqa: BLE001 - a missing facility must not raise out of redaction
        return set()


def _home_spellings() -> tuple[str, ...]:
    """Every spelling of the reader's home this process can learn: as given,
    resolved (`os.path.realpath`), and on Windows the long and 8.3 short
    forms. Longest first, so the most specific fold wins."""
    try:
        home = str(Path.home())
    except Exception:  # noqa: BLE001
        return ()
    if not home:
        return ()
    spellings = {home}
    try:
        spellings.add(os.path.realpath(home))
    except OSError:
        pass
    spellings |= _windows_path_forms(home)
    return tuple(sorted((s for s in spellings if s), key=len, reverse=True))


def _long_form(path: str | None) -> str | None:
    """`path` resolved and, on Windows, in its long (non-8.3) spelling.

    Applied to every PATH VALUE the subject binding records BEFORE redaction:
    an interpreter under `C:\\Users\\DEVUSER~1.BOX\\...` names the profile
    folder in a form the login and machine tokens do not match, so folding
    alone left `<redacted>~1.BOX` behind (round-1 architecture F6). The long
    form spells the folder out, and the tokens are then removed from it. The
    shape above is a PLACEHOLDER; this file may not carry the development
    host's own spelling of it (A-025, round-2 security P3-2), and
    `test_no_host_derived_spelling_survives_in_the_probe_module` sweeps the
    module source for the `<LOGIN>~1` / `~1.<MACHINE>` forms so it cannot
    come back.
    """
    if not path:
        return path
    try:
        resolved = os.path.realpath(path)
    except OSError:
        resolved = path
    if sys.platform == "win32":
        for form in _windows_path_forms(resolved):
            if "~" not in form:
                return form
    return resolved


def _identity_tokens() -> tuple[tuple[str, ...], str, str]:
    """The reader's home spellings, login and machine name -- to be removed."""
    try:
        login = getpass.getuser()
    except Exception:  # noqa: BLE001 - a container with no passwd entry
        login = ""
    return _home_spellings(), login, platform.node()


#: One separator, or two. A path inside a JSON string carries DOUBLED
#: backslashes, so a pattern built with single separators walks straight past
#: `C:\\\\Users\\\\...` in a `json.dumps` blob -- which is exactly the form the
#: validator's whole-record backstop checks (round-2 security P3-1). The same
#: rule, for the same reason, as `tests/test_independent_inspection.py::
#: _identity_leaks`.
_SEPARATOR = r"[\\/]{1,2}"


def _separator_tolerant(spelling: str) -> str:
    """`spelling` as a pattern matching it RAW and JSON-ESCAPED alike."""
    return _SEPARATOR.join(re.escape(part) for part in re.split(r"[\\/]", spelling))


def _fold_home(text: str, spellings: tuple[str, ...]) -> str:
    """Every occurrence of any spelling of home, anywhere in `text`, becomes
    `~` -- case-folded by the platform's `os.path.normcase`, in both the raw
    and the JSON-escaped separator spelling, and only where a separator or the
    end follows, so `C:\\Users\\DevuserX` is not `C:\\Users\\Devuser`. Not
    merely the prefix: an interpreter path inside a sentence is still the
    profile folder."""
    for spelling in spellings:
        pattern = _separator_tolerant(os.path.normcase(spelling)) + rf"(?={_SEPARATOR}|$)"
        folded = os.path.normcase(text)
        out = []
        cursor = 0
        for match in re.finditer(pattern, folded):
            out.append(text[cursor:match.start()])
            out.append("~")
            cursor = match.end()
        out.append(text[cursor:])
        text = "".join(out)
    return text


def redact(text: str | None) -> str | None:
    """`text` with every spelling of home folded to `~` and the login and
    machine name removed.

    Over-redaction is the safe direction here: the login and machine name are
    removed wherever they occur (case-insensitively), and a token shorter than
    three characters is not searched for, because a one- or two-letter login
    would erase most English. The path SHAPE is preserved -- enough to see the
    origin sits under the worktree -- while the identity is not. Idempotent:
    `redact(redact(t)) == redact(t)`, which is what lets the validator use it
    as a check.

    BOTH SPELLINGS OF A SEPARATOR. `validate_record` applies this to the whole
    record as `json.dumps(record)`, in which every backslash is doubled; a home
    pattern built from single separators matched nothing there, so a nested
    JSON string carrying a home path passed the backstop untouched (round-2
    security P3-1). Home is now matched raw AND doubled. The login and machine
    tokens never contained a separator, so they were always caught in either
    form.
    """
    if not text:
        return text
    homes, login, node = _identity_tokens()
    text = _fold_home(text, homes)
    for token in (login, node):
        if token and len(token) >= 3:
            text = re.sub(re.escape(token), "<redacted>", text, flags=re.IGNORECASE)
    return text


# ---------------------------------------------------------------------------
# Loopback only. The probe measures the local control plane and nothing else.
# ---------------------------------------------------------------------------

def require_loopback(host: str) -> str:
    """The loopback address to connect to; `NonLoopbackHostError` otherwise.

    Decided WITHOUT name resolution: a literal IP must be loopback, and the
    only name admitted is `localhost`. Anything else -- a LAN address, a
    documentation address, a hostname -- is refused by name before a socket
    is opened, so the tool cannot be turned on another machine's surface.

    `localhost` is NORMALISED to 127.0.0.1 rather than passed through
    (round-2 security P4-1). Admitting it by name and then connecting by name
    leaves the destination to the resolver, and the `hosts` file is writable
    by an administrator on this platform: a `localhost` pointing elsewhere
    would have been admitted by a rule whose whole purpose is that it cannot
    be. What the probe returns is what it connects to and what it records, so
    the refusal decides the destination rather than merely the spelling.
    """
    if host == "localhost":
        return _ONBOARDING_HOST
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise NonLoopbackHostError(
            f"host {host!r} is not a loopback address; the probe measures the local "
            "control plane only (127.0.0.0/8, ::1, or 'localhost')"
        ) from None
    if not address.is_loopback:
        raise NonLoopbackHostError(
            f"host {host!r} is not a loopback address; the probe measures the local "
            "control plane only (127.0.0.0/8, ::1, or 'localhost')"
        )
    return host


# ---------------------------------------------------------------------------
# The deadline. Checked between requests and before every artefact read.
# ---------------------------------------------------------------------------

class Deadline:
    """A wall-clock budget for the whole probe."""

    def __init__(self, seconds: float):
        if not (seconds > 0):
            raise ValueError(f"deadline must be a positive number of seconds, not {seconds!r}")
        self.seconds = float(seconds)
        self._until = time.monotonic() + self.seconds

    def remaining(self) -> float:
        return self._until - time.monotonic()

    def exceeded(self) -> bool:
        return self.remaining() <= 0

    #: What an operation still gets after the deadline has passed. Not zero:
    #: a zero timeout is an immediate failure on some calls and "no timeout"
    #: on others, and the tail of a cut-short run still has to end cleanly.
    FLOOR_S = 0.05

    def budget(self, timeout: float) -> float:
        """A per-operation timeout that cannot outlive the deadline.

        `min(timeout, remaining)` is the clamp -- every operation the probe
        starts is bounded by whichever of its own timeout and the run's
        remaining budget is smaller -- floored at `FLOOR_S`. Without it the
        effective bound was the deadline PLUS the longest single timeout
        still to run (60 s on the `Get-CimInstance` query), and the docstring
        that said otherwise was held by nothing (round-2 security P3-3 / test
        F-4). Pinned by `test_the_deadline_budget_clamps_every_operation_it_bounds`
        and, on the subject-binding subprocesses, by
        `test_the_deadline_bounds_the_subject_binding_subprocesses`.
        """
        return max(self.FLOOR_S, min(timeout, self.remaining()))


# ---------------------------------------------------------------------------
# Socket exchanges. The probe's ONLY transport is a real loopback socket.
# ---------------------------------------------------------------------------

def _exchange(host: str, port: int, method: str, path: str, *,
              body: bytes | None = None, headers: dict[str, str] | None = None,
              timeout: float = 5.0) -> tuple[int | None, bytes]:
    """One request on the real socket. Returns (status, body); status is None
    when nothing answered -- a surface that is absent, refused or unreachable."""
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(65536)
    except (OSError, http.client.HTTPException):
        return None, b""
    finally:
        connection.close()


def _runtime_identity(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """What `/api/runtime` discloses, if a Forge runtime answers there."""
    status, body = _exchange(host, port, "GET", "/api/runtime", timeout=timeout)
    if status != 200:
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if isinstance(payload, dict) and payload.get("schema"):
        return payload
    return None


def _membership(method: str, path: str) -> tuple[bool, bool]:
    """(allowlisted, authority_route), DERIVED from the constants."""
    return (method, path) in ALLOWLISTED_PAIRS, path in AUTHORITY_ROUTES


def _request_fact(host: str, port: int, method: str, path: str,
                  timeout: float) -> dict[str, Any]:
    """One unauthenticated probe of one (method, path), as a socket fact.

    Redeem carries an Origin matching the surface (a same-origin browser POST)
    and a nonsense nonce, so its allowlisted route is reached and refused at the
    nonce rather than at the gate; the row records that the Origin was
    SYNTHESISED by the probe. Every other request is bare.
    """
    headers: dict[str, str] = {}
    synthesised: list[str] = []
    body: bytes | None = None
    if path == "/api/session/redeem":
        headers["Origin"] = f"http://{host}:{port}"
        synthesised.append("Origin")
    if method in ("POST", "PUT", "PATCH"):
        headers["content-type"] = "application/json"
        payload = ({"nonce": "not-a-real-nonce"} if path == "/api/session/redeem"
                   else {"actor": {"kind": "human", "ident": "probe"}})
        body = json.dumps(payload).encode("utf-8")
    status, response = _exchange(host, port, method, path, body=body, headers=headers, timeout=timeout)
    text = response.decode("utf-8", errors="replace")
    echoed = bool(text) and (path in text or "not-a-real-nonce" in text)
    allowlisted, authority = _membership(method, path)
    return {
        "method": method,
        "path": path,
        "attempted": True,
        "status": status,
        "body_length": len(response),
        "echoed": echoed,
        "synthesised_headers": synthesised,
        "allowlisted": allowlisted,
        "authority_route": authority,
        "mechanism": MECH_SURFACE,
    }


def _unattempted_fact(method: str, path: str, reason: str) -> dict[str, Any]:
    """A matrix cell the probe did not reach (the deadline ran out first)."""
    allowlisted, authority = _membership(method, path)
    return {
        "method": method,
        "path": path,
        "attempted": False,
        "status": None,
        "body_length": 0,
        "echoed": False,
        "synthesised_headers": [],
        "allowlisted": allowlisted,
        "authority_route": authority,
        "mechanism": MECH_SURFACE,
        "detail": reason,
    }


# ---------------------------------------------------------------------------
# System executables: absolute, under %SystemRoot%, never from the cwd.
# ---------------------------------------------------------------------------

#: The two spellings that carry their OWN volume, matched here rather than
#: delegated: `<letter>:` followed by a separator is DRIVE-ROOTED, and exactly
#: two separators followed by a non-separator is a UNC share or a `\\?\` /
#: `\\.\` device path. Everything else -- a drive-RELATIVE `C:tools`, a
#: root-relative `\tools` or `/tools`, a relative entry, the empty entry -- is
#: completed by something the working directory chooses, and is refused.
_DRIVE_ROOTED = re.compile(r"^[A-Za-z]:[\\/]")
_VOLUME_ROOTED = re.compile(r"^[\\/]{2}[^\\/]")


def _is_drive_absolute(entry: str, *, platform_name: str = sys.platform) -> bool:
    """Whether `entry` names a location from the root of a NAMED volume.

    `os.path.isabs` is not that test on Windows: `\\foo` is "absolute" there
    and means `foo` from the root of the CURRENT drive, which the working
    directory chooses -- so a root-relative `PATH` entry was admitted by a
    walk whose whole purpose is that the working directory never chooses the
    executable (round-2 security P4-4). A drive letter or a UNC share names a
    volume; nothing else does. Off Windows, absolute is absolute.

    THE RULE IS SPELLED OUT HERE INSTEAD OF DELEGATED because every stdlib
    predicate that could answer it moves under this function, and a security
    rule whose verdict depends on which interpreter is running is not a rule
    (round-3 CI: this same helper, red on two jobs at two different rows).
    Measured facts, not recalled ones:

      * `os.path` IS `ntpath` on Windows (`os.path is ntpath` -> True), so the
        non-win32 arm answered with WINDOWS semantics on a Windows host:
        `os.path.isabs("C:\\tools")` is True there and False on Linux, and the
        arm that is supposed to describe POSIX said the opposite of POSIX;
      * `ntpath.isabs` changed at 3.13 -- a root-relative `/usr/bin` or
        `\\tools` is no longer absolute there, while 3.10-3.12 call it
        absolute, so the win32 arm's own answer moved between interpreters;
      * `ntpath.splitdrive` is no oracle for UNC either: on 3.10 it leaves
        `\\\\server\\share` with an empty tail, which makes `ntpath.isabs`
        return False for a UNC share that 3.12 calls absolute.

    So this answer is a function of `entry` and `platform_name` and of nothing
    else -- no `ntpath`, no `posixpath`, no `os.path`. It is a WHITELIST of the
    two shapes above; a spelling this rule cannot NAME is refused rather than
    guessed at, which is the safe direction for a predicate that decides
    whether a `PATH` entry may contribute an executable.
    """
    if platform_name == "win32":
        return bool(_DRIVE_ROOTED.match(entry) or _VOLUME_ROOTED.match(entry))
    return entry.startswith("/")


def _system_executable(name: str, *, environ: Any = None,
                       platform_name: str = sys.platform) -> str | None:
    """The absolute path of `name`, or None.

    `%SystemRoot%` first, at the location the executable ships in; then every
    DRIVE-ABSOLUTE entry of `PATH`. A relative entry -- `.`, the empty entry
    that means the current directory -- a drive-RELATIVE one (`C:tools`, which
    the current directory ON C: completes) and a root-relative one (`\\tools`,
    which the current drive decides) are all skipped, so nothing planted in
    or under the working directory is ever chosen. `_is_drive_absolute` draws
    that line on its own arithmetic, not the running interpreter's.
    """
    environ = os.environ if environ is None else environ
    candidates: list[Path] = []
    system_root = environ.get("SystemRoot") or environ.get("SYSTEMROOT")
    if system_root:
        for parts in _SYSTEM_LOCATIONS.get(name, (("System32",),)):
            candidates.append(Path(system_root).joinpath(*parts) / name)
    for entry in (environ.get("PATH") or "").split(os.pathsep):
        if entry and _is_drive_absolute(entry, platform_name=platform_name):
            candidates.append(Path(entry) / name)
    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    return None


def _run_system(name: str, arguments: list[str], timeout: float) -> subprocess.CompletedProcess:
    """Run one of the two system executables the artefact reads use, by its
    absolute path. Raises `_QueryUnavailable` when it cannot be found or run.
    The ONLY place this module starts a process other than `git`."""
    executable = _system_executable(name)
    if executable is None:
        raise _QueryUnavailable(f"{name} was not found under SystemRoot or on an absolute PATH entry")
    try:
        return subprocess.run(  # noqa: S603
            [executable, *arguments], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise _QueryUnavailable(f"{name} could not be run: {error.__class__.__name__}") from None


# ---------------------------------------------------------------------------
# Artefact reads. Each degrades to `not_applicable` with a reason -- never to a
# pass -- when the host lacks the facility. All are ACL/capability INFERENCES.
# ---------------------------------------------------------------------------

def _not_applicable(name: str, reason: str) -> dict[str, Any]:
    """There was nothing to try: no path, no such facility, no such process."""
    return {"name": name, "outcome": ARTEFACT_NOT_APPLICABLE, "mechanism": MECH_ACL,
            "detail": reason}


def _observed(name: str, detail: str) -> dict[str, Any]:
    """A capability this caller ACQUIRED. Never a denial -- see `_refused`."""
    return {"name": name, "outcome": ARTEFACT_OBSERVED, "mechanism": MECH_ACL, "detail": detail}


def _refused(name: str, detail: str) -> dict[str, Any]:
    """The facility EXISTED and denied this caller.

    A third word, added because a denial and an acquisition shared `observed`
    -- `OpenProcess` failing with ERROR_ACCESS_DENIED, and a present file this
    principal could not open, both recorded the word for a capability the
    caller has (round-2 test F-3). A `refused` can never satisfy a capability
    claim: `capability_acquired()` is False for it, and it is a different fact
    from `not_applicable`, which means there was nothing to try at all.
    """
    return {"name": name, "outcome": ARTEFACT_REFUSED, "mechanism": MECH_ACL, "detail": detail}


def capability_acquired(artefact: dict[str, Any]) -> bool:
    """Whether `artefact` records a capability this caller ACQUIRED.

    The ONLY sanctioned way to read an artefact as evidence of a capability,
    for the same reason `is_separated` is the only way to read the separation
    word: `outcome == "observed"` written out at each call site is one edit
    away from `outcome != "not_applicable"`, which reads a refusal as an
    acquisition. An outcome outside the vocabulary RAISES rather than reading
    as False, so an unknown word is never silently benign.
    """
    outcome = artefact.get("outcome")
    if outcome not in ARTEFACT_OUTCOMES:
        raise ProbeRecordError(
            f"artefact {artefact.get('name')!r} outcome is {outcome!r}; the vocabulary is "
            f"{ARTEFACT_OUTCOMES} (an artefact degrades to not_applicable or records a "
            "refusal, never a pass)")
    return outcome == ARTEFACT_OBSERVED


def _artefact_path_read(name: str, path: Path | None) -> dict[str, Any]:
    """Attempt to open a runtime artefact a same-user caller could reach.

    Present and openable is `observed`; present and NOT openable is `refused`
    -- the ACL said no, which is the opposite fact and used to wear the same
    word.
    """
    if path is None:
        return _not_applicable(name, "no path supplied to the probe; not read as a stranger")
    if not path.exists():
        return _not_applicable(name, "the artefact does not exist on this host")
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            handle.read(1)
        return _observed(name, f"readable by this principal ({size} bytes)")
    except OSError as error:
        return _refused(name, f"present but not readable by this principal: "
                              f"{error.__class__.__name__}")


def _seal_dir_listing(seal_dir: Path | None) -> dict[str, Any]:
    if seal_dir is None:
        return _not_applicable("seal_dir_listing", "no seal directory supplied to the probe")
    if not seal_dir.exists():
        return _not_applicable("seal_dir_listing", "the seal directory does not exist on this host")
    try:
        count = sum(1 for _ in seal_dir.iterdir())
        return _observed("seal_dir_listing", f"listable by this principal ({count} entries)")
    except OSError as error:
        return _refused("seal_dir_listing", f"present but not listable by this principal: "
                                            f"{error.__class__.__name__}")


def _open_process_vm_read(pid: int) -> tuple[int, int]:
    """`OpenProcess(PROCESS_VM_READ, pid)` -> (handle, last error).

    The one place this module touches the Win32 API. Split out so the mapping
    from an error code to an OUTCOME can be pinned deterministically on every
    platform: the ACCESS_DENIED branch depends on the host's own privileges,
    and a branch that only some hosts reach is a branch no CI run holds.
    """
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(_PROCESS_VM_READ, False, int(pid))
    if handle:
        kernel32.CloseHandle(handle)
        return int(handle), 0
    return 0, ctypes.get_last_error()


def _process_vm_read(pid: int | None, *, probe_pid: int,
                     platform_name: str = sys.platform,
                     open_process: Callable[[int], tuple[int, int]] | None = None) -> dict[str, Any]:
    """Attempt `OpenProcess(PROCESS_VM_READ)` on the surface's pid via ctypes.

    A Windows facility. Success means this principal COULD read the owner's
    process memory (where the bearer lives) -- an ACL/capability inference, NOT
    the bearer, which this probe never reads. THE SELF RULE comes first: when
    the surface's pid is this probe's own pid (the in-process self-probe), a
    handle on oneself measures nothing and the artefact is `not_applicable`
    with the reason `self process` (round-1 security P2-3). A pid that names no
    process is `not_applicable` too. Off Windows: `not_applicable`.

    THREE OUTCOMES, NOT TWO (round-2 test F-3). A handle acquired is
    `observed`. ERROR_ACCESS_DENIED -- a live process this principal may not
    open, which is the interesting negative result and the one a confinement
    claim would rest on -- is `refused`, not `observed`; it used to be
    `observed` with the word "refused" buried in the detail, so a denial and an
    acquisition were the same machine-readable fact. Any other failure is
    `refused` too: the process was there and the call did not give this caller
    the handle. `open_process` is the seam the deterministic pins drive.
    """
    if pid is None:
        return _not_applicable("process_vm_read", "the surface disclosed no pid to open")
    if int(pid) == int(probe_pid):
        return _not_applicable(
            "process_vm_read",
            f"self process: the surface pid {pid} is this probe's own pid; a handle on "
            "oneself measures nothing (a cross-process witness is needed)",
        )
    if platform_name != "win32":
        return _not_applicable("process_vm_read", "OpenProcess is a Windows facility; not available on this host")
    try:
        handle, error = (open_process or _open_process_vm_read)(int(pid))
        if handle:
            return _observed("process_vm_read",
                             "PROCESS_VM_READ handle acquired on the surface pid by this principal")
        if error == _ERROR_INVALID_PARAMETER:
            return _not_applicable("process_vm_read",
                                   f"no such process: pid {pid} names no process (error {error})")
        if error == _ERROR_ACCESS_DENIED:
            return _refused("process_vm_read",
                            f"OpenProcess denied this principal PROCESS_VM_READ on pid {pid} "
                            f"(error {error}, ERROR_ACCESS_DENIED): the process is there and "
                            "this caller may not open it")
        return _refused("process_vm_read",
                        f"OpenProcess refused a PROCESS_VM_READ handle on pid {pid} (error {error})")
    except Exception as error:  # noqa: BLE001 - a missing facility must not raise out of the probe
        return _not_applicable("process_vm_read",
                               f"OpenProcess could not be attempted: {error.__class__.__name__}")


def _digest_fragments(lines: list[str]) -> list[str]:
    """Every URL fragment on the given command lines, as sha256 prefixes."""
    fragments: set[str] = set()
    for line in lines:
        for match in re.finditer(r"#([A-Za-z0-9_-]{16,})", line):
            fragments.add("sha256:" + hashlib.sha256(match.group(1).encode("ascii")).hexdigest()[:12])
    return sorted(fragments)


def _powershell_query(timeout: float) -> list[str]:
    """The browser handler command lines via `Get-CimInstance Win32_Process`."""
    completed = _run_system("powershell.exe", [
        "-NoProfile", "-NonInteractive", "-Command",
        "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe' OR Name='msedge.exe' OR Name='firefox.exe'\" "
        "| Select-Object -ExpandProperty CommandLine",
    ], timeout)
    if completed.returncode != 0:
        raise _QueryUnavailable("the Win32_Process query did not succeed on this host")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _browser_handler_cmdline(*, query: Callable[[float], list[str]] | None = None,
                             platform_name: str = sys.platform,
                             timeout: float = 60.0) -> dict[str, Any]:
    """Read browser command lines (the nuisance channel A-027 concedes).

    `os.startfile` places the start-link URL, fragment included, on the browser
    handler's command line. A same-user caller can read it. A Windows facility;
    any nonce found on a command line is recorded as a sha256 PREFIX, never in
    the clear. `query` is the seam the unit pins drive a synthetic line through;
    the default is the PowerShell query. Off Windows: `not_applicable`.
    """
    if platform_name != "win32":
        return _not_applicable("browser_handler_cmdline",
                               "Win32_Process is a Windows facility; not available on this host")
    try:
        lines = (query or _powershell_query)(timeout)
    except _QueryUnavailable as why:
        return _not_applicable("browser_handler_cmdline", str(why))
    if not lines:
        return _not_applicable("browser_handler_cmdline",
                               "no browser handler process is running to disclose a command line")
    fragments = _digest_fragments(lines)
    detail = f"readable by this principal ({len(lines)} browser command line(s))"
    if fragments:
        detail += f"; url fragments present, recorded as digests: {fragments}"
    return _observed("browser_handler_cmdline", detail)


def _browser_history(*, local_appdata: str | None = None,
                     platform_name: str = sys.platform) -> dict[str, Any]:
    """Attempt to reach the browser's on-disk history stores (A-027).

    An ACL fact: whether this principal can open the history file the browser
    records the navigated URL into. Measured on the development host as
    SYSTEM/Admin/user only (A-027); the probe attempts the well-known paths
    under `local_appdata` (default `%LOCALAPPDATA%`) and degrades to
    `not_applicable` when none exists.
    """
    if platform_name != "win32":
        return _not_applicable("browser_history",
                               "the measured history stores are Windows paths; not available on this host")
    local = os.environ.get("LOCALAPPDATA") if local_appdata is None else local_appdata
    if not local:
        return _not_applicable("browser_history", "LOCALAPPDATA is unset; no history store path to reach")
    candidates = [
        Path(local) / "Google" / "Chrome" / "User Data" / "Default" / "History",
        Path(local) / "Microsoft" / "Edge" / "User Data" / "Default" / "History",
    ]
    present = [path for path in candidates if path.exists()]
    if not present:
        return _not_applicable("browser_history", "no measured history store exists on this host")
    readable = 0
    for path in present:
        try:
            with path.open("rb") as handle:
                handle.read(1)
            readable += 1
        except OSError:
            pass
    if not readable:
        return _refused("browser_history",
                        f"0 of {len(present)} present history store(s) opened: this principal was "
                        "denied every one")
    return _observed("browser_history",
                     f"{readable} of {len(present)} present history store(s) readable by this principal")


# ---------------------------------------------------------------------------
# Subject binding (A-026): what interpreter, what source, what principal.
# ---------------------------------------------------------------------------

SUBJECT_KEYS = ("probe_pid", "probe_executable", "probe_executable_sha256", "sys_executable",
                "nornyx_forge_file", "nornyx_forge_origin", "tree_git_sha", "principal", "surface")
SURFACE_KEYS = ("reachable", "instance", "pid", "port", "expected_instance",
                "expected_instance_matches", "detail")

#: What the subject-binding subprocesses get when no deadline is clamping them.
_SUBJECT_TIMEOUT_S = 30.0


def _interpreter_sha256() -> str | None:
    try:
        digest = hashlib.sha256()
        with open(sys.executable, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return "sha256:" + digest.hexdigest()
    except OSError:
        return None


def _tree_git_sha(root: Path, timeout: float = _SUBJECT_TIMEOUT_S) -> str | None:
    """The tree's HEAD, bounded by `timeout` -- which the caller clamps to
    what is left of the run's deadline (round-2 architecture F-A: this call
    and `_principal` were outside the deadline, and a probe asked for 0.5 s
    took 6.67 s with two 3 s subprocesses here)."""
    try:
        completed = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode:
        return None
    revision = completed.stdout.strip()
    return f"git:{revision}" if revision else None


def _principal(timeout: float = _SUBJECT_TIMEOUT_S) -> dict[str, Any]:
    """This process's OS principal -- the SID on Windows, the uid on POSIX --
    read from INSIDE the probe, with the login and machine name redacted."""
    entry: dict[str, Any] = {"platform": sys.platform, "sid": None, "uid": None}
    if sys.platform == "win32":
        try:
            completed = _run_system("whoami.exe", ["/user"], timeout)
            match = re.search(r"S-1-[0-9-]+", completed.stdout or "")
            entry["sid"] = match.group(0) if match else None
        except _QueryUnavailable:
            entry["sid"] = None
    else:
        entry["uid"] = os.getuid() if hasattr(os, "getuid") else None
    return entry


def _surface_identity(identity: dict[str, Any] | None, port: int,
                      expect_instance: str | None) -> dict[str, Any]:
    """The surface half of the subject: what `/api/runtime` disclosed, and
    whether it is the instance the caller expected -- COMPUTED, and recomputed
    by the validator; None when either side is unknown.

    THE BODY IS UNTRUSTED, AND TYPE-CHECKED HERE. `/api/runtime` is read off a
    loopback socket that anything on this host may be serving, so `pid` and
    `instance` are checked before they are recorded: a `pid` that is not an
    integer and an `instance` that is not a string are not surface facts, and
    the whole identity is refused as MALFORMED -- the surface is recorded
    unreachable, with the reason in `detail`. A hostile listener answering
    `pid` as a list used to reach `int(pid)` in the memory-handle read and
    crash the probe with a traceback that printed the host's own paths, which
    falsified the exit-code enumeration in the README and `--help` (round-2
    security P2-1).

    A malformed identity is RECORDED, not fatal: the classification is derived
    from the request log and never from `/api/runtime`, so a run against a
    hostile listener still produces a record that says what it saw. What it may
    not do is carry a value of the wrong type into arithmetic.
    """
    detail: str | None = None
    if identity is not None:
        pid, instance = identity.get("pid"), identity.get("instance")
        if not (pid is None or (isinstance(pid, int) and not isinstance(pid, bool))):
            detail = (f"the surface answered /api/runtime with a pid of type "
                      f"{type(pid).__name__}, not an integer; the identity is refused as "
                      "malformed and the surface recorded unreachable")
        elif not (instance is None or isinstance(instance, str)):
            detail = (f"the surface answered /api/runtime with an instance of type "
                      f"{type(instance).__name__}, not a string; the identity is refused as "
                      "malformed and the surface recorded unreachable")
        if detail is not None:
            identity = None
    instance = identity.get("instance") if identity else None
    return {
        "reachable": identity is not None,
        "instance": instance,
        "pid": identity.get("pid") if identity else None,
        "port": port,
        "expected_instance": expect_instance,
        "expected_instance_matches": (
            None if (identity is None or expect_instance is None) else instance == expect_instance
        ),
        "detail": detail,
    }


def _subject_binding(root: Path, surface: dict[str, Any], *,
                     clock: "Deadline | None" = None) -> dict[str, Any]:
    """What interpreter, what source, what principal -- bounded by `clock`.

    The two subprocesses here (`git rev-parse`, `whoami /user`) carried their
    own 30 s timeouts and nothing else, so the run's deadline did not reach
    them: `probe(deadline=0.5)` with two 3 s subprocesses took 6.67 s
    (round-2 architecture F-A). Both are now clamped by `Deadline.budget`, so
    the deadline bounds the WHOLE probe and the claim beside it is one a
    measurement holds.
    """
    timeout = clock.budget(_SUBJECT_TIMEOUT_S) if clock is not None else _SUBJECT_TIMEOUT_S
    try:
        forge_file = importlib.import_module("nornyx_forge").__file__
    except Exception:  # noqa: BLE001
        forge_file = None
    try:
        spec = importlib.util.find_spec("nornyx_forge")
        origin = spec.origin if spec is not None else None
    except Exception:  # noqa: BLE001
        origin = None
    return {
        "probe_pid": os.getpid(),
        "probe_executable": redact(_long_form(sys.executable)),
        "probe_executable_sha256": _interpreter_sha256(),
        "sys_executable": redact(_long_form(sys.executable)),
        "nornyx_forge_file": redact(_long_form(forge_file)),
        "nornyx_forge_origin": redact(_long_form(origin)),
        "tree_git_sha": _tree_git_sha(root, timeout),
        "principal": _principal(clock.budget(_SUBJECT_TIMEOUT_S) if clock is not None
                                else _SUBJECT_TIMEOUT_S),
        "surface": surface,
    }


# ---------------------------------------------------------------------------
# The classification, derived from the request log alone.
# ---------------------------------------------------------------------------

def _is_2xx(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def _is_denied(status: int | None) -> bool:
    return status in (401, 403)


def _checked_membership(entry: dict[str, Any]) -> tuple[bool, bool]:
    """A row's (allowlisted, authority_route), DERIVED from the constants; a
    stored flag that disagrees with the derivation is refused, not read."""
    method, path = entry.get("method"), entry.get("path")
    allowlisted, authority = _membership(method, path)
    for key, derived in (("allowlisted", allowlisted), ("authority_route", authority)):
        stored = entry.get(key)
        if stored is not None and bool(stored) != derived:
            raise ProbeRecordError(
                f"request {method} {path} stores {key}={stored!r} but the constant derives "
                f"{derived!r}; a row's stored flag disagrees with ALLOWLISTED_PAIRS/"
                "AUTHORITY_ROUTES and is refused rather than read"
            )
    return allowlisted, authority


@dataclass(frozen=True)
class Derivation:
    """A classification with the reason it was reached and the coverage it
    was reached over. `coverage` is recomputed by the validator."""

    state: str
    reason: str
    coverage: dict[str, Any]


def derive(requests: list[dict[str, Any]], *, bearer_acquired: bool = False,
           deadline_note: str | None = None) -> Derivation:
    """The classification for the caller that produced `requests`.

    Derived from the UNAUTHENTICATED request log, never from the caller's own
    account of itself and never from the authenticated positive control. The
    rule, in order:

      * any gated 2xx, or a bearer acquired
        THROUGH the surface                    -> `authority_reachable`
                                                  (dominates at ANY coverage:
                                                  a counterexample is never
                                                  withheld);
      * the deadline expired anywhere in the
        run (`deadline_note` present)          -> `inconclusive`, with the
                                                  note and the coverage;
      * any cell of DOCUMENTED_PATHS x
        PROBED_METHODS unanswered              -> `inconclusive`, with the
                                                  count and the reason (the
                                                  surface absent, a partial
                                                  log, the deadline);
      * an allowlisted 2xx and every gated
        cell denied (401/403)                  -> `admitted_nuisance`;
      * no allowlisted 2xx and every gated
        cell denied                            -> `reachable_unadmitted`;
      * anything else (a gated cell answering
        something other than 2xx/401/403)      -> `inconclusive`, with the cell.

    Allowlist membership is derived from `ALLOWLISTED_PAIRS` for every row; a
    row whose stored flag disagrees raises `ProbeRecordError`.

    THE DEADLINE RULE IS "ANY EXPIRY", DELIBERATELY (round-2 architecture
    F-B). It was "the matrix was truncated", which left a run whose matrix
    completed and whose ARTEFACT READS were then cut off looking exactly like
    a complete one -- `deadline_exceeded` false, every cell answered, a
    confinement-shaped state. The two candidate repairs were to rename the
    flag `matrix_deadline_exceeded` and add `artefacts_truncated`, or to make
    any expiry inconclusive. BOTH are taken here: `artefacts_truncated` counts
    what was cut off, and the state of a cut-short run is `inconclusive`. The
    reason is that the alternative asks a reader to decide which missing
    evidence mattered, and this record exists so that nobody has to.
    """
    memberships = [(entry, _checked_membership(entry)) for entry in requests]
    gated = [entry for entry, (allowlisted, _) in memberships if not allowlisted]
    allowlisted_rows = [entry for entry, (allowlisted, _) in memberships if allowlisted]
    answered_cells = {(e.get("method"), e.get("path")) for e in requests if e.get("status") is not None}
    unanswered = sorted(MATRIX_CELLS - answered_cells)
    coverage = {
        "expected_cells": len(MATRIX_CELLS),
        "answered_cells": len(MATRIX_CELLS) - len(unanswered),
        "unanswered_cells": [list(cell) for cell in unanswered],
    }
    breaches = [e for e in gated if _is_2xx(e.get("status"))]
    if breaches or bearer_acquired:
        why = ("a bearer was acquired through the surface" if bearer_acquired and not breaches
               else "a gated route answered 2xx to an unauthenticated caller: "
               + ", ".join(f"{e.get('method')} {e.get('path')} {e.get('status')}" for e in breaches[:5]))
        return Derivation(STATE_AUTHORITY_REACHABLE, why + " (dominates at any coverage)", coverage)
    if deadline_note:
        why = (f"the run was cut short: {deadline_note}; {coverage['answered_cells']} of "
               f"{coverage['expected_cells']} matrix cells answered. Any expiry of the deadline, "
               "at any point in the run, is inconclusive: a state that would count as "
               "confinement is earned over a whole run, and this one did not finish")
        return Derivation(STATE_INCONCLUSIVE, why, coverage)
    if unanswered:
        # `deadline_note` was appended here; it cannot reach this point any
        # more, because an expiry is decided above and its reason carries the
        # coverage. A partial log with no expiry is a surface that stopped
        # answering, which is a different fact and says so.
        if not answered_cells:
            why = "the surface is absent: no request answered"
        else:
            why = (f"coverage incomplete: {coverage['answered_cells']} of {coverage['expected_cells']} "
                   "matrix cells answered")
        return Derivation(STATE_INCONCLUSIVE, why, coverage)
    allowlisted_2xx = [e for e in allowlisted_rows if _is_2xx(e.get("status"))]
    not_denied = [e for e in gated if not _is_denied(e.get("status"))]
    if not_denied:
        first = not_denied[0]
        why = ("a gated cell answered neither 2xx nor 401/403: "
               f"{first.get('method')} {first.get('path')} {first.get('status')}")
        return Derivation(STATE_INCONCLUSIVE, why, coverage)
    if allowlisted_2xx:
        why = (f"every matrix cell answered; {len(allowlisted_2xx)} allowlisted cell(s) answered 2xx "
               "and every gated cell was denied (401/403)")
        return Derivation(STATE_ADMITTED_NUISANCE, why, coverage)
    why = "every matrix cell answered; no allowlisted cell answered 2xx and every gated cell was denied"
    return Derivation(STATE_REACHABLE_UNADMITTED, why, coverage)


def classify(requests: list[dict[str, Any]], *, bearer_acquired: bool = False) -> str:
    """`derive(...).state` -- the state alone."""
    return derive(requests, bearer_acquired=bearer_acquired).state


def is_separated(record: dict[str, Any]) -> bool | None:
    """The record's `principal_separated` as True / False / None -- the ONLY
    sanctioned way to truth-test it. A word outside the vocabulary (including
    the retired `"true"`/`"false"` strings and Python booleans) raises."""
    value = record.get("principal_separated")
    if value == SEPARATION_SEPARATED:
        return True
    if value == SEPARATION_NOT_SEPARATED:
        return False
    if value == SEPARATION_UNKNOWN:
        return None
    raise ProbeRecordError(
        f"principal_separated is {value!r}; the vocabulary is {SEPARATION_VOCABULARY} "
        "(a string that is not one of these, or a Python boolean, is refused so it can "
        "never be truth-tested by accident)"
    )


def not_confinement_reason(separation: str) -> str:
    """Why `admitted_nuisance` is NOT confinement for this caller, by its
    separation word. Recorded beside the state whenever the state is
    `admitted_nuisance` and the principal is not measured separate."""
    if separation == SEPARATION_NOT_SEPARATED:
        return (
            "the caller reached the allowlisted pairs and moved no authority state, but it "
            "runs as the surface's own OS principal (principal_separated=not_separated); a "
            "same-user caller can read the browser handler command line and Forge's process "
            "memory (A-027), so admitted_nuisance is confinement only for a principal separated "
            "from the owner, which this caller is not. A bearer gate constrains the surface; "
            "it establishes nothing about a provider."
        )
    return (
        "the caller reached the allowlisted pairs and moved no authority state, but whether "
        "it runs as a principal separated from the surface's owner was not measured "
        "(principal_separated=unknown); admitted_nuisance is confinement only for a principal "
        "measured separate from the owner (A-027), which is not established for this caller. "
        "A bearer gate constrains the surface; it establishes nothing about a provider."
    )


# ---------------------------------------------------------------------------
# The record validator: a record must describe what it claims to have measured.
# ---------------------------------------------------------------------------

def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeRecordError(message)


def validate_record(record: dict[str, Any]) -> None:
    """Refuse a record that does not answer for itself. Raises ProbeRecordError.

    The refusals this exists for:
      * a transport declared as anything but `loopback_socket`, and a socket
        fact whose mechanism is not `observed_surface_record` (M6, as far as
        a validator can go: the transport is a DECLARATION, see the module
        docstring);
      * a stored `classification` or `classification_reason` or `coverage`
        that disagrees with what the record's own request log derives (M8),
        a surface-absent record that claims any state, and a row whose
        stored allowlist/authority flag disagrees with the constants;
      * `unreachable`, which this harness cannot derive;
      * a `principal_separated` outside the vocabulary, or `separated`, which
        C2 may never record;
      * an incomplete subject block; a surface that is not the expected
        instance; an `expected_instance_matches` that was declared rather
        than computed; a memory-handle artefact claimed `observed` on the
        probe's own pid;
      * a positive control that claims admission without a recorded request;
      * an artefact reporting a pass, or a socket mechanism; an artefact whose
        own detail records a denial under the ACQUIRED outcome, or a `refused`
        that does not say it was refused; an `artefacts_truncated` that is not
        the count of reads the deadline cut off, or reads cut off by a
        deadline the record says did not expire;
      * a host identity in the clear -- raw or JSON-escaped -- a bearer, or a
        raw nonce.
    """
    _require(isinstance(record, dict), "a record is a JSON object")
    _require(record.get("schema") == SCHEMA,
             f"not a {SCHEMA} record: schema={record.get('schema')!r}")
    _require(record.get("transport") == TRANSPORT,
             "a control-plane probe is a socket measurement; a record whose transport is "
             f"{record.get('transport')!r} is not one (a TestClient or in-process ASGI result "
             "is not a socket result)")
    requests = record.get("requests")
    _require(isinstance(requests, list), "the record carries no request log to check its claim against")
    for entry in requests:
        _require(isinstance(entry, dict), "a request row is a JSON object")
        _require(isinstance(entry.get("method"), str) and isinstance(entry.get("path"), str),
                 f"request row {entry!r} names no method/path")
        if entry.get("attempted") is False:
            _require(entry.get("status") is None,
                     f"request {entry['method']} {entry['path']} was not attempted but carries a status")
        if entry.get("status") is None:
            _checked_membership(entry)
            continue  # an unanswered probe witnessed nothing; it carries no mechanism claim
        _require(entry.get("mechanism") == MECH_SURFACE,
                 f"request {entry['method']} {entry['path']} answered {entry['status']} but its "
                 f"mechanism is {entry.get('mechanism')!r}, not {MECH_SURFACE!r}; a socket fact must "
                 "be labelled as one")
    state = record.get("classification")
    if state in NOT_DERIVABLE_HERE:
        raise ProbeRecordError(
            f"classification {state!r} is not derivable by this harness: it needs a positive "
            "control from a separated principal proving the same instance was up while this "
            "caller could not connect (C3); this record's vocabulary is "
            f"{STATES}"
        )
    _require(state in STATES, f"classification {state!r} is not one of {STATES}")
    recomputed = derive(requests, bearer_acquired=bool(record.get("bearer_acquired_through_surface")),
                        deadline_note=record.get("deadline_note"))
    _require(state == recomputed.state,
             f"the record claims classification {state!r}, but its own request log derives "
             f"{recomputed.state!r} ({recomputed.reason}); a label may not disagree with the record")
    _require(record.get("classification_reason") == recomputed.reason,
             f"the record's classification_reason {record.get('classification_reason')!r} is not "
             f"what its own log derives: {recomputed.reason!r}")
    _require(record.get("coverage") == recomputed.coverage,
             "the record's coverage block disagrees with its own request log: recorded "
             f"{record.get('coverage')!r}, derived {recomputed.coverage!r}")
    _require(record.get("deadline_exceeded") is (record.get("deadline_note") is not None),
             "deadline_exceeded must say exactly whether a deadline_note was recorded")
    _require(not record.get("deadline_exceeded") or state == STATE_INCONCLUSIVE
             or state == STATE_AUTHORITY_REACHABLE,
             "a probe that ran out of deadline can be inconclusive or carry a dominating "
             "counterexample; it cannot have earned a confined state")
    responded = [r for r in requests if r.get("status") is not None]
    _require(bool(responded) or state == STATE_INCONCLUSIVE,
             f"the surface is absent (no request answered) but the record claims {state!r}; an "
             "absent surface is inconclusive, never a state -- including the one shape every "
             "other rule here accepts, a record whose log answered nothing and which claims "
             "authority_reachable through bearer_acquired_through_surface")

    separation = record.get("principal_separated")
    _require(separation != SEPARATION_SEPARATED,
             f"principal_separated is {SEPARATION_SEPARATED!r}; C2 may not record it -- only a "
             "measured separate principal (C3) may claim separation")
    _require(separation in SEPARATION_VALUES,
             f"principal_separated is {separation!r}; C2 records one of {SEPARATION_VALUES} "
             f"(vocabulary {SEPARATION_VOCABULARY}; the retired 'true'/'false' strings and Python "
             "booleans are refused)")
    is_separated(record)
    if state == STATE_ADMITTED_NUISANCE:
        _require(record.get("not_confinement_reason") == not_confinement_reason(separation),
                 "an admitted_nuisance record for a principal not measured separate must carry "
                 "not_confinement_reason for its separation word, verbatim")
    else:
        _require(record.get("not_confinement_reason") is None,
                 "not_confinement_reason belongs to admitted_nuisance alone")

    for artefact in record.get("artefacts", []):
        _require(isinstance(artefact, dict) and isinstance(artefact.get("name"), str),
                 f"artefact {artefact!r} is not a named object")
        _require(artefact.get("outcome") in ARTEFACT_OUTCOMES,
                 f"artefact {artefact['name']!r} outcome is {artefact.get('outcome')!r}; an artefact "
                 f"is one of {ARTEFACT_OUTCOMES} -- it degrades to not_applicable or records a "
                 "refusal, never a pass")
        _require(artefact.get("mechanism") == MECH_ACL,
                 f"artefact {artefact['name']!r} mechanism is {artefact.get('mechanism')!r}; a "
                 f"filesystem/capability fact is an inference ({MECH_ACL}), kept apart from a "
                 "socket measurement")
        _require(isinstance(artefact.get("detail"), str) and bool(artefact["detail"]),
                 f"artefact {artefact['name']!r} carries no detail saying what was observed or why not")
        # The word and the sentence have to agree. A denial recorded under the
        # word for an acquired capability is exactly how a refusal came to read
        # as one (round-2 test F-3), and a refusal that does not say it was
        # refused leaves the reader nothing to check the word against.
        denial = bool(_DENIAL_DETAIL.search(artefact["detail"]))
        _require(not (capability_acquired(artefact) and denial),
                 f"artefact {artefact['name']!r} carries the acquired outcome "
                 f"{ARTEFACT_OBSERVED!r} while its own detail records a denial "
                 f"({artefact['detail']!r}); a facility that existed and said no is "
                 f"{ARTEFACT_REFUSED!r}, and it may never satisfy a capability claim")
        _require(artefact["outcome"] != ARTEFACT_REFUSED or denial,
                 f"artefact {artefact['name']!r} is {ARTEFACT_REFUSED!r} but its detail "
                 f"({artefact['detail']!r}) does not say it was refused or denied")
    truncated = record.get("artefacts_truncated")
    cut_off = sum(1 for artefact in record.get("artefacts", [])
                  if isinstance(artefact, dict)
                  and str(artefact.get("detail", "")).startswith(_DEADLINE_TRUNCATED))
    _require(truncated == cut_off,
             f"artefacts_truncated is {truncated!r} but {cut_off} artefact read(s) say the "
             "deadline cut them off; the count is computed from the artefacts, never declared")
    _require(not cut_off or record.get("deadline_exceeded") is True,
             f"{cut_off} artefact read(s) were cut off by the deadline but deadline_exceeded is "
             f"{record.get('deadline_exceeded')!r}; a run short of the evidence it claims cannot "
             "also report that it finished")

    subject = record.get("subject")
    _require(isinstance(subject, dict) and bool(subject), "the record carries no subject block")
    missing = [key for key in SUBJECT_KEYS if key not in subject]
    _require(not missing, f"the subject block is incomplete; missing {missing}")
    _require(isinstance(subject["probe_pid"], int) and not isinstance(subject["probe_pid"], bool),
             "subject.probe_pid must be the probe's own pid, an integer")
    _require(isinstance(subject["principal"], dict) and "platform" in subject["principal"],
             "subject.principal must name the platform it was read on")
    surface = subject["surface"]
    _require(isinstance(surface, dict), "subject.surface is not an object")
    missing = [key for key in SURFACE_KEYS if key not in surface]
    _require(not missing, f"the subject's surface block is incomplete; missing {missing}")
    _require(surface["reachable"] in (True, False), "subject.surface.reachable must be a boolean")
    expected_match = (
        None if (not surface["reachable"] or surface["expected_instance"] is None)
        else surface["instance"] == surface["expected_instance"]
    )
    _require(surface["expected_instance_matches"] is expected_match,
             f"subject.surface.expected_instance_matches is {surface['expected_instance_matches']!r} "
             f"but the surface's own instance and the expectation compute {expected_match!r}; the "
             "match is computed, never declared")
    _require(expected_match is not False,
             f"the surface answering on port {surface['port']} is instance {surface['instance']!r}, "
             f"not the expected {surface['expected_instance']!r}; this record does not describe "
             "the subject it was pointed at")
    if surface.get("pid") is not None and int(surface["pid"]) == int(subject["probe_pid"]):
        for artefact in record.get("artefacts", []):
            if artefact.get("name") == "process_vm_read":
                _require(artefact.get("outcome") == "not_applicable",
                         "the surface pid is the probe's own pid; a process_vm_read artefact "
                         "claimed observed on one's own process measures nothing and is refused")

    control = record.get("positive_control")
    _require(isinstance(control, dict) and {"attempted", "status", "admitted"} <= set(control),
             "the record carries no positive_control block")
    if control["attempted"]:
        request = control.get("request")
        _require(isinstance(request, dict) and request.get("method") == "GET"
                 and request.get("path") == "/api/state" and request.get("bearer_presented") is True
                 and request.get("mechanism") == MECH_SURFACE,
                 "an attempted positive control must record the bearered GET /api/state it made")
        _require(control["admitted"] is (control["status"] == 200),
                 f"positive_control.admitted={control['admitted']!r} disagrees with its status "
                 f"{control['status']!r}; admission is the status, never a declaration")
    else:
        _require(control["status"] is None and control["admitted"] is None,
                 "a positive control that was not attempted can carry neither a status nor admission")

    blob = json.dumps(record)
    _require(redact(blob) == blob,
             "the record names the host in the clear (a home path, the login or the machine "
             "name); A-025 forbids it and the producer redacts it")
    _refuse_embedded_secret(blob)


def _refuse_embedded_secret(blob: str) -> None:
    """A record may carry a nonce only as a `sha256:` prefix and no bearer at all.

    A token or a raw nonce is a URL-safe base64 run; the credential this surface
    mints is 43 characters (`token_urlsafe(32)`), random bytes whose base64
    encoding all but certainly mixes upper case, lower case and digits. That
    fingerprint is what this refuses -- so a hex digest (no upper case), a git
    sha (no upper case) and a Windows SID (`S-1-...`, no lower case) are not
    mistaken for a credential, while the bearer and the nonce are. The positive
    control stores a status, never a token, and channel nonces are digested.
    """
    for run in re.findall(r"[A-Za-z0-9_-]{40,}", blob):
        if re.search(r"[a-z]", run) and re.search(r"[A-Z]", run):
            raise ProbeRecordError(
                "the record carries a long credential-shaped token; a bearer or a "
                "raw nonce must never enter the record (nonces are sha256 prefixes only)"
            )


# ---------------------------------------------------------------------------
# The probe run.
# ---------------------------------------------------------------------------

def _positive_control(host: str, port: int, session_file: Path, timeout: float, *,
                      exchange: Callable[..., tuple[int | None, bytes]] = _exchange) -> dict[str, Any]:
    """Authenticate one gated read with the bearer read from the session file.

    Proves the surface is live and the harness not vacuous. Records THAT a
    bearered `GET /api/state` was made and its status, never the token; the
    request is deliberately kept out of `requests`, so it does not feed the
    classification. `exchange` is the seam the unit pin drives, so a control
    that claims admission without making the request is a red test.
    """
    if not session_file.exists():
        return {"attempted": False, "status": None, "admitted": None,
                "detail": "the session file does not exist"}
    try:
        token = json.loads(session_file.read_text(encoding="utf-8"))["token"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {"attempted": False, "status": None, "admitted": None,
                "detail": f"the session file could not be read: {error.__class__.__name__}"}
    status, _ = exchange(host, port, "GET", "/api/state",
                         headers={"Authorization": "Bearer " + token}, timeout=timeout)
    return {
        "attempted": True, "status": status, "admitted": status == 200,
        "request": {"method": "GET", "path": "/api/state", "bearer_presented": True,
                    "mechanism": MECH_SURFACE},
        "detail": "authenticated /api/state read, proving the surface is live; the token is not recorded",
    }


def probe(port: int, *, host: str = _ONBOARDING_HOST, expect_instance: str | None = None,
          session_file: str | Path | None = None,
          principal_separated: str = SEPARATION_NOT_SEPARATED,
          runtime_record: str | Path | None = None, runtime_log: str | Path | None = None,
          seal_dir: str | Path | None = None, root: Path | None = None,
          timeout: float = 5.0, deadline: float = DEFAULT_DEADLINE_S) -> dict[str, Any]:
    """Run the probe against a live surface and return a validated record.

    `principal_separated` is `not_separated` for the in-process self-probe
    (C2) and `unknown` for any other caller; `separated` is never recorded
    here. `host` must be loopback, and `localhost` is normalised to the
    address it names. `deadline` bounds the WHOLE run -- the matrix, the
    reopen pull, the positive control, the artefact reads and the two
    subject-binding subprocesses, each clamped by `Deadline.budget`. A matrix
    cell not reached before it is recorded unattempted; the reads it cut off
    say so and are counted in `artefacts_truncated`; and the record of any run
    the deadline cut short is `inconclusive` with the reason, at whatever
    coverage.
    """
    if principal_separated not in SEPARATION_VALUES:
        raise ValueError(
            f"principal_separated must be one of {SEPARATION_VALUES}, not {principal_separated!r}")
    host = require_loopback(host)
    clock = Deadline(deadline)
    root = root or Path(__file__).resolve().parents[1]

    identity = _runtime_identity(host, port, clock.budget(timeout))
    surface = _surface_identity(identity, port, expect_instance)

    requests: list[dict[str, Any]] = []
    deadline_note: str | None = None
    for path in DOCUMENTED_PATHS:
        for method in PROBED_METHODS:
            if deadline_note is None and clock.exceeded():
                deadline_note = (f"deadline of {clock.seconds:g} s exceeded after "
                                 f"{len(requests)} request(s)")
            if deadline_note is not None:
                requests.append(_unattempted_fact(method, path, "not attempted: " + deadline_note))
                continue
            requests.append(_request_fact(host, port, method, path, clock.budget(timeout)))

    # The explicit reopen pull: STATUS only. The matrix already answered the
    # allowlisted POST (one mint, the browser opened once); this second,
    # explicit pull is recorded apart so the nuisance trigger's rate limit is
    # visible (429 inside the interval) without changing the classification.
    reopen_status: int | None = None
    if not clock.exceeded():
        reopen_status, _ = _exchange(host, port, "POST", "/api/runtime/reopen", body=b"{}",
                                     headers={"content-type": "application/json"},
                                     timeout=clock.budget(timeout))

    positive_control: dict[str, Any] = {"attempted": False, "status": None, "admitted": None,
                                         "detail": "no --session-file supplied"}
    if session_file is not None and not clock.exceeded():
        positive_control = _positive_control(host, port, Path(session_file), clock.budget(timeout))
    elif session_file is not None:
        positive_control["detail"] = _DEADLINE_TRUNCATED

    def guarded(name: str, read: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        if clock.exceeded():
            return _not_applicable(name, f"{_DEADLINE_TRUNCATED} before this read")
        return read()

    probe_pid = os.getpid()
    artefacts = [
        guarded("runtime_record", lambda: _artefact_path_read(
            "runtime_record", Path(runtime_record) if runtime_record else None)),
        guarded("runtime_log", lambda: _artefact_path_read(
            "runtime_log", Path(runtime_log) if runtime_log else None)),
        guarded("seal_dir_listing", lambda: _seal_dir_listing(Path(seal_dir) if seal_dir else None)),
        guarded("process_vm_read", lambda: _process_vm_read(surface["pid"], probe_pid=probe_pid)),
        guarded("browser_handler_cmdline", lambda: _browser_handler_cmdline(
            timeout=clock.budget(60.0))),
        guarded("browser_history", lambda: _browser_history()),
    ]

    # The clock may have run out AFTER the matrix -- during the reopen pull,
    # the positive control or the artefact reads. That used to leave
    # `deadline_exceeded` false beside artefact rows saying the deadline cut
    # them off, and a confinement-shaped state over evidence that was never
    # gathered (round-2 architecture F-B). The flag is set wherever the clock
    # expires, and `derive` makes any expiry inconclusive.
    artefacts_truncated = sum(1 for artefact in artefacts
                              if artefact["detail"].startswith(_DEADLINE_TRUNCATED))
    if deadline_note is None and clock.exceeded():
        deadline_note = (f"deadline of {clock.seconds:g} s exceeded after the request matrix, "
                         f"during the reads that follow it ({artefacts_truncated} artefact "
                         "read(s) not attempted)")

    derivation = derive(requests, bearer_acquired=False, deadline_note=deadline_note)
    record = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "transport": TRANSPORT,
        "subject": _subject_binding(root, surface, clock=clock),
        "requests": requests,
        "coverage": derivation.coverage,
        "deadline_seconds": clock.seconds,
        "deadline_exceeded": deadline_note is not None,
        "deadline_note": deadline_note,
        "artefacts_truncated": artefacts_truncated,
        "reopen_pull_status": reopen_status,
        "positive_control": positive_control,
        "artefacts": artefacts,
        "bearer_acquired_through_surface": False,
        "classification": derivation.state,
        "classification_reason": derivation.reason,
        "principal_separated": principal_separated,
        "not_confinement_reason": (
            not_confinement_reason(principal_separated)
            if derivation.state == STATE_ADMITTED_NUISANCE else None
        ),
    }
    validate_record(record)
    return record


# ---------------------------------------------------------------------------
# Operator CLI.
# ---------------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probe_control_plane",
        description="Probe a live Forge onboarding control plane from this process and write a "
                    "nornyx.forge.control_plane_probe.v1 record. Runs no provider and changes no "
                    "admission criterion (Tranche C, slice C2). Against a browser-granted surface "
                    "the run opens the owner's browser once (one reopen mint).",
        epilog=f"exit codes: {EXIT_NO_AUTHORITY} admitted_nuisance or reachable_unadmitted (no "
               f"authority reached by this caller; NOT confinement of anything); "
               f"{EXIT_AUTHORITY_REACHABLE} authority_reachable; {EXIT_INCONCLUSIVE} inconclusive; "
               f"{EXIT_REFUSED} the probe refused to run (a non-loopback host, an --out inside the "
               "repository) or the record failed its own validation. Every refusal is one line on "
               "stderr naming no path, and nothing else leaves this tool: a hostile surface cannot "
               "turn a bad body into a traceback.",
    )
    parser.add_argument("--port", type=int, required=True, help="The loopback port the surface serves on")
    parser.add_argument("--host", default=_ONBOARDING_HOST,
                        help="The loopback host (default 127.0.0.1); a non-loopback host is "
                             "refused and 'localhost' is normalised to 127.0.0.1")
    parser.add_argument("--expect-instance", default=None, help="The instance token the surface should report")
    parser.add_argument("--session-file", default=None,
                        help="Operator-supplied path to this run's session file, for the positive control only")
    parser.add_argument("--principal-separated", choices=SEPARATION_VALUES, default=SEPARATION_UNKNOWN,
                        help="'not_separated' for a self-probe as the surface owner; 'unknown' otherwise")
    parser.add_argument("--runtime-record", default=None, help="Path to the runtime record, if this caller may reach it")
    parser.add_argument("--runtime-log", default=None, help="Path to the runtime log, if this caller may reach it")
    parser.add_argument("--seal-dir", default=None, help="Path to the seal directory, if this caller may reach it")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request socket timeout in seconds")
    parser.add_argument("--deadline", type=float, default=DEFAULT_DEADLINE_S,
                        help=f"Wall-clock bound for the whole run in seconds (default {DEFAULT_DEADLINE_S:g})")
    parser.add_argument("--out", default=None,
                        help="Write the record here (JSON, LF); a path inside the repository "
                             "working tree is REFUSED. It is always printed too")
    return parser


#: A filesystem path left in a message. Scrubbed from every refusal line: the
#: crash this replaces printed a traceback whose frames spelled the host's own
#: directories (round-2 security P2-1), and a refusal is one line that says
#: what was refused, not where this machine keeps its files.
_PATH_FRAGMENT = re.compile(
    r"(?:[A-Za-z]:[\\/]|(?<![\w~.])/(?:home|Users|root|usr|opt|tmp|var|etc)/)[^\s'\"]*")

#: How much of a refusal reaches stderr. One line, and a bounded one.
_REFUSAL_LIMIT = 400


def _refusal_line(error: BaseException) -> str:
    """ONE line for stderr, naming no path.

    Three things, in order: `redact` folds every spelling of home and removes
    the login and the machine name; any remaining path fragment -- a
    drive-letter path, a POSIX home or system path -- becomes `<path>`, because
    a path this host did not put in `redact`'s token list is still a path; and
    the whole thing is collapsed to one line and bounded. An operator reading
    a refusal learns which rule refused, never where this machine keeps
    anything.
    """
    message = redact(f"{error}") or error.__class__.__name__
    message = _PATH_FRAGMENT.sub("<path>", message)
    message = " ".join(message.split())
    if len(message) > _REFUSAL_LIMIT:
        message = message[:_REFUSAL_LIMIT - 3] + "..."
    return f"probe_control_plane: refused: {message}"


def _require_out_outside_the_tree(out: str, root: Path) -> None:
    """`--out` may not write inside the repository working tree.

    Documented against and then left to the operator, which is a rule held by
    nobody (round-2 architecture F-D). A record written into the tree is an
    untracked artefact in a repository whose evidence cycle reads the tree, and
    the next `git add -A` commits a measurement as if it were source. Compared
    on RESOLVED paths, so `..` and a symlink into the tree are refused too. The
    message names no path.
    """
    try:
        inside = Path(out).resolve().is_relative_to(root.resolve())
    except OSError:
        inside = False
    if inside:
        raise ValueError(
            "--out points inside this repository's working tree; a probe record is a "
            "measurement, not source, and the evidence cycle commits what it finds in the "
            "tree. Choose a path outside it")


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        if arguments.out:
            _require_out_outside_the_tree(arguments.out, root)
        record = probe(
            arguments.port,
            host=arguments.host,
            expect_instance=arguments.expect_instance,
            session_file=arguments.session_file,
            principal_separated=arguments.principal_separated,
            runtime_record=arguments.runtime_record,
            runtime_log=arguments.runtime_log,
            seal_dir=arguments.seal_dir,
            timeout=arguments.timeout,
            deadline=arguments.deadline,
        )
    # Every refusal this tool can reach is one exit code and one line.
    # `NonLoopbackHostError` is a ValueError; `TypeError` is here because a
    # hostile surface can put a value of any type into a body this tool reads,
    # and a traceback out of `main()` falsified the exit-code enumeration in
    # the README, in A-028 and in `--help` (round-2 security P2-1).
    except (ProbeRecordError, ValueError, TypeError) as refusal:
        print(_refusal_line(refusal), file=sys.stderr)
        return EXIT_REFUSED
    serialised = json.dumps(record, indent=2)
    if arguments.out:
        # A probe record refuses to be a REPORT.md: it is written as JSON, LF,
        # to the operator's chosen path, never as prose into the tree.
        Path(arguments.out).write_text(serialised + "\n", encoding="utf-8", newline="")
    print(serialised)
    return EXIT_CODES[record["classification"]]


if __name__ == "__main__":  # pragma: no cover - the process entry
    raise SystemExit(main())
