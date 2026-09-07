"""The control-plane session and its gate -- Tranche B.

WHAT WOULD FALSIFY THIS SLICE: an HTTP request without this run's bearer that
changes state, lifecycle, provider selection, BRD or the runtime; a token or
nonce reachable where the provider can look; a token from another run, project
or a guess admitted; a comparison that is not constant-time; a route outside the
allowlist reachable without a token; a stale run's token still working; a
provider PROCESS that inherits Forge's environment; a credential that makes the
gate raise instead of refuse; or a response that carries a secret.

The invariants, and where each is pinned:

  INV-B1  no un-bearered request moves state -- test_no_bearer_is_refused_on_every_authority_route,
          test_a_refused_write_leaves_the_state_unchanged,
          test_the_composed_route_census_refuses_everything_but_the_four_allowlisted_pairs
          (state bytes and lifecycle unchanged across the whole route table).
  INV-B2  the secrets never reach the provider or any record/log/page/env/response --
          test_the_provider_environment_excludes_forge_variables_and_secrets,
          test_the_real_build_route_runs_the_real_flow_and_the_provider_process_sees_neither_secret
          (a REAL DevelopmentFlow, a fake provider EXECUTABLE resolved by name),
          test_the_unauthenticated_surfaces_carry_no_secret,
          test_no_response_carries_a_secret_or_a_cookie. (The runtime record,
          log and trail are pinned in tests/test_windows_runtime.py.)
  INV-B3  a foreign, guessed, partial or one-byte-off token is refused, constant-time --
          test_a_random_bearer_is_refused, test_a_one_byte_change_is_refused,
          test_every_partial_prefix_suffix_and_padded_bearer_is_refused,
          test_a_previous_runs_token_is_refused,
          test_verify_and_redeem_compare_only_through_compare_digest (an AST
          walk over both methods, after two lexical pins let a swapped `==` through),
          test_a_nonce_is_not_a_bearer.
  INV-B4  no other browser context can move authority -- the redeem/reopen
          Origin and Sec-Fetch checks: test_redeem_enforces_browser_provenance,
          test_origin_is_compared_by_full_serialization,
          test_reopen_admits_a_non_browser_but_refuses_a_foreign_origin,
          test_a_forge_cookie_is_refused_on_a_gated_request,
          test_the_allowlisted_routes_ignore_cookies, test_a_navigation_post_is_refused.
  INV-B5  the gate covers every route of the COMPOSED surface --
          test_the_composed_route_census_refuses_everything_but_the_four_allowlisted_pairs,
          test_the_route_census_refuses_every_gated_route (the bare surface),
          test_a_websocket_handshake_is_closed_before_accept.
  INV-B6  per run fresh secrets, the previous run's dead -- test_each_run_mints_fresh_secrets,
          test_a_second_mint_invalidates_the_first, the slot tests, and the
          reopen-queue tests (a local reopen cannot evict the person's pending
          Reconnect nonce; the queue's depth is what the rate limit admits in one TTL).
  INV-B7  an app has a session and gate by construction -- test_create_app_always_installs_the_gate.

The mutation for each is recorded in <scratch>/b-repair/REPORT.md.
"""

from __future__ import annotations

import ast
import asyncio
import hmac
import inspect
import json
import math
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from types import MappingProxyType

import pytest
from fastapi.testclient import TestClient
from session_client import authed_client, bearer_header
from starlette.routing import Route

import nornyx_forge
from nornyx_forge import claude_worker, codex_worker, control_plane_session
from nornyx_forge.capsule import PROVIDERS
from nornyx_forge.control_plane_session import (
    ALLOWLIST,
    BAD_SHAPE,
    COOKIE_REFUSED,
    CROSS_ORIGIN,
    LAUNCH_SLOT,
    NO_SESSION,
    NONCE_INVALID,
    NONCE_TTL_S,
    REOPEN_PENDING_BOUND,
    REOPEN_SLOT,
    WEBSOCKET_REFUSED_CODE,
    ControlPlaneSession,
    SessionGate,
    _bearer,
)
from nornyx_forge.onboarding_app import create_app
from nornyx_forge.provider_contract import GovernedEligibility
from nornyx_forge.windows_runtime import (
    REOPEN_BUSY,
    REOPEN_FAILED,
    REOPEN_INTERVAL_S,
    REOPEN_NOT_GRANTED,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / ".nornyx" / "contracts"
#: The source the grep tests read is the package that was IMPORTED, not a
#: tree derived from this test file's location: an editable install pinning
#: another checkout would otherwise have these tests reading one tree while
#: every other test exercised another (second review P4-2; A-026).
SRC = Path(nornyx_forge.__file__).resolve().parent
HUMAN = {"kind": "human", "ident": "casey"}

#: The allowlist, HARDCODED here rather than read from the module, so that a
#: route added to `ALLOWLIST` is a red test and not a moved oracle.
EXPECTED_ALLOWLIST = frozenset({
    ("GET", "/"),
    ("GET", "/api/runtime"),
    ("POST", "/api/session/redeem"),
    ("POST", "/api/runtime/reopen"),
})
#: Every method the census probes on every path, declared or not.
PROBED_METHODS = ("GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE")
#: The only response headers this surface may emit. Declared, so that a header
#: carrying a secret (or any Set-Cookie) is refused by NAME, not by a grep for
#: one spelling.
ALLOWED_RESPONSE_HEADERS = frozenset({
    "content-type", "content-length", "date", "server", "connection", "transfer-encoding",
    # Emitted by the redeem 200 alone -- the one response that carries the
    # token -- and pinned there as present; declared here so the declared set
    # stays the whole vocabulary.
    "cache-control", "pragma",
})
#: The served URL the composed surface answers to (TrustedHost admits 127.0.0.1).
SERVED = "http://127.0.0.1:8710"


def _app(tmp_path: Path, **kwargs):
    return create_app(tmp_path / "capsule", CONTRACTS, seal_dir=tmp_path / "seals", **kwargs)


def _eligible(provider: str) -> GovernedEligibility:
    return GovernedEligibility(provider=provider, eligible=True, confinement="established",
                              reason="deterministic seam; no provider executes")


def _composed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, browser_granted: bool = True,
              opener=None, clock=None):
    """The surface as the Windows runtime SERVES it: `assemble` (create_app plus
    the Host rule) with the operational routes attached afterwards. Returns the
    app, the stop-request log and the opened-browser log; `opener` replaces
    the browser adapter (a failing one, for the owner-failure specimens);
    `clock` drives the reopen route's rate limiter (the real interval,
    injected time) so a specimen can step past the interval without waiting."""
    from nornyx_forge import onboarding_serve  # noqa: PLC0415
    from nornyx_forge.windows_runtime import RUNTIME_SCHEMA, attach_runtime_routes  # noqa: PLC0415

    monkeypatch.setattr(onboarding_serve, "SEAL_DIR", tmp_path / "seals")
    monkeypatch.setattr(onboarding_serve, "resolve_packaged_root", lambda: ROOT)
    app = onboarding_serve.assemble(tmp_path / "project")
    stops: list[int] = []
    opened: list[str] = []
    timing = {} if clock is None else {"clock": clock}
    attach_runtime_routes(
        app,
        identity={"schema": RUNTIME_SCHEMA, "instance": "0123456789abcdef", "bundle_root": str(tmp_path),
                  "bundle_mode": "developer", "project_dir": str(tmp_path / "project"), "port": 8710,
                  "pid": 1, "python": sys.executable, "started_at": "2026-01-01T00:00:00Z"},
        request_stop=lambda: stops.append(1),
        session=app.state.session, open_browser=opener or opened.append, url=SERVED + "/",
        browser_granted=browser_granted, **timing,
    )
    return app, stops, opened


def _asgi(app, method: str, path: str, *, host: str = "127.0.0.1:8710") -> tuple[int, object]:
    """One request driven through the COMPOSED app as a raw ASGI scope, so the
    path reaches the gate exactly as spelled -- an HTTP client normalises dot
    segments and doubled slashes before they leave it, and the property under
    test is what the gate does with the unnormalised form. Returns the status
    and the decoded JSON body (None when empty)."""
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
        "scheme": "http", "path": path, "raw_path": path.encode("latin-1"), "query_string": b"",
        "root_path": "", "headers": [(b"host", host.encode("latin-1"))],
        "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 8710),
    }
    sent: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    status = next(message["status"] for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return status, (json.loads(body) if body else None)


def _snapshot(root: Path) -> dict[str, bytes]:
    return {str(path.relative_to(root)): path.read_bytes()
            for path in sorted(root.rglob("*")) if path.is_file()}


# ---------------------------------------------------------------------------
# ControlPlaneSession: token, nonce, TTL, two slots (INV-B3, B6)
# ---------------------------------------------------------------------------

def test_a_fresh_session_verifies_only_its_own_token():
    session = ControlPlaneSession()
    assert session.verify(session.token) is True
    assert session.verify("not-the-token") is False
    assert session.verify(None) is False
    assert session.verify(session.token + "x") is False


#: The CALL spellings of the same three comparisons. `ast.Compare` does not
#: see any of them: `candidate.__eq__(self._token_bytes)` and
#: `candidate.__eq__(outstanding) or compare_digest(...)` each survived all 97
#: tests of this module (round-4 test P3), and `operator.eq` reached through
#: `__import__` died only to the architecture gate, which is a different
#: property. A dunder attribute is a comparison wherever it is called; the
#: bare names are the `from operator import eq` spelling -- and, because the
#: rule below reads the ALIAS rather than the name it binds, the
#: `from operator import eq as _same` spelling too (round-6 test T-P3-1,
#: which survived 98/98 when only uses were read).
_COMPARISON_DUNDERS = frozenset({"__eq__", "__ne__", "__contains__"})
_COMPARISON_FUNCTIONS = frozenset({"eq", "ne", "contains"})

#: The builtins and `operator` helpers that fetch a method BY NAME. Round-5
#: test P3-b: reading only CALLS left `checker = candidate.__eq__` followed by
#: `checker(...)`, and `getattr(candidate, "__eq__")(...)`, alive through all
#: 98 tests -- the call site names nothing forbidden, so nothing was found.
#: Round-7 finding F-2(a) added the other half: reading only the LITERAL
#: argument left `methodcaller('__e' + 'q__', self._token_bytes)(candidate)`
#: alive through all 99, because the string the detector wanted to read does
#: not exist until run time. The rule below therefore refuses a COMPUTED name
#: to any of these three outright.
_ATTRIBUTE_LOOKUPS = frozenset({"getattr", "attrgetter", "methodcaller"})

#: Where the NAME argument sits in a call to each of them: `getattr(object,
#: name)` puts it second, `attrgetter(name)` and `methodcaller(name, *args)`
#: first.
_NAME_ARGUMENT = {"getattr": 1, "attrgetter": 0, "methodcaller": 0}


def _comparison_reference(node: ast.AST) -> bool:
    """True when `node` NAMES a comparison, wherever it appears.

    Not "calls": names. The round-4 detector asked whether a `Call`'s callee
    was a forbidden name, so binding the method first and calling the binding
    later passed. A comparison method that is fetched at all is a comparison
    that can be called, so the fetch is what is refused -- as an attribute
    (`candidate.__eq__`), as a bare name (`from operator import ne`), as a
    LITERAL string handed to `getattr`/`attrgetter`/`methodcaller`, as a
    dunder string literal anywhere at all (`type(c).__dict__["__eq__"]` and
    every other route through the name), and AT THE IMPORT ITSELF.

    Those three functions carry a rule of their own, and it is stronger than
    "match the string": a name handed to them that is NOT a string literal is
    refused whatever it would evaluate to. Round-7 finding F-2(a) is why.
    `methodcaller('__e' + 'q__', self._token_bytes)(candidate)` survived all
    99 tests of this module, because the argument is a `BinOp` and the string
    the detector was matching never appears in the source at all. Any
    concatenation, name, format or `chr()` walk would have done the same, so
    what is refused is the whole class: a by-name fetch whose name this reader
    cannot see is a by-name fetch that could be any name. `getattr(a, "spam")`
    -- a literal that is not a comparison -- is still allowed, which is what
    keeps the rule a rule about computed names rather than about `getattr`.

    That last one is round-6 test T-P3-1, and it is why the rule is written
    on the binding rather than on the use. `from operator import eq as _same`
    followed by `if not _same(candidate, self._token_bytes): return False`
    survived all 98 tests of this module: the `Name` at the call site is
    `_same`, which is forbidden nowhere, and the only node that carries the
    word `eq` is the `ast.alias`, which the detector never looked at. An
    ALIAS RULE closes the whole family at once -- whatever the asname, the
    alias's `name` is the imported object's real name, so `eq as _same`,
    `ne as _n` and `contains as _in` are all reported, and no future asname
    needs a new rule. The `ImportFrom` is reported alongside it so that the
    reported text names the module the comparison came from.

    Conservative on purpose: a local variable spelled `eq` or a literal
    `"__eq__"` with some innocent purpose would be reported. Neither method
    has one, and a detector that errs toward reporting is the right error for
    this property."""
    forbidden = _COMPARISON_DUNDERS | _COMPARISON_FUNCTIONS
    if isinstance(node, ast.Attribute):
        return node.attr in forbidden
    if isinstance(node, ast.Name):
        return node.id in forbidden
    if isinstance(node, ast.alias):
        # The BINDING, not the bound name: `asname` is the caller's choice and
        # `name` is the object's, so no rename escapes this.
        return node.name in forbidden
    if isinstance(node, ast.ImportFrom):
        return node.module == "operator" and any(
            alias.name in _COMPARISON_FUNCTIONS for alias in node.names)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value in _COMPARISON_DUNDERS
    if isinstance(node, ast.Call):
        fetch = (node.func.attr if isinstance(node.func, ast.Attribute)
                 else getattr(node.func, "id", None))
        if fetch not in _ATTRIBUTE_LOOKUPS:
            return False
        if any(isinstance(argument, ast.Constant) and isinstance(argument.value, str)
               and argument.value in forbidden for argument in node.args):
            return True
        # A COMPUTED name to a by-name fetch is refused whatever it computes:
        # the reader cannot see it, so it could be any name (round-7 F-2(a)).
        # A missing name argument -- `methodcaller(*names)`, `getattr(a)` --
        # is unreadable in the same way and is refused with it.
        position = _NAME_ARGUMENT[fetch]
        named = node.args[position:position + 1]
        return not named or not (isinstance(named[0], ast.Constant)
                                 and isinstance(named[0].value, str))
    return False


def _comparisons_in(function) -> list[str]:
    """Every equality or membership comparison in `function`'s source, as
    text, whether it is WRITTEN as an operator, CALLED, BOUND for a later
    call, or FETCHED by name. Read from the IMPORTED object with `inspect`,
    parsed as an AST, so the operand order, spacing and spelling of a
    comparison change nothing about whether it is found.

    WHAT THIS PIN IS, said plainly: it is SPELLING-BASED. It cannot prove that
    a comparison is constant time, and it does not try to. What it does is
    forbid the spellings through which a short-circuiting comparison gets back
    in -- every one this repository's reviews have found, and the general
    shape of each rather than the instance. A spelling nobody has thought of
    is the standing residual, and the reason the positive controls below name
    every shape a round actually found.

    Ordering comparisons (`<`, `>`, `<=`, `>=`) are deliberately NOT here:
    `redeem` compares the clock against a stored expiry, and neither is a
    secret. What this refuses is a comparison that could read one."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    return [ast.unparse(node) for node in ast.walk(tree)
            if (isinstance(node, ast.Compare)
                and any(isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn))
                        for op in node.ops))
            or _comparison_reference(node)]


def _compare_digest_calls_in(function) -> int:
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    return sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "compare_digest"
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "hmac"
    )


@pytest.mark.parametrize("method", [ControlPlaneSession.verify, ControlPlaneSession.redeem],
                         ids=["verify", "redeem"])
def test_verify_and_redeem_compare_only_through_compare_digest(method):
    """The comparison primitive is the property (a behavioural timing assertion
    is flaky), and `==` passes every functional test here, so the source is
    the oracle -- but as an AST, not as substrings. Two lexical pins in a row
    were permeable: `candidate == self._token_bytes` was caught by a grep for
    `== self._token` while the swapped `self._token_bytes == candidate` passed
    80 tests (round-3 test P1, M06b), and `redeem`'s nonce comparison was not
    read at all (M24). Now NEITHER method may contain any `==`, `!=`, `in` or
    `not in` comparison -- whatever the operands, in whatever order -- and
    each must call `hmac.compare_digest` at least once. Proved red under all
    four operand-order mutants on both call sites.

    A THIRD permeable shape was found in round 4: the operator WRITTEN as a
    CALL. `if candidate.__eq__(self._token_bytes): return True` in `verify`
    and `candidate.__eq__(outstanding) or hmac.compare_digest(...)` in
    `redeem` each survived all 97 tests, because `ast.Compare` sees neither;
    `operator.eq` reached through `__import__` died only to the architecture
    gate, which pins imports, not this property. `_comparisons_in` now reads
    calls as well, and the two mutants are red here."""
    assert _comparisons_in(method) == [], (
        f"{method.__qualname__} compares with ==, !=, in or not in, written or "
        f"called: {_comparisons_in(method)}")
    assert _compare_digest_calls_in(method) >= 1, f"{method.__qualname__} never calls hmac.compare_digest"


def test_the_comparison_detector_sees_a_comparison_however_it_is_spelled():
    """The detector's own positive and negative controls, so a change that
    quietly narrowed it would be red here rather than silently permissive.

    Each positive names WHAT THE DETECTOR MUST REPORT, not merely that it
    reported something (round-5 test P4-c). `!= []` was the old assertion, and
    it is satisfied by a detector that finds the wrong node -- or by one that
    reports every node in the function. The text below is the source of the
    thing that has to be caught.

    Round 4 contributed the three CALL spellings. Round 5 contributed the two
    that survived them (test P3-b): a comparison method BOUND and called
    later, and one FETCHED by name -- neither of which is a call to anything
    forbidden at the point of the call. Round 6 contributed the one that
    survived THOSE (test T-P3-1): the comparison imported under a NEW NAME,
    `from operator import eq as _same`, where the call site names only
    `_same` and the word `eq` appears in no node the detector was reading.
    Its expected text is the alias itself, `eq as _same`, so a detector that
    reported the import statement while missing the alias -- or one that
    matched the asname and would therefore need a new rule per rename -- is
    red here. Round 7 contributed the one that survived THAT (finding
    F-2(a)): the name COMPUTED rather than written, `methodcaller('__e' +
    'q__', ...)`, where the string the detector matched exists only at run
    time; its expected text is the whole fetch, and `computed_getattr` is the
    same shape through a variable. The negatives are the ordering comparison
    `redeem` really contains, `hmac.compare_digest` itself, and a LITERAL
    by-name fetch of something innocent -- without that last one, a detector
    that reported every `getattr` would pass the two computed positives."""
    def called_dunder(a, b):  # pragma: no cover - read as source, never run
        return a.__eq__(b)

    def called_operator(a, b):  # pragma: no cover - read as source, never run
        import operator
        return operator.contains(a, b)

    def called_bare(a, b):  # pragma: no cover - read as source, never run
        from operator import ne
        return ne(a, b)

    def bound_then_called(a, b):  # pragma: no cover - read as source, never run
        checker = a.__eq__
        return checker(b)

    def fetched_by_name(a, b):  # pragma: no cover - read as source, never run
        return getattr(a, "__eq__")(b)  # noqa: B009 - the spelling IS the specimen

    def fetched_by_attrgetter(a, b):  # pragma: no cover - read as source, never run
        import operator
        return operator.attrgetter("__eq__")(a)(b)

    def imported_under_another_name(a, b):  # pragma: no cover - source only
        from operator import eq as _same
        return _same(a, b)

    def imported_under_another_name_ne(a, b):  # pragma: no cover - source only
        from operator import ne as _differs
        return _differs(a, b)

    def computed_methodcaller(a, b):  # pragma: no cover - source only
        import operator
        return operator.methodcaller("__e" + "q__", b)(a)

    def computed_getattr(a, b):  # pragma: no cover - source only
        name = "__e" + "q__"
        return getattr(a, name)(b)

    def ordering_and_digest(a, b, now, expires):  # pragma: no cover - source only
        if now > expires:
            return False
        return hmac.compare_digest(a, b)

    def literal_fetch_of_something_else(a, b):  # pragma: no cover - source only
        return getattr(a, "encode")(b)  # noqa: B009 - the spelling IS the specimen

    must_report = {
        called_dunder: "a.__eq__",
        called_operator: "operator.contains",
        called_bare: "ne",
        bound_then_called: "a.__eq__",
        fetched_by_name: "getattr(a, '__eq__')",
        fetched_by_attrgetter: "operator.attrgetter('__eq__')",
        imported_under_another_name: "eq as _same",
        imported_under_another_name_ne: "ne as _differs",
        computed_methodcaller: "operator.methodcaller('__e' + 'q__', b)",
        computed_getattr: "getattr(a, name)",
    }
    for specimen, expected in must_report.items():
        reported = _comparisons_in(specimen)
        assert expected in reported, (specimen.__name__, expected, reported)
    # The import statement is reported BESIDE its alias, so the text says
    # which module the comparison was fetched from and not only that some
    # name called `eq` was bound.
    aliased = _comparisons_in(imported_under_another_name)
    assert "from operator import eq as _same" in aliased, aliased
    assert _comparisons_in(ordering_and_digest) == []
    # The computed-name rule is a rule about COMPUTED names, not about
    # `getattr`: a literal name that is not a comparison is still allowed, so
    # the two positives above are the rule biting and not the detector
    # reporting every by-name fetch it sees.
    assert _comparisons_in(literal_fetch_of_something_else) == [], (
        "the computed-name rule swallowed an innocent literal fetch, which makes the "
        "two computed specimens above prove nothing")


def test_the_session_module_binds_no_comparison_function_by_import():
    """The other half of the alias finding, at MODULE scope.

    `_comparisons_in` reads one function's source, so an `operator` import
    lifted to the top of `control_plane_session` -- with only the bound name
    used inside `verify` -- would be a comparison the per-method pin cannot
    see, whatever rule it carries. The module is small and imports no
    `operator` at all (`hmac`, `json`, `secrets`, `threading`, `time`,
    `collections.deque`, `types.MappingProxyType`, `typing`), so the honest
    close is to forbid the binding outright, at every scope, rather than to
    leave the residual named and open.

    WHAT THIS READS, exactly: `ast.alias` and `ast.ImportFrom` nodes -- that
    is, comparison functions arriving BY IMPORT. It was called "anywhere"
    until round 8, which is a name for a wider property than it has: a
    comparison helper DEFINED in the module rather than imported is not a
    binding this reader looks at (round-7 finding F-2(b)). That residual is
    closed by the test below, not by this one, and the name now says so.

    Read from `__file__` on the IMPORTED module, so it is the shipped source
    and not a path this test chose."""
    source = Path(control_plane_session.__file__).read_text(encoding="utf-8")
    bindings = [ast.unparse(node) for node in ast.walk(ast.parse(source))
                if isinstance(node, (ast.alias, ast.ImportFrom))
                and _comparison_reference(node)]
    assert bindings == [], (
        "control_plane_session binds a comparison function by import; the "
        f"per-method AST pin cannot see a module-scope alias: {bindings}")


def _module_scope_callables(tree: ast.Module) -> dict[str, ast.AST]:
    """Every callable bound at MODULE scope: name -> the node that binds it."""
    defined: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined[node.name] = node
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    defined[target.id] = node.value
        elif (isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Lambda)
              and isinstance(node.target, ast.Name)):
            defined[node.target.id] = node.value
    return defined


def _method_node(tree: ast.Module, class_name: str, method: str) -> ast.AST:
    """The `ast` node of one method of one class, from the module's source."""
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for member in node.body:
                if (isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and member.name == method):
                    return member
    raise AssertionError(f"{class_name}.{method} is not in the module source")


def _module_helpers_reached_from(tree: ast.Module, *starts: ast.AST) -> set[str]:
    """The module-scope callables those nodes NAME, transitively.

    "Name", not "call", for the reason the per-method detector is written that
    way: `checker = _same` followed by `checker(...)` calls nothing named."""
    defined = _module_scope_callables(tree)
    reached: set[str] = set()
    frontier = list(starts)
    while frontier:
        for inner in ast.walk(frontier.pop()):
            if isinstance(inner, ast.Name) and inner.id in defined and inner.id not in reached:
                reached.add(inner.id)
                frontier.append(defined[inner.id])
    return reached


def test_no_module_scope_helper_does_verify_or_redeems_comparison():
    """The residual the import pin above leaves: a helper DEFINED here.

    Round-7 finding F-2(b). A module-scope `def _same(a, b): return a == b`,
    called from `verify`, survived all 99 tests of this module and every gate.
    The per-method pin reads one function's source and finds `_same(...)`,
    which is forbidden nowhere; the import pin reads bindings and finds no
    import. A locally defined helper is neither.

    THE WIDENING THAT WAS ASKED FOR IS FALSE OF THIS MODULE, and was measured
    before it was rejected: "no module-scope callable containing an `==`,
    `!=`, `in` or `not in` comparison" fails on three legitimate ones today --
    `_credential_bytes` checks `character in _CREDENTIAL_ALPHABET`, `_headers`
    checks `name in collected`, and `_bearer` checks `authorization !=
    authorization.strip()` and the scheme against `'bearer'`. None compares
    anything to a secret. So what is pinned is the DELEGATION rather than the
    comparison: the module-scope callables `verify` and `redeem` reach,
    transitively, are enumerated EXACTLY, and the comparisons of the one they
    do reach are enumerated exactly too. Both doors are shut -- a new helper
    changes the first list, and moving the secret comparison into the one
    allowed helper changes the second -- and neither is `!= []`, which is
    satisfied by a reader that finds the wrong thing.

    Read from `__file__` on the IMPORTED module, like the pin above."""
    source = Path(control_plane_session.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    reached = _module_helpers_reached_from(
        tree,
        _method_node(tree, "ControlPlaneSession", "verify"),
        _method_node(tree, "ControlPlaneSession", "redeem"))
    assert reached == {"_credential_bytes"}, (
        "verify/redeem name a module-scope callable other than the credential shape "
        "check; a comparison delegated to it is invisible to the per-method AST pin "
        f"and to the import pin alike: {sorted(reached)}")
    shape_check = _comparisons_in(control_plane_session._credential_bytes)
    assert shape_check == ["character in _CREDENTIAL_ALPHABET"], (
        "the one module-scope helper verify/redeem reach no longer compares only a "
        f"candidate's characters against the public alphabet: {shape_check}")


def test_mint_produces_one_nonce_that_redeems_once():
    session = ControlPlaneSession()
    nonce = session.mint()
    assert session.redeem(nonce) == session.token
    assert session.redeem(nonce) is None, "a nonce is single-use"


def test_a_wrong_guess_neither_matches_nor_consumes_the_nonce():
    session = ControlPlaneSession()
    nonce = session.mint()
    assert session.redeem("wrong") is None
    assert session.redeem(nonce) == session.token, "a guess must not invalidate the real nonce"


def test_a_second_mint_invalidates_the_first():
    session = ControlPlaneSession()
    first = session.mint()
    second = session.mint()
    assert session.redeem(first) is None, "the previous nonce is dead"
    assert session.redeem(second) == session.token


def test_a_nonce_expires_after_its_ttl():
    clock = {"t": 1000.0}
    session = ControlPlaneSession(ttl=120.0, clock=lambda: clock["t"])
    nonce = session.mint()
    clock["t"] += 121.0
    assert session.redeem(nonce) is None, "an expired nonce is refused"


def test_create_apps_session_expires_a_nonce_at_the_default_ttl(tmp_path: Path):
    """Test P2 (round 3): every TTL test passed `ttl=` explicitly, so
    `NONCE_TTL_S` was read by no test and 120 -> 86400 passed 144 (M25). The
    constant is pinned, and the session `create_app` mints -- with no `ttl`
    and no `clock` argument -- is proved to expire at it: the session resolves
    its default clock when it is constructed, so the standard library's
    `time.monotonic` is replaced for exactly the construction and nothing
    else. Valid through the 120th second inclusive; dead one instant past it."""
    assert NONCE_TTL_S == 120.0
    clock = {"t": 5000.0}
    with pytest.MonkeyPatch.context() as construction:
        construction.setattr(time, "monotonic", lambda: clock["t"])
        app = _app(tmp_path, flow_factory=lambda *a, **k: None)
    session = app.state.session
    at_boundary = session.mint()
    clock["t"] += 120.0
    assert session.redeem(at_boundary) == session.token, "a nonce died before its 120 s were up"
    past = session.mint()
    clock["t"] += 120.001
    assert session.redeem(past) is None, "a nonce outlived the default TTL"
    inside = session.mint()
    clock["t"] += 119.0
    assert session.redeem(inside) == session.token


def test_each_run_mints_fresh_secrets():
    first, second = ControlPlaneSession(), ControlPlaneSession()
    assert first.token != second.token
    nonce = first.mint()
    assert second.redeem(nonce) is None, "one run's nonce does not redeem on another"
    assert second.verify(first.token) is False, "one run's token is dead on another"


def test_the_launch_and_reopen_slots_are_independent():
    """Two single-use nonces: redeeming one leaves the other outstanding, and
    the one redeemed is dead. A local process calling reopen therefore cannot
    invalidate the launch bootstrap the person's page is about to redeem."""
    session = ControlPlaneSession()
    launch = session.mint(LAUNCH_SLOT)
    reopen = session.mint(REOPEN_SLOT)
    assert launch != reopen
    assert session.redeem(reopen) == session.token
    assert session.redeem(reopen) is None, "the reopen nonce is single-use"
    assert session.redeem(launch) == session.token, "redeeming the reopen nonce killed the launch nonce"
    assert session.redeem(launch) is None


def test_a_reopen_mint_replaces_neither_the_launch_nonce_nor_a_pending_reopen_nonce():
    """Security P3-1 (round 3), the reviewer's A/B/C at the session level. A:
    the person's Reconnect mints a reopen nonce. B: a local caller's reopen
    mints another. C: the person's page redeems ITS nonce -- and gets the
    token. A single reopen slot answered C with None (measured: 404 on the
    wire). Every nonce stays single-use and the launch nonce is untouched."""
    session = ControlPlaneSession()
    launch = session.mint(LAUNCH_SLOT)
    person = session.mint(REOPEN_SLOT)
    intruder = session.mint(REOPEN_SLOT)
    assert intruder != person
    assert session.redeem(person) == session.token, "a later reopen mint evicted the person's pending nonce"
    assert session.redeem(person) is None, "the person's reopen nonce is single-use"
    assert session.redeem(launch) == session.token, "a reopen mint invalidated the launch nonce"
    assert session.redeem(intruder) == session.token
    assert session.redeem(intruder) is None, "the intruder's reopen nonce is single-use"


def test_the_reopen_queue_holds_exactly_its_bound_and_evicts_the_oldest_past_it():
    """Without the route's rate limit (a direct mint) the queue is bounded:
    the bound-plus-first mint evicts the oldest and only the oldest."""
    session = ControlPlaneSession()
    minted = [session.mint(REOPEN_SLOT) for _ in range(REOPEN_PENDING_BOUND + 1)]
    assert session.redeem(minted[0]) is None, "the oldest reopen nonce survived past the bound"
    for nonce in minted[1:]:
        assert session.redeem(nonce) == session.token, "a nonce inside the bound was evicted"
        assert session.redeem(nonce) is None


def test_under_the_rate_limit_no_unexpired_reopen_nonce_is_ever_evicted():
    """The bound is DERIVED, not chosen: with one mint per `REOPEN_INTERVAL_S`
    and a nonce valid through `mint + NONCE_TTL_S` inclusive, the most nonces
    that can be outstanding at once is floor(TTL / interval) + 1 -- at t = 0,
    10, ..., 120 with today's constants, thirteen. Under an injected clock
    stepping at exactly the interval, every one of them still redeems at the
    last mint's instant (a bound of twelve would have evicted the first), and
    an expired one is pruned rather than kept."""
    clock = {"t": 0.0}
    session = ControlPlaneSession(clock=lambda: clock["t"])
    admitted = int(NONCE_TTL_S // REOPEN_INTERVAL_S) + 1
    assert admitted == REOPEN_PENDING_BOUND == 13
    minted = []
    for step in range(admitted):
        clock["t"] = step * REOPEN_INTERVAL_S
        minted.append(session.mint(REOPEN_SLOT))
    assert clock["t"] == NONCE_TTL_S, "the last mint sits exactly at the first nonce's expiry instant"
    for nonce in minted:
        assert session.redeem(nonce) == session.token, "an unexpired nonce was evicted under the rate limit"
    # Expiry PRUNES, and that word is now measured rather than asserted about.
    # Round-4 test P4: re-appending every expired entry instead of dropping it
    # survived all 97 tests here, because a dead nonce answers None whether it
    # was removed or merely refused. The queue's own LENGTH is the property, so
    # the queue is read: `_nonces` is private and this is the one place that
    # reaches into it, deliberately, because nothing public exposes depth.
    queue = session._nonces[REOPEN_SLOT]
    assert len(queue) == 0, "the thirteen redeemed nonces were consumed, not kept"
    stale = [session.mint(REOPEN_SLOT) for _ in range(3)]
    assert len(queue) == 3
    clock["t"] += NONCE_TTL_S + 0.001
    assert session.redeem(stale[0]) is None
    assert len(queue) == 0, "expired entries were kept, not pruned"
    for dead in stale[1:]:
        assert session.redeem(dead) is None, "a pruned nonce must not come back"
    fresh = session.mint(REOPEN_SLOT)
    assert len(queue) == 1
    assert session.redeem(fresh) == session.token
    assert len(queue) == 0


def test_a_local_reopen_after_the_interval_does_not_invalidate_the_persons_reconnect_nonce(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The reviewer's specimen on the wire, over the COMPOSED surface with the
    real rate limiter under an injected clock. A: the person presses Reconnect
    (a browser POST: Origin matches Host) -> 200, a page opens with nonce N1.
    B: eleven seconds later a local process calls reopen (no Origin) -> 200,
    a page opens with N2. C: the person's page redeems N1 -> 200 with the
    token. Measured before the queue: C was 404. Both nonces single-use."""
    clock = {"t": 1000.0}
    app, _stops, opened = _composed(tmp_path, monkeypatch, clock=lambda: clock["t"])
    raw = TestClient(app, base_url=SERVED)
    token = app.state.session.token

    def redeem(nonce: str):
        return raw.post("/api/session/redeem", json={"nonce": nonce}, headers={"Origin": SERVED})

    assert raw.post("/api/runtime/reopen", headers={"Origin": SERVED}).status_code == 200
    person = opened[0].split("#", 1)[1]
    clock["t"] += 11.0
    assert raw.post("/api/runtime/reopen").status_code == 200
    intruder = opened[1].split("#", 1)[1]
    assert intruder != person
    redeemed = redeem(person)
    assert redeemed.status_code == 200 and redeemed.json() == {"token": token}, redeemed.text
    assert redeem(person).status_code == 404
    assert redeem(intruder).status_code == 200
    assert redeem(intruder).status_code == 404


def test_the_reopen_queue_bound_is_what_the_rate_limit_admits_in_one_ttl():
    """The two constants live in two modules (the interval is the runtime's
    policy, the bound the session's); this joins them so that a change to
    either without the other is a red test, not a silent mismatch."""
    assert REOPEN_PENDING_BOUND == math.floor(NONCE_TTL_S / REOPEN_INTERVAL_S) + 1
    assert REOPEN_PENDING_BOUND == 13 and NONCE_TTL_S == 120.0 and REOPEN_INTERVAL_S == 10.0


def test_a_launch_mint_replaces_only_the_launch_slot():
    session = ControlPlaneSession()
    reopen = session.mint(REOPEN_SLOT)
    first_launch = session.mint(LAUNCH_SLOT)
    second_launch = session.mint(LAUNCH_SLOT)
    assert session.redeem(first_launch) is None
    assert session.redeem(reopen) == session.token, "a launch mint invalidated the reopen nonce"
    assert session.redeem(second_launch) == session.token


def test_expiry_is_kept_per_slot():
    clock = {"t": 1000.0}
    session = ControlPlaneSession(ttl=120.0, clock=lambda: clock["t"])
    launch = session.mint(LAUNCH_SLOT)
    clock["t"] += 100.0
    reopen = session.mint(REOPEN_SLOT)
    clock["t"] += 30.0
    assert session.redeem(launch) is None, "the launch nonce outlived its TTL"
    assert session.redeem(reopen) == session.token, "the reopen nonce expired with the launch nonce"


def test_an_unknown_slot_is_refused_loudly():
    with pytest.raises(ValueError, match="unknown nonce slot"):
        ControlPlaneSession().mint("cookie")


@pytest.mark.parametrize("presented", ["\xff", "ÿþ", "nonceé", "", None, 42, b"bytes", "with space",
                                       "tab\there", "unicode\u2028sep"])
def test_a_value_outside_the_credential_alphabet_is_refused_without_raising(presented):
    """`hmac.compare_digest` raises TypeError on a non-ASCII str (measured under
    review: a 500 and a traceback per request). Such a value is not a
    credential and is refused BEFORE any comparison -- by verify and by redeem
    -- and refusing it consumes nothing."""
    session = ControlPlaneSession()
    nonce = session.mint()
    assert session.verify(presented) is False
    assert session.redeem(presented) is None
    assert session.redeem(nonce) == session.token, "a refused value consumed the real nonce"


# ---------------------------------------------------------------------------
# Bearer parsing: `Bearer <credential>` and nothing looser -- one space, no
# surrounding or embedded whitespace, no second field -- with the SCHEME NAME
# matched case-insensitively, as RFC 7235 SS2.1 requires of every auth scheme
# and RFC 6750's Bearer inherits (security F-5; round 6 cited 6750 alone, and
# the round-6 reviewer corrected the attribution). "Exactly
# `Bearer <credential>`" read as case-sensitive and never was (round-5 P4).
# ---------------------------------------------------------------------------

def test_the_bearer_parser_accepts_exactly_one_shape():
    assert _bearer("Bearer abc") == "abc"
    assert _bearer("bearer abc") == "abc", "the scheme is case-insensitive (RFC 7235 SS2.1)"
    assert _bearer("BEARER abc") == "abc"
    for lax in ("Bearer  abc", "Bearer abc ", " Bearer abc", "Bearer\tabc", "Bearer abc extra",
                "Token abc", "Bearer", "Bearer ", "Bearerabc", "abc", "Bearer abc, Bearer abc",
                "Bearer a bc", "Bearer abc\n", "", None):
        assert _bearer(lax) is None, repr(lax)


@pytest.mark.parametrize("shape", ["Bearer  {t}", "Bearer {t} ", "Bearer\t{t}", "Bearer {t} extra",
                                   "Token {t}", "Bearer{t}", "{t}", "Bearer {t}, Bearer {t}"])
def test_a_lax_authorization_header_is_refused_on_the_wire(tmp_path: Path, shape: str):
    app = _app(tmp_path)
    token = app.state.session.token
    response = TestClient(app).get("/api/state", headers={"Authorization": shape.format(t=token)})
    assert response.status_code == 401, shape
    assert response.json() == NO_SESSION
    for scheme in ("bearer", "BEARER", "Bearer"):
        assert TestClient(app).get("/api/state", headers={
            "Authorization": f"{scheme} {token}"}).status_code == 200


# ---------------------------------------------------------------------------
# The gate over the composed app (INV-B1, B5, B7)
# ---------------------------------------------------------------------------

_AUTHORITY_POSTS = [
    "/api/project", "/api/proposals", "/api/proposals/P-1/confirm",
    "/api/proposals/P-1/reject", "/api/journey/start", "/api/journey/confirm-scope",
    "/api/journey/retry", "/api/journey/ready", "/api/journey/restore",
    "/api/build", "/api/brd",
]
_AUTHORITY_GETS = ["/api/state", "/api/governance", "/api/build", "/api/sharing-preview"]


@pytest.mark.parametrize("path", _AUTHORITY_POSTS)
def test_no_bearer_is_refused_on_every_authority_route(tmp_path: Path, path: str):
    client = TestClient(_app(tmp_path))
    response = client.post(path, json={"actor": HUMAN})
    assert response.status_code == 401
    assert response.json() == {"refused": "no session for this Forge instance"}


@pytest.mark.parametrize("path", _AUTHORITY_GETS)
def test_no_bearer_is_refused_on_authority_reads(tmp_path: Path, path: str):
    response = TestClient(_app(tmp_path)).get(path)
    assert response.status_code == 401
    assert response.json() == {"refused": "no session for this Forge instance"}


def test_the_correct_bearer_is_admitted(tmp_path: Path):
    client = authed_client(_app(tmp_path))
    assert client.get("/api/state").status_code == 200


def test_a_refused_write_leaves_the_state_unchanged(tmp_path: Path):
    app = _app(tmp_path)
    authed = authed_client(app)
    raw = TestClient(app)
    assert authed.post("/api/project", json={
        "project_id": "p1", "project_name": "P", "actor": HUMAN}).status_code == 200
    before = authed.get("/api/state").json()["digest_chain_length"]
    refused = raw.post("/api/proposals", json={
        "field": "intent", "value": "x", "actor": HUMAN})
    assert refused.status_code == 401
    after = authed.get("/api/state").json()["digest_chain_length"]
    assert after == before, "a refused, un-bearered write moved the authority chain"


def test_a_random_bearer_is_refused(tmp_path: Path):
    client = TestClient(_app(tmp_path))
    response = client.get("/api/state", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


def test_a_one_byte_change_is_refused(tmp_path: Path):
    app = _app(tmp_path)
    token = app.state.session.token
    flipped = ("A" if token[-1] != "A" else "B").join([token[:-1], ""])
    response = TestClient(app).get("/api/state", headers={"Authorization": f"Bearer {flipped}"})
    assert response.status_code == 401


def test_every_partial_prefix_suffix_and_padded_bearer_is_refused(tmp_path: Path):
    """INV-B3 behaviourally: every proper prefix, every proper suffix, every
    single character of the real token, the token with a byte before or after
    it, and the empty credential are refused with the fixed body. A `token in
    self._token` mutant admits every prefix and suffix; a length-only mutant
    admits nothing here but is pinned by test_a_random_bearer_is_refused."""
    app = _app(tmp_path)
    client = TestClient(app)
    token = app.state.session.token
    candidates = ({token[:i] for i in range(1, len(token))}
                  | {token[i:] for i in range(1, len(token))}
                  | set(token) | {token + "x", "x" + token, ""})
    assert token not in candidates and len(candidates) > 2 * (len(token) - 1)
    for candidate in sorted(candidates):
        response = client.get("/api/state", headers={"Authorization": f"Bearer {candidate}"})
        assert response.status_code == 401, repr(candidate)
        assert response.json() == NO_SESSION, repr(candidate)
    assert client.get("/api/state", headers=bearer_header(app)).status_code == 200


def test_a_nonce_is_not_a_bearer(tmp_path: Path):
    """A nonce is the bootstrap, not the credential: presented as a bearer it is
    refused, and the attempt does not consume it."""
    app = _app(tmp_path)
    nonce = app.state.session.mint()
    assert app.state.session.verify(nonce) is False
    response = TestClient(app).get("/api/state", headers={"Authorization": f"Bearer {nonce}"})
    assert response.status_code == 401 and response.json() == NO_SESSION
    assert app.state.session.redeem(nonce) == app.state.session.token, "the attempt consumed the nonce"


def test_a_previous_runs_token_is_refused(tmp_path: Path):
    first = _app(tmp_path / "one")
    second = _app(tmp_path / "two")
    stale = first.state.session.token
    response = TestClient(second).get("/api/state", headers={"Authorization": f"Bearer {stale}"})
    assert response.status_code == 401
    assert authed_client(second).get("/api/state").status_code == 200


def test_a_forge_cookie_is_refused_on_a_gated_request(tmp_path: Path):
    """On a GATED route a forge_session cookie is an ambient credential this
    surface never issued: refused 400 before the bearer is looked at, with
    the right bearer beside it or with none, whatever the cookie's case."""
    app = _app(tmp_path)
    with_bearer = TestClient(app).get("/api/state", headers={
        **bearer_header(app), "Cookie": "forge_session=abc; other=1"})
    assert with_bearer.status_code == 400
    assert with_bearer.json() == {"refused": "Forge sets no session cookie; this request carried one"}
    without = TestClient(app).post("/api/build", json={"actor": HUMAN},
                                   headers={"Cookie": "other=1; Forge_Session_x=1"})
    assert without.status_code == 400 and without.json() == with_bearer.json()


def test_the_allowlisted_routes_ignore_cookies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Security N-1. Cookies are host-scoped, not port-scoped: a listener on
    another loopback port can set `forge_session` for 127.0.0.1, and a rule
    that judged the page's own top-level navigation by it let that listener
    deny the person their page (measured under the second review). Forge
    reads no cookie and the page sends none, so the four allowlisted pairs
    ignore one -- the page, the identity, a redeem and a reopen all answer as
    if it were absent -- while the cookie is still no credential: a gated
    request carrying it and no bearer is refused."""
    app, _stops, opened = _composed(tmp_path, monkeypatch)
    session = app.state.session
    raw = TestClient(app, base_url=SERVED)
    cookie = {"Cookie": "forge_session=planted-by-another-port; forge_session_v2=x"}
    page = raw.get("/", headers=cookie)
    assert page.status_code == 200 and "Nornyx Forge" in page.text
    assert "set-cookie" not in {name.lower() for name in page.headers}
    assert raw.get("/api/runtime", headers=cookie).status_code == 200
    redeemed = raw.post("/api/session/redeem", json={"nonce": session.mint(LAUNCH_SLOT)},
                        headers={**cookie, "Origin": SERVED})
    assert redeemed.status_code == 200 and redeemed.json() == {"token": session.token}
    assert raw.post("/api/runtime/reopen", headers=cookie).status_code == 200 and len(opened) == 1
    assert raw.get("/api/state", headers=cookie).status_code == 400


def test_a_navigation_post_is_refused(tmp_path: Path):
    """A cross-site top-level form navigation is a non-GET with Sec-Fetch-Mode:
    navigate -- refused structurally, even with a valid bearer."""
    app = _app(tmp_path)
    response = TestClient(app).post("/api/build", json={"actor": HUMAN}, headers={
        **bearer_header(app), "Sec-Fetch-Mode": "navigate"})
    assert response.status_code == 403


def test_the_route_census_refuses_every_gated_route(tmp_path: Path):
    """INV-B5 on the BARE surface. Every (method, path) the app declares,
    except the four allowlisted, refuses an un-bearered request -- known path
    or not. The composed surface, with the routes the runtime attaches, is
    censused by the next test."""
    app = _app(tmp_path)
    client = TestClient(app)
    checked = 0
    for route in app.routes:
        # A live route this census cannot probe is a hole, not a skip.
        assert isinstance(route, Route) and route.methods, f"a live route this census cannot probe: {route!r}"
        path = route.path
        concrete = path.replace("{proposal_id}", "P-1")
        for method in route.methods:
            if (method, path) in ALLOWLIST:
                assert client.request(method, concrete).status_code != 401, (method, path)
                continue
            assert client.request(method, concrete).status_code == 401, (method, path)
            checked += 1
    assert checked >= len(_AUTHORITY_POSTS), f"the census checked too few routes: {checked}"


def test_the_composed_route_census_refuses_everything_but_the_four_allowlisted_pairs(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """INV-B5 and INV-B1 over the surface the runtime SERVES: `assemble` plus
    `attach_runtime_routes` (stop and reopen present). The allowlist is
    compared against a HARDCODED set of four pairs; every other live
    (method, path) -- HEAD, OPTIONS, PUT, PATCH and DELETE included, declared
    or not -- refuses 401 without a bearer, and afterwards every persisted byte
    and the lifecycle are unchanged and stop was never requested. Mutations
    this turns red: exempting /api/runtime/stop; adding any route to
    ALLOWLIST; matching the allowlist by prefix (GET / would admit everything)."""
    assert ALLOWLIST == EXPECTED_ALLOWLIST, "the allowlist is not exactly the four pairs"
    app, stops, opened = _composed(tmp_path, monkeypatch)
    authed = authed_client(app, base_url=SERVED)
    raw = TestClient(app, base_url=SERVED)
    assert authed.post("/api/project", json={
        "project_id": "p1", "project_name": "Portal", "actor": HUMAN}).status_code == 200
    assert authed.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": HUMAN}).status_code == 200
    lifecycle_before = authed.get("/api/state").json()["experience"]
    bytes_before = _snapshot(tmp_path)

    # EVERY live route must be one this census can probe: a plain HTTP Route
    # with a path and methods. A Mount, a WebSocketRoute or any other kind is
    # a hole the probes below cannot see into, so its presence FAILS the
    # census rather than being skipped (round-2 test P2-1 measured a Mount
    # plus a path-prefix exemption in the gate passing GREEN under a census
    # that looked only at routes with `.methods`).
    unprobeable = [route for route in app.routes if not isinstance(route, Route) or not route.methods]
    assert unprobeable == [], f"live routes this census cannot probe: {unprobeable}"
    paths = {route.path for route in app.routes}
    assert {"/api/runtime/stop", "/api/runtime/reopen", "/api/runtime", "/api/build"} <= paths, paths
    refused: set[tuple[str, str]] = set()
    admitted: set[tuple[str, str]] = set()
    for path in sorted(paths):
        concrete = path.replace("{proposal_id}", "P-1")
        for method in PROBED_METHODS:
            headers = {"Origin": SERVED} if path == "/api/session/redeem" else {}
            body = {"nonce": "not-a-nonce"} if path == "/api/session/redeem" else {"actor": HUMAN}
            response = raw.request(method, concrete, headers=headers,
                                   json=body if method in ("POST", "PUT", "PATCH") else None)
            if (method, path) in EXPECTED_ALLOWLIST:
                assert response.status_code != 401, (method, path, response.text)
                admitted.add((method, path))
                continue
            assert response.status_code == 401, (method, path, response.status_code, response.text)
            if method == "HEAD":
                # A HEAD response carries no body on the wire; the fixed
                # body's length is what the gate declared.
                assert response.content == b""
                assert response.headers["content-length"] == str(len(json.dumps(dict(NO_SESSION))))
            else:
                assert response.json() == NO_SESSION, (method, path)
            refused.add((method, path))
    assert admitted == EXPECTED_ALLOWLIST, admitted
    assert len(refused) == len(paths) * len(PROBED_METHODS) - len(EXPECTED_ALLOWLIST), len(refused)
    assert ("POST", "/api/runtime/stop") in refused and ("HEAD", "/") in refused

    assert stops == [], "an un-bearered request stopped the runtime"
    assert _snapshot(tmp_path) == bytes_before, "an un-bearered request changed a persisted byte"
    assert authed.get("/api/state").json()["experience"] == lifecycle_before
    assert len(opened) == 1 and opened[0].startswith(SERVED + "/#"), "reopen opens the owner's browser once"
    # The composed surface still works with the bearer: stop is reachable, once.
    assert authed.post("/api/runtime/stop", json={"actor": HUMAN}).status_code == 200
    assert stops == [1]


#: EIGHT paths that route nowhere or nearly somewhere, one per near-miss
#: shape: an unknown path; a doubled leading slash; a trailing slash on an
#: allowlisted route; an upper-cased allowlisted route; a dot-segment spelling
#: a normalising client would fold onto `/api/state`; a trailing slash on the
#: redeem route; an extra segment under the reopen route; and a leading
#: `/./`. Driven as raw ASGI scopes so each reaches the gate as spelled.
#:
#: The COUNT is asserted beside the list, and the eight shapes are named
#: above: round-4 test P4 measured this tuple shrunk to a single path and the
#: suite stayed green, because nothing read its length.
NEAR_MISS_PATHS = ("/nope", "//api/state", "/api/runtime/", "/API/RUNTIME", "/api/runtime/../state",
                   "/api/session/redeem/", "/api/runtime/reopen/x", "/./api/runtime")


def test_unrouted_and_near_miss_paths_are_refused_with_the_fixed_body(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Architecture F4 (round 3): "known path or not" was pinned only over the
    route table. Over the COMPOSED surface every near-miss and unrouted path,
    on every probed method, is the fixed 401 -- never a router 404 or 405 that
    would tell a caller which paths exist -- and afterwards nothing was
    opened and stop was never requested. The allowlist is EXACT strings, so
    fail-closed here is by construction; this makes it measured."""
    app, stops, opened = _composed(tmp_path, monkeypatch)
    assert len(NEAR_MISS_PATHS) == len(set(NEAR_MISS_PATHS)) == 8, (
        "the near-miss set shrank; each entry is a distinct shape named beside the list")
    for path in NEAR_MISS_PATHS:
        for method in PROBED_METHODS:
            status, body = _asgi(app, method, path)
            assert status == 401, (method, path, status, body)
            if method != "HEAD":
                assert body == dict(NO_SESSION), (method, path, body)
    # The same spellings through an HTTP client, where the client leaves them
    # alone, agree with the raw drive; the two dot-segment spellings are
    # folded by the client and are pinned by the raw drive above alone.
    raw = TestClient(app, base_url=SERVED)
    for path in ("/nope", "//api/state", "/api/runtime/", "/API/RUNTIME", "/api/session/redeem/"):
        response = raw.get(path)
        assert response.status_code == 401 and response.json() == NO_SESSION, (path, response.text)
    assert stops == [] and opened == []


def test_create_app_always_installs_the_gate(tmp_path: Path):
    """INV-B7. Fail closed by construction: create_app mints a session and
    installs the gate, with no parameter to disable either."""
    import inspect  # noqa: PLC0415

    app = _app(tmp_path)
    assert isinstance(app.state.session, ControlPlaneSession)
    assert any(m.cls is SessionGate for m in app.user_middleware), "the gate is not installed"
    # OUTERMOST of what create_app installs: Starlette runs the last-added
    # middleware first, so a middleware added after the gate would see (and
    # could answer) a request the gate never judged. `assemble` adds the Host
    # rule outside it afterwards, which refuses before the gate and moves nothing.
    assert app.user_middleware[0].cls is SessionGate, [m.cls for m in app.user_middleware]
    parameters = set(inspect.signature(create_app).parameters)
    for escape in ("gate", "no_gate", "session", "authenticate", "insecure"):
        assert escape not in parameters, f"create_app exposes a gate escape hatch: {escape}"


# ---------------------------------------------------------------------------
# The gate itself: non-HTTP scopes, and a decision that cannot raise
# ---------------------------------------------------------------------------

def _drive(gate: SessionGate, scope: dict) -> list[dict]:
    """Run the pure ASGI gate over one scope and return what it sent."""
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(gate(scope, receive, send))
    return sent


def test_a_websocket_handshake_is_closed_before_accept(tmp_path: Path):
    """No session can ride a websocket, so the gate closes the handshake before
    it is accepted -- even with the bearer, and on any path -- and the router
    never sees it (security F-4: a websocket upgrade used to reach the router)."""
    from starlette.websockets import WebSocketDisconnect  # noqa: PLC0415

    app = _app(tmp_path)
    client = TestClient(app)
    for path in ("/api/state", "/", "/api/session/redeem"):
        with pytest.raises(WebSocketDisconnect) as info:  # noqa: SIM117
            with client.websocket_connect(path, headers=bearer_header(app)):
                pass
        assert info.value.code == WEBSOCKET_REFUSED_CODE == 4401, path


def test_only_lifespan_passes_through_and_unknown_scope_types_are_dropped():
    reached: list[str] = []

    async def inner(scope, receive, send):
        reached.append(scope["type"])

    gate = SessionGate(inner, ControlPlaneSession())
    assert _drive(gate, {"type": "lifespan"}) == [] and reached == ["lifespan"]
    sent = _drive(gate, {"type": "websocket", "path": "/api/state", "headers": []})
    assert sent == [{"type": "websocket.close", "code": 4401}] and reached == ["lifespan"]
    assert _drive(gate, {"type": "something-else", "path": "/", "headers": []}) == []
    assert reached == ["lifespan"], "an unknown scope type reached the application"


def test_the_gate_cannot_raise_for_its_own_logic():
    """A scope the gate cannot even parse is the fixed 401, never an exception
    escaping to the server (which would be a 500 and a traceback in the runtime
    log). The inner application is not reached."""
    reached: list[str] = []

    async def inner(scope, receive, send):
        reached.append(scope["path"])

    gate = SessionGate(inner, ControlPlaneSession())
    broken = {"type": "http", "method": "GET", "path": "/api/state",
              "headers": [(b"authorization",)]}  # not a pair: unpacking raises inside the gate
    sent = _drive(gate, broken)
    assert reached == []
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 401
    assert json.loads(sent[1]["body"]) == NO_SESSION
    for name, value in sent[0]["headers"]:
        assert name.decode() in ("content-type", "content-length")
        assert b"\n" not in value


def test_a_non_ascii_bearer_or_nonce_is_refused_not_a_500(tmp_path: Path):
    """Security F-1, on the wire: `Authorization: Bearer \\xff` is 401 and a
    non-ASCII nonce is 404, each with its fixed body; neither raises (the
    client would surface the server exception), and neither consumes the
    outstanding nonce."""
    app = _app(tmp_path)
    client = TestClient(app, raise_server_exceptions=True)
    nonce = app.state.session.mint()
    response = client.get("/api/state", headers={b"authorization": b"Bearer \xff"})
    assert response.status_code == 401 and response.json() == NO_SESSION
    response = client.get("/api/state", headers={b"authorization": "Bearer ÿþ".encode("latin-1")})
    assert response.status_code == 401 and response.json() == NO_SESSION
    response = client.post("/api/session/redeem", json={"nonce": "ÿþ"},
                           headers={"Origin": "http://testserver"})
    assert response.status_code == 404
    assert response.json() == {"refused": "this start link is no longer valid; start Forge again"}
    response = client.post("/api/session/redeem", json={"nonce": 42}, headers={"Origin": "http://testserver"})
    assert response.status_code == 422
    assert client.post("/api/session/redeem", json={"nonce": nonce},
                       headers={"Origin": "http://testserver"}).status_code == 200


# ---------------------------------------------------------------------------
# Bootstrap by nonce: redeem, and browser provenance (INV-B4)
# ---------------------------------------------------------------------------

def test_a_valid_nonce_redeems_for_the_token(tmp_path: Path):
    """And the one response that carries the token is marked uncacheable
    (security P4-4, round 3): `Cache-Control: no-store` and `Pragma: no-cache`,
    so neither a browser cache nor an HTTP/1.0 intermediary holds the bearer
    past the page's closure."""
    app = _app(tmp_path)
    nonce = app.state.session.mint()
    response = TestClient(app).post("/api/session/redeem", json={"nonce": nonce},
                                    headers={"Origin": "http://testserver"})
    assert response.status_code == 200
    assert response.json() == {"token": app.state.session.token}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_an_invalid_nonce_is_refused_with_a_fixed_body(tmp_path: Path):
    app = _app(tmp_path)
    app.state.session.mint()
    response = TestClient(app).post("/api/session/redeem", json={"nonce": "wrong"},
                                    headers={"Origin": "http://testserver"})
    assert response.status_code == 404
    assert response.json() == {"refused": "this start link is no longer valid; start Forge again"}


def test_redeem_enforces_browser_provenance(tmp_path: Path):
    """INV-B4 on the wire: a redeem from another origin, from `null`, with a
    cross-site fetch marker, or with neither an Origin nor a Sec-Fetch marker
    (browsers always send Origin on such a POST) is refused 403 before the
    nonce is ever consulted."""
    app = _app(tmp_path)

    def redeem(headers):
        nonce = app.state.session.mint()
        return TestClient(app).post("/api/session/redeem", json={"nonce": nonce}, headers=headers)

    assert redeem({"Origin": "http://evil.example"}).status_code == 403
    assert redeem({"Origin": "null"}).status_code == 403
    assert redeem({"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert redeem({"Sec-Fetch-Site": "same-site"}).status_code == 403
    assert redeem({}).status_code == 403, "a redeem with no Origin and no Sec-Fetch-Site is refused"
    # The matching origin still works, so the checks are not simply refusing all.
    assert redeem({"Origin": "http://testserver"}).status_code == 200


def test_origin_is_compared_by_full_serialization(tmp_path: Path):
    """Test P2-4: the Origin must equal `http://<Host>` exactly. A prefix of the
    real port, a suffix on the host, another scheme, a trailing slash, a
    different case, and the host without its port are all refused; a
    `startswith` in either direction admits at least one of them."""
    app = _app(tmp_path)
    client = TestClient(app, base_url=SERVED)

    def redeem(origin: str) -> int:
        nonce = app.state.session.mint()
        return client.post("/api/session/redeem", json={"nonce": nonce}, headers={"Origin": origin}).status_code

    for foreign in ("http://127.0.0.1:87", "http://127.0.0.1:871", "http://127.0.0.1:87100",
                    "http://127.0.0.1:8710.evil.example", "http://127.0.0.1:8710.", "http://127.0.0.1",
                    "https://127.0.0.1:8710", "http://127.0.0.1:8710/", "HTTP://127.0.0.1:8710",
                    "http://127.0.0.1:8710http://127.0.0.1:8710", "http://127.0.0.2:8710"):
        assert redeem(foreign) == 403, foreign
    assert redeem(SERVED) == 200
    plain = TestClient(app)  # Host: testserver
    for foreign in ("http://testserver.evil.example", "http://testserve", "http://testserver:80"):
        nonce = app.state.session.mint()
        assert plain.post("/api/session/redeem", json={"nonce": nonce},
                          headers={"Origin": foreign}).status_code == 403, foreign


def test_reopen_admits_a_non_browser_but_refuses_a_foreign_origin(tmp_path: Path):
    """reopen may be called by the second launcher (no Origin, no Sec-Fetch),
    which redeem forbids; but a foreign Origin is refused for reopen too. The
    route is attached by the runtime, so on this bare surface a permitted
    request falls through the gate to a 404 rather than a 403."""
    app = _app(tmp_path)
    foreign = TestClient(app).post("/api/runtime/reopen", headers={"Origin": "http://evil.example"})
    assert foreign.status_code == 403
    permitted = TestClient(app).post("/api/runtime/reopen")
    assert permitted.status_code == 404, "a no-origin reopen is admitted by the gate (route absent here)"


# ---------------------------------------------------------------------------
# FastAPI defaults off, and refusals that echo nothing
# ---------------------------------------------------------------------------

def test_the_docs_and_schema_routes_are_absent(tmp_path: Path):
    app = _app(tmp_path)
    assert app.docs_url is None and app.redoc_url is None and app.openapi_url is None
    client = authed_client(app)  # a bearer, so a present route would answer 200
    for path in ("/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"):
        assert client.get(path).status_code == 404, path


def test_a_malformed_body_is_refused_without_echoing_it(tmp_path: Path):
    app = _app(tmp_path)
    client = authed_client(app)
    response = client.post("/api/project", json={"unexpected": "shape"})
    assert response.status_code == 422
    body = response.json()
    assert body == {"refused": "the request did not have the shape this route accepts"}
    assert "input" not in body and "ctx" not in body


def test_no_cors_middleware_and_no_set_cookie_anywhere_in_src():
    for module in sorted(SRC.glob("*.py")):
        text = module.read_text(encoding="utf-8")
        assert "CORSMiddleware" not in text, f"{module.name} installs CORS"
        assert "set_cookie" not in text, f"{module.name} sets a cookie"


def test_the_unauthenticated_surfaces_carry_no_secret(tmp_path: Path):
    """The allowlisted page and the 401 body reveal neither the token nor a
    nonce; the token lives in memory and the page's closure only."""
    app = _app(tmp_path)
    token = app.state.session.token
    nonce = app.state.session.mint()
    page = TestClient(app).get("/").text
    refused = TestClient(app).get("/api/state").text
    for secret in (token, nonce):
        assert secret not in page and secret not in refused


def test_no_response_carries_a_secret_or_a_cookie(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Test P1-4/P1-5/P2-2/P2-3: over the COMPOSED surface, every response this
    slice can emit -- 401, 403, 404, 422, redeem 200, reopen 200/429/409, the
    page and /api/runtime -- carries only DECLARED headers, no Set-Cookie under
    any spelling, and no token or nonce in any header or body. The one body
    that carries the token by design is redeem's, and it is exactly
    {"token": ...}; reopen's success body is exactly {"reopening": true}."""
    app, _stops, opened = _composed(tmp_path, monkeypatch)
    refused_app, _s, _o = _composed(tmp_path / "no-browser", monkeypatch, browser_granted=False)
    session = app.state.session
    token = session.token
    launch_nonce = session.mint(LAUNCH_SLOT)
    raw = TestClient(app, base_url=SERVED)
    authed = authed_client(app, base_url=SERVED)

    redeemed = raw.post("/api/session/redeem", json={"nonce": session.mint(REOPEN_SLOT)},
                        headers={"Origin": SERVED})
    assert redeemed.status_code == 200 and redeemed.json() == {"token": token}
    reopened = raw.post("/api/runtime/reopen")
    assert reopened.status_code == 200 and reopened.json() == {"reopening": True}
    reopen_nonce = opened[0].split("#", 1)[1]
    observed = {
        "401": raw.get("/api/state"),
        "403": raw.post("/api/session/redeem", json={"nonce": launch_nonce}, headers={"Origin": "null"}),
        "404": raw.post("/api/session/redeem", json={"nonce": "wrong"}, headers={"Origin": SERVED}),
        "422": authed.post("/api/project", json={"unexpected": True}),
        "reopen 429": raw.post("/api/runtime/reopen"),
        "reopen 409": TestClient(refused_app, base_url=SERVED).post("/api/runtime/reopen"),
        "page": raw.get("/"),
        "runtime": raw.get("/api/runtime"),
        "authed state": authed.get("/api/state"),
        "redeem 200": redeemed,
        "reopen 200": reopened,
    }
    assert observed["401"].status_code == 401 and observed["403"].status_code == 403
    assert observed["404"].status_code == 404 and observed["422"].status_code == 422
    assert observed["reopen 429"].status_code == 429 and observed["reopen 409"].status_code == 409
    secrets = (token, launch_nonce, reopen_nonce)
    for label, response in observed.items():
        names = {name.lower() for name in response.headers}
        assert names <= ALLOWED_RESPONSE_HEADERS, (label, names - ALLOWED_RESPONSE_HEADERS)
        assert "set-cookie" not in names and not response.cookies, label
        for name, value in response.headers.items():
            for secret in secrets:
                assert secret not in value and secret not in name, (label, name)
        if label != "redeem 200":
            for secret in secrets:
                assert secret not in response.text, (label, secret[:6])
    assert session.redeem(launch_nonce) == token, "the launch nonce did not survive a reopen and its refusals"


def test_a_reopen_the_owner_cannot_perform_is_a_503_that_names_nothing(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Security N-2 / architecture P4-3 on the composed surface: the owner's
    browser adapter raises a class the branch never named, carrying the
    target -- the reply is 503 with the fixed body, only declared headers, no
    nonce and no token anywhere in it, and the launch slot is untouched."""
    from nornyx_forge.windows_runtime import REOPEN_FAILED  # noqa: PLC0415

    class HandlerRefused(Exception):
        pass

    targets: list[str] = []

    def failing(url: str) -> None:
        targets.append(url)
        raise HandlerRefused(f"the default handler declined {url}")

    app, _stops, _opened = _composed(tmp_path, monkeypatch, opener=failing)
    session = app.state.session
    launch_nonce = session.mint(LAUNCH_SLOT)
    response = TestClient(app, base_url=SERVED).post("/api/runtime/reopen")
    assert response.status_code == 503 and response.json() == REOPEN_FAILED
    assert len(targets) == 1 and targets[0].startswith(SERVED + "/#")
    reopen_nonce = targets[0].split("#", 1)[1]
    names = {name.lower() for name in response.headers}
    assert names <= ALLOWED_RESPONSE_HEADERS and "set-cookie" not in names
    for secret in (session.token, launch_nonce, reopen_nonce, targets[0]):
        assert secret not in response.text
        assert all(secret not in value for value in response.headers.values())
    assert session.redeem(launch_nonce) == session.token


def test_an_adapter_whose_str_raises_is_still_a_503_that_names_nothing(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Security P4-4 (round 3): the scrubber ran `str(exc)` INSIDE the except
    that caught the adapter; an exception class whose `__str__` raises would
    throw from there, out of the branch, into a traceback carrying whatever
    the instance held -- here, the fragment URL. The TestClient re-raises
    server exceptions, so an escape is a red test, not a 500."""
    class Unspeakable(Exception):
        def __init__(self, url: str) -> None:
            super().__init__(url)
            self.url = url

        def __str__(self) -> str:
            raise RuntimeError("this exception cannot be rendered")

    targets: list[str] = []

    def failing(url: str) -> None:
        targets.append(url)
        raise Unspeakable(url)

    app, _stops, _opened = _composed(tmp_path, monkeypatch, opener=failing)
    session = app.state.session
    launch_nonce = session.mint(LAUNCH_SLOT)
    response = TestClient(app, base_url=SERVED).post("/api/runtime/reopen")
    assert response.status_code == 503 and response.json() == REOPEN_FAILED
    assert len(targets) == 1 and targets[0].startswith(SERVED + "/#")
    reopen_nonce = targets[0].split("#", 1)[1]
    for secret in (session.token, launch_nonce, reopen_nonce, targets[0]):
        assert secret not in response.text
        assert all(secret not in value for value in response.headers.values())
    assert session.redeem(launch_nonce) == session.token


@pytest.mark.parametrize("body", [NO_SESSION, COOKIE_REFUSED, CROSS_ORIGIN, NONCE_INVALID, BAD_SHAPE,
                                  REOPEN_BUSY, REOPEN_NOT_GRANTED, REOPEN_FAILED],
                         ids=["no_session", "cookie", "cross_origin", "nonce_invalid", "bad_shape",
                              "reopen_busy", "reopen_not_granted", "reopen_failed"])
def test_the_fixed_refusal_bodies_cannot_be_grown_in_place(body):
    """Architecture F5 (round 3): the fixed bodies were shared module dicts,
    so a handler that mutated one would have served the mutation to every
    later caller. They are read-only views now, and each is exactly one
    `refused` sentence that names nothing of any request."""
    assert isinstance(body, MappingProxyType)
    with pytest.raises(TypeError):
        body["refused"] = "grown"  # type: ignore[index]
    with pytest.raises(TypeError):
        body["extra"] = "grown"  # type: ignore[index]
    assert list(body) == ["refused"] and isinstance(body["refused"], str)


def test_the_page_declares_a_content_security_policy_the_inline_page_can_live_under():
    """Security N-7, pinned LEXICALLY: the served shell carries a CSP meta
    before its style and its script that allows only what the inline page
    needs -- inline script and style, same-origin fetches -- and nothing else:
    no external script or style source, no frames, no forms, no base, no
    host or scheme source at all. No JavaScript executes in this suite; the
    operator run in a real browser is the behavioural witness, as it is for
    the fragment bootstrap (A-027)."""
    from nornyx_forge.onboarding_app import _PAGE  # noqa: PLC0415

    marker = 'http-equiv="Content-Security-Policy" content="'
    assert _PAGE.index(marker) < _PAGE.index("<style>") < _PAGE.index("<script>")
    policy = _PAGE.split(marker, 1)[1].split('"', 1)[0]
    directives = {}
    for clause in policy.split(";"):
        name, *sources = clause.split()
        directives[name] = sources
    assert directives == {
        "default-src": ["'none'"],
        "script-src": ["'unsafe-inline'"],
        "style-src": ["'unsafe-inline'"],
        "connect-src": ["'self'"],
        "base-uri": ["'none'"],
        "form-action": ["'none'"],
    }, directives
    assert "http:" not in policy and "https:" not in policy and "*" not in policy


def test_the_page_keeps_the_token_in_a_closure_not_web_storage():
    """F15 and INV-B2 in the page, pinned LEXICALLY: the page source redeems
    the fragment, keeps the token in a JavaScript variable, warns on unload,
    and builds store content with the DOM -- and spells no web storage,
    cookie or innerHTML access. No JavaScript executes in this suite, so this
    is a pin on the source text, not an observation of a browser; the
    behavioural witness is the operator run (A-027, Tranche I/J)."""
    from nornyx_forge.onboarding_app import _PAGE  # noqa: PLC0415

    assert "location.hash" in _PAGE and "history.replaceState" in _PAGE
    assert "/api/session/redeem" in _PAGE and 'credentials: "omit"' in _PAGE
    assert "Authorization" in _PAGE and "Bearer " in _PAGE
    assert "beforeunload" in _PAGE
    assert "createElement" in _PAGE and "textContent" in _PAGE
    for forbidden in ("localStorage", "sessionStorage", "document.cookie", "innerHTML"):
        assert forbidden not in _PAGE, f"the page uses {forbidden}"


# ---------------------------------------------------------------------------
# Provider exclusion (INV-B2, mechanism 7)
# ---------------------------------------------------------------------------

def test_the_provider_environment_excludes_forge_variables_and_secrets(monkeypatch, tmp_path: Path):
    """A child process launched with a worker's provider environment sees no
    FORGE_* variable -- even one parked with the bearer as its value -- and keeps
    ordinary variables. This is the env both workers pass to subprocess.run."""
    session_token = ControlPlaneSession().token
    monkeypatch.setenv("FORGE_WORKER_MODE", "claude-code")
    monkeypatch.setenv("FORGE_SECRET_DECOY", session_token)
    # A BARE `FORGE` -- no underscore -- parked with the bearer: a
    # `startswith("FORGE_")` rule let it through (security P4-3, round 3).
    monkeypatch.setenv("FORGE", session_token)
    monkeypatch.setenv("ORDINARY_KEEP", "keep-me")
    monkeypatch.setenv("FORGERY_KEEP", "not-forge's")
    env = claude_worker._provider_env()
    assert codex_worker._provider_env() == env, "both workers filter identically"
    assert "FORGE" not in env and "FORGE" not in codex_worker._provider_env(), "a bare FORGE variable survived"
    dumped = subprocess.run(
        [sys.executable, "-c", "import os, json; print(json.dumps(dict(os.environ)))"],
        env=env, capture_output=True, text=True, check=True, cwd=str(tmp_path), timeout=120,
    )
    child = json.loads(dumped.stdout)
    assert not any(key.startswith("FORGE_") for key in child), "a FORGE_ variable reached the child"
    assert "FORGE" not in child, "a bare FORGE variable reached the child"
    assert child.get("ORDINARY_KEEP") == "keep-me", "the ordinary environment was dropped"
    assert child.get("FORGERY_KEEP") == "not-forge's", "a name that merely begins with FORGE was dropped"
    assert session_token not in child.values(), "the bearer reached the provider environment"


def test_both_workers_pass_the_explicit_provider_environment():
    """DIAGNOSTIC, not the pin: the pin is the real-provider test below, which
    reads what the process actually received."""
    for module in (claude_worker, codex_worker):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "env=_provider_env()" in source, f"{module.__name__} inherits the environment unchanged"
        assert "def _provider_env" in source


#: What the session module's docstring claims the architecture gate forbids
#: it. Named here, not read from the gate, so a shrunk entry is a red test.
_SESSION_MODULE_FORBIDDEN = ("fastapi", "starlette", "uvicorn", "subprocess")


def test_the_architecture_gate_forbids_the_web_framework_in_the_session_module(tmp_path: Path):
    """Architecture F1 (round 3): the module docstring and the PR claimed
    `check_architecture.py` enforced "no Starlette/FastAPI" on the gate, and
    an injected `import fastapi` PASSED -- the module was absent from the
    gate's `forbidden` map. Now, over a copy of what the gate reads, the
    pristine tree passes and each forbidden name injected into
    `control_plane_session.py` fails the gate with a violation naming the
    file and the name. Bounded per run."""
    workspace = tmp_path / "repo"
    (workspace / "scripts").mkdir(parents=True)
    shutil.copy2(ROOT / "scripts" / "check_architecture.py", workspace / "scripts")
    shutil.copy2(ROOT / "pyproject.toml", workspace / "pyproject.toml")
    shutil.copytree(ROOT / "src", workspace / "src", ignore=shutil.ignore_patterns("__pycache__"))
    contract = Path(".nornyx") / "contracts" / "architecture_governance.nyx"
    (workspace / contract.parent).mkdir(parents=True)
    shutil.copy2(ROOT / contract, workspace / contract)

    def gate() -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "scripts/check_architecture.py"], cwd=workspace,
                              capture_output=True, text=True, timeout=300, check=False)

    healthy = gate()
    assert healthy.returncode == 0, healthy.stdout[-600:] + healthy.stderr[-600:]
    target = workspace / "src" / "nornyx_forge" / "control_plane_session.py"
    pristine = target.read_text(encoding="utf-8")
    assert pristine.count("import hmac\n") == 1
    for name in _SESSION_MODULE_FORBIDDEN:
        target.write_text(pristine.replace("import hmac\n", f"import hmac\nimport {name}\n", 1),
                          encoding="utf-8")
        broken = gate()
        assert broken.returncode == 2, (name, broken.stdout[-600:])
        violations = json.loads(broken.stdout)["violations"]
        assert (f"src/nornyx_forge/control_plane_session.py imports forbidden dependency {name}"
                in violations), (name, violations)
    target.write_text(pristine, encoding="utf-8")
    assert gate().returncode == 0


#: What the fake provider records on every invocation. Written where the
#: interpreter will find it (see _install_fake_codex); the dump path is baked in.
_RECORDER = """\
import json, os, sys
with open({dump!r}, "a", encoding="utf-8") as sink:
    sink.write(json.dumps({{"argv": sys.argv, "cwd": os.getcwd(), "env": dict(os.environ),
                           "listing": sorted(os.listdir(os.getcwd()))}}) + "\\n")
print('{{"type": "turn.completed"}}')
sys.exit(3)
"""

#: Variables a child may carry that Forge did not pass: what the interpreter
#: launcher (Windows venv redirector) or the POSIX shell that execs the
#: recorder adds on its own. Nothing else may differ from `_provider_env()`.
_LAUNCHER_ADDED = frozenset({"__PYVENV_LAUNCHER__", "PWD", "OLDPWD", "SHLVL", "_"})


def _host_rewritten(expected_env: dict[str, str], workspace: Path, dump: Path) -> set[str]:
    """Keys whose value the HOST rewrites in a child started through the fake
    provider image, measured on a CONTROL run of that same image by name with
    exactly `expected_env` -- the difference from the build's runs being only
    who started it. On this workstation an endpoint-security product stamps
    SSLKEYLOGFILE with a per-process pipe name, and does so per executable
    image: a plain interpreter child did not show it, the copied image did.
    The strict comparison below excludes what the host changes and nothing
    Forge could have changed. The control's dump is consumed here."""
    completed = subprocess.run(["codex", "exec", "--control"], env=expected_env, cwd=str(workspace),
                               capture_output=True, check=False, timeout=60)
    assert completed.returncode == 3, completed.stderr
    lines = dump.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, "the control run did not record exactly one dump"
    control = json.loads(lines[0])["env"]
    dump.unlink()
    return ({key for key, value in expected_env.items() if control.get(key) != value}
            | (set(control) - set(expected_env)))


def _install_fake_codex(monkeypatch: pytest.MonkeyPatch, bin_dir: Path, workspace: Path, dump: Path) -> None:
    """A fake `codex` the worker resolves BY NAME through PATH, exactly as it
    resolves the real CLI. It records argv, cwd, the environment and the
    workspace listing, prints one JSON event and exits 3, so the real flow's
    acceptance loop stays short.

    Windows: CreateProcess appends `.exe` to a bare name and never runs a .cmd
    for one (measured on this host: only `codex.EXE` is found), so the fake is
    a copy of the interpreter named codex.exe with the venv's pyvenv.cfg (and
    any DLLs beside a base interpreter) next to it; the Codex command's first
    argument is `exec`, which the interpreter reads as a script path relative
    to its cwd -- the workspace -- so the recorder is written there under that
    name. POSIX: a shell script on PATH that execs the interpreter on the
    recorder.
    """
    bin_dir.mkdir()
    recorder = _RECORDER.format(dump=str(dump))
    if sys.platform == "win32":
        shutil.copy2(sys.executable, bin_dir / "codex.exe")
        for beside in list(Path(sys.executable).parent.glob("*.dll")):
            shutil.copy2(beside, bin_dir / beside.name)
        cfg = Path(sys.prefix) / "pyvenv.cfg"
        if cfg.exists():
            shutil.copy2(cfg, bin_dir / "pyvenv.cfg")
        (workspace / "exec").write_text(recorder, encoding="utf-8")
    else:
        (bin_dir / "recorder.py").write_text(recorder, encoding="utf-8")
        launcher = bin_dir / "codex"
        launcher.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} "
                            f"{shlex.quote(str(bin_dir / 'recorder.py'))} \"$@\"\n", encoding="utf-8")
        launcher.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    found = shutil.which("codex")
    assert found and Path(found).parent.resolve() == bin_dir.resolve(), found


def test_the_real_build_route_runs_the_real_flow_and_the_provider_process_sees_neither_secret(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """INV-B2 through the REAL path (test P2-6): the real /api/build route, the
    real DevelopmentFlow (no flow_factory), and a fake provider EXECUTABLE that
    the Codex worker resolves by name and starts as a PROCESS. What that process
    actually received -- argv, cwd, environment, workspace listing -- carries
    neither the token nor a nonce, no FORGE_* variable (a decoy parked with the
    bearer as its value included), and is exactly `_provider_env()` plus what
    the launcher itself adds. The stubbed-flow test above pins the route's
    arguments; this one pins the process."""
    project = tmp_path / "project"
    project.mkdir()
    dump = tmp_path / "provider-dump.jsonl"
    _install_fake_codex(monkeypatch, tmp_path / "bin", project, dump)
    app = create_app(project / "capsule", CONTRACTS, seal_dir=tmp_path / "seals", eligibility=_eligible)
    token = app.state.session.token
    nonce = app.state.session.mint()
    monkeypatch.setenv("FORGE_SECRET_DECOY", token)
    monkeypatch.setenv("FORGE_WORKER_MODE", "claude-code")
    monkeypatch.setenv("ORDINARY_KEEP", "keep-me")
    expected_env = claude_worker._provider_env()
    assert expected_env == codex_worker._provider_env()
    rewritten = _host_rewritten(expected_env, project, dump)
    assert not any(key.startswith("FORGE_") for key in rewritten), rewritten
    assert len(rewritten) <= 2, f"the host rewrites more than expected; the comparison is losing teeth: {rewritten}"
    client = authed_client(app)

    assert client.post("/api/project", json={
        "project_id": "p1", "project_name": "Portal", "actor": HUMAN}).status_code == 200
    intent = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": HUMAN}).json()["proposal_id"]
    assert client.post(f"/api/proposals/{intent}/confirm", json={"actor": HUMAN}).status_code == 200
    chosen = client.post("/api/proposals", json={
        "field": "provider", "value": {"name": "codex"}, "actor": HUMAN}).json()["proposal_id"]
    assert client.post(f"/api/proposals/{chosen}/confirm", json={"actor": HUMAN}).status_code == 200
    assert client.post("/api/brd").status_code == 200
    assert client.post("/api/journey/confirm-scope", json={"actor": HUMAN}).json()["stage"] == "CONFIRM"
    started = client.post("/api/build", json={"actor": HUMAN})
    assert started.status_code == 200 and started.json() == {"status": "running", "provider": "codex"}

    outcome = None
    for _ in range(3000):
        outcome = client.get("/api/build").json()
        if outcome["status"] in ("finished", "failed"):
            break
        threading.Event().wait(0.05)
    assert outcome is not None and outcome["status"] == "finished", outcome
    result = outcome["result"]
    assert outcome["accepted"] is False and outcome["provider"] == "codex"
    assert result.get("acceptance_provenance"), "the real flow's trusted greenfield gates did not run"
    assert result.get("engineering_provider") == {"selected": "codex"}

    dumps = [json.loads(line) for line in dump.read_text(encoding="utf-8").splitlines()]
    assert len(dumps) >= 2, "the provider process was not started for architecture and implementation"
    for record in dumps:
        text = json.dumps(record)
        assert token not in text and nonce not in text, "a secret reached the provider process"
        env = record["env"]
        assert not any(key.startswith("FORGE_") for key in env), sorted(k for k in env if k.startswith("FORGE_"))
        assert env.get("ORDINARY_KEEP") == "keep-me"
        for key, value in expected_env.items():
            if key not in rewritten:
                assert env.get(key) == value, key
        extras = set(env) - set(expected_env) - rewritten
        assert extras <= _LAUNCHER_ADDED, extras
        assert Path(record["cwd"]).resolve() == project.resolve()
        assert "capsule" in record["listing"] and "BRD.md" in record["listing"]
        assert "exec" in " ".join(record["argv"]) and "--json" in record["argv"]
    for path in project.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert token.encode() not in data and nonce.encode() not in data, path
    assert list(PROVIDERS)  # the providers vocabulary is unchanged by this slice


class _CapturingFlow:
    """The real build route's flow seam, capturing what it is handed. It runs
    no provider; the point is what the route passes it and leaves in the
    environment, not what a build does."""

    seen: list[dict] = []
    env: dict[str, str] = {}

    def __init__(self, root, **kwargs):
        _CapturingFlow.seen.append({"root": str(root), "kwargs": {k: str(v) for k, v in kwargs.items()}})
        self.root = root

    def run(self):
        _CapturingFlow.env = dict(os.environ)
        return {"accepted": False, "gates": ["captured"], "execution_backend": "sequential"}


def test_the_real_build_route_hands_the_flow_neither_secret(tmp_path: Path):
    """Through the real /api/build route: the flow is constructed with only the
    project directory, worker mode, repo mode and provider -- never the token or
    a nonce -- the build thread's environment carries neither, and neither
    appears in the project workspace the provider would be handed."""
    _CapturingFlow.seen = []
    _CapturingFlow.env = {}
    app = create_app(tmp_path / "capsule", CONTRACTS, seal_dir=tmp_path / "seals",
                     flow_factory=_CapturingFlow, eligibility=_eligible)
    client = authed_client(app)
    token = app.state.session.token
    nonce = app.state.session.mint()

    assert client.post("/api/project", json={
        "project_id": "p1", "project_name": "Portal", "actor": HUMAN}).status_code == 200
    intent = client.post("/api/proposals", json={
        "field": "intent", "value": "Build a portal.", "actor": HUMAN}).json()["proposal_id"]
    assert client.post(f"/api/proposals/{intent}/confirm", json={"actor": HUMAN}).status_code == 200
    chosen = client.post("/api/proposals", json={
        "field": "provider", "value": {"name": "codex"}, "actor": HUMAN}).json()["proposal_id"]
    assert client.post(f"/api/proposals/{chosen}/confirm", json={"actor": HUMAN}).status_code == 200
    assert client.post("/api/brd").status_code == 200
    assert client.post("/api/journey/confirm-scope", json={"actor": HUMAN}).json()["stage"] == "CONFIRM"
    assert client.post("/api/build", json={"actor": HUMAN}).status_code == 200

    for _ in range(500):
        if client.get("/api/build").json()["status"] in ("finished", "failed"):
            break
        threading.Event().wait(0.02)
    assert _CapturingFlow.seen, "the build route never constructed the flow"
    assert _CapturingFlow.env, "the flow never ran"
    construction = json.dumps(_CapturingFlow.seen)
    assert token not in construction and nonce not in construction
    assert set(_CapturingFlow.seen[0]["kwargs"]) == {"worker_mode", "repo_mode", "provider"}
    assert token not in _CapturingFlow.env.values() and nonce not in _CapturingFlow.env.values()
    assert not any(key.startswith("FORGE_") and value in (token, nonce)
                   for key, value in _CapturingFlow.env.items())
    for path in (tmp_path / "capsule").rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert token.encode() not in data and nonce.encode() not in data, path
