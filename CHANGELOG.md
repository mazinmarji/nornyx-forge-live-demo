# Changelog

## Unreleased — hardening from adversarial review

- The runtime's session file is visible only when it is complete, and the
  Windows host harness waits for a bearer it can PARSE. The windows-runtime CI
  job failed once at PR #46's head with a `401` on the first bearered
  `POST /api/project`, one child ever started and its record `ready`. The
  cause was a write in two steps: `write_session_file` created the FINAL name
  with `O_EXCL` and wrote the payload afterwards, and `HostRuntime.wait_for`
  returned as soon as that name EXISTED, so a reader landing between the
  create and the content parsed nothing, got `None` from `.token`, and sent
  its first request bare — out of exactly the wait that had just returned.
  Tranche B closed this race class for the harnesses' EXISTENCE wait and left
  the CONTENT window open; the bundle smoke was immune only because it polls
  until the token parses. The payload is now staged as `<name>.tmp` beside the
  target — created with `O_EXCL` at mode `0600`, flushed and fsynced — and
  moved onto the final name by an operation that REFUSES an existing target
  (`os.rename` on Windows, `os.link` then unlink on POSIX), so the final path
  never holds partial content and the pre-existing-file semantics are
  unchanged: a file already there is left as found, the person is told by
  path, and this run's bearer is written nowhere — exactly, because a target
  already there is refused BEFORE the staging file is created, so no bearer
  reaches any disk for that case. The check is not the refusal: the move
  still is, and a target that appears after the check is refused by it just
  the same. A staging name already taken is reported as the different fact it
  is rather than as "the target already exists"; the move retries a Windows
  sharing violation on the sibling `write_record`'s own 20 × 50 ms, because
  the file is polled by exactly the readers that cause one; the staging file
  this call made never outlives it, on success or failure; and a file that
  took the staging name AFTER a successful move is left alone rather than
  deleted. ONE RESIDUAL, stated in A-027 rather than implied: a hard kill
  between the fsync and the move leaves `<name>.tmp` holding a live bearer in
  the fenced directory, because a `finally` does not run when a process dies.
  Both harness waits now poll `.token` rather than the path, with a failure
  message that says whether the file existed and whether it parsed. TESTS:
  nine, mutation-checked — the final path never observable with partial
  content under a 200 ms pause between create and content (reverting to
  create-then-write is red on the first observation inside the window), the
  move refusing a target already there, no staging file outliving a placement
  either way, both waits held against a writer that deliberately exposes an
  empty file (existence-only waits are red with `None` for a bearer),
  `os.open` never reached for a target already there, two sharing violations
  survived with the two pauses they cost, a foreign staging file surviving a
  successful move, and every placement failure naming the file it could not
  use. The windows-runtime job's collected-count floor is now DERIVED from a
  live collection of the modules its own command names, rather than restated
  in prose — the prose had gone false, and nothing was reading it. Nothing
  about the fence, the mode, the after-readiness ordering or the shipped
  launchers changed; no shipped launcher passes `--session-file` at all.
- Control-plane session capability (Tranche B). The onboarding surface is
  local and unauthenticated, and A-024 measured that a Codex worker confined
  to the project workspace still reaches loopback and its POST is accepted
  under the Host rule -- so any local process could drive the authority-moving
  routes as if it were the person. It now admits an authority-moving request
  only when it carries this run's bearer. A per-run token is minted in
  `create_app` (the real composition root, not `assemble`) and enforced by a
  pure ASGI middleware (`nornyx_forge.control_plane_session.SessionGate`,
  `layer.domain`, no web framework) installed so it wraps every route,
  including the operational routes attached afterwards; everything but four
  allowlisted routes (`GET /`, `GET /api/runtime`, `POST /api/session/redeem`,
  `POST /api/runtime/reopen`) is refused `401` with a fixed body unless the
  `Authorization: Bearer` matches, compared with `hmac.compare_digest`. The
  token and the bootstrap nonce live only in Forge's process memory and the
  page's JavaScript closure: no cookie, no web storage, no session file on any
  default path, and no secret in any log, record, URL path, environment, prompt
  or argv Forge controls (the browser handler's command line receives the
  fragment URL; A-027 states the bound) -- because the measured
  `CodexSandboxUsers` ACLs give a confined
  provider read over the profile, the runtime dir and the seal dir (A-027).
  The launcher opens the page at `/#<nonce>`; the fragment is never sent to a
  server, the page redeems it once for the token, and a reload loses the
  session by design (a Reconnect button asks the owning process to open a
  fresh page; the second launcher uses the same reopen route; the console
  composition has no runtime routes, so reopen is 404 there and the page
  says so). The two unauthenticated POSTs carry Origin/`Sec-Fetch-Site`
  checks, a navigation POST is refused `403`, and a `forge_session*` cookie
  is refused `400` on gated requests while the allowlisted routes ignore
  cookies (round 3 below); the
  FastAPI docs and schema routes are off, `access_log` is off on every launch
  path, and the validation-error handler echoes nothing. The workers pass the
  provider an explicit environment stripped of `FORGE_*`. The bundle smoke and
  the runtime tests read the token from an explicit `--session-file` the
  shipped launchers never pass. `PROVIDER_CONFINEMENT`,
  `CONFINEMENT_PROPERTIES` and `governed_build_eligibility` are untouched;
  both providers stay ineligible; no Experience stage, CONFIRM, READY, seal,
  lock, token or port semantics changed. The non-HTTP authority paths, the
  same-user provider, and the shipped `codex exec` confinement are out of
  scope and disclosed in A-027.
- Tranche B repair round, closing the first review's findings. Credentials
  are compared as bytes after an alphabet check, so a non-ASCII bearer or
  nonce is the fixed `401`/`404` instead of a `500` with a traceback in the
  runtime log (security F-1, measured); the gate's own decision cannot raise;
  `Authorization` is accepted only as `Bearer <credential>` — one space, no
  surrounding or embedded whitespace, no second field — with the scheme name
  matched case-insensitively as RFC 6750 requires (F-5);
  a websocket handshake is closed before accept and non-HTTP scopes other
  than `lifespan` are dropped (F-4). On the browser-open FAILURE branch the
  record, log and notice no longer carry the fragment URL: they name the
  fragmentless URL and scrub the nonce from the exception text (architecture
  P1-1, measured: a nonce read from the record redeemed for the token). The
  bootstrap nonce lives in two independent slots, each single-use, and the
  second is a QUEUE rather than one slot: `launch` holds ONE nonce, replaced
  by the next launch mint, while `reopen` holds up to `REOPEN_PENDING_BOUND`
  = `floor(NONCE_TTL_S / REOPEN_INTERVAL_S) + 1` = 13, the most nonces the
  reopen route's own rate limit can leave outstanding within one TTL -- so
  under that limit no unexpired reopen nonce is evicted by another caller's
  reopen either. A local process calling reopen therefore invalidates neither
  the person's pending launch bootstrap nor a Reconnect nonce their own page
  minted; reopen refuses `409` on a `--no-browser` run and
  a joining launcher told `409`/`429` notifies with the fragmentless URL (F-3,
  P3-2). `--session-file` is fenced like `--runtime-dir` -- absolute, in an
  existing directory, outside the project, the runtime directory, the seal
  directory and the user profile -- before anything is created, written only
  after readiness with mode `0600` where the OS honours a mode, and the
  bundle smoke's comment now says where its file lands and why that is
  acceptable for the smoke alone (F-2, P3-1). Evidence made to pin the
  prose: a route census over the COMPOSED surface against a hardcoded
  allowlist with state bytes, lifecycle and stop checked; every partial
  bearer refused behaviourally; a declared response-header set on every
  response; Origin full-serialization specimens; `access_log=False` on the
  Windows runtime pinned by Config and by the log; the session file's
  after-readiness ordering pinned; and INV-B2's provider leg driven through
  the REAL `DevelopmentFlow` with a fake provider executable resolved by
  name, whose received environment, argv, cwd and workspace are read back.
  A-027 now scopes "no argv" to argv Forge controls, discloses the browser
  handler's command line, the two-slot design and the residual reopen
  nuisance, the `--session-file` reachability and fence, and that fragment
  preservation through ShellExecute is unmeasured until the operator run.
- Tranche B round 3, closing the second review's findings. TESTS: no launch
  that must return is called synchronously any more -- each is held to a
  watched deadline (`_returns`) that reads the record such a launch would
  write if it became a server, so a fence-removed or lock-broken regression
  is a red test within about a second rather than a hang (test P1-1/P1-2;
  measured: the `[profile]` session-file case assumed pytest's temp root lay
  under the profile, true on the workstation and false on the Linux matrix,
  where the unfenced launch served forever and the CI run had to be
  cancelled); that case now relocates the profile so it CONTAINS the
  candidate and asserts it; the composed route census FAILS on any live
  route it cannot probe (a `Mount`, a `WebSocketRoute`) instead of skipping
  it (P2-1); the Windows host suite sends an un-bearered and a wrong-bearer
  stop to the real child and requires `401` with the record still `ready`,
  the process alive, and the log free of request lines and tracebacks
  (P2-2); the runaway recovery posts stop with the bearer (P3-2); the
  source-grep tests read the IMPORTED package (P4-2); the web-storage pin
  says it is lexical (P3-1). RUNTIME: a `forge_session*` cookie is refused
  `400` on GATED requests only and ignored on the four allowlisted pairs --
  cookies are host-scoped, so a listener on another loopback port could set
  one for `127.0.0.1` and the previous rule let it deny the person `GET /`
  (security N-1); an owner whose browser adapter raises answers reopen `503`
  with a fixed body, and the joining launcher tells the person with the
  fragmentless URL instead of reading a `200` as success (N-2, architecture
  P4-3); the readiness, reopen and join branches catch EVERY exception class
  and scrub it, so no class can carry the fragment URL into a traceback
  (specimen: a handler's own exception class); the session file is created
  exclusively, and a file already there is left as found, told by path, and
  not removed at stop (P4-2); the fence resolves the runtime directory
  itself (P4-1). PAGE: a `Content-Security-Policy` meta (`default-src
  'none'`, inline script and style, same-origin connect only, no base, no
  form action), Reconnect branches for `429` and `503` (N-4, N-7), and the
  `replaceState` comment scoped to the address bar and the session-history
  entry (architecture P3). DOCS: the sentence that said the console path
  uses the reopen route is corrected -- the console composition has no
  runtime routes (N-3); A-027 discloses the browser's persistent history
  store as a channel beside the handler command line, bounded by the nonce's
  single use and TTL and NOT by principal separation on this host, the
  single reopen slot shared with the person's Reconnect, and that
  `--no-browser` reopen polling is unbounded but stateless (N-4, N-5, P3).
- Tranche B round 4, closing the third review's findings and the CI failure.
  CI: the windows-runtime job failed on a TEST listener that did one `recv`
  and answered -- `http.client` sends a POST's head and body in separate
  sends, and a close with the body unread is a RST that discards the
  client's received response on Windows (10054; reproduced at 1 in 300).
  Every listener script now reads the whole request through one helper,
  proved with a forced two-segment request and 200 exchanges with no reset.
  SECURITY (P2-1, blocking): `\\?\`, `\\.\`, `//?/` and UNC spellings
  bypassed the `--session-file` fence and the pre-existing `--runtime-dir`
  fence -- `Path.resolve()` keeps the prefix, so the plain roots are never
  among the parents; measured end to end, `\\?\<profile>\stolen.json`
  launched ready and wrote the bearer inside the profile. Both fences now
  refuse those spellings by name before resolution (the session-file fence
  refuses every double-separator spelling, UNC included; the runtime-dir
  fence refuses the namespace prefixes on the runtime AND the project
  directory), pinned per root over real launches that create nothing, plus
  8.3, junction, trailing-dot and trailing-space specimens. The reopen slot
  is a bounded QUEUE (P3-1): a local caller's reopen no longer evicts the
  nonce the person's Reconnect just minted; the depth is derived from the
  rate limit and the TTL (13) and the two constants are pinned together.
  `_provider_env()` also drops a bare `FORGE` (P4-3); the redeem 200 is
  `Cache-Control: no-store` (P4-4); a browser adapter whose `__str__` raises
  can no longer throw from inside the scrubbing `except` (P4-4). ARCHITECTURE:
  `control_plane_session.py` is in the gate's `forbidden` map for `fastapi`,
  `starlette`, `uvicorn`, `subprocess` (F1; an injected `import fastapi` had
  passed), the refusal bodies are read-only views (F5), the composed census
  covers near-miss and unrouted paths (F4), and the continuation lines left
  misaligned by the `authed_client` rename are aligned (F6). TESTS: the
  constant-time pin is an AST walk over BOTH `verify` and `redeem` (P1; two
  lexical pins had let a swapped `==` through), the console start link is
  read from stdout with `uvicorn.run` replaced (P1; printing the bearer had
  passed), `NONCE_TTL_S` is pinned through `create_app`'s own session under
  an injected clock (P2), the `[seal]` fence case fences against a seal
  directory of its own (P4), and the test harnesses wait for the session
  file as well as the `ready` record (a measured `401` on a first request
  sent before the after-readiness write). DOCS: A-027 measures the history
  stores' DACLs instead of inferring them (P3-3: the sandbox group reads
  `%LOCALAPPDATA%` and not the two stores), joins the reopen trigger with the
  two channels it feeds (F2, P3-2), softens the Origin claim to browser
  provenance (P4-2), lists what `/api/runtime` discloses (P4-1), names the
  profile root as the one environment-derived fence root (F3), and discloses
  the UNC-alias residual of the runtime-dir fence.
- Tranche B round 5, rebased onto the provider-adapter parity slice and
  closing the fourth review's findings. TESTS (blocking, P2): the two
  POST-RESOLUTION fence refusals had no witness -- deleting
  `_double_separator(resolved)` in the session-file fence, or the second
  `_namespace_prefixed(runtime_dir)` in `launch`, left the whole runtime
  module green, because no plain path on this host resolves to a prefixed
  one while the docstrings said spellings are refused "before resolving, and
  again after". The CALLER-SUPPLIED candidate's resolution is now a seam
  (`resolve=Path.resolve`, threaded from `launch` into the fence; the fenced
  roots are still resolved for real and `main` passes no seam, pinned), and a
  test presents the resolution a substituted drive or junction chain onto a
  UNC share would give -- red for both blocks on both platforms. The AST
  constant-time pin also reads comparisons written as CALLS (`__eq__`,
  `__ne__`, `__contains__`, `operator.eq/ne/contains`): `candidate.__eq__(...)`
  in `verify` and in `redeem` had each survived the whole module. Queue
  pruning is measured on the queue's LENGTH (re-appending expired entries had
  survived), `NEAR_MISS_PATHS` asserts its own count, the console start
  link's FRAGMENT is read on stderr and the log records as well as the
  bearer, and the join path's `_said` site has its first specimen (a browser
  adapter whose `__str__` raises: exit 3, the fixed notice, no traceback).
  ARCHITECTURE: the bundle smoke awaited nothing before reading the session
  file the runtime writes AFTER readiness -- the race the two test harnesses
  closed in round 4, left in the shipped smoke -- so it read None and sent
  three bare requests; it now waits inside the record wait's own deadline and
  records `session_file` as a REQUIRED observation, so a bearer that never
  arrived is named once instead of surfacing as three unexplained 401s. The
  dead `reopen_interval` parameter is deleted in favour of the module
  constant it always held; the last two raw `str(exc)` sites are guarded with
  `_said`; the host harness's dead-child check is a sibling `if` again, so a
  child that records ready and dies no longer spins to 240 s (pinned in
  seconds, on every platform); and an embedded NUL in either caller-supplied
  path is the fixed "Forge could not start" rather than a `ValueError`
  traceback. DOCS: A-027 and VALIDATION carry the UNC residual on BOTH fence
  operands (a UNC alias of the PROJECT with a plain runtime directory passes
  and creates the runtime directory inside the project, measured), the
  console path's live nonce on stdout, the smoke's session file under
  `%LOCALAPPDATA%\Temp` on its four conditions, and the seam the
  post-resolution witnesses use.
- Tranche B round 6, closing round 5's CI failure and the fifth review's
  findings. SECURITY (blocking): an embedded NUL in a caller-supplied path is
  now refused EXPLICITLY and FIRST in every fence — the session file, the
  runtime directory and the project directory — before the spelling checks,
  before `resolve` and before any root comparison, with a fixed notice that
  echoes no path. It had been caught in an `except ValueError`, which made the
  ANSWER a property of the interpreter: `ntpath.realpath` non-strict RETURNS a
  NUL-bearing path (leaving an 8.3 segment unexpanded), and on CPython ≤ 3.12
  `Path.resolve` raises only because of the trailing `p.stat()` it adds in
  non-strict mode, which 3.13 no longer does — so on 3.13 the fence compared
  an UNRESOLVED spelling against its roots and the profile refusal answered
  first. That is an ordering hole, not only the windows-latest test failure it
  produced; and on ≤ 3.12 a NUL in `--project-dir` was a traceback, because
  that operand was resolved while building the fence list, outside every
  `try`. The console launcher's comment claiming its start-link nonce "stays
  off disk" is replaced by what is true — the nonce is single use and
  TTL-bounded and is not the bearer — and by the disclosure that a redirected
  console puts it in a file, from which review redeemed it for that run's
  bearer (A-027); a lexical pin holds the sentence gone. TESTS: the smoke's
  session-file wait is ordered by an EVENT rather than by
  `time.monotonic()`, whose 15.6 ms resolution on Windows ≤ 3.12 put 46 of 300
  readings of a 0.3 s wait under 0.3 and failed that module 2 of 9 unmutated
  runs; the "no second budget" claim beside it now has a witness; the fenced
  roots of `_session_file_refusal` are witnessed as resolved for real and
  never through the candidate seam (`launch`'s own roots were not, and are
  witnessed in round 7); the constant-time AST pin reads a comparison method
  REFERENCED rather than only called, so `checker = candidate.__eq__` and
  `getattr(candidate, "__eq__")` are caught, and it states that it is a
  spelling pin and cannot prove constant time; the two `_said` sites added in
  round 5 get their first specimens; and `_provider_env`'s stripping is pinned
  in the provider suite — which the windows-runtime CI job did NOT run when
  this was written, and runs from round 7 on.
  DOCS: the smoke contract says eight and is checked against its tuple, the
  VALIDATION smoke row carries the wait, and `Bearer` is described as it is
  handled — the scheme name matched case-insensitively, nothing else lax
  (round 6 credited that rule to RFC 6750; round 7 corrects the attribution).
- Tranche B round 7, closing the sixth review's findings. SECURITY
  (blocking): `--bundle-root` is `launch`'s FOURTH caller-supplied path and
  was outside the NUL rule while that rule's own docstring claimed "every
  fence". It is refused now with the other three, before anything is created:
  `verify_launched_bundle` resolves the launched folder outside every `try`
  and is reached from a `try` that catches only `RuntimeRefusal`, so on
  CPython ≤ 3.12 a NUL there was a traceback — and it runs AFTER
  `runtime_dir.mkdir()`, so that refusal had already created the runtime
  directory it was refusing. The rule now ENUMERATES the four paths it
  quantifies over (and the three flags that are not paths) instead of
  asserting a universal, and names both resolutions that catch nothing rather
  than one. TESTS: the constant-time pin reads the IMPORT, not only the use —
  `from operator import eq as _same` with `_same(candidate, ...)` survived all
  98 tests because the only node carrying the word `eq` was the `ast.alias`,
  which the detector never looked at — and the binding is forbidden at every
  scope of `control_plane_session`, since a per-method AST pin cannot see a
  module-scope alias at all. `launch`'s own fenced roots get the
  aliasing-resolver witness `_session_file_refusal` got in round 6: routing
  the seal directory and the candidate project through the candidate seam had
  survived all 87 tests of that module. The NUL case now crosses FOUR
  operands, both resolutions and both profile placements. CI: the
  windows-runtime job runs `tests/test_provider_execution.py`, which round 6's
  entry above said it already did. DOCS: `Bearer`'s case-insensitivity is
  attributed to RFC 7235 §2.1, which makes every auth scheme name
  case-insensitive and which RFC 6750 inherits; the console comment says the
  windowless launcher prints no start link and puts no nonce on any stream —
  it does present the fragmentless URL — rather than "no link at all"; and the
  NUL test states the mutant mechanism that was MEASURED (`Path.is_dir`
  swallows the `ValueError`, so a fence without the rule ADMITS the path and
  the runtime becomes a server) instead of a raise that does not happen.
- Post-PR-18 hardening: the two non-blocking findings of the independent
  review of PR-18, closed before the next programme tranche. N1: the
  bundle builder's `--smoke` said `pass` whenever a stopped runtime record
  existed, while the launcher's exit code, the three route statuses, the
  instance-token comparison on `/api/runtime` and the stop outcome were
  recorded and never judged (measured at the base: exit code 7, HTTP 500
  on every route, a foreign token and a failed stop still produced
  `pass`). The smoke now records every observation its contract names
  and derives `result` from them through one verdict function,
  `evaluate_smoke_observations` (report schema v2): the launcher returned
  0; the record reached `ready` with the runtime's schema, a token and a
  port; `/api/runtime` answered 200 with a JSON object of that schema
  whose instance IS the recorded one; `/api/state` answered 200 with a
  usable state object; `/` answered 200 as HTML; the stop route answered
  200 with `stopping` for that instance; and the record then reached
  `stopped` for the same instance. Anything else -- including an
  observation that is absent or made twice -- is a `fail` that names the
  observation, and `--smoke` refuses by that name. This strengthens the
  instrument the operator's embedded-interpreter run will be measured
  with; it performs no such run and creates no operator evidence. N3:
  the loopback Host rule PR-18 installed on the Windows runtime's
  composition now belongs to `onboarding_serve.assemble`, the one
  composition every production launch path serves, so the console
  `onboard` path and the Windows launcher inherit one and the same rule
  (`127.0.0.1` and `localhost`, nothing wider); the runtime's own copy is
  gone, and a repository-wide census pins that no composition under
  `src/` omits it. A Host check is not authentication: A-015's
  single-person, loopback, unauthenticated trust boundary is unchanged,
  and the two tests that used the test client's default `testserver`
  Host now carry a loopback base URL rather than the rule being widened
  for them. No Experience stage, CONFIRM, READY, eligibility, confinement
  vocabulary, declaration, admission, seal, lock, token or port semantics
  changed; both providers remain governed-ineligible; the real
  embedded-Python operator run remains NOT PERFORMED. Three in-session
  read-only inspections then hardened the smoke against a hostile listener
  on its scratch port -- a nested body or record is invalid rather than a
  raise, the scratch never outlives a raise, the record is kept as five
  bounded fields, an over-long token is refused, every exchange ends
  within twice its time budget (a watchdog plus the receive timeout,
  measured), a body short of its declared length is refused -- and gave
  its exception paths and bounds tests.
- The Windows folder bundle is a runtime a basic user can double-click
  (PR-18). At b1780ee `Forge.cmd` ran `onboard` through `os.execvp`, which
  on Windows spawns the server and returns at once, hardcoded an
  interpreter a developer bundle does not carry, opened no browser, and let
  a second launch die on a bind error nobody could see. Now
  `nornyx_forge.windows_runtime` (entered through the standard-library-only
  `windows_launch`) refuses unless the launched folder is the code that is
  running, refuses a self-contained bundle started on a foreign interpreter,
  takes the project directory as an explicit absolute argument, holds one
  runtime per project under an operating-system file lock, binds a loopback
  port before the server exists (the preferred port when free, otherwise
  one the system hands out), and opens the browser only after a thread has
  read the server's own instance token back through the socket, within a
  bounded timeout that fails visibly. A second double-click opens the
  running page; the same project served from another folder is refused; a
  stale record identifies nothing; an unrelated occupant of the port costs
  a port, never a process. Failures are message boxes under `pythonw` and a
  launch-failure trail. The record, lock and log are operational state
  under the profile, outside every project, never read by the onboarding
  surface, and pinned unable to reach a governance answer. The builder
  writes `forge-bundle.json` naming the bundle's kind, a self-contained
  launcher that names no fallback interpreter, a developer launcher that
  says it carries none, refuses an embeddable archive without
  `pythonw.exe`, and can run the built folder's own launcher (`--smoke`).
  The page gained a "Stop Forge" control. A `windows-runtime` CI job runs
  the Windows-hosted tests on `windows-latest` under a skip census. The
  real embedded-interpreter run stays the operator's act (A-017); the
  console flash of `cmd.exe`, the git prerequisite, and the developer
  launcher's quoting limit are disclosed in A-023. Three in-session
  read-only inspections then hardened it: both launchers turn off
  `cmd.exe`'s current-directory command lookup before naming any command
  (a planted `pyw.cmd` in the launch directory had run in place of the
  Python launcher); the browser adapter parses the URL and accepts only a
  loopback authority; the runtime answers only to a loopback Host header;
  a joining launch retries the lock and treats a finished run's record as
  provisional; notices quote and cut what they echo from disk or a socket;
  the readiness-timeout notice is raised from the main thread; the stop
  route validates its actor as the surface does; an out-of-range port and
  a runtime directory inside the project or the seals are refusals; and a
  crash after the import guard is still a message box and a trail entry.
- Declared is not eligible: the governed basic-user build executes an
  engineering provider only when Forge has established that the provider is
  confined to the project subject, and today that is neither of them
  (independent review of 89910b8, R1). The seal had narrowed what a
  provider could do to the authority store, but the default Claude provider
  runs with general shell capability and no filesystem confinement as the
  same operating-system user whose files hold the seal, so the anchor and
  the actor it constrains shared a trust domain. The Provider Contract now
  carries, as data, what Forge has established about each adapter's
  confinement -- Claude `none`, Codex `declared` (a sandbox flag passed to a
  CLI, not independently established) -- and `governed_build_eligibility`
  decides from that table alone. `/api/build` refuses an ineligible provider
  before the lifecycle moves and before any flow is constructed, tries no
  other provider, changes no execution mode, and the page lists the reason;
  the served surface passes no other decision. The rest of the journey is
  unchanged. Two anchor states are kept apart (R2): a store Forge ever
  sealed carries a committed marker, so a protected store whose seal is
  missing is TAMPERED with nothing to restore from, while a store with
  neither is the legacy case, reported unsealed. The seal's currency is
  reported as not independently anchored and monotonic external anchoring
  is deferred rather than claimed (R3).
- The authority store is sealed against the provider that builds beside
  it (P17-B1). The capsule store lives under the basic-user project
  directory and `/api/build` hands that directory to the engineering
  provider as a writable workspace, so a worker with Write or Bash could
  rewrite `experience.json` or `capsule.json`, recompute the one-link
  digest chain, and commit the result inside the store's own repository.
  Measured at 47bd370 through the build seam and through the real
  `DevelopmentFlow` worker seam: a forged READY was rendered mid-build,
  persisted, and read back after a restart, and a committed forgery left a
  clean tree; forged capsule authority was rendered the same way. Now
  `CapsuleStore` records a seal -- the revision and the exact bytes of both
  authority files -- in a Forge-owned directory outside every project
  after each of its own commits, and checks the store against it on every
  load: revision, working tree, bytes. While a build runs the surface
  answers every read from the authority it sealed when the build began and
  refuses every write; when the flow returns it checks the seal before
  translating the result, restores the sealed authority when the store
  moved, and records the run as a failure that names what moved. A forgery
  left for a later process is TAMPERED on every route until a person
  restores the sealed authority explicitly. The seal is out of a
  workspace-write sandbox's reach and within the same operating-system
  user's reach; A-022 states that bound and withdraws the earlier claim
  that detection "belongs to git history". Three in-session reviews of the
  repair were applied before this entry was final: the served page's script
  had stopped parsing (a statement inserted between an `if` and its `else`),
  which no API test could see and a structural pin now holds; the developer
  CLI's `build --project-dir` read the capsule unsealed and now reads it
  under the same seal; a worker that replaced the store's `.git` with a
  plain file crashed the restoration and left the store stuck, and the
  rebuild now removes what it finds by shape; a damaged or foreign seal
  file was reported as an absent project and is now the TAMPERED finding
  with nothing to restore from; a seal that cannot be written is the
  store's refusal, not a traceback; creating a project is refused while a
  build has the store sealed (a worker that deleted the store mid-build
  could otherwise have a client re-create it and overwrite the seal); and a
  store whose directory the worker removed outright is rebuilt from the
  seal rather than tripping on the missing working directory. Also: a
  build thread that fails to start releases the build lock and the seal,
  so the next build is not refused as already running.
- The basic-user journey is orchestrated through the Experience Contract
  (PR-17). Measured at 9a16851 through the real onboarding app: creating a
  project, confirming its intent and provider, deriving the BRD, starting a
  build and receiving its result -- accepted or not -- and restarting the
  server all left the lifecycle `absent`, with no `experience.json` on disk
  and no lifecycle route; the contract and its tests existed and nothing a
  user did reached them. Now project creation starts a persisted lifecycle
  at DISCOVER through `start_experience`, in the same first store revision
  as the capsule, and the surface offers semantic actions -- start
  tracking, confirm scope, start build, retry, mark ready -- that
  `experience_journey` maps onto the one canonical transition each names.
  No route takes a stage from the client. Confirming a capsule proposal is
  not the lifecycle's CONFIRM: that is an explicit human act with three
  named prerequisites (confirmed intent, confirmed provider, derived BRD),
  refused by the contract for any other actor kind. The build enters BUILD
  through `advance` under the person who started it and requires a
  recorded lifecycle at a pre-build stage, or one already at BUILD with no
  run in progress, which is re-run without a second transition; on
  completion the surface, as a system actor, records TEST from the translated `flow_run` evidence and
  GOVERN from the translated `gate_results`, both through
  `experience_build.flow_evidence` and nothing a worker wrote, and stops
  there. A flow that raised, returned nothing usable, or was not accepted
  is recorded as a failure of the stage the workflow is at, in the
  contract's words, and is retried only through the contract's retry.
  READY is offered only when the persisted GOVERN evidence would satisfy
  the contract and is entered only by a human presenting exactly that
  evidence, read back from the store; a build whose acceptance profile ran
  no Nornyx gate -- which is the shipped greenfield profile -- ends
  honestly at GOVERN, because the translator produces no governance
  validation for it and nothing here supplies one. A capsule from before
  this change stays `absent` until a human starts tracking it at DISCOVER;
  no stage is inferred from its files. One in-process lock serialises every
  read and write of the store -- capsule and lifecycle alike, the build
  thread included, because both files share one git repository and every
  save stages the whole tree (a review measured a concurrent proposal
  committing a half-saved lifecycle as its own) -- so a repeated or stale
  request is judged against the current persisted state, and the build
  status is published only after the lifecycle it produced is persisted. A
  completed run is persisted whole or recorded as one failure at BUILD,
  never left at TEST, from which the contract declares no way back. A
  store refusal reaches the browser in the store's own words; only a
  missing store is reported as "no project". The page shows the persisted stage, its status, the actions
  the contract allows, what still blocks the others, the build status for
  this server session, and each refusal verbatim; its script names no
  stage and decides nothing. The trust boundary is unchanged: loopback
  only, the human unauthenticated (A-015), provider output still only
  proposed content.

- The governance evidence tool asks git under policy-neutral configuration,
  not the reader's. Binding every git question to the governed tree's own
  repository (the entry below) established which repository answers; an
  independent review of that change measured that it did not establish the
  configuration git answers under. In a fresh clone holding a governed,
  untracked `src/untracked.py`, nine reader-controlled routes -- the
  `GIT_CONFIG_COUNT` family, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL`,
  `GIT_CONFIG_SYSTEM`, an `XDG_CONFIG_HOME` config and its ignore file, a
  `HOME` gitconfig and its ignore file, an include -- each left the root
  resolving correctly while `git ls-files --others --exclude-standard` named
  nothing, and the dirty-tree gate reported the tree clean. A reader
  attributes file naming a clean filter hid a modified governed file the same
  way. Every git question now runs through one runner: the `GIT_CONFIG_*`
  family is dropped by prefix, `GIT_ATTR_SOURCE` is dropped with the
  steering variables (found under review: it reads attributes from a commit
  instead of the working tree), the system gitconfig and system attributes
  file are switched off, the global gitconfig is pointed at the empty
  device, git's messages are pinned untranslated, and `core.excludesFile`,
  `core.attributesFile`, `core.fsmonitor` and `core.longpaths` are pinned on
  the command line, which outranks every environment route. `HOME` is left
  alone. The repository's own `.git/config`, `.gitattributes` and
  `.gitignore` still apply. Git failures remain refusals, and a genuine
  change to the governed tree is still reported. Two consequences found under
  review are handled and disclosed in A-021: severing the global file also
  severed `core.longpaths`, under which git on Windows answered NOTHING,
  exit 0, for a governed path beyond MAX_PATH, so the key is pinned on; and a
  checkout owned by another user can no longer be verified, because the
  reader's `safe.directory` allowance is out of reach -- the tool now reports
  that refusal in git's words instead of calling the repository absent and
  its provenance `git:unbound`.
- A historical claim corrected: the previous entry said that with no
  repository above the tree, git's silent no-index fallback read the tree as
  clean. That reproduces on git 2.55 (since 2.51, `diff --no-index` takes the
  first two paths as directories and the rest as limits, so a thirteen-path
  `git diff` outside a repository exits 0 printing nothing) and does not on
  git 2.43, where the same command is a usage error and the tool refused --
  which is what the independent review measured. The established defect is
  the enclosing foreign repository; the no-repository outcome was a property
  of the git version. The tool's own docstrings, the tests and A-021 now say
  so; the merged pull request's description is left as written.
- The governance evidence tool asks git about the governed tree and nothing
  else. Every git question ran with the tree as working directory and trusted
  whatever repository git discovered walking upward, so a tree with no `.git`
  of its own -- the archive the anchored-measurement harness extracts -- was
  answered for by whichever repository enclosed the temp directory, and, when
  none did, by whatever the reader's git does outside a repository (see the
  correction above). Measured on one archive extracted byte for byte into
  three places: the verdict changed with the enclosing repository while the
  files did not. The tool now refuses a tree that is not the root of the
  repository git resolves, refuses one git cannot place at all rather than
  leaving the answer to git, and drops the environment variables that re-aim
  git. The harness commits each extraction to a repository of its own before
  re-running `--verify` there.
- Approval records are emitted by the YAML serializer instead of hand-formatted
  text. Interpolating artifact-controlled fields let a crafted `status` close
  the record, forge the managed end-marker, and append a rogue approval that
  then survived the documented cleanup. Fields must now be plain single-line
  scalars, and any `approval_record` outside the managed markers is refused
  rather than tolerated.
- `--materialize-approval-window` has an inverse. Withdrawing an approval left
  the authority declarations pinned to the short reviewer window, which re-rotted
  the baseline once that date passed; the placeholder is now restored.
- `--review-binding` is guarded like every other write path. It is the document
  a human reads before approving, and it was still reporting a stale approval as
  granted while `HEAD` had diverged.
- A corrupt or unwritable approval ledger is a governed refusal rather than a
  raw `sqlite3` error surfacing as a 500. A ledger that cannot record a claim
  cannot promise single use, so the effect is withheld.
- `--sync-contracts` validates the timestamps it interpolates. It is a second
  writer into the same records, and the values come verbatim out of the human
  artifact, so a crafted `expires_at` reached a raw f-string and appended a
  forged approval while the run reported `synced` and exit 0. Both writers now
  assert the single-managed-approval invariant.
- `--verify` re-parses the contracts instead of only re-hashing artifacts.
  Hashing an artifact says nothing about the contract that references it, so a
  contract carrying a second `approval_record` still reported `pass`.
- The capability an action approval is validated against is the one the risk
  level actually exercises, not the one the caller names in the request. A
  high-risk act labelled `execute_low_risk_action` matched a grant bound to that
  label on every field — the digest covers the same mislabelled request — and
  released the effect. The mismatch now withholds without spending the grant.
- Runtime producer version is read from the package rather than hardcoded.
- An action approval is validated against the execution context, not against the
  caller's description of it. Checking that `request.capability` matched the
  exercised capability fixed one field and left the rest: every other field the
  approval was compared against still came from the caller-supplied request, so a
  valid unspent approval for mission A released mission B's callback. The runtime
  now builds the canonical `ActionRequest` itself — mission, request id,
  capability, governed revision and destination all derived from the execution
  context — and validates the approval against that. A supplied request is a
  claim that gets checked field by field; on mismatch the action is denied, the
  approval is neither validated as releasable nor consumed, the callback is never
  invoked, and the exact mismatch is recorded in runtime evidence.
  `evaluate_and_execute` takes an `action_descriptor`, which is the only part a
  caller can still determine, because nothing else can know what an opaque
  callable is meant to do.
- A request id is derived from its mission (`REQ-<mission_id>`), so the same id
  presented under a different mission is a different request and matches no
  approval issued for either.
- CI builds the image and launches the application for real. The live launch was
  opt-in and therefore usually unrun, leaving BRD-005 asserted by
  `docker compose config`, which only parses YAML.
- An approval is honored only when the governed tree still holds the approved
  content. `require_approval_matches_head()` proved the approved revision equals
  `git rev-parse HEAD`, which says which commit is checked out and nothing about
  the files on disk — and every governed operation reads the files. An
  uncommitted edit to a contract or to governed source was therefore inspected,
  bound into evidence, and reported as approved content. Tracked governed inputs
  must now be unmodified in both index and working tree, and untracked files
  inside governed paths are refused; only the tool's own regenerated outputs may
  differ, because it rewrites them before anything is inspected.
- Adopting an approval is one atomic operation, `--adopt-approval`. The steps
  rewrite the contracts, so run separately each would see the previous one's
  output as drift; the alternative — exempting `.nyx` files from the check —
  would have cut the hole in the file the check exists to protect.
- `--materialize-approval-window` no longer globs `*human_approval.json`, so a
  file merely named like an approval can no longer set the authority window, and
  no longer interpolates `expires_at` through a raw f-string. Both canonical
  artifacts now go through one validator shared with indexing, wiring and
  revision pinning: JSON object, human producer, required fields, safe scalars,
  timezone-aware ISO-8601 timestamps, `generated_at` before `expires_at`, the
  P7D cap, and agreement between records where both exist.

### Corrected claim — the baseline does expire, and here is what does not

0.3.0 said "the public baseline no longer expires". That was false. It rested on
`MACHINE_EVIDENCE_EXPIRES = "2099-01-01T00:00:00Z"` — a finite date far enough
away to look like forever. At 2100 the baseline produced `EVIDENCE_STALE`,
`ARCH_EVIDENCE_STALE` and `APPROVAL_EXPIRED`.

What Nornyx 1.11.0 actually supports, verified against the real CLI:

- **Authority declarations genuinely do not expire.** `expires_at: null` is
  accepted and stays accepted at 2100 and 2200. The baseline now carries that.
- **Machine evidence has no non-expiring representation.** The schema declares
  `expires_at: {"oneOf": [timestamp, null]}` but the freshness evaluator raises
  `EVIDENCE_TIME_INVALID` when it is absent, so the schema advertises something
  the evaluator refuses. Architecture evidence does not offer it at all. This is
  recorded as a Nornyx capability gap rather than papered over.
- **Agent authorization intervals must be bounded**, which is correct — an
  agent's authority is exactly the kind that should lapse.

So machine evidence and authorization intervals carry an honest finite window,
and the guarantee is regeneration rather than permanence:
`check_pre_approval_baseline.py --regenerate`. Tests prove it restores a healthy
pre-approval baseline at 2100 and 2200, and a separate test proves an
un-regenerated far-future check still fails — otherwise the window would be
decorative. See `docs/governance/EVIDENCE_FRESHNESS.md`.

Human approval expiry is unchanged: never generated, never extended, P7D cap.

## 0.3.0

### Breaking — capability contract

The single `execute_high_risk_action` capability is replaced by two:

| Before | After |
|---|---|
| `execute_high_risk_action` (risk `high`, gated) | `request_high_risk_action` (risk `medium`, ungated) |
| | `execute_high_risk_effect` (risk `high`, gated) |

Proposing an action and releasing its effect are now distinct. An execution
agent may always prepare a proposal; it obtains the effect capability only
through a separate, action-bound human approval (`high_risk_action_authority`).

Previously a capability named `execute_*` was *allowed* before execution
authority existed, and only the later trust-zone crossing refused the effect —
so the evidence read as though execution had been authorized when only the
request had. The runtime now records the request decision and the effect
decision separately.

Any contract, lock, or evidence referencing `execute_high_risk_action` as a
capability name must be regenerated. The *action* name `execute_high_risk_action`
is unchanged; only the capability that carries it was split.

### Governance

- Authority declarations carry a far-future baseline placeholder instead of a
  dated window. A declaration says who may approve and over what scope; it is
  not itself an approval, and a dated value expired the public baseline.
  `--materialize-approval-window` sets the real window from the signing instant
  when an approval instance is inserted. Nornyx still enforces the P7D cap.
- Machine-generated evidence is bound by content hash and subject revision
  rather than a wall clock, so the reviewer-ready baseline no longer rots.
  Human approval remains short-lived, because authority genuinely decays.
- Runtime action approvals are bound to one exact consequential request:
  approval id, request id, subject revision, capability, request digest,
  destination, human approver and role, validity window, and single use. A
  grant for one action cannot release another.
- Human approvals are never generated, upgraded, backdated, or overwritten by
  tooling; a non-human producer is refused outright.
- An approved subject revision no longer silently rebinds to `HEAD`.
- Evidence synchronisation preserves per-record validity instead of applying one
  index-wide window.
- The `architect` versus `architecture_reviewer` ambiguity is resolved: the
  required role is the one a reviewer signs as, and separation-of-duties and the
  change record follow it.

### Tests and tooling

- Absent, valid, expired, not-yet-valid, and over-long approval windows are all
  proven against the real Nornyx gate, using a labelled synthetic fixture that
  needs no real approval.
- The pre-approval baseline is asserted healthy at future instants, so it cannot
  quietly rot.
- CI asserts the true pre-approval state instead of assuming contracts validate;
  the strict path reports not-applicable until an approval exists.
- Nested generated runtime evidence is gitignored.
- Tool version metadata is read from the package so it cannot drift.

## 0.2.0

Initial public reference implementation.
