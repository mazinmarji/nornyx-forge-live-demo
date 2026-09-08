# Validation record

## Locally verified in the release workspace

- Python source compilation for `src/` and `scripts/`.
- The full test suite through `scripts/check_test_coverage.py`, which is the
  gate: bare `pytest` reports a count without auditing skips, and a run where
  every governance test skipped once passed for exactly that reason. A fixed
  number stood here and went stale immediately; the census reports the count,
  the expected skips and the unexpected ones, and fails on the last.
- Repository structure and secret-pattern validation.
- Architecture dependency and command-isolation checks.
- Security checks for embedded credentials, unsafe subprocess shell mode, `eval`, and `exec`.
- Deterministic BRD-to-build flow: eleven requirements, certified foundation GO,
  zero repair attempts. For a certified Forge repository the gate count is
  deliberately not pinned: `default_gates()` resolves optional repository tools
  on PATH. For `repo_mode="greenfield"`, the count and profile are deterministic:
  six bounded static checks plus isolated test execution from
  `nornyx.greenfield.python.v1`, invoked from trusted Forge bytes without PATH or
  project import resolution. The test process receives a private subject copy,
  disables project `conftest.py` hooks and discovery configuration, and applies
  OS resource limits: address space and CPU time on POSIX with a process budget
  applied above the real user id's ambient task count (an absolute
  `RLIMIT_NPROC` ceiling refused the verifier's own runner on GitHub-hosted
  runners), or a Job Object on Windows. The POSIX budget is an increment, set
  into both the soft and hard limits so the subject cannot raise it, and a host
  whose ambient count cannot be read is refused rather than run unconfined. The runner and executor use the same digest-verified
  in-memory byte-snapshot pattern as the top-level verifier. Before execution,
  static inspection refuses hard termination, reflection, and pytest lifecycle
  control, including folded and opaque reflected capability acquisition. Before
  collection it scrubs both interpreter argument vectors; during execution an
  audit hook confines writes to the pytest temp root, checks link destinations,
  binds the completion write to its owning executor thread, and refuses process
  starts. Audit, trace, profile, async-generator, and monitoring callbacks are
  statically refused, with the mutable `sys` callback entrypoints disabled before
  project imports. A separate trusted supervisor requires a
  complete executed-test record, a normal-completion sentinel, and the expected
  executor digest, and retains only a bounded output tail. The trusted
  executor writes that record on either outcome, so a present, trusted
  record reporting failures is a genuine subject-test failure, kept distinct
  from a completion that never arrived; both fail closed. The absolute Python
  environment entrypoint is preserved on POSIX rather than resolving the venv
  symlink to its base interpreter; that resolved target is separately validated
  and recorded. This keeps trusted dependencies available under `-I` without
  consulting PATH. On Linux, the only loader path admitted to the verifier and
  test child is derived from the trusted Python installation, never inherited
  from `LD_LIBRARY_PATH`; this supports shared-library setup-python runtimes
  without giving the project native-library precedence. Read the count and provenance from the build report
  produced by the run it describes.
- Live FastAPI health, dashboard, and demonstration endpoints through `scripts/smoke_http.py`.
- Low-risk action executed; high-risk external action prevented.
- Local demonstration evidence stream validated, with its event count and
  stream digest recorded in the run output rather than fixed in this file.

## Windows basic-user runtime (PR-18)

Three evidence classes, kept apart and labelled. A synthetic zip is not an
interpreter; a Linux test of Windows-style strings is not Windows runtime
evidence; a model's report is not a human observation.

- **Cross-platform deterministic** -- `tests/test_windows_runtime.py` and
  `tests/test_windows_bundle.py`: real loopback sockets, real file locks,
  real records, a real uvicorn loop driven in-process, the real onboarding
  surface where the property is about it, and the builder over synthetic
  archives. Run by every Linux census job and on a Windows workstation.
- **Windows-hosted automated** -- `tests/test_windows_host_runtime.py`: the
  runtime as a real child process from a real bundle folder (the builder's
  own copy step) at a path with spaces and non-ASCII characters, started
  from an unrelated working directory, on the host's own CPython -- the
  DEVELOPER-bundle arrangement, through the developer launcher's bootstrap
  verbatim. Skipped by declaration off Windows; executed by the
  `windows-runtime` CI job on `windows-latest`, which fails on any skip.
- **Operator evidence** -- the real embedded-interpreter run. The repository
  supplies no embeddable archive and the builder never downloads one
  (A-017), so this run needs the operator's archive and its SHA-256:

  ```bash
  python scripts/build_windows_bundle.py --python-embed <python-3.13.x-embed-amd64.zip> --python-embed-sha256 <sha256> --smoke
  ```

  `--smoke` invokes the built folder's own `Forge.cmd` (plus `--no-browser`,
  a scratch project and a scratch runtime directory), waits for the runtime
  record to say ready, reads `/api/runtime`, `/api/state` and `/`, stops the
  runtime through its own route, and writes `<dist>-smoke.json` beside the
  folder. Its `result` is derived from the recorded observations (see the
  post-PR-18 hardening below): `pass` means every one of them succeeded,
  and a failure names the observation. A manual double-click and the
  browser opening are observed by the operator, not by a test. Neither had
  been performed when this section was written, and neither has been
  performed since; the section says so instead of implying otherwise.

Which interpretation of Windows CI the repository supports: A-020 reserves
release CI, packaging, signing and the installer for the distribution
tranche; nothing in the repository reserved runtime validation. A Windows job
that runs four test modules and publishes nothing is runtime validation, so
one was added; it is not a release pipeline and does not build
`ForgeSetup.exe`.

Proof matrix. "Established" means a test that runs on every commit holds it;
"Windows-hosted" means the `windows-runtime` job and a Windows workstation
hold it with real processes; "operator" means it awaits the operator's act.

| Property | Result | Evidence class |
| --- | --- | --- |
| W1 bundle-root independence: the launch directory cannot select a different Forge | established | deterministic (the launched folder must equal the resolved package root; the real resolver refuses any other folder from any cwd) + Windows-hosted (unrelated cwd) |
| W2 the runtime imports the code carried in the bundle | established | Windows-hosted (`/api/runtime` reports the copied folder as its root and the shipped module answers) |
| W3 loopback only | established | deterministic (bind and probe are pinned to `127.0.0.1`) + Windows-hosted (`netstat` shows `127.0.0.1:port` only; a LAN address refuses) |
| W4 no terminal command required | established for the launcher text; operator for the double-click | deterministic (the launcher passes root, project and entry itself; the person types nothing) + operator |
| W5 readiness before browser | established | deterministic (the opener records the server's own token at the moment of the call; a stalled startup times out visibly and opens nothing) |
| W6 duplicate launch | established | deterministic + Windows-hosted (a second process exits 0, starts no listener, replaces no record; another folder is refused) |
| W7 stale runtime metadata | established | deterministic + Windows-hosted (a record naming an impostor's port is overwritten; the impostor is untouched) |
| W8 unrelated port owner | established | deterministic + Windows-hosted (an occupant of the preferred port costs a port; a non-Forge answer is not Forge) |
| W9 runtime restart | established | deterministic + Windows-hosted (stop through the route, exit 0, lock released, start again as a new instance) |
| W10 project authority explicit and bounded | established | deterministic (a relative project is refused before anything starts; cwd changes nothing) |
| W11 paths with spaces | established | Windows-hosted (bundle and project paths both carry spaces) |
| W12 non-ASCII paths | established | Windows-hosted (bundle `Forge Bündle 測試`, project `Forge Prøject 專案`, git-backed store created there) |
| W13 self-contained interpreter integrity | established for the builder; operator for the real archive | deterministic (a wrong digest and a one-byte change refuse before extraction; an archive without `pythonw.exe` refuses) |
| W14 no system-Python substitution | established for the runtime and the launcher text; operator for the real archive | deterministic (a self-contained bundle refuses a foreign interpreter; the launcher names no fallback) + Windows-hosted (the literal launcher without its interpreter exits 2 with a message) |
| W15 no runtime download | structurally indicated | deterministic (the runtime's only HTTP is a loopback probe; the builder fetches nothing); no network capture was taken |
| W16 PR-17 provider refusal survives | established | Windows-hosted (the governed build refuses `codex` before BUILD through a real runtime; the lifecycle stays at CONFIRM) + the existing eligibility module |
| W17 browser journey survives | established up to the governed boundary | Windows-hosted (create, propose, confirm, provider, BRD, confirm scope, refused build) |
| W18 operational state cannot create governance authority | established | deterministic (a forged record and marker change nothing `/api/state` says; the surface's source never reads runtime state) |
| W19 ordinary-user execution | structurally indicated, and measured once | deterministic (no registry, service, task, firewall or privileged port anywhere; state under the profile); on the development host the Windows-hosted module ran with `IsUserAnAdmin` = 0 |
| W20 restart persistence | established | deterministic + Windows-hosted (a project created before a stop is read back after a restart with its revision and lifecycle) |

Not claimed by any row: a self-contained runtime observed on the operator's
embeddable interpreter, a human observation of the double-click, provider
confinement, an installer, signing, release readiness, A-018.

Mutation session on the development host: each mutation applied to
`windows_runtime.py` alone, the named modules run, the file restored from
the bytes read before the mutation, and the restored tree run green
afterwards. The count is the number of tests that went red.

| Regression introduced | Modules run | Red |
| --- | --- | --- |
| readiness check removed: the browser opens without the probe | deterministic | 2 (the readiness test, three repeats out of three, and the bounded-timeout test) |
| the working directory becomes the bundle authority | deterministic + Windows-hosted | 24 |
| the probe accepts any answer on the port as Forge | deterministic | 1 |
| the duplicate-instance lock always reports acquired | deterministic | 5 |
| the server binds every interface instead of loopback | deterministic | 2 |
| a self-contained bundle accepts a foreign interpreter | deterministic | 1 |
| the join path accepts a schema answer without the recorded token | deterministic | 1 (added after the test-adequacy inspection found no red) |
| the served composition reads the bundle marker into `/api/state` | deterministic | 1 (the pin now runs through `assemble`, where the inspection placed the leak) |
| `ready` recorded before the probe answered | deterministic | 1 |

Two things the session taught, kept as tests rather than memory: a
regressed lock turned the second-launch tests into servers that never
returned, so those launches are now held to a deadline and a regression is
a red test rather than a hang; and a readiness test with a fast-starting
app did not discriminate the removed probe, because the server was
listening by the time the opener looked -- the test now starts its app
slowly and probes briefly, and the mutation is red three times out of
three.

### Post-PR-18 hardening: the smoke verdict (N1) and the common Host boundary (N3)

Two findings of the independent review of PR-18, both P2 and non-blocking
at merge, closed in a maintenance slice before the next programme tranche.
Their provenance is kept here because a repair that forgets its finding
is a repair nobody can check. The review record itself is held by the
founder outside this repository -- it is not a comment on PR #39 -- and its
two findings reached this slice through the founder's instruction for it;
this section is their in-tree record, and the labels N1 and N3 are the
review's own.

**N1 -- the smoke result could say `pass` without the observations it
claimed.** Non-blocking at merge because no operator smoke evidence had
yet been recorded. Measured at the base (`1ed49f6`) with the launcher, the
listener and the record scripted: an exit code of 7, HTTP 500 on all three
routes, an instance token that was not the record's and a failed stop
request still produced `"result": "pass"`, because the only condition was
that a stopped record existed. Now `smoke_bundle` records every
observation its contract names -- launcher exit code; the record's schema,
token, port and `ready`; for each route the status, the parse outcome and,
on `/api/runtime`, the schema and instance; the stop status, `stopping` and
instance; the stopped record -- and `result` is derived from those
recorded steps by `evaluate_smoke_observations` and from nothing else. A
pass requires all seven observations, each made exactly once and each
succeeding, with the instance compared against the recorded runtime's own
token. Bodies are not archived: a recorded string is cut at 200
characters, the runtime record is kept as five bounded fields (the four
the verdict reads, plus `reason` so a failed record explains itself), a
body is read within a byte bound, every exchange ends within twice its
time budget (a watchdog plus the receive timeout, measured), and a body
shorter than its declared length is a broken answer,
and a token longer than the recorded-fact bound is refused at the record
rather than compared truncated. The report schema is `nornyx.forge.windows_bundle_smoke.v2`,
because a v1 `pass` and a v2 `pass` do not mean the same thing. This
strengthens the instrument the operator's embedded-interpreter run will be
measured with; it performs no such run, so it creates no operator evidence,
and it is not governance evidence about approval, READY, eligibility or
model safety. Proved without an interpreter, in `tests/test_windows_bundle.py`:
S1 all observations correct -> pass; S2 `/api/runtime` non-success -> not
pass; S3 expected schema with the wrong, absent or schema-only instance ->
not pass; S4 invalid JSON -> not pass; S5 `/api/state` failed or unusable ->
not pass; S6 `/` failed or missing -> not pass; S7 stop refused, failed or
unreachable -> not pass; S8 never stopped -> not pass; S9 a stopped record
alone -> not pass, both over scripted observations and through the smoke
over a scripted launcher; plus a missing or duplicated observation, an
unready record ending the smoke with the rest reported unobserved, and the
static pin that `result` has one source. Three in-session read-only
inspections (test adequacy, architecture, security) then hardened the
instrument and its tests, each finding P3 and each reproduced before it was
applied: a deeply nested body or record is recorded as invalid rather than
raised; the scratch directory is removed on every exit, a raise included;
the record is kept as five bounded fields; a token longer than the
recorded-fact bound is refused; every exchange ends within twice its time
budget (the round-2 security inspection measured that a deadline checked between
reads did NOT hold against a real trickling socket, because `read` loops
receives internally, so the bound is now a watchdog that shuts the socket
down, pinned by a real loopback listener trickling its body and its
headers; round 3 then measured that the shutdown does not wake a receive
already pending on Windows, so the bound is twice the budget, stated as
such and pinned by a trickle slower than the budget); a body shorter than
its declared length, as far as it is read, is refused, the length taken
from http.client's own parse rather than a parse of our own (round 4
measured that a hostile header raised out of the smoke, and that a length
above the read bound escaped the comparison); the launcher's `timed_out`
is recorded on both branches; and the
exception-recording paths, the output bounds and the reason strings gained
through-smoke tests. Two observations stay outside this slice, disclosed
rather than absorbed: both launchers `start` a detached child while the
smoke captures output, so the launcher-timeout branch is untested against
the real launcher (pre-existing at the base); and
`test_a_finished_runs_record_is_provisional_for_a_moment`, untouched here,
failed once in eight runs on the development host with a
record-read-during-write refusal -- a pre-existing race in the join path,
not repaired by this slice.

**N3 -- the Host boundary protected one composition of the surface and not
the other.** Non-blocking at merge because the governed Windows entry was
protected while the older console composition remained weaker. At the base
`onboarding_serve.assemble` built the surface with no Host middleware
(measured: `Host: evil.example` and `Host: testserver` answered 200), and
only `windows_runtime._own_runtime` added `TrustedHostMiddleware` around
the app it was handed. The rule now lives in `assemble`, the one
composition every production launch path serves -- the console `onboard`
path runs `onboarding_serve.main` over it, and the Windows runtime receives
it through a seam whose default is `assemble` -- with exactly `127.0.0.1`
and `localhost`; the runtime's own copy is removed so the policy is applied
once. It is a Host-header check, not authentication: A-015's single-person,
loopback, unauthenticated boundary is unchanged. Two tests that used the
test client's default `testserver` Host now carry a loopback base URL; the
rule was not widened to admit it. Proved in `tests/test_onboarding_launch.py`
and `tests/test_windows_runtime.py`: H1/H2 `127.0.0.1` and `localhost`
(with and without a port) answer; H3 `evil.example`, `testserver`, a LAN
address, look-alike suffixes and an empty Host are refused with 400 on
reads and on a write that would have created the store; H4 the console
composition `main` serves inherits the rule; H5 the Windows runtime, through
the served composition on a real socket, refuses foreign, look-alike, LAN,
`testserver` and empty Hosts on every route and on the stop, answers both
loopback identities with and without a port, and restates no rule of its
own; H6 a census over `src/` finds the surface constructed once,
composed once inside `assemble`, the rule installed once with exactly the
declared identities, no other module naming it, and every server
construction fed by `assemble`.

Composition census, measured over `src/` at this head: `FastAPI(` is
constructed in `nornyx_forge/onboarding_app.py` (the onboarding surface)
and `demo_app/main.py` (the governed demonstration application, a
different surface that neither imports nor composes onboarding);
`create_app(` is called only inside `onboarding_serve.assemble`; `uvicorn`
serves at two sites, `onboarding_serve.main` (the console path, over
`assemble(...)` directly) and `windows_runtime._own_runtime` (over the
`assemble_app` seam, default `assemble`, pinned); `TrustedHostMiddleware`
appears only in `onboarding_serve`. Both production paths therefore inherit
the boundary, and no third composition exists.

Mutation session on the development host, same method as PR-18's: each
regression applied to the named file alone with the pristine bytes held in
memory, the named tests run, the file restored byte-for-byte and verified,
and a baseline of the same selection run green before the session. The
count is the number of tests that went red.

| Regression introduced | Tests run | Red |
| --- | --- | --- |
| runtime-token matching ignored on /api/runtime | `test_windows_bundle.py` | 2 (test_a_recorded_fact_is_bounded_and_a_hostile_listener_is_not_this_runtime, test_s3_the_expected_schema_with_the_wrong_instance_is_not_a_pass) |
| endpoint statuses ignored | `test_windows_bundle.py` | 6 (test_a_stop_request_that_raises_is_recorded_and_the_stopped_wait_still_runs, test_an_unreachable_route_is_recorded_and_the_remaining_routes_are_still_read, test_s2_a_non_success_status_on_the_runtime_route_is_not_a_pass, test_s5_a_failed_or_unusable_state_response_is_not_a_pass, test_s6_a_failed_or_missing_root_page_is_not_a_pass, test_s9_a_stopped_record_alone_is_insufficient) |
| result reduced to 'a stopped record exists' | `test_windows_bundle.py` | 11 (test_a_launcher_that_never_returns_is_recorded_as_timed_out, test_a_nested_body_or_record_is_invalid_not_a_raise, test_a_record_that_never_says_ready_ends_the_smoke_with_the_rest_unobserved, test_a_recorded_fact_is_bounded_and_a_hostile_listener_is_not_this_runtime, test_a_stop_request_that_raises_is_recorded_and_the_stopped_wait_still_runs, test_a_token_longer_than_the_fact_bound_is_not_a_forge_record, test_an_unreachable_route_is_recorded_and_the_remaining_routes_are_still_read, test_s4_through_the_smoke_a_body_that_is_not_json_is_recorded_not_raised, test_s8_through_the_smoke_a_runtime_that_never_stops_is_not_a_pass, test_s9_through_the_smoke_the_base_defect_no_longer_passes, test_the_result_has_one_source_and_the_smoke_shares_the_runtimes_schema) |
| a missing observation is not a failure | `test_windows_bundle.py` | 5 (test_a_record_that_never_says_ready_ends_the_smoke_with_the_rest_unobserved, test_s6_a_failed_or_missing_root_page_is_not_a_pass, test_s8_a_runtime_that_never_reaches_stopped_is_not_a_pass, test_s9_a_stopped_record_alone_is_insufficient, test_the_launcher_and_the_ready_record_are_required_too) |
| the stopped record's instance not compared | `test_windows_bundle.py` | 1 (test_s8_a_runtime_that_never_reaches_stopped_is_not_a_pass) |
| any Forge-schema answer accepted (schema-only) | `test_windows_bundle.py` | 4 (test_a_recorded_fact_is_bounded_and_a_hostile_listener_is_not_this_runtime, test_a_token_longer_than_the_fact_bound_is_not_a_forge_record, test_s3_the_expected_schema_with_the_wrong_instance_is_not_a_pass, test_the_launcher_and_the_ready_record_are_required_too) |
| the common Host middleware removed from assemble | `test_onboarding_launch.py`, H5 and the seam pin in `test_windows_runtime.py`, E5 in `test_governed_provider_eligibility.py` | 4 (test_h3_a_foreign_host_is_refused_before_any_route_runs, test_h4_the_console_onboard_composition_inherits_the_host_rule, test_h5_the_windows_runtime_composition_answers_only_to_a_loopback_host, test_h6_no_production_composition_of_the_surface_omits_the_host_rule) |
| foreign hosts accepted (wildcard) | `test_onboarding_launch.py`, H5 and the seam pin in `test_windows_runtime.py`, E5 in `test_governed_provider_eligibility.py` | 4 (test_h3_a_foreign_host_is_refused_before_any_route_runs, test_h4_the_console_onboard_composition_inherits_the_host_rule, test_h5_the_windows_runtime_composition_answers_only_to_a_loopback_host, test_h6_no_production_composition_of_the_surface_omits_the_host_rule) |
| testserver admitted for test convenience | `test_onboarding_launch.py`, H5 and the seam pin in `test_windows_runtime.py`, E5 in `test_governed_provider_eligibility.py` | 3 (test_h3_a_foreign_host_is_refused_before_any_route_runs, test_h5_the_windows_runtime_composition_answers_only_to_a_loopback_host, test_h6_no_production_composition_of_the_surface_omits_the_host_rule) |
| a LAN address admitted | `test_onboarding_launch.py`, H5 and the seam pin in `test_windows_runtime.py`, E5 in `test_governed_provider_eligibility.py` | 3 (test_h3_a_foreign_host_is_refused_before_any_route_runs, test_h5_the_windows_runtime_composition_answers_only_to_a_loopback_host, test_h6_no_production_composition_of_the_surface_omits_the_host_rule) |
| the policy moved back to the Windows runtime alone (the base arrangement) | `test_onboarding_launch.py`, H5 and the seam pin in `test_windows_runtime.py`, E5 in `test_governed_provider_eligibility.py` | 4 (test_h3_a_foreign_host_is_refused_before_any_route_runs, test_h4_the_console_onboard_composition_inherits_the_host_rule, test_h5_the_windows_runtime_composition_answers_only_to_a_loopback_host, test_h6_no_production_composition_of_the_surface_omits_the_host_rule) |

Not claimed by this slice: the real embedded-Python operator run (NOT
PERFORMED), a human observation of the double-click, provider confinement
or admission, an installer, signing, release readiness, A-018, or any
change to the Experience stages, the human-only CONFIRM and READY, provider
eligibility, the seal, the runtime lock, the instance token or the port
handling, all of which the PR-17 and PR-18 suites re-ran unchanged.

## Control-plane session (Tranche B)

The onboarding surface now admits an authority-moving request only when it
carries this run's bearer (A-027). The gate is a pure ASGI middleware installed
in `create_app`, the token and the bootstrap nonce live in process memory and
the page only, and the workers pass the provider an environment stripped of
`FORGE_*`. "Established" means a test that runs on every commit holds it.

| Property | Result | Evidence class |
| --- | --- | --- |
| INV-B1 no un-bearered request moves state | established | deterministic (every authority route refuses `401` without the bearer; a refused write leaves the digest chain unchanged) |
| INV-B2 token and nonce reach no argv Forge controls, env, prompt, workspace, record, log, trail, `/api/runtime`, unauthenticated page or response header | established | deterministic (a real runtime bootstrap over a socket, on the success AND the browser-failure branch, with every response header checked against a declared set; the real build route with the REAL `DevelopmentFlow` and a fake provider executable resolved by name, whose received environment, argv, cwd and workspace listing are read back -- `test_the_real_build_route_runs_the_real_flow_and_the_provider_process_sees_neither_secret`; a real child process launched with the provider environment) |
| INV-B3 a foreign, guessed, partial or one-byte-off token is refused, constant-time | established | deterministic (`hmac.compare_digest` over bytes on BOTH call sites, pinned by an AST walk over the imported `verify` and `redeem` that forbids any `==`/`!=`/`in`/`not in` comparison in either -- red under all four operand-order mutants; every proper prefix, suffix and single character of the token, the token with a byte added, and a previous run's token are refused with the fixed body; a nonce presented as a bearer is refused) |
| INV-B4 no other browser context moves authority | established | deterministic (redeem and reopen compare the full Origin serialization against `http://<Host>` and `Sec-Fetch-Site`; from a browser, which sets both headers itself, a prefix of the port and a suffix on the host are refused; a NON-browser caller sets both headers and passes the check, which is browser provenance and not caller authentication -- what it then reaches is a redeem that needs a nonce it lacks and a reopen that returns no secret, and every other route needs the bearer; a navigation POST is refused; a `forge_session*` cookie is refused on gated requests and IGNORED on the allowlisted routes, because cookies are host-scoped and a listener on another loopback port can set one for `127.0.0.1`) |
| INV-B5 the gate covers every route of the COMPOSED surface, attached ones included | established | deterministic (`test_the_composed_route_census_refuses_everything_but_the_four_allowlisted_pairs`: over `assemble` plus `attach_runtime_routes`, every (method, path) but a HARDCODED four -- HEAD, OPTIONS, PUT, PATCH and DELETE included -- refuses `401` without a bearer, with persisted bytes and lifecycle unchanged and stop never requested; the census fails on any live route it cannot probe, a `Mount` or a `WebSocketRoute`; a websocket handshake is closed before accept) |
| INV-B6 per run fresh token and nonce; the previous run's dead | established | deterministic (a second mint kills the first; two sessions share no secret) |
| INV-B7 an app has a session and gate by construction | established | deterministic (`create_app` always installs the gate and exposes no disable parameter) |
| the docs and schema routes are off | established | deterministic (`openapi_url`, `docs_url`, `redoc_url` are `None`; each 404s under a bearer) |
| the smoke authenticates its own calls | established | deterministic (the smoke passes `--session-file`, reads the token, and sends the bearer on `/api/state` and stop; a real listener confirms the header; the path lies outside the child's relocated profile and the scratch project and runtime dirs. It WAITS for the file, which the runtime writes after it records `ready` — reading the instant the record said ready got None and sent every later call bare, three `401`s naming no cause — and `session_file` is one of the eight REQUIRED observations, so a bearer that never arrives is a named failure rather than a silent None: `test_the_smoke_waits_for_the_session_file_the_runtime_writes_after_readiness` orders the two by an event, not by a clock, and `test_a_session_file_that_never_arrives_is_named_by_the_report` holds the wait inside the smoke's single `timeout`) + operator (the real embedded-interpreter smoke remains NOT PERFORMED) |
| a malformed credential is a fixed refusal, never a `500` | established | deterministic (a non-ASCII bearer is `401` and a non-ASCII nonce `404` on the TestClient and on the real runtime, where 100 such requests leave no traceback in `<key>.log`; a scope the gate cannot parse is the fixed `401`; a lax `Authorization` shape is refused) |
| the launch nonce survives a reopen; a local reopen cannot evict the person's pending Reconnect nonce; reopen is refused on a `--no-browser` run | established | deterministic (the launch slot and a reopen QUEUE on the session and over the composed surface: person Reconnect `200`, local reopen 11 s later `200`, the person's redeem `200` and each nonce single-use; the queue's depth is what the 10 s rate limit admits within one 120 s TTL -- floor(120/10)+1 = 13 -- proved under an injected clock stepping at exactly the interval, and the two constants are pinned together; `409` with a fixed body under `--no-browser`; an owner whose browser adapter raises, whatever the exception's class and even when its own `__str__` raises, answers `503` with a fixed body and scrubs the exception; a joining launcher told `409`/`429`/`503` notifies with the fragmentless URL) |
| `--session-file` is fenced, written only after readiness, and visible only complete | established | deterministic (relative, in-project, in-runtime-dir, in-seal-dir, under-profile, missing-directory and directory paths are refused before anything is created; the `\\?\` spelling of each of the four roots, the `\\.\` and `//?/` spellings and a UNC spelling are refused BY NAME before resolution, over a real launch that creates nothing, after `\\?\<profile>\stolen.json` had launched ready and written the bearer inside the profile; the `--runtime-dir` fence refuses the same prefixes on the runtime and the project directory; an 8.3 short name and a junction alias resolve into their root and are refused by it; a trailing dot or space stays inside its root; the `[seal]` case fences against a seal directory of its own, outside the profile; the file follows the `ready` record and never precedes it; VISIBLE ONLY COMPLETE -- the payload is staged as `<name>.tmp` and moved onto the final name by an operation that refuses an existing target, and under a slow write every observation of the final path is either absent or a whole record carrying the bearer, where the old create-then-write shape exposed an empty file and a reader sent its first request bare (a `401` on CI); created exclusively, and a pre-existing file is left as found, told by path and not removed at stop, while a staging name already taken is reported as the different fact it is; no staging file outlives a placement that succeeded or failed; the fence resolves the runtime directory itself; `0600` on POSIX) |
| the page declares a Content-Security-Policy and a Reconnect branch per refusal | established (lexical) | deterministic (a pin on the page source, not a browser observation: the meta precedes style and script with `default-src 'none'`, inline script and style, same-origin connect, no base and no form action; the page has branches for `404`, `409`, `429` and `503`) |
| no test hangs under a regression | established | deterministic (every launch that must return is held to a watched deadline that reads the record a runaway server writes and stops it with the bearer; the `[profile]` session-file case makes its precondition true and asserts it; measured under mutation: the fence-removed and parent-check-removed mutants are red within seconds, not hung) |
| the runtime writes no access-log line | established | deterministic (the `uvicorn.Config` the runtime builds carries `access_log=False`, and after real requests `<key>.log` holds no request line) |
| the fragment survives ShellExecute into the default browser | NOT PERFORMED | operator (Tranche I/J: the page's own redeem succeeding in a launcher-opened browser is the witness; A-027) |

Not claimed by any row: any change to `PROVIDER_CONFINEMENT`,
`CONFINEMENT_PROPERTIES` or `governed_build_eligibility` (both providers stay
ineligible); defence against an unconfined same-user provider that can read
process memory (Claude's eligibility is unchanged); the non-HTTP authority
paths (the build thread's TEST/GOVERN translation, the seal-break failure,
`brd_present()`, the restore TOCTOU), which A-027 leaves to Tranches D and F;
any confinement claim about the shipped `codex exec` path, which A-024
records as unmeasured; the browser handler's own command line, which receives
the fragment URL and is bounded by principal separation only (A-027); the
browser's persistent history store, which records the opened URL, fragment
included -- measured on this host as NOT readable by the sandbox group for
the two stores checked, with other browsers, profiles and hosts unmeasured
(A-027); the reopen trigger, which a local process may still pull once per
10 s and which mints a fresh nonce onto those two channels each time, bounded
by the nonce's single use, TTL and the page's redeem race, and the one reopen
RATE-LIMIT slot it shares with the person's Reconnect (the nonce it can no
longer evict is established above); a UNC alias of a fenced root against the
launch fence, on BOTH of its operands -- the first disclosure named the
`--runtime-dir` side alone, and the project side is the same hole from the
other direction: a UNC alias of the PROJECT with a plain `--runtime-dir`
passes the fence and the runtime directory is created inside the project
(measured on a scratch project) (A-027); the start link the console `onboard`
path prints, which carries a LIVE launch nonce on stdout and so lands on disk
for that nonce's 120 s wherever the console is redirected to a file, bounded
by the nonce's single use and TTL and never the bearer itself (A-027); the
post-resolution half of the session-file and runtime-directory fences, whose
witness presents the resolution through a seam because no plain path on this
host resolves to a prefixed one and `subst`/`net use` would change the host,
not the scratch (A-027); the bundle smoke's own session file under
`%LOCALAPPDATA%\Temp` (A-027); and any
behaviour of the page in a real browser, its CSP included, which is pinned
lexically here and observed only in the operator run.

## Control-plane probe harness (Tranche C, slice C2)

`scripts/probe_control_plane.py` observes a live onboarding surface over a real
loopback socket, as a local stranger would, and writes a
`nornyx.forge.control_plane_probe.v1` record. This slice changes no admission
criterion and runs no provider; the only caller it classifies is the test
process itself (A-028 DRAFT). "Established" means a test that runs on every
commit holds it; the Windows-only artefact facilities degrade to
`not_applicable` off Windows, so the census and the self-probe run on every CI
platform, and the module also joins the windows-runtime job. Two things are
kept apart in every row below: what is proved IN PROCESS (the route table,
read from the served composition) and what is proved ON THE WIRE (what each
documented cell answers an unauthenticated caller -- the wire cannot see a
route table, and a gated route and an unrouted path both answer the fixed 401
by design). The record is a self-report: its `transport` is a declaration the
producer makes, and the validator cannot tell a log built in process and
labelled as a socket log from one that opened a socket; what holds the label
honest is the producer, which has no in-process path, pinned by reading its
code.

| Property | Result | Evidence class |
| --- | --- | --- |
| C9 the probe's documented path list equals the served composition's route table (in process) | established | deterministic (`test_the_documented_paths_equal_the_served_compositions_route_table`: `DOCUMENTED_PATHS` equals the concrete paths of `assemble` plus `attach_runtime_routes` -- the composition the live fixture launches -- the probe's four allowlisted pairs equal the surface's own `ALLOWLIST`, and the probe's methods equal the session census's `PROBED_METHODS`; a `Mount` or a `WebSocketRoute` injected into a copy reddens the census) |
| C9 over a real socket, the four allowlisted pairs answer and every other documented cell is refused 401 | established | deterministic (`test_the_live_census_admits_only_the_four_allowlisted_pairs`: the served composition launched through the `Launch` harness on a real port, every cell of the 133-cell matrix answered; this proves the gate's coverage over the documented cells and any hole in it, NOT the route table, which is the in-process row's) |
| R10 the in-process self-probe classifies itself `admitted_nuisance` with `principal_separated: not_separated`, and says why that is not confinement | established | deterministic (`test_the_self_probe_is_admitted_nuisance_and_not_separated`: `is_separated(record)` is `False`, `bearer_acquired_through_surface` false, `not_confinement_reason` verbatim for the separation word; `authority_reachable` needs a gated 2xx, which does not happen from the network side) |
| R10 the confined-looking state was earned over the whole matrix | established | deterministic (`coverage` 133 of 133 cells answered, nothing unattempted, the deadline not exceeded; a state other than `inconclusive` requires every `DOCUMENTED_PATHS` x `PROBED_METHODS` cell answered, and a gated 2xx dominates at any coverage: `test_a_partial_log_cannot_earn_a_confined_state`, `test_a_gated_2xx_dominates_at_any_coverage`) |
| allowlist membership is derived from the constant, never read from a row | established | deterministic (`test_allowlist_membership_is_derived_from_the_constant_not_the_row`: a gated 2xx relabelled `allowlisted: true` is refused by `classify` and by the validator; with the flags stripped the derivation is `authority_reachable`) |
| R10 the surface was live, so the census is not vacuous | established | deterministic (the positive control's bearered `GET /api/state` answered 200 in the same run in which the bare one answered 401; through the `exchange` seam exactly one bearered request is observed and the token is not recorded; a control claiming admission without a request, or against its status, is refused) |
| M6 a record declaring a non-socket transport, or labelling a socket fact as an inference, is refused | established | deterministic (`test_a_non_socket_transport_declaration_is_refused`, `test_a_socket_fact_labelled_as_an_inference_is_refused`) |
| M6 that a record's `loopback_socket` label was earned on a socket | not tested; stated | the record is a self-report. Measured by `test_the_validator_cannot_refuse_a_self_declared_transport_and_the_docs_say_so`: a `TestClient`-built matrix carrying self-declared socket labels is ACCEPTED by the validator. What holds the label honest is the producer: `probe()` has one transport, `http.client` over loopback, and no in-process path, pinned by `test_the_harness_runs_no_provider_and_starts_no_synchronous_launch` |
| M8 a label may not disagree with the record's own log | established | deterministic (a gated 2xx logged while the state claims `reachable_unadmitted` is refused; so is a `classification_reason` or a `coverage` block not derived from the log; a surface-absent record is `inconclusive`, never a state) |
| C2 derives three states plus `inconclusive`; `unreachable` is not in its vocabulary | established | deterministic (`test_unreachable_is_not_in_this_harnesss_vocabulary`: `STATES` is exactly `reachable_unadmitted` / `admitted_nuisance` / `authority_reachable` / `inconclusive`; a record claiming `unreachable` is refused by name, with the reason it needs a positive control from a separated principal, which a later slice may supply) |
| `principal_separated` is a three-word vocabulary with one truth-test helper | established | deterministic (`is_separated` answers True / False / None for `separated` / `not_separated` / `unknown` and raises on anything else, the retired `"true"`/`"false"` strings and Python booleans included; the validator refuses `separated` from C2 by name) |
| the self-probe's memory handle is `not_applicable` on its own pid; the cross-process witness acquires it on Windows | established | deterministic (`test_the_self_probe_memory_handle_is_not_applicable_on_its_own_pid` on every platform, with the record's `probe_pid` equal to the surface pid; `test_the_cross_process_witness_opens_the_memory_handle_on_windows_only` runs the CLI in a child process against the same live surface: `observed` with a handle acquired in the windows-runtime job, `not_applicable` on the Linux matrix; a record claiming `observed` on its own pid is refused) |
| the record names no host: home in every spelling, the login and the machine name are redacted, and 8.3 short forms are expanded first | established | deterministic (`test_redaction_folds_every_spelling_of_home_and_removes_the_login_and_machine`: synthetic long and `~1` spellings fold to `~`, the tokens are removed wherever they occur, the boundary holds, the fold is idempotent; the real host's tokens are a known-positive control; the validator refuses a record still naming any of them) |
| the whole-record backstop matches home RAW and JSON-ESCAPED | established | deterministic (`test_the_redaction_backstop_matches_a_json_escaped_home_path`: the backstop runs over `json.dumps(record)`, in which every Windows separator is DOUBLED, and a single-separator pattern walked straight past it -- a record carrying a doubled home path in a field, or inside a nested JSON string, is now refused; an unrelated doubled path is the known negative) |
| the module source carries no host-derived spelling, 8.3 forms included | established | deterministic (`test_no_host_derived_spelling_survives_in_the_probe_module`: anchored on `probe.__file__` and on this test module, sweeping for the login and machine name AS PATH SEGMENTS -- a bare substring would be red on a GitHub runner over a file that leaks nothing -- and for the `<LOGIN>~1` and `~1.<MACHINE>` 8.3 forms; four known positives, and the `DEVUSER~1.BOX` placeholder as the known negative) |
| the record RETAINS the principal's Windows SID, and says so | disclosed, not redacted | `subject.principal.sid` (`S-1-5-21-...`) is kept deliberately: a subject binding whose principal is redacted binds nothing (A-026). A SID is a machine-and-account identifier -- it names the account the probe ran as, and its prefix identifies the issuing machine or domain. It is not a login, not a password, not a credential, and it authenticates nobody by itself. Stated in A-028 rather than left to a reader of the record (round-2 security P4-2) |
| what removed the identity from the LIVE record's paths | measured, and it is not what the phrase suggests | the live fixture RELOCATES the profile, so the recorded paths are not under the run's real home and the home-fold does not apply to them; the login and machine-name token removal is what did the work there. The fold is exercised against this host's real home by the pin above. Both mechanisms exist and neither is credited with the other's work (round-2 security P4-3) |
| the subject block is required and the instance match is computed | established | deterministic (an absent, empty or incomplete subject is refused; `expected_instance_matches` is False / None / True from the builder for a mismatch / no expectation / a match, the validator recomputes it, and a False match is refused as not-the-subject) |
| the artefact producers observe what is there and degrade on what is not | established | deterministic (a present file or seal directory is `observed` with its size or count and a missing one `not_applicable` with the reason; through the query seam a synthetic browser command line carrying a real nonce yields its `sha256:` prefix and the raw nonce nowhere; a fake `LOCALAPPDATA` tree drives the history branch on every host; a pid that names no process is `not_applicable`, never `observed`) |
| a REFUSAL is a third outcome, not an observation | established | deterministic (`observed` is a capability acquired, `refused` a facility that exists and denied this caller, `not_applicable` nothing to try; `capability_acquired()` is True for `observed` alone and raises on a word outside the vocabulary. Both branches that used to say `observed` for a denial are pinned: a present artefact whose `open` raises -- the OS produces the error, not a stub -- in `test_a_present_artefact_this_principal_cannot_open_is_refused_not_observed`, and every `OpenProcess` result in `test_the_memory_handle_maps_every_open_process_outcome_and_a_denial_is_refused` (handle -> `observed`, error 5 -> `refused`, error 87 -> `not_applicable`, anything else -> `refused`), driven through the `open_process` seam so the ACCESS_DENIED branch is held on every platform and not only where the host denies it. The REAL call on pid 4 is asserted too, degrading rather than skipping. The validator refuses either collapse back to `observed`, and a `refused` that does not say it was refused) |
| the OpenProcess VM-read, browser command-line and history reads are inferences, not measurements | established | deterministic (each artefact carries mechanism `inferred_acl` and one of the three outcomes, never a pass; the validator refuses a pass and a socket mechanism on an artefact) |
| `powershell.exe` and `whoami.exe` are resolved absolutely under `%SystemRoot%`, never from the working directory | established | deterministic (`test_system_executables_are_resolved_absolutely_and_never_from_the_cwd`: a copy planted in the cwd is not chosen even when nothing else resolves; a DRIVE-ABSOLUTE `PATH` entry is required, because on Windows `\tools` is "absolute" and means `tools` from the root of the CURRENT drive -- with a real planted copy at the place it resolves to as the known positive: the executable IS there, asked of the filesystem, and the entry is refused anyway. The predicate itself is pinned as a TABLE, both platform arms, on every interpreter, and asked a SECOND time with every stdlib path predicate replaced by one that raises -- so its verdict cannot move with the running interpreter, which is what it did in round 3, red on two CI jobs at two different rows) |
| `--host` must be loopback, and it decides the destination rather than the spelling | established | deterministic (a documentation address, a LAN address, the wildcard and a hostname are refused with `NonLoopbackHostError` before any socket opens; `main()` exits 4 on one line; `localhost` is NORMALISED to 127.0.0.1, so the resolver and a writable `hosts` file cannot choose where an admitted name connects, and a `localhost` run against a dead port produces the same absent-surface record 127.0.0.1 does) |
| `--out` may not write inside the repository working tree | established | deterministic (`test_an_out_path_inside_the_repository_is_refused_by_the_tool`: three paths inside the tree, one of them through `..`, are refused on RESOLVED paths with exit 4 before any socket opens and no file written; a path outside still writes LF JSON. Documented against and refused by nobody until now -- a record written into the tree is a measurement where the evidence cycle would commit it as source) |
| the whole probe is bounded by a deadline -- every operation, and any expiry is `inconclusive` | established | deterministic (`test_a_black_holed_surface_ends_the_probe_at_the_deadline_as_inconclusive`: a listener that accepts and never answers ends the probe inside the deadline plus one request timeout plus the clamped tail, `inconclusive`, the unreached cells unattempted and the reads skipped and COUNTED in `artefacts_truncated`. `test_the_deadline_budget_clamps_every_operation_it_bounds` holds `Deadline.budget` as arithmetic -- the smaller of the operation's timeout and what remains, floored at `FLOOR_S` after expiry -- and `test_the_deadline_bounds_the_subject_binding_subprocesses` holds the two subject-binding subprocesses to it against a stub that takes 3 s and honours its timeout, asserting both the wall clock and the timeouts the calls received. `test_a_deadline_expiring_after_the_matrix_is_recorded_counted_and_inconclusive` covers the case that used to escape: a complete matrix whose artefact reads were cut short is `deadline_exceeded`, counted, and `inconclusive` at 133/133) |
| `main()` exit codes: 0 `admitted_nuisance` or `reachable_unadmitted` (no authority reached; not a confinement verdict), 2 `authority_reachable`, 3 `inconclusive`, 4 refused or invalid | established | deterministic (`test_main_exit_codes_follow_the_classification`; `test_main_maps_every_refusal_to_exit_four_on_one_line_naming_no_path` holds every `ProbeRecordError`, `ValueError` and `TypeError` to exit 4 with ONE stderr line carrying no path; `test_a_hostile_runtime_body_never_becomes_a_traceback` drives nine hostile `/api/runtime` bodies -- `pid` as a list, a dict, a string, a boolean, an `instance` as a list, non-JSON, a JSON list, no schema, a 200-character instance -- through a real loopback listener and gets a clean exit and a valid record, or exit 4, never a traceback. The identity body is type-checked where it is recorded, so a malformed `pid` records an unreachable surface with the reason instead of reaching `int(pid)`) |
| the record carries no bearer and no raw nonce | established | deterministic (a credential-shaped run in the record is refused; channel nonces are recorded as sha256 prefixes only; the live record carries neither `"token"` nor `Bearer `) |
| the harness runs no provider and starts no synchronous launch | established | deterministic (`test_the_harness_runs_no_provider_and_starts_no_synchronous_launch` reads the code: every process start in the probe module is `git` or an absolute system executable resolved by `_run_system`, no string constant names a provider CLI, no in-process transport is imported; in the test module the only process started is `sys.executable` and `launch` is never called -- every launch goes through the watched `Launch` harness) |

Not claimed by any row: any provider state (no provider ran); any change to
`CONFINEMENT_PROPERTIES`, `PROPERTY_EVIDENCE_MECHANISMS`,
`governed_build_eligibility` or `PROVIDER_CONFINEMENT` (all untouched, both
providers still ineligible); that the bearer gate is confinement (it constrains
the surface, not a caller's principal); a provider-principal probe under a
separate OS account, which is operator evidence for a later slice; that the
off-Windows arm was observed on the development host (patching `sys.platform`
breaks `windows_runtime` at import, so the Linux CI matrix is that witness);
that running the tool is free of side effects (against a browser-granted
surface it opens the owner's browser once per run: one reopen mint, the
explicit pull answering 429); one host being the platform (other browsers,
profiles and hosts are unmeasured, A-027); and that the architecture gate has
read this harness at all -- `scripts/` is outside `check_architecture.py`'s
scope (`SOURCE_ROOT` is `src`), a PRE-EXISTING boundary this slice neither
introduced nor narrowed, recorded in A-028's "does NOT establish" list as a
Tranche C follow-up.

## The admission criterion after the proxy was retired (Tranche C, slice C1)

`control_plane_reachability` asked whether a provider could open a loopback
connection at all. That was a PROXY for authority acquisition, sound while
Forge's control plane was unauthenticated. A-027 gated it -- every
authority-moving route now requires this run's bearer -- which makes
reachability IRRELEVANT rather than ABSENT, and PA-01 found no sandbox setting
that removes it. So the criterion asked for the absence of something still
present that nothing can remove, and no provider could ever satisfy it, for a
reason about the proxy rather than about any provider. C1 retires it and
requires `control_plane_authority: denied` instead: whether a process confined
as Forge's adapter confines it can acquire or move Forge authority THROUGH the
control plane, on the surface Forge actually serves, decided by that surface's
own record. This slice runs no provider and takes no measurement; it changes
one criterion, adds one evidence mechanism, and moves no row (A-028).

| Property | Result | Evidence class |
| --- | --- | --- |
| U1 the criterion requires `control_plane_authority: denied`, and no longer requires reachability | established | deterministic (`test_the_criterion_requires_control_plane_authority_and_not_reachability` asserts the whole table as a literal, so "one property replaced, nothing else moved" is checkable rather than claimed) |
| U1 the retired name is kept as DATA and votes on nothing | established | deterministic (`test_the_retired_criterion_is_recorded_as_retired_rather_than_deleted`: `RETIRED_PROPERTIES` records what it required, who was competent for it and what its required outcome entails; a probe under the retired name still validates -- the recorded measurement spells its probes that way and is not rewritten -- and is not authoritative, because a retired name has no row in `PROPERTY_EVIDENCE_MECHANISMS`) |
| U2 only `observed_surface_record` is competent for the new property | established | deterministic (`test_only_a_surface_record_is_competent_for_control_plane_authority`, over `observed_process_result`, `observed_listener_record` and both non-enforcement mechanisms: each turns the green assessment red on the mechanism field alone. A controlled test listener is not Forge's gated surface -- it can answer "did anything arrive at me", not "did anything move Forge") |
| U3 the state-to-outcome mapping, including the separation conditional | established | deterministic (`test_the_state_to_outcome_mapping_is_the_four_states_and_the_bookkeeping_value` over every state and every separation word, PARAMETRISED FROM `CONTROL_PLANE_STATES + (None,)` so a state with no expected outcome fails as a missing row, with `test_the_mapping_table_and_the_state_vocabulary_cover_each_other` closing the other direction; `test_a_reached_surface_state_is_confinement_only_for_a_separated_principal` over BOTH guarded states: `denied` only with `separated`, `inconclusive` otherwise and by default, and C2's harness may never record `separated`; `test_the_mapping_refuses_a_state_or_a_separation_word_it_does_not_know` refuses a Python boolean by name) |
| U3 only `unreachable` yields the required outcome without a measured separation | established | deterministic (`test_only_unreachable_yields_the_required_outcome_without_measured_separation` derives, by CALLING the mapping, the set of states that answer `denied` at `not_separated` and asserts it is exactly `{unreachable}` -- a closed set, so a sixth state mapped `denied` reddens here and so does deleting the guard. The round-1 head failed this row: `reachable_unadmitted` answered `denied` at `not_separated` and `unknown`, establishing the property from a record C2 can produce for an unconfined caller running as the surface's own OS principal. `unreachable` is entitled to it because it is the one state that is not a statement about what a reached surface's log saw -- no connection existed, and a bearer cannot be spent on a socket that never opened) |
| U3 the documents that call the widening guarded name the states the code guards | established | deterministic (`test_every_document_calling_the_widening_guarded_names_the_states_the_code_guards`, in both directions: the guarded set is MEASURED by calling the mapping and must equal the states the sentence names, and every document making the claim -- `CHANGELOG.md`, this file, `ASSUMPTIONS.md`, `provider_contract.py`, and the test module's own docstring, checked through `__doc__` rather than its source so its own constant cannot satisfy it -- must carry the phrase. Round 1 had five sentences saying the widening was guarded while half of it was not, and nothing noticed) |
| M5 the witness selection can never name a retired property | established | deterministic (`test_the_witness_selection_can_never_name_a_retired_property` reads the PARSED body of `assess_confinement`: the one assignment to `witnesses` is located and its names checked as a positive control, then every retired property name is refused as a string CONSTANT -- the retired property is a string at every site that could use it -- and `RETIRED_PROPERTIES` and `subsumed_control_plane_state` are refused by name. The laundering route was held by one example before this; the structural assertion closes the line that would reopen it) |
| U3 the contract's state vocabulary is the probe harness's own | established | deterministic (`test_the_contracts_control_plane_vocabulary_is_the_probe_harnesses_own`: the states are restated in `provider_contract.py` rather than imported -- the probe is a stranger to the surface, and `layer.domain` may not reach into `scripts/` -- and held equal to `probe_control_plane.STATES` plus `NOT_DERIVABLE_HERE`, with the separation vocabulary and the surface mechanism held equal too) |
| U4 both providers remain ineligible, and each refusal names a missing measurement rather than an approval | established | deterministic (`test_both_providers_are_ineligible_and_the_reason_names_the_missing_property`: Codex unmet on `control_plane_authority` alone -- no record of Forge's own gated surface from a Codex principal exists -- Claude unmet on every property because its evidence does not exist and Codex's does not travel; "approval" appears in neither reason) |
| M5 the retired criterion's required outcome entails the new property's | established | deterministic (`test_every_recorded_reachability_denial_entails_the_new_property`, measured over the two reachability probes in `docs/governance/codex_confinement_measurement.json`: at the outcome the retired criterion required, each entails the state `unreachable`, which maps to `denied` at every separation word. What PA-01 actually recorded is `allowed`, twice, so the required outcome is a labelled counterfactual over real probes) |
| M5 the entailment runs one way | established | deterministic (`test_the_entailment_runs_one_way_over_every_recorded_outcome`, over every recorded probe and every outcome the vocabulary allows: it fires for the retired required outcome and for nothing else, and never for an unobserved attempt or an observer the retired criterion did not trust. A reachability that was ALLOWED entails nothing, because with the surface gated, reaching it no longer says whether authority moved) |
| M5 the retired evidence does not ADMIT the new property | established | deterministic (`test_a_retired_denial_still_does_not_admit_the_new_property`: handed the world the old criterion admitted, the assessment still reports `control_plane_authority` unmet for want of a competent observation. The entailment yields a STATE, never a probe, so no listener record is re-labelled as an observation of a surface nobody watched -- the mechanism substitution A-024's P2-2 closed) |
| M5 evidence satisfying only the new property retro-admits nothing | established | deterministic (`test_a_measurement_satisfying_only_the_new_property_admits_nothing_else`: the criterion is a conjunction, and the other five properties stay unmet) |
| M7 an `inconclusive`, unobserved or absent probe cannot satisfy the property | established | deterministic (`test_an_inconclusive_or_unobserved_authority_probe_cannot_satisfy_it`, `test_an_absent_probe_record_is_inconclusive_and_never_a_refusal`: at the mapping, no state at all is `inconclusive` and never the required outcome; at the assessment, a measurement carrying no observation is unmet with the reason naming the property) |

Not claimed by any row: that the replacement is stronger in EVERY direction. It
is not, and saying so would be the substitution this repository keeps finding.
It is stronger in what it asks about (authority, not connectivity) and in who
must witness it (Forge's own gated surface, not a stand-in listener), and it is
WIDER in which physical worlds can satisfy it -- a caller refused everywhere
that moves authority now has somewhere to land, where the old criterion refused
it for connecting at all. That widening is what makes the criterion satisfiable
by an honest measurement, and it is guarded by the separation conditional
(A-027's two same-user channels) rather than free: `reachable_unadmitted` and
`admitted_nuisance` -- both of the states the widening opens, and both read off
a REACHED surface's request log -- count as confinement only for a principal
measured SEPARATE from the surface's owner. `unreachable` alone is
unconditional, and says no connection existed rather than what a log saw. Also
not claimed: anything
about a provider (none ran); that the new property is satisfiable in practice
(an open question a measurement must answer, where the old one was closed by
construction); that a bearer gate is confinement (it constrains the surface); any
change to `governed_build_eligibility`'s rule, to `assess_confinement`'s
unanimity rule or to `PROVIDER_CONFINEMENT` (untouched, both providers still
ineligible); and any movement on the permanently-blocked approval and
inspection diagnostics, which are unrelated to confinement and unchanged.
`docs/governance/CODEX_CONFINEMENT_MEASUREMENT.md` and its JSON still name
`control_plane_reachability` throughout and were deliberately not edited: they
record what was measured in the vocabulary of the criterion then in force, and
rewriting a measurement to match a later criterion is how a record stops being
one.

## Requires a normal internet-connected machine or GitHub Actions

The release workspace cannot reach public package indexes or GitHub from its shell. Therefore the following are delegated to the included CI workflow and the end user's bootstrap environment:

- installation of `nornyx==1.11.0`;
- installation of `nornyx-agentic-adapters[crewai]==0.3.0`;
- installation and native kickoff of `crewai==1.15.4`;
- Nornyx contract generation, lock creation, lock verification, and strict runtime evidence validation;
- Docker image construction.

## Verify from a CLONE, not from an archive

A `git archive` extraction carries the content and no `.git`. Several proofs
shell out to `git ls-files` to establish what a clean checkout contains, so in
an archive they fail for a reason that has nothing to do with the control under
test -- an independent review measured 62 failures and 10 errors across 16
modules, including all FOURTEEN `test_removing_the_control_revives_the_defect`
cases, the mutation catalogue, and three false-green guards. (This said
"nineteen" and was never true of the node it names: the inventory holds
nineteen classes, and that node is parametrised over the FOURTEEN with a
single mutation each. FIVE of the nineteen are excluded, and this named three.
H03, H04 and H13 are PENDING -- two are
compound-only, one is an obsolete historical attack. H11 and H12 are
DELEGATED: they carry no mutation of their own at all, so they were never
candidates for this runner and were simply not mentioned. 19 - 3 - 2 = 14,
which is what collects; a reader doing the arithmetic the passage invited
landed on 16. So the sentence
credited that runner with five classes the repository elsewhere takes care
to say it does not prove. `TASK11_CLOSURE.md` recorded the right figure the
whole time.) Those are the
central "every historical defect stays dead" evidence, and they pass in any git
checkout.

`tests/mutation_workspace.NotAGitCheckout` now says so at the point of failure
rather than leaving a reviewer to work it out from sixty-two tracebacks. The
requirement itself is real and is not being engineered away: these proofs
compare against what git tracks, and without git there is nothing to compare
against.

## Which mode actually runs, measured

Every row below was produced by running the mode, not by reading configuration.
The previous version of this section said the normal bootstrap, the CI demo job
and the Docker path "request strict Nornyx/CrewAI execution and fail closed",
and that only an explicit local smoke path was labelled `deterministic_fallback`.
The shipped container requests neither: `demo_app.main` names
`demonstration_authority()`, which is `deterministic_demo` and `sequential`. The
sentence described the strict posture while the thing that ships runs the
permissive one, which is the dangerous direction to be wrong in.

| Requested mode | Observed policy | Observed executor | Outcome |
| --- | --- | --- | --- |
| `demo_app.main` / Docker (`deterministic_demo`, `sequential`) | deterministic fallback | `sequential` | runs; high-risk effect prevented |
| `RuntimeAuthorityConfig()` bare default (`nornyx`, `crewai`) | none — refused | none | `NornyxRuntimeUnavailable` |

| `nornyx` + any executor | none — refused | none | with a runtime lock: `CONTRACT_INVALID: AN_APPROVAL_RECORD_MISSING, APPROVAL_EVIDENCE_MISSING, EVIDENCE_REQUIRED_MISSING`; **on a clean checkout: `RUNTIME_LOCK_MISSING`** |
| `deterministic_demo` + `crewai` | deterministic fallback | `crewai_flow` — CrewAI really executed | runs; high-risk effect prevented |
| `deterministic_demo` + `crewai`, CrewAI absent | — | — | `ExecutionBackendUnavailable`; refuses rather than downgrading silently |
| malformed policy or execution backend | — | — | `GovernedSubjectError` at construction |


**Correction to the bare-default row.** That row reads as though nothing runs
on `RuntimeAuthorityConfig()`. The BUILD path does: `cli.py` constructs
`DevelopmentFlow(root, worker_mode=..., repo_mode=..., target_repo=...)` with
no config at all, so the bare default is exactly what that path uses, and it
is not refused there. The refusal the row describes belongs to the runtime
authority path, not to every construction of the default.

> **What a reader actually sees.** The `nornyx` row's diagnostic is what a
> tree with a PREPARED RUNTIME LOCK reports. `.nornyx/runtime/` is gitignored
> and the lock cannot be produced without a human approval
> (`prepare_runtime.py` exits 2 and writes only `preparation-report.json`), so
> on a clean checkout the refusal arrives one step earlier as
> `RuntimeError: RUNTIME_LOCK_MISSING`. Both are the same absence at different
> depths.
>
> README.md and ONE_PROMPT.md have carried this caveat for the identical
> string; this document was measured as the one of the four that did not, while
> asserting that every row "was produced by running the mode". It was --- in a
> tree the reader does not have.

Reading the table:

- **The strict path genuinely fails closed here, and the reason is honest.**
  Nornyx refuses because this repository holds no human approval record. That is
  the true state, not a broken installation, and it is why the demonstration
  does not run strict: a demonstration that refuses every case is not one.
- **`deterministic_demo` is a cooperative control, not Nornyx authorization.**
  It still prevents the high-risk external action, and every decision it makes
  is labelled `source: deterministic_fallback`. It is not represented as Nornyx
  runtime evidence anywhere.
- **"CrewAI execution" is only claimed when CrewAI executed.**
  `observed_execution_backend` is derived from which driver ran, never restated
  from the configuration, and requesting `crewai` where CrewAI cannot be
  imported raises rather than running the sequential driver under that name.

`tests/test_execution_mode_truth.py` asserts MOST rows, not every row. The
`deterministic_demo` + `crewai` row is asserted in
`tests/test_authority_config.py` instead, and the bare-default row is executed
nowhere -- the closest test runs `("nornyx", "sequential")`, a different pair.
Claiming one module covers the table left a reader one grep from believing a
row was proven that is not. It does still assert that this file
does not reacquire the claim it used to make.
