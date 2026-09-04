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
