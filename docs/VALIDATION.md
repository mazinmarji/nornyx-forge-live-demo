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
  OS resource limits. The runner and executor use the same digest-verified
  in-memory byte-snapshot pattern as the top-level verifier. Before execution,
  static inspection refuses hard termination, reflection, and pytest lifecycle
  control; during execution an audit hook confines writes to the pytest temp
  root and refuses process starts. A separate trusted supervisor requires a
  complete executed-test record, a normal-completion sentinel, and the expected
  executor digest, and retains only a bounded output tail. Read the count and
  provenance from the build report
  produced by the run it describes.
- Live FastAPI health, dashboard, and demonstration endpoints through `scripts/smoke_http.py`.
- Low-risk action executed; high-risk external action prevented.
- Local demonstration evidence stream validated, with its event count and
  stream digest recorded in the run output rather than fixed in this file.

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
