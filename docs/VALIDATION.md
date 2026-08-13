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
- Deterministic BRD-to-build flow: eleven requirements, certified foundation GO, five gates passed, zero repair attempts.
- Live FastAPI health, dashboard, and demonstration endpoints through `scripts/smoke_http.py`.
- Low-risk action executed; high-risk external action prevented.
- Local demonstration evidence stream validated, with its event count and
  stream digest recorded in the run output rather than fixed in this file.

## Requires a normal internet-connected machine or GitHub Actions

The release workspace cannot reach public package indexes or GitHub from its shell. Therefore the following are delegated to the included CI workflow and the end user's bootstrap environment:

- installation of `nornyx==1.11.0`;
- installation of `nornyx-agentic-adapters[crewai]==0.2.0`;
- installation and native kickoff of `crewai==1.15.4`;
- Nornyx contract generation, lock creation, lock verification, and strict runtime evidence validation;
- Docker image construction.

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
| `nornyx` + any executor | none — refused | none | `CONTRACT_INVALID: AN_APPROVAL_RECORD_MISSING, APPROVAL_EVIDENCE_MISSING, EVIDENCE_REQUIRED_MISSING` |
| `deterministic_demo` + `crewai` | deterministic fallback | `crewai_flow` — CrewAI really executed | runs; high-risk effect prevented |
| `deterministic_demo` + `crewai`, CrewAI absent | — | — | `ExecutionBackendUnavailable`; refuses rather than downgrading silently |
| malformed policy or execution backend | — | — | `GovernedSubjectError` at construction |

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

`tests/test_execution_mode_truth.py` asserts every row, including that this file
does not reacquire the claim it used to make.
