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

The normal bootstrap, GitHub Actions demo job, and Docker path request strict Nornyx/CrewAI execution and fail closed when dependencies, contracts, or locks are invalid. Only the explicit local fallback smoke path is labeled `deterministic_fallback`; it is not represented as Nornyx runtime evidence.
