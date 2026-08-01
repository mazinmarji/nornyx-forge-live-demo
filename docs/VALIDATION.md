# Validation record

## Locally verified in the release workspace

- Python source compilation for `src/` and `scripts/`.
- Twelve unit and repository tests.
- Repository structure and secret-pattern validation.
- Architecture dependency and command-isolation checks.
- Security checks for embedded credentials, unsafe subprocess shell mode, `eval`, and `exec`.
- Deterministic BRD-to-build flow: eleven requirements, certified foundation GO, five gates passed, zero repair attempts.
- Live FastAPI health, dashboard, and demonstration endpoints through `scripts/smoke_http.py`.
- Low-risk action executed; high-risk external action prevented.
- Fourteen-event local demonstration evidence stream validated.

## Requires a normal internet-connected machine or GitHub Actions

The release workspace cannot reach public package indexes or GitHub from its shell. Therefore the following are delegated to the included CI workflow and the end user's bootstrap environment:

- installation of `nornyx==1.11.0`;
- installation of `nornyx-agentic-adapters[crewai]==0.2.0`;
- installation and native kickoff of `crewai==1.15.4`;
- Nornyx contract generation, lock creation, lock verification, and strict runtime evidence validation;
- Docker image construction.

The normal bootstrap, GitHub Actions demo job, and Docker path request strict Nornyx/CrewAI execution and fail closed when dependencies, contracts, or locks are invalid. Only the explicit local fallback smoke path is labeled `deterministic_fallback`; it is not represented as Nornyx runtime evidence.
