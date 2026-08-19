# Nornyx Forge Live Demo

**From a BRD and a public repository to a governed, running agentic application — with one Claude Code prompt.**

This repository is a public reference implementation for demonstrating three Nornyx value claims:

1. **Software-development governance** — requirements, goals, permissions, tests, repair budgets, evidence, and release gates are explicit and revision-bound.
2. **Architecture governance** — declared modules and layers, and the architecture evidence set, are checked before acceptance. Interfaces and trust boundaries are DECLARED but not checked: `architecture_governance.nyx` carries `interfaces: []` and empty boundary lists, and `scripts/check_architecture.py` reads only `modules` and `layers`. The previous wording named them as checked.
3. **Delivery speed** — Repo Scout reuses a suitable foundation, deterministic gates catch defects early, and bounded repair loops reduce uncontrolled re-iteration.

## What runs

- **Claude Code** performs repository analysis, architecture, implementation, review, and repair.
- **CrewAI Flow** coordinates the development workflow (`nornyx-forge build`)
  without requiring a CrewAI model API key. The live application runs the
  sequential backend by default and says so: `demonstration_authority()`
  names `execution_backend="sequential"`, and the evidence reports
  `framework: "CrewAI Flow-compatible sequential execution"`. Selecting
  `crewai` refuses rather than downgrading if CrewAI cannot execute, so the
  label always describes what ran.
- **Nornyx** validates the generated BRD contract, architecture contract, runtime network, and control/evidence boundary.
- **FastAPI** serves the live governed customer-operations application and dashboard.

The default is an **autonomous demonstration**, not a production approval. Human review is not performed and the evidence says so explicitly.

## The one prompt

Open Claude Code in any directory and paste the prompt in [`ONE_PROMPT.md`](ONE_PROMPT.md). It tells Claude to clone this repository, run the autonomous workflow, start the application, and report the URLs.

After cloning manually, start Claude Code with the local plugin loaded:

```bash
claude --plugin-dir .
```

Then use the current Claude Code session and its subagents:

```text
/nornyx-forge:build-app BRD.md
```

The recommended one-prompt instructions are in [`ONE_PROMPT.md`](ONE_PROMPT.md).
They run reviewer subagents in-session and finish with:

```bash
python scripts/bootstrap.py --autonomous --worker-mode in-session
```

The optional fully scripted mode uses bounded `claude -p` workers:

```bash
python scripts/bootstrap.py --autonomous --worker-mode claude-code
```

## Fast local verification without Claude or external APIs

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e '.[demo,dev]'
python scripts/check_test_coverage.py
python scripts/validate_repository.py
```

## Full live mode

Prerequisites:

- Git
- Python 3.10–3.13
- Docker Desktop or Docker Engine
- Claude Code installed and authenticated

Then paste [`ONE_PROMPT.md`](ONE_PROMPT.md) into Claude Code. The current
session uses its Agent subagents directly, records their review findings, and
runs the in-session bootstrap without a separate model API key. Those findings
are a self-reported observation, not an independent inspection: independence
requires an attestation signed by a reviewer who is not the builder, verified
against a trust store outside this repository. Without one the evidence set
reports `assurance_state: not_independently_inspected`, which is its current
state.

The workflow generates `.nornyx/generated/brd_contract.nyx` and creates evidence
under `.nornyx/runs/`.

**On a fresh clone it then stops, and that is correct.** `scripts/bootstrap.py`
appends `--strict-nornyx` whenever `--skip-install` is absent, and on this
branch strict mode refuses, because no human approval record exists. Measured:

```
$ python -m nornyx_forge.cli demo --offline --strict-nornyx
{"status": "blocked", "reason": "nornyx_runtime_unavailable",
 "detail": "AuthorizerLoadError: CONTRACT_INVALID: AN_APPROVAL_RECORD_MISSING,
            APPROVAL_EVIDENCE_MISSING, EVIDENCE_REQUIRED_MISSING"}
exit 2
```

`bootstrap.run()` raises `SystemExit` on a nonzero return, so the launch step
below is **not reached** on the path this section documents. Declining to
execute governed actions without an approval is the system working; the earlier
version of this paragraph claimed the workflow "launches the application, and
prints" the URLs, and that was false.

Where the launch does happen -- with `--skip-install`, so no `--strict-nornyx`,
and with Docker present and `--no-launch` absent -- `bootstrap.py` runs
`docker compose up --build -d` and prints:

- Application: `http://localhost:8000`
- Governance dashboard: `http://localhost:8000/dashboard`
- API documentation: `http://localhost:8000/docs`

The execution backend is `sequential` on both paths. `cli.py` requests it
unconditionally, and a run reports `configured_execution_backend: sequential`
alongside `observed_execution_backend: sequential`. **CrewAI is not requested by
this workflow**, and the previous wording "strict Nornyx/CrewAI execution" said
otherwise. `tests/test_execution_mode_truth.py` pins all three claims against
the code and against an executed run.

## Public repository modes

The BRD-to-build workflow supports:

- `certified`: use the bundled, Nornyx-ready foundation.
- `target`: qualify a user-provided public repository.
- `scout`: search GitHub and rank compatible repositories.
- `greenfield`: start without an upstream foundation.

Repo Scout never treats stars or README claims as proof. It generates a scored suitability report and separates metadata evidence from build/runtime evidence.

## Assurance boundary

The live demo uses cooperative controls over declared surfaces. It does not claim mandatory sandbox enforcement, runtime truth attestation, or production approval. See [`docs/ASSURANCE_BOUNDARY.md`](docs/ASSURANCE_BOUNDARY.md) and [`docs/CLAUDE_CODE_AND_CREWAI.md`](docs/CLAUDE_CODE_AND_CREWAI.md).

## Source of truth

Nornyx semantics and current supported CrewAI adapter behavior are sourced from:

- https://github.com/mazinmarji/nornyx
- https://github.com/crewAIInc/crewAI
- https://github.com/crewAIInc/skills

## Validation

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the exact locally verified and CI-delegated checks.

## License

MIT.
