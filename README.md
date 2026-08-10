# Nornyx Forge Live Demo

**From a BRD and a public repository to a governed, running agentic application — with one Claude Code prompt.**

This repository is a public reference implementation for demonstrating three Nornyx value claims:

1. **Software-development governance** — requirements, goals, permissions, tests, repair budgets, evidence, and release gates are explicit and revision-bound.
2. **Architecture governance** — target components, layers, interfaces, trust boundaries, and architecture evidence are checked before acceptance.
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

The workflow generates `.nornyx/generated/brd_contract.nyx`, creates evidence under `.nornyx/runs/`, requires strict Nornyx/CrewAI execution in the installed path, launches the application, and prints:

- Application: `http://localhost:8000`
- Governance dashboard: `http://localhost:8000/dashboard`
- API documentation: `http://localhost:8000/docs`

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
