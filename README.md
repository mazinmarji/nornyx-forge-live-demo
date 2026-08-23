# Nornyx Forge Live Demo

**Claude Code is the engineer. Nornyx Forge is the governed transformation and conformance system around it. Nornyx supplies the authority semantics underneath it.**

Nornyx Forge is a public reference implementation for demonstrating three Nornyx value claims:

1. **Software-development governance** — requirements, goals, permissions, tests, repair budgets, evidence, and release gates are explicit and revision-bound.
2. **Architecture governance** — target components, layers, interfaces, trust boundaries, and architecture evidence are checked before acceptance.
3. **Delivery speed** — Repo Scout reuses a suitable foundation, deterministic gates catch defects early, and bounded repair loops reduce uncontrolled re-iteration.

## Preferred entry point: the Claude Code Skill

After cloning the repository, start Claude Code with the local plugin:

```bash
claude --plugin-dir .
```

Then invoke Forge through the Skill:

```text
/nornyx-forge:build-app BRD.md
```

The Skill is the preferred human-facing interface. Claude Code performs the reasoning, repository analysis, architecture, implementation, review, and repair work. The Skill does **not** become the governance authority: deterministic Forge/Nornyx controls remain responsible for the properties they mechanically validate.

See [`docs/FORGE_SKILL_BOUNDARY.md`](docs/FORGE_SKILL_BOUNDARY.md) for the exact separation between model reasoning, Forge conformance, Nornyx governance semantics, and human or organizational authority.

## What runs

- **Claude Code** performs repository analysis, architecture, implementation, review, and repair.
- **Nornyx Forge Skill** orchestrates the engineering workflow and invokes the required deterministic gates.
- **CrewAI Flow** coordinates the development and live application workflows without requiring a CrewAI model API key in the default mode.
- **Nornyx** validates the generated BRD contract, architecture contract, runtime network, and control/evidence boundary.
- **FastAPI** serves the live governed customer-operations application and dashboard.

The default is an **autonomous demonstration**, not a production approval. Human review is not performed and the evidence says so explicitly. In-session model reviewers are bounded review evidence; they are not external independent confirmation or human approval.

## Bootstrap from outside a clone

[`ONE_PROMPT.md`](ONE_PROMPT.md) remains a convenience for users starting in an arbitrary directory. It clones this repository, loads the Forge instructions, and then executes the same `build-app` Skill. It is not a second assurance path.

The recommended path inside an existing clone is the Skill invocation above.

The current Claude Code session and its subagents finish with:

```bash
python scripts/bootstrap.py --autonomous --worker-mode in-session
```

The optional fully scripted mode uses bounded `claude -p` workers:

```bash
python scripts/bootstrap.py --autonomous --worker-mode claude-code
```

## What the Skill cannot replace

A prompt or Skill can direct Claude to analyze, design, code, test, and repair. It cannot create authority merely by saying that something is approved, verified, safe, production-ready, or governed.

Forge therefore keeps the following outside model discretion:

- deterministic repository, architecture, security, evidence, and Nornyx validation;
- mechanically bounded assurance claims;
- approval and evidence-integrity checks;
- runtime action-boundary enforcement integration;
- any real human or organizational authority required by the governed contract.

If Claude's interpretation conflicts with a deterministic result, the deterministic result controls and the conflict must be reported.

## Fast local verification without Claude or external APIs

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
pytest
python scripts/validate_repository.py
```

## Full live mode

Prerequisites:

- Git
- Python 3.10–3.13
- Docker Desktop or Docker Engine
- Claude Code installed and authenticated

Then start Claude Code with the local plugin and invoke:

```text
/nornyx-forge:build-app BRD.md
```

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

The live demo uses cooperative controls over declared surfaces. It does not claim mandatory sandbox enforcement, runtime truth attestation, or production approval. A gate may claim only the exact property it mechanically measures. See [`docs/ASSURANCE_BOUNDARY.md`](docs/ASSURANCE_BOUNDARY.md), [`docs/FORGE_SKILL_BOUNDARY.md`](docs/FORGE_SKILL_BOUNDARY.md), and [`docs/CLAUDE_CODE_AND_CREWAI.md`](docs/CLAUDE_CODE_AND_CREWAI.md).

## Source of truth

Nornyx semantics and current supported CrewAI adapter behavior are sourced from:

- https://github.com/mazinmarji/nornyx
- https://github.com/crewAIInc/crewAI
- https://github.com/crewAIInc/skills

## Validation

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the exact locally verified and CI-delegated checks.

## License

MIT.
