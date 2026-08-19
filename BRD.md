# BRD — Governed Customer Operations Center

## BRD-001 Purpose

Build a visually clear customer-operations application that demonstrates a live multi-stage agentic workflow governed by Nornyx.

## BRD-002 Users

- Customer submits a support or remediation case.
- Operations analyst monitors the case.
- Governance observer inspects policy decisions and evidence.

## BRD-003 Functional requirements

### BRD-F-001 Case intake

A user can submit a case with customer name, summary, risk level, and requested action.

### BRD-F-002 Agentic workflow

The customer-operations Flow processes each case through Intake, Knowledge,
Resolution, Risk, Execution, and Audit stages. The shipped path drives those
stages with `run_sequential()` and reports
`observed_execution_backend: sequential`; selecting the CrewAI backend
explicitly runs a real Flow kickoff. Naming CrewAI unconditionally here was
true of one path and false of the one that ships.

### BRD-F-003 No mandatory model API key

The default live mode uses Claude Code workers authenticated through the local Claude Code installation. A deterministic offline mode must remain available for CI and reproducible demonstrations.

### BRD-F-004 Governed actions

Low-risk actions may execute automatically. High-risk external actions must be refused in autonomous-demo mode because no human production approval exists.

### BRD-F-005 Evidence

Every stage and policy decision is recorded with mission ID, timestamp, actor, capability, decision, reason, and subject revision.

### BRD-F-006 Dashboard

The application displays current cases, agent stages, decisions, prevented actions, evidence status, and declared assurance limitations.

### BRD-F-007 Repo Scout

The Forge CLI can search public GitHub repositories from BRD-derived criteria and can qualify a user-provided repository before code changes.

## BRD-004 Non-functional requirements

- Python 3.10–3.13.
- Docker-based launch.
- No secrets committed.
- Tests run without network access.
- Bounded repair attempts.
- Architecture separates API, application services, agentic flow, governance, persistence, and UI.

## BRD-005 Acceptance criteria

- `pytest` passes.
- `python scripts/validate_repository.py` passes.
- `nornyx-forge demo --offline` produces a valid runtime evidence report.
- `docker compose up --build` starts the application when Docker and demo dependencies are available.
- High-risk execution is visibly prevented in autonomous-demo mode.
- The final report does not claim human approval or Tier 3 mandatory enforcement.
