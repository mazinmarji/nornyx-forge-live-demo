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

**PARTIALLY MET, and the requirement is NOT being reworded to match the code.**
An independent review measured the shipped `demo --offline` path and I
reproduced it in a clean checkout with its own environment. Of 14 events:

| field | present | note |
| --- | --- | --- |
| `mission_id` | 14/14 | |
| `timestamp` | 14/14 | |
| `actor` | 14/14 | |
| `capability` | 2/14 | carried by the two POLICY DECISIONS, not by stage events |
| `decision` | 2/14 | as above |
| `reason` | 2/14 | as above |
| `subject_revision` | 0/14 | never populated on this path |

Two different gaps, and they are not equally excusable. A stage event has no
capability to name and no decision to report, so `2/14` reflects a requirement
written as if every event were a policy decision; the wording is broader than
the thing it describes. `subject_revision` is different: the field exists on
every event and is null on all of them, so the evidence stream cannot say which
revision of the governed subject produced it. That is a real hole, not a
category error.

Nothing verified this before. `parse_brd` reads headings only, and no test
referenced a real BRD id -- the requirements suite runs on synthetic fixtures.
`tests/test_brd_evidence_shape.py` now pins the measured shape, so the gap
cannot widen silently and closing it shows up as a diff.

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
