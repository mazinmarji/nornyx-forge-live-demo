---
name: build-app
description: Use Claude Code as the engineering front end to Nornyx Forge; transform a BRD and suitable repository into a governed agentic application while deterministic Forge/Nornyx controls remain authoritative.
argument-hint: "[BRD path] [--repo URL|auto|certified]"
allowed-tools: Read, Glob, Grep, Edit, Write, Bash, Agent
---

# Build app with Nornyx Forge

This Skill is the preferred Claude Code entry point to Nornyx Forge.

Claude Code is the engineering worker: it may reason, analyze, design, implement,
review, and repair. The Skill is orchestration and procedure. Neither Claude Code
nor this Skill is an authority source and neither may substitute a model judgment
for a deterministic Forge/Nornyx control.

Use the supplied BRD, defaulting to `BRD.md`. Execute the workflow in
`BOOTSTRAP.md` from the current Claude Code session.

## Authority and assurance contract

The following rules are non-negotiable:

1. A Claude statement such as "safe", "approved", "verified", "production-ready",
   or "governed" is never evidence by itself.
2. The Skill may generate proposed contracts, code, tests, and evidence artifacts,
   but only the repository's deterministic validators and Nornyx semantics decide
   whether their mechanically declared properties hold.
3. The builder may not synthesize, infer, extend, or self-approve human authority.
4. A failing gate must remain failing until the measured property is repaired. Do
   not weaken, skip, relabel, grandfather, or reinterpret a gate to obtain green.
5. Review subagents provide bounded in-session review evidence. They do not count
   as external independent confirmation, human review, certification, or
   production approval.
6. Free-form prose cannot create, upgrade, or satisfy authoritative approval,
   inspection, assurance, or production-readiness state.
7. Runtime consequential effects must remain behind the implemented action
   boundary and its configured governance/approval checks. A prompt instruction is
   not an enforcement mechanism.
8. When a deterministic result conflicts with Claude's interpretation, the
   deterministic result controls and the conflict must be reported.

See `docs/FORGE_SKILL_BOUNDARY.md` for the architectural boundary.

## Required stages

1. Check the environment and install the project in `.venv`.
2. Normalize requirements and preserve BRD traceability.
3. Select the certified foundation, qualify a supplied target, or run Repo Scout.
4. Generate or update Nornyx project, architecture, and runtime contracts as
   proposals subject to deterministic validation.
5. Invoke the solution-architect subagent.
6. Invoke bounded builder subagents, using isolated worktrees where supported.
7. Run deterministic repository, test, architecture, security, evidence, and
   Nornyx gates.
8. Invoke separate read-only test, architecture, and security inspector subagents.
9. Return blocking findings to the builder and repair within budget without
   weakening gates.
10. Write `.nornyx/in-session/reviews.json` using the schema below.
11. Run `python scripts/bootstrap.py --autonomous --worker-mode in-session`.
12. Launch and exercise the CrewAI Flow and report evidence and limitations.

Required review artifact:

```json
{
  "schema": "nornyx.forge.in_session_reviews.v1",
  "human_review": "not_performed",
  "builder_self_approval": false,
  "reviews": [
    {"role": "test-inspector", "status": "pass", "findings": [], "evidence": []},
    {"role": "architecture-inspector", "status": "pass", "findings": [], "evidence": []},
    {"role": "security-inspector", "status": "pass", "findings": [], "evidence": []}
  ]
}
```

A reviewer must use `status: "fail"` while any blocking finding remains. The
builder cannot author or approve the inspector records. Autonomous demo mode may
continue without a human reviewer, but it must never claim human review,
independent external confirmation, certification, or production approval.

## Completion report

Report separately:

- what Claude Code built or changed;
- which deterministic Forge/Nornyx gates actually ran and their exact results;
- the authoritative evidence/verdict produced by those gates;
- which review evidence came only from in-session model subagents;
- whether human approval or external independent review exists;
- every unsupported or intentionally bounded assurance claim.

Never collapse these categories into a single "Forge passed" statement.
