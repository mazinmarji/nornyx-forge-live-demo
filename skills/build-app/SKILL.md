---
name: build-app
description: Build the complete Nornyx Forge demonstration from BRD to running application.
argument-hint: "[BRD path] [--repo URL|auto|certified]"
allowed-tools: Read, Glob, Grep, Edit, Write, Bash, Agent
---

# Build app with Nornyx Forge

Use the supplied BRD, defaulting to `BRD.md`. Execute the workflow in
`BOOTSTRAP.md` from the current Claude Code session.

Required stages:

1. Check the environment and install the project in `.venv`.
2. Normalize requirements and preserve BRD traceability.
3. Select the certified foundation, qualify a supplied target, or run Repo Scout.
4. Generate or update Nornyx project, architecture, and runtime contracts.
5. Invoke the solution-architect subagent.
6. Invoke bounded builder subagents, using isolated worktrees where supported.
7. Run deterministic repository, test, architecture, security, and Nornyx gates.
8. Invoke separate read-only test, architecture, and security inspector subagents.
9. Return blocking findings to the builder and repair within budget without weakening gates.
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
continue without a human reviewer, but it must never claim human or production
approval.
