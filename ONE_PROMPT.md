# One-prompt bootstrap

Paste this into an authenticated **interactive Claude Code** session. This mode
uses the current session and Claude Code subagents directly; it does not require
an Anthropic Console API key or nested `claude -p` calls.

```text
Clone https://github.com/mazinmarji/nornyx-forge-live-demo into the current
working directory, enter the repository, and read BOOTSTRAP.md, CLAUDE.md,
BRD.md, skills/build-app/SKILL.md, every agent definition under agents/, and
the Nornyx contracts before making changes.

Execute the complete build-app skill in this Claude Code session. Use BRD.md as
the authoritative business requirement. Use the bundled certified foundation
unless the user supplied a target repository or Repo Scout identifies a clearly
superior public repository that passes qualification.

Use Claude Code subagents through the Agent tool for requirements analysis,
repository scouting, architecture, bounded implementation, test inspection,
architecture inspection, security inspection, and evidence reporting. Do not
start nested Claude Code processes and do not request a model API key.

Run deterministic tests, architecture checks, security checks, and Nornyx
validation between phases. Do not ask for intermediate design, implementation,
architecture, testing, or review confirmation. Resolve ordinary ambiguity
through documented assumptions. Never weaken a failing gate. Repair within the
declared attempt and budget limits.

The builder may not approve its own work. After the separate read-only test,
architecture, and security inspectors finish, write this evidence file:

  .nornyx/in-session/reviews.json

using schema nornyx.forge.in_session_reviews.v1, with human_review set to
not_performed, builder_self_approval set to false, and one pass/fail record for
each required inspector. Preserve all findings; do not mark a review pass while
it has unresolved blocking findings.

Then run:

  python scripts/bootstrap.py --autonomous --worker-mode in-session

Continue until the application is implemented, all acceptance gates pass, the
CrewAI customer-operations Flow completes its demonstration scenarios, and the
application is running. Stop only on a declared hard stop, unavailable
prerequisite, exhausted budget, or unresolved security/legal ambiguity.

At completion report the application URL, dashboard URL, API documentation URL,
build evidence verdict, runtime evidence verdict, repository foundation and
revision, measured value report, and every limitation or unsupported assurance
claim.
```

## Scripted alternative

For a non-interactive personal runner that deliberately invokes bounded
`claude -p` workers, use:

```bash
python scripts/bootstrap.py --autonomous --worker-mode claude-code
```

That alternative may consume the Claude plan's programmatic/Agent SDK allowance.
