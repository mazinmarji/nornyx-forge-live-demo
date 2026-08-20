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

Continue until the application is implemented, all acceptance gates pass, and
the customer-operations Flow completes its demonstration scenarios.

On a fresh clone the run STOPS BEFORE LAUNCH, and that is correct.
`bootstrap.py` appends `--strict-nornyx` when `--skip-install` is absent;
measured on a fresh clone, that demo exits 2 with

    "detail": "RuntimeError: RUNTIME_LOCK_MISSING: ...nornyx.agentic_network.lock
               does not exist"

This sentence used to name AN_APPROVAL_RECORD_MISSING and to stop mid-clause.
A review measured a fresh clone and found that code appears zero times: it is
what a tree with a PREPARED RUNTIME LOCK reports, and no reader has one.

> **What a reader actually sees.** `.nornyx/runtime/` is gitignored and the
> lock CANNOT be produced without a human approval (`prepare_runtime.py` exits
> 2, names the absent approval, and writes only `preparation-report.json`),
> so on a clean checkout the proximate refusal is
> `RuntimeError: RUNTIME_LOCK_MISSING`. Same absence, reported at a different
> depth: no approval exists, so the lock cannot be prepared, so the authorizer
> cannot load. The exit code (2), `status: blocked` and
> `reason: nornyx_runtime_unavailable` are identical either way.
`run()` raises SystemExit on a nonzero return, so the launch and the URL
prints below are never reached. Declining to execute governed actions
without an approval is the system working.

The shipped flow runs `run_sequential()`; `observed_execution_backend` is
`sequential`. It is not a CrewAI kickoff, and this section previously said
it was. Stop only on a declared hard stop, unavailable
prerequisite, exhausted budget, or unresolved security/legal ambiguity.

At completion report the URLs IF the launch was reached, otherwise the exact
refusal and its diagnostics, plus
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
