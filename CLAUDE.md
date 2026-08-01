# Nornyx Forge operating instructions

Treat `BRD.md` as the business source of truth and `.nornyx/contracts/*.nyx` as the governance source of truth.

## Required behavior

- Work goal by goal; never implement unbounded repository-wide changes.
- Use Repo Scout/Qualifier before adopting an upstream public repository.
- Record assumptions in `docs/requirements/ASSUMPTIONS.md`.
- Preserve traceability from BRD IDs to code, tests, and evidence.
- Keep application side effects behind explicit services or tools.
- Run deterministic gates before AI review.
- Use separate read-only test, architecture, and security reviewers; a builder may not approve its own patch.
- In the recommended one-prompt mode, use the current session Agent tool rather than nested `claude -p`.
- Record inspector verdicts in `.nornyx/in-session/reviews.json` before in-session acceptance.
- Do not modify Nornyx policies merely to make a failing implementation pass.
- Never commit `.env`, tokens, Claude credentials, or generated runtime evidence containing secrets.
- Do not deploy to production or publish an external PR without explicit user authorization.

## Success criteria

The task is complete only when:

- all BRD acceptance criteria are represented by tests;
- architecture checks pass;
- Nornyx contracts validate;
- the live application starts;
- its CrewAI Flow runs;
- Nornyx evidence is emitted;
- final limitations are disclosed.
