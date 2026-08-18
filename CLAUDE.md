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
- Nornyx contract structure and governed-content integrity validate:
  `--verify` reports `integrity_state: intact` with zero problems, and no
  structural or integrity diagnostic remains;
- production-approval readiness is NOT satisfied, and is not expected to be.
  This is a separate criterion on purpose. Folding it into the one above
  required reading "contracts validate" as "validation may still return
  approval-absence diagnostics", which redefines a failing approval gate as
  successful validation -- the exact substitution of a label for the thing
  that this repository keeps finding. Two of the three contracts fail today,
  for this reason and only this reason.

  The sole diagnostics an autonomous run may leave outstanding are those
  `scripts/check_pre_approval_baseline.py` accepts:

      AN_APPROVAL_RECORD_MISSING
      APPROVAL_EVIDENCE_MISSING
      EVIDENCE_REQUIRED_MISSING

  Any other validation or integrity diagnostic fails the criterion above.
  Clearing these three requires a genuine human approval record. Creating,
  adopting, inferring, or backdating one is forbidden, so no autonomous run
  may close this criterion, and none may report it closed;
- the live application starts;
- its CrewAI Flow runs;
- Nornyx evidence is emitted;
- final limitations are disclosed.
