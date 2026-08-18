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
- its configured execution path runs successfully, with the observed backend
  matching the selected backend;
- Nornyx evidence is emitted;
- final limitations are disclosed.

### What "configured execution path" means

The criterion deliberately names no backend. Its predecessor read "its CrewAI
Flow runs", which named no path either -- and was true of one path while false of
the one that ships. Naming today's default instead would fossilise it: the
criterion would go false the moment the shipped default changed, for a change
that ought to satisfy it.

What is required is that the selected backend is the one that actually runs, and
that the application reports which. Measured on this baseline, both directions:

    SHIPPED DEMONSTRATION PATH -- demonstration_authority()
      execution_backend selected     sequential
      CustomerCaseFlow driven by     run_sequential()
      observed_execution_backend     sequential
      framework reported             CrewAI Flow-compatible sequential execution
      CrewAI kickoff used            no

    EXPLICIT CREWAI SELECTION -- execution_backend="crewai"
      CustomerCaseFlow driven by     CustomerCaseFlow.kickoff()
      observed_execution_backend     crewai_flow
      framework reported             CrewAI Flow kickoff
      run_sequential used            no

Both were observed by running the code and spying on the driver, not read from
configuration. CrewAI is genuinely functional here; the shipped path simply does
not select it. If `crewai` is selected while CrewAI cannot be imported the run
RAISES rather than downgrading to sequential under an unchanged label -- that
silent downgrade is how a suite once stayed green with CrewAI absent.

Three facts, kept apart. The shipped path selects and runs sequential. Explicit
CrewAI selection runs a real Flow kickoff. `demonstration_authority()` hardcodes
sequential. None of them is "CrewAI does not run".

`observed_execution_backend` is derived from the execution path rather than
restated from configuration, which is what makes this criterion checkable
instead of tautological. Pinned by `tests/test_execution_mode_truth.py`:
`test_the_observed_backend_comes_from_the_driver_not_the_configuration`,
`test_the_sequential_path_reports_the_sequential_driver`, and
`test_crewai_cannot_be_claimed_when_crewai_cannot_run`.

