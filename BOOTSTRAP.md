# Bootstrap contract

The bootstrap process is intentionally deterministic around the model work.

## Required sequence

1. Run `python scripts/environment_check.py`.
2. Create `.venv` and install `.[demo,dev]`.
3. Validate `.nornyx/contracts/forge_control.nyx` and `.nornyx/contracts/runtime_network.nyx` with the installed Nornyx CLI.
4. Produce or update `.nornyx/foundation-decision.json` using certified, target, scout, or greenfield mode.
5. In interactive mode, use the current Claude Code session and Agent subagents; do not start nested Claude processes.
6. Execute the CrewAI development flow in `in-session` mode after the bounded implementation work.
7. Run repository, architecture, security, and test gates after every implementation goal.
8. Invoke separate read-only test, architecture, and security inspectors at phase boundaries.
9. Write `.nornyx/in-session/reviews.json`; the builder may not author its own approval.
10. Permit at most three repair attempts per failed goal.
11. Write evidence before advancing the state machine.
12. Start the live application and execute the runtime demonstration scenarios.

## Autonomous demonstration authority

This repository permits automatic continuation through non-production gates. It does not issue a human approval or production release decision.

The final report must include:

```yaml
assurance_mode: autonomous_demonstration
human_review: not_performed
production_approval: not_granted
```

## Hard stops

- Secret or credential discovered in tracked content.
- No compatible license for a selected upstream repository.
- Requested destructive or production operation.
- Nornyx contract or architecture gate cannot be made valid without weakening the BRD.
- Repair budget exhausted.
- Claude Code, Docker, Python, or Git unavailable for the requested live mode.
