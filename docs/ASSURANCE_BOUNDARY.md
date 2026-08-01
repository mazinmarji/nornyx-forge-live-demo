# Assurance boundary

This repository demonstrates cooperative governance over declared software-development and runtime surfaces.

It does not establish:

- mandatory interception of every Claude Code or CrewAI operation;
- independent authentication of agents or approvers;
- proof that every recorded runtime observation is true;
- production readiness, regulatory compliance, or human approval;
- permission to modify or deploy third-party repositories.

Autonomous demonstration mode automatically continues through local acceptance gates. Its final evidence must state that human review was not performed and production approval was not granted.

## Strict Nornyx authorization requires human approval evidence

`nornyx.builtin.module.agentic_network_governance` requires
`.nornyx/contracts/runtime_network.nyx` to carry an `approval_record` whose
producer is `type: human` and whose `status` is `pass` before `nornyx check`
succeeds and before `nornyx agentic-network generate/lock` can run.

An autonomous run cannot produce that record. Nornyx enforces this structurally:
`_usable_evidence_records` counts only records with `status: "pass"`, so an
honest record documenting the *absence* of approval correctly fails to satisfy
the requirement. Fabricating one would violate the module's own
`denied_actor_types` (`ai_tool`, `autonomous_agent`, `model`, `generated_output`)
and the `agent_grants_human_approval` denial in `RuntimeGovernance`.

Consequences when no human approval record exists:

- `nornyx check .nornyx/contracts/runtime_network.nyx` fails.
- `scripts/prepare_runtime.py` fails at its first step, so no runtime lock is produced.
- `NornyxActionBoundary` cannot load `nornyx.agentic`. With
  `FORGE_ALLOW_POLICY_FALLBACK=false` (the `docker-compose.yml` default) the
  application **fails closed** and refuses to process any case.
- With the fallback permitted, the demonstration runs and still denies
  high-risk external actions, but every decision is labelled
  `source: deterministic_fallback` rather than `nornyx.agentic`.

The fallback is a cooperative control, not the official Nornyx authorization
path. Do not describe fallback decisions as Nornyx runtime authorization.

## Evaluation instant

Temporal validity is evaluated at `runtime_as_of()`, which defaults to the real
current time and may be pinned with `FORGE_RUNTIME_AS_OF` for reproducible runs.
A pinned value must be timezone-aware; an invalid one raises rather than
reverting to the live clock.

An approval is therefore judged against the moment it is actually exercised. The
seven-day agentic-network approval window is real elapsed time: an approval
issued at *T* stops satisfying `nornyx check` after *T + 7 days*, and the
contract must then be re-approved by a human. Nothing in this repository may
backdate an approval to widen that window.
