# Forge Skill boundary

## Purpose

The Claude Code Skill is the preferred human-facing entry point to Nornyx Forge.
It exists to make Forge easy to invoke from the engineering environment where
repository understanding, architecture work, implementation, repair, and review
already happen.

The Skill is not the governance authority.

A useful shorthand is:

> Claude Code is the engineer. Forge is the governed transformation and
> conformance system around the engineer. Nornyx supplies the authority and
> governance semantics underneath it.

## What the Skill may do

The Skill may:

- inspect a BRD and repository;
- identify requirements and consequential actions;
- propose architecture and implementation changes;
- generate or update candidate Nornyx contracts;
- create tests and hostile-path probes;
- invoke bounded builder and reviewer subagents;
- run deterministic Forge/Nornyx gates;
- repair defects while preserving the measured gate property;
- collect and report mechanically produced evidence;
- launch the governed demonstration after the required controls pass.

These activities are engineering and orchestration.

## What the Skill may not do

The Skill may not create authority by assertion. In particular it may not:

- manufacture or infer human approval;
- treat a model review as external independent confirmation;
- convert prose such as "approved", "safe", or "production-ready" into
  authoritative state;
- waive, skip, weaken, relabel, or grandfather a failing deterministic control;
- substitute its own interpretation for a Nornyx or Forge validation result;
- mark generated evidence authentic merely because Claude generated it;
- bypass the action boundary for consequential effects;
- claim a broader property than the invoked control mechanically measures.

If Claude disagrees with a deterministic result, the deterministic result
controls. The disagreement is diagnostic information, not authority.

## Authority layers

### 1. Engineering reasoning

Claude Code and its subagents analyze, design, implement, inspect, and repair.
Their output is proposed work and bounded review evidence.

### 2. Forge conformance machinery

Forge scripts, validators, tests, evidence-binding mechanisms, and action-boundary
controls mechanically evaluate explicitly declared properties. A green result
means only that the measured predicate passed.

### 3. Nornyx governance semantics

Nornyx contracts and decision semantics define identities, capabilities,
authority, approvals, architecture constraints, runtime governance, and related
evidence rules used by Forge.

### 4. Human or organizational authority

Where an accountable human approval, independent review, certification, or other
external authority is required, only the corresponding real authority can
satisfy it. Model output cannot synthesize it.

## Why a Skill does not replace Forge

A sophisticated prompt or Skill can reproduce much of Forge's visible workflow:
repository analysis, code generation, architecture work, test generation,
contract authoring, and repair loops.

It cannot by itself provide the same assurance because the model would otherwise
be both builder and attester. Once a Skill includes deterministic validators,
content-addressed evidence, approval checks, replay controls, and runtime action
boundaries, it has not eliminated Forge; it has made Forge available through a
Skill interface.

The preferred architecture is therefore:

```text
Claude Code
    |
    v
Nornyx Forge Skill
    |
    +--> reasoning / design / implementation / repair
    |
    v
Forge deterministic conformance and evidence
    |
    v
Nornyx governance semantics / decisions
    |
    v
Action boundary / enforcement integration
    |
    v
Consequential effect
```

## Claim discipline

The Skill and documentation must preserve the following invariant:

> A gate may claim only the exact property it mechanically measures.

Examples:

- a model inspector pass is not human review;
- an in-session review is not external independent confirmation;
- successful contract generation is not successful contract validation;
- successful validation is not human approval;
- architecture approval is not approval for an exact consequential runtime
  action;
- documentation prose cannot create authoritative assurance state.

## User experience

After cloning the repository and starting Claude Code with the local plugin, the
preferred invocation is:

```text
/nornyx-forge:build-app BRD.md
```

`ONE_PROMPT.md` remains a bootstrap convenience for users starting outside an
existing clone. It should lead into the same Skill and deterministic machinery,
not define a second assurance path.

## Product direction

Forge should become increasingly easy to consume as a Claude Code Skill while
keeping its valuable state outside model discretion. Repository transformation
and code generation will continue to commoditize; deterministic governance,
evidence binding, conformance, approval semantics, and runtime enforcement are
the non-delegable core.
