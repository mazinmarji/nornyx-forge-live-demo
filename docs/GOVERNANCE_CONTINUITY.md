# Governance continuity and revision boundary

**Status:** architectural clarification and future design constraint. This document does not authorize a hosted control plane, a multi-agent runtime, a managed service, or any new product scope.

## Principle

> **Forge governs revisions; the produced application governs actions; Nornyx defines both; the owner decides.**

Forge's role is to transform confirmed intent into a governed application revision, validate that revision, and bind its lifecycle records to the content that revision was confirmed over. That binding names the governed content -- the capsule's chain tip beside the digest of the confirmed requirements -- and not the artefact the build produced: nothing in the lifecycle digests the generated application, and a binding says what a build was licensed to consume, never what it produced (`docs/requirements/ASSUMPTIONS.md`, A-032). A produced application must continue to operate without a runtime dependency on Forge.

The produced application must carry the governance needed at operation time: the Nornyx contract, the action boundary, human-approval requirements where applicable, and verifiable evidence. Runtime action decisions belong to that application and its Nornyx governance boundary, not to a continuously running Forge service.

## What this describes at the current baseline

No governed produced application exists at this baseline, and none can be produced here: no build provider is eligible on any platform. `PROVIDER_CONFINEMENT` carries no `established` row -- `claude/windows` is `none` and `codex/windows` is `declared` -- and `governed_build_eligibility` fails closed on a declared or absent confinement, so the governed build executes no provider (`docs/requirements/ASSUMPTIONS.md`, A-024, A-033).

Every requirement this document states for the produced application is therefore an architectural constraint on future work, and not a demonstrated runtime property of anything that exists today. The set those requirements range over is currently empty. Nothing here records a measurement of a produced application, and nothing here should be read as evidence that one has ever been built or run.

## Lifecycle continuity

The intended continuity is:

```text
DISCOVER -> CONFIRM -> BUILD -> TEST -> GOVERN -> READY
                                                    |
                                                    v
                                          independent operation
                                                    |
                                                    v
                                        material business change
                                                    |
                                                    v
                                           CHANGE -> RE-GOVERN
                                                    |
                                                    v
                                              new revision
```

The top row names the stages the Experience Contract makes mandatory on any path to READY; the contract declares optional stages between them, and CONFIRM is its human scope gate. `CHANGE -> RE-GOVERN` is a future factory edge, not a claim that this path is implemented today. It means that a material change to business intent, the agent set, authority, tools, policy, or other governed content should return to Forge as a new governed revision rather than turning Forge into the application's live operating control plane.

## Portable governance boundary

A Forge-produced application should remain portable and independently operable. The preferred boundary is:

- governance semantics and authorization are defined by Nornyx;
- the application embeds or consumes the smallest portable governance/action-boundary capability it needs;
- governance artifacts and evidence remain independently verifiable;
- the application does not require `nornyx_forge` at runtime;
- Forge may be re-entered for a new governed revision, but is not an always-on dependency.

Some subject-agnostic mechanisms exercised in Forge may later be candidates for extraction into Nornyx or a portable kernel. That would require a separate architecture and governance decision. This document does not authorize such extraction.

## What remains Forge-only

The following remain factory concerns unless a later decision explicitly says otherwise:

- project capsule and source-revision authority;
- build-provider qualification, and the per-platform confinement an engineering CLI must be shown to be under before it is eligible for a governed build;
- greenfield verification;
- build/test/governance lifecycle state;
- Forge-specific evidence about the generation and acceptance process;
- Windows/basic-user factory runtime and installation mechanics.

## Non-goals

This principle does not make Forge:

- a hosted or commercial runtime control plane;
- a generic multi-agent orchestrator;
- an agent identity provider or registry;
- a gateway or policy-enforcement proxy for deployed businesses;
- a CRM, accounting, email, payment, workflow, memory, or analytics platform;
- a persistent multi-tenant authority store;
- the place where customer business data or credentials must live.

Those functions belong either to the produced application, Nornyx, external platforms, or to a capability that would require its own separate authorization decision.

## Why this boundary exists

The same words can mean different things at build time and operation time. Forge's current authority subject is a software/project revision; its provider qualification governs code-writing tools; its lifecycle ends at READY; and its local control surface is not a fleet-scale business control plane. Reusing those mechanisms directly for an operating business would therefore create false equivalence and unnecessary coupling.

The reusable value is the governance continuity itself: confirmed intent, executable policy, human authority where required, and evidence should remain connected across the build/operate/change lifecycle without making Forge a permanent runtime dependency.
