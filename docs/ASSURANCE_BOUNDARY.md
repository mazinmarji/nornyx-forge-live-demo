# Assurance boundary

This repository demonstrates cooperative governance over declared software-development and runtime surfaces.

It does not establish:

- mandatory interception of every Claude Code or CrewAI operation;
- authentication of the *agents* themselves — an inspector's key attests that a
  trusted reviewer signed a verdict, not that any particular model or process
  produced it;
- any claim about where the trust stores came from: both the approver store and
  the reviewer store are supplied by the operator, and this repository verifies
  signatures against them without establishing how the keys inside were vetted;
- proof that every recorded runtime observation is true;
- production readiness, regulatory compliance, or human approval;
- permission to modify or deploy third-party repositories.

Autonomous demonstration mode automatically continues through local acceptance gates. Its final evidence must state that human review was not performed and production approval was not granted.

## What an "independent inspection" is allowed to mean

`assurance_state: independently_inspected` is derived, never read. It requires
all three inspector roles — test, architecture, security — each covered by an
Ed25519 attestation that verifies against `FORGE_REVIEWER_TRUST_STORE`, each
signed by a *distinct* reviewer, and each naming the current
`inspection_subject_digest` inside the signature.

Independence is computed from authenticated identity: a reviewer whose identity
equals the builder's is refused with `REVIEWER_IS_THE_BUILDER`. An earlier
version read a `builder_self_approval: false` field out of the attestation
itself, which meant the builder certified their own independence in a file
anyone could write; that field no longer decides anything.

Two consequences worth stating plainly:

- With no reviewer trust store present, nothing authenticates and the state is
  `not_independently_inspected`. That is this repository's current position.
- `integrity_state` and `assurance_state` are separate. An intact evidence set
  describing the content that is here now is a different claim from a completed
  independent inspection, and a missing inspection does not make the evidence
  set compromised.

Reviewer keys are not approver keys: separate stores, separate schemas, separate
roles. A reviewer signs "I inspected this content"; an approver signs "this
effect may be released". One key satisfying both would let whoever authorizes a
payment also certify that the code releasing it had been independently reviewed.
Signing lives in `scripts/`, which the runtime image never copies — the image
carries verification material only.

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
- `NornyxActionBoundary` cannot load `nornyx.agentic`. Whether the
  application then **fails closed** or falls back is decided by
  `RuntimeAuthorityConfig.policy_backend`, not by any environment variable:
  `"nornyx"` refuses, `"deterministic_demo"` permits the fallback. The mode is
  bound into the governed subject, so the two are different things to approve.
- This paragraph previously attributed that behaviour to
  `FORGE_ALLOW_POLICY_FALLBACK=false` "the `docker-compose.yml` default". That
  variable was retired and nothing read it, so the sentence described a
  fail-closed deployment that did not exist -- and the effective default is
  `deterministic_demo`, the permissive one. Recorded rather than quietly
  corrected, because a document that has been wrong once about which control is
  load-bearing should say so.
- With the fallback permitted, the demonstration runs and still denies
  high-risk external actions, but every decision is labelled
  `source: deterministic_fallback` rather than `nornyx.agentic`.

The fallback is a cooperative control, not the official Nornyx authorization
path. Do not describe fallback decisions as Nornyx runtime authorization.

## Evaluation instant

Temporal validity is evaluated at `runtime_as_of()`, which returns the real
current time. There is **no environment override**. `FORGE_RUNTIME_AS_OF` used
to exist and was removed: an independent review proved it revived an expired
approval and backdated the ledger record of its consumption. An environment
variable is ambient authority — anything in the process can set it, nothing
declares that it did, and the resulting evidence is indistinguishable from an
honest run.

Determinism for tests comes from `RuntimeContext.for_test(root, at=...)`, an
argument a caller must name at the construction site. A repository test fails if
`RuntimeContext.for_test(` appears anywhere under `src/`.

## Governed revision

Three facts are kept separate and never collapsed into one value:

| | |
|---|---|
| `actual_revision` | what git says is checked out, or `None` if it cannot say |
| `declared_revision` | what the contract claims to govern |
| `revision_verified` | whether those were compared and agreed |

`FORGE_RUNTIME_REVISION` also used to exist and was also removed: it re-aimed an
approval issued for one revision onto another.

Behaviour splits three ways, and the two refusals are deliberately distinct
because their remedies are:

| State | Consequential release |
|---|---|
| verified, revisions agree | may proceed |
| verified, revisions disagree | `GOVERNED_REVISION_MISMATCH` |
| revision cannot be derived (no git, as in a container) | `GOVERNED_REVISION_UNVERIFIED` |

An unverifiable revision does **not** stop the application starting or a
low-risk demonstration running; neither borrows authority from it. It blocks
revision-bound consequential authority, and nothing wider. Nornyx still
evaluates capability and trust-zone crossing independently and may refuse for
its own reasons.

Neither refusal consumes the approval — the tree being unconfirmable is not a
reason to destroy a human's grant.

**Known limitation.** Inside a built container there is no `.git`, so
`revision_verified` is `false` and revision-bound consequential authority is
unavailable there. Turning that into `true` requires image build provenance
anchored on a canonical governed-content digest, with the git SHA as provenance
rather than as the integrity primitive. That is not implemented.

An approval is therefore judged against the moment it is actually exercised. The
seven-day agentic-network approval window is real elapsed time: an approval
issued at *T* stops satisfying `nornyx check` after *T + 7 days*, and the
contract must then be re-approved by a human. Nothing in this repository may
backdate an approval to widen that window.
