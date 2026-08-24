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
roles. A reviewer key signs for content inspection; an approver key signs
for effect release. One key satisfying both would let whoever authorizes a
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
argument a caller must name at the construction site.

`test_no_production_source_constructs_a_test_context` fails if any file under
`src/` CALLS it -- a call node whose callee is named `for_test`, wherever the
receiver comes from.

This used to read "a repository test fails if `RuntimeContext.for_test(`
appears anywhere under `src/`", which is a claim about TEXT and is false: the
string appears at `src/nornyx_forge/nornyx_runtime.py:3070`, inside a
docstring explaining why production must not use the seam, and the guard
passes. An auditor checking the sentence as written finds a hit in shipped
source and concludes the control is broken.

The guard is AST-based on purpose, and stronger than the sentence it replaces
on the axis that matters -- it catches an aliased receiver, which a substring
scan for `RuntimeContext.for_test(` would miss -- and weaker only on
mentions, which are not uses. Its own comment says so: a substring "cannot
tell a CALL from a docstring that names the seam while explaining why
production must not use it".

## Governed revision

**THE REVISION MODEL DESCRIBED HERE NO LONGER EXISTS.** This section set out
`actual_revision`, `declared_revision` and `revision_verified`, and two
refusal codes, `GOVERNED_REVISION_MISMATCH` and
`GOVERNED_REVISION_UNVERIFIED`. None of them is defined anywhere in `src/`
or `scripts/` -- `nornyx_runtime.py` records that the model is "gone, not
deprecated in place", and `tests/test_subject_provenance.py` BANS a
re-introduction. Authority is content-digest bound: `governed_subject_digest`
and `governed_revision_digest`. Git provenance is observed by
`subject_observer.observe_source_commit` and reaches no decision.

The container caveat that followed is retired with it: there is no
`revision_verified` to be false inside an image.

An approval is therefore judged against the moment it is actually exercised. The
seven-day agentic-network approval window is real elapsed time: an approval
issued at *T* stops satisfying `nornyx check` after *T + 7 days*, and the
contract must then be re-approved by a human. Nothing in this repository may
backdate an approval to widen that window.

## The bounded claim surface

Machine assurance here verifies a **closed, explicitly declared claim
surface**: the governance contracts and the structured evidence records whose
content is bound by hash. Arbitrary natural-language prose is **not**
mechanically certified, and cannot create, upgrade, or satisfy assurance,
inspection, approval, or production-readiness state.

This is a deliberate boundary, not an unfinished control. A lint sweep does
read the documents in this repository for unearned governance sentences, and
it catches many of them, but it is defence in depth and nothing here may
describe it as a certification of English. The measured limit is recorded with
its specimen in `tests/test_claim_surface_boundary.py`: the sentence *cleared
for production deployment by the CAB* is not recognised by that grammar and is
not going to be, because recognising it means enumerating the nouns that
denote governance authorities -- CAB, board, committee, council, release
authority -- and the sentence after that one would be *the release authority
gave the green light*. A grammar that chases English never closes.

What the same module measures instead is that missing such a sentence costs
nothing that matters: the residual is inserted into a governed document,
committed so the content digest genuinely sees it, and the authoritative
verdict is required to be identical. A false statement placed on the
STRUCTURED surface is refused in the same module, and the mechanism that
refuses it is named -- the content hash binding a record to what it describes,
not the approval check, which the forgery alone would have satisfied.

Prose remains subject to human editorial review. That is the correct authority
for free text, and stating it here is what keeps this control's claim equal to
what it measures.

### Which control refuses a forged structured claim

Not the approval-absence diagnostic. That distinction is measured, and it is
the opposite of what a reader would assume.

Falsifying `architecture_approval_record.json` so that it claims an approval
makes `approval_blocked` go **false** for the architecture contract, because
the forgery removes the very absence that diagnostic reports. The
approval-presence logic alone would therefore accept the forgery. What refuses
it is `EVIDENCE_ARTIFACT_HASH_MISMATCH` -- the content hash binding a record
to the content it describes.

So the evidence binding is the control that carries this property, and the
approval-absence diagnostic must never be described as preventing structured
approval forgery. `test_a_false_claim_on_the_structured_surface_is_refused`
asserts both directions, so this note cannot go stale quietly: it requires the
absence check to stop firing under forgery AND the hash mismatch to appear.
