# Governance Evidence Assessment

**Status:** Experimental methodology v0.1  
**Scope:** Repository-visible technical governance evidence  
**Implementation status:** Methodology only; no assessment engine is provided by this document

## Purpose

Governance claims in AI and agentic software are difficult to compare because repositories use different frameworks, policy systems, CI controls, identity models and terminology. This methodology provides a technology-neutral way to describe **what governance properties are evidenced, how strong the available evidence is, and what remains unverified**.

It does not measure whether a repository uses Nornyx. Nornyx receives no preferential treatment. A property may be satisfied by Nornyx, OPA, Cedar, platform-native controls, custom mechanisms or another implementation when the required evidence exists.

The methodology is designed to make uncertainty explicit. Absence of visible evidence is not automatically proof that a control does not exist, and a committed policy artifact is not automatically proof that the control is enforced at runtime.

## What this assessment is — and is not

This methodology assesses repository-visible technical governance evidence for a defined repository revision and declared observation surface.

It may examine properties such as:

- governance source of truth;
- change and approval control;
- revision binding and drift detection;
- agent/tool authority and capability controls;
- evidence integrity and provenance;
- CI/CD and supply-chain governance;
- enforcement claims, deny-path evidence and coverage boundaries.

It does **not** establish:

- organizational AI-governance maturity;
- regulatory compliance;
- certification;
- production safety;
- legal sufficiency;
- actual production topology from source alone;
- hidden IAM, network, cloud or platform controls that are not observable;
- that recorded runtime events actually occurred merely because records exist;
- that a repository is "secure" or "well governed" as a whole.

Assessments must be framed as evidence findings, not compliance or certification verdicts.

## Assessment unit

Every assessment must identify:

- repository;
- exact target commit SHA;
- methodology version;
- assessment date;
- assessor;
- observation surfaces used;
- known access limitations.

A finding applies only to the property and surface actually assessed. A PASS in one dimension or surface does not upgrade the repository as a whole.

## Result states

The allowed result states are:

| State | Meaning |
|---|---|
| **PASS** | The required property is supported by evidence at or above the minimum evidence class defined for that property, within the declared observation scope. |
| **PARTIAL** | Some required elements are evidenced, but one or more required elements or enforcement linkages are incomplete. |
| **FAIL** | Evidence demonstrates that the declared/required property is violated or that a claimed control does not operate as stated within the assessed scope. |
| **NOT PRESENT** | No implementation of the property is present within an observation surface where presence can reasonably be determined. |
| **NOT ASSESSED** | The property was intentionally not evaluated. |
| **UNVERIFIABLE** | Available evidence cannot establish the property or its absence. |
| **OUT OF SCOPE** | The property does not apply to the declared assessment scope. |

No overall numeric score, letter grade, badge or ranking is part of methodology v0.1.

## Evidence classes

Every PASS or PARTIAL finding must cite the evidence used and classify its strength.

### E1 — narrative claim

Examples:

- README statement;
- policy prose;
- architecture narrative;
- marketing or feature claim.

E1 is useful context but is **never sufficient by itself for PASS**.

### E2 — declared repository configuration

Examples:

- CODEOWNERS;
- CI workflow configuration;
- policy/configuration files;
- schemas;
- permission declarations;
- versioned governance contracts;
- checked-in rulesets or generated control artifacts.

E2 proves declared configuration exists at the assessed revision. It does not by itself prove the control runs or cannot be bypassed.

### E3 — demonstrated CI/enforcement evidence

Examples:

- tests exercising allow and deny paths;
- CI checks that fail on prohibited state;
- execution artifacts demonstrating a control operated;
- reproducible validation output bound to the assessed revision.

E3 is stronger than declaration because the relevant behavior is demonstrated, but the producer may still be cooperative or part of the governed system.

### E4 — platform-enforced evidence

Examples where access permits verification:

- branch-protection/ruleset APIs;
- required-review settings;
- protected environments;
- repository/platform controls external to the checked-in code.

E4 applies only when the platform state itself can be verified. A workflow file that intends to require a check is not E4 unless the platform requirement is also evidenced.

### E5 — cryptographic or independently attested evidence

Examples:

- signed provenance;
- verified attestations;
- independently controlled evidence records;
- cryptographically bound producer identity where the verification path is available.

Metadata that merely claims to be independent is not E5.

## Observability classes

Findings must identify what can be observed.

### O1 — repository-content observable

Evidence is present in the repository at the target SHA.

### O2 — platform/API observable

Evidence requires repository-host/platform API state such as branch protection, rulesets, required checks or environment controls.

### O3 — runtime-evidence observable

Evidence requires runtime or CI execution records supplied for assessment.

### O4 — attestation-only

The property requires authenticated/independent evidence or a protected runtime path that cannot be inferred from repository content.

### O5 — unavailable / unverifiable

The required observation surface is unavailable to the assessor.

A control must not be marked NOT PRESENT merely because the required observation surface is unavailable. Use UNVERIFIABLE where absence cannot be established.

## Confidence

PASS and PARTIAL findings must include one confidence label:

- **HIGH** — evidence directly establishes the property within the declared scope and the observation surface is complete enough for the claim.
- **MEDIUM** — evidence is strong but one relevant assumption or observation limitation remains.
- **LOW** — evidence supports only a bounded interpretation and substantial uncertainty remains.

Confidence does not replace evidence class. An E2 artifact can be high-confidence evidence that a declaration exists while still being insufficient to prove runtime enforcement.

## Assessment dimensions

Methodology v0.1 uses seven dimensions. Each assessment may mark a dimension OUT OF SCOPE when justified.

### D1 — governance source of truth

Questions include:

- Is governance explicit and discoverable?
- Is the source versioned?
- Are authoritative and derived governance artifacts distinguishable?
- Can conflicting governance sources be detected or bounded?

A README claim alone cannot PASS this dimension.

### D2 — change and approval control

Questions include:

- Are consequential changes subject to defined review/approval requirements?
- Is approver authority represented or externally verifiable where claimed?
- Is approval bound to the subject being approved rather than generic prose?
- Can absence of required approval be distinguished from approval success?

Repository evidence cannot establish enterprise authority that exists only outside the available observation surface; use UNVERIFIABLE where appropriate.

### D3 — revision binding and drift detection

Questions include:

- Can governance artifacts be tied to an exact revision?
- Are generated/derived controls checked for drift?
- Can an approval or evidence package be distinguished when it belongs to a different revision?
- Is the binding deterministic/reproducible?

A version string without integrity/revision linkage is not sufficient by itself.

### D4 — agent/tool authority and capability control

Questions include:

- Are agent/tool capabilities explicit?
- Are denied/unknown/revoked states distinguishable?
- Are delegation/handoff boundaries explicit where applicable?
- Are identity claims separated from authenticated identity where relevant?
- Are denied actions demonstrated on the claimed governed surface?

This dimension must not assume that an agent framework's advertised capabilities are the same as the governance controls applied to the assessed repository itself.

### D5 — evidence integrity and provenance

Questions include:

- Are governance decisions/actions accompanied by structured evidence?
- Is evidence bound to the relevant revision or decision context?
- Can missing evidence be represented honestly rather than silently treated as success?
- Is producer provenance explicit?
- Are replay/order/integrity constraints defined where relevant?

Producer-supplied evidence is not automatically independent evidence.

### D6 — CI/CD and supply-chain governance

Questions include:

- Are required governance/security checks represented and, where observable, platform-required?
- Are dependencies/build artifacts subject to provenance/integrity controls?
- Are established mechanisms such as OpenSSF Scorecard or SLSA applicable and referenced rather than reimplemented without reason?

This methodology does not attempt to replace dedicated supply-chain-security tools.

### D7 — enforcement-claim honesty and coverage

Questions include:

- Does the repository claim that controls "enforce", "prevent" or "block" actions?
- Is a deny path actually demonstrated?
- Are covered, unsupported and unwrapped surfaces distinguished?
- Can the governed process bypass the mechanism?
- Does the evidence strength match the wording of the claim?

A cooperative wrapper may provide real enforcement on declared surfaces while remaining bypassable elsewhere. The assessment must state that boundary rather than converting it into a system-wide claim.

## Assurance-tier relationship

Where useful, assessments may reference the existing Nornyx assurance-tier vocabulary as a claim-boundary aid:

- **Tier 1 — design-time governance:** validated/locked/approved declarations; no runtime enforcement claim.
- **Tier 2 — cooperative runtime enforcement:** the governed execution path invokes an enforcing component on declared surfaces; bypass remains possible by avoiding that path.
- **Tier 3 — independent enforcement and attestation:** enforcement and evidence production are outside the governed subject's bypass/control boundary.

A tier applies only to a specific claim/surface with supporting evidence. Repository inspection alone cannot establish Tier 3. Tier-3 claims require evidence of independent enforcement, authenticated producer identity, protected capture/attestation and coverage beyond what source inspection can prove.

## Anti-gaming and anti-governance-theater rules

1. **Narrative claims never earn PASS alone.**
2. **Presence is not enforcement.** A committed policy/configuration artifact without demonstrated linkage to the claimed control is capped at PARTIAL where enforcement is required.
3. **Generated artifacts require source/binding context.** Generated files do not prove which source governed them unless the linkage is evidenced.
4. **Tests must exercise the claimed property.** A generic green test suite is not evidence of a specific deny path.
5. **Unknown external controls are not failures.** Use UNVERIFIABLE when the necessary observation surface is unavailable.
6. **Sponsor-owned projects receive no exception.** Nornyx and Forge are assessed by the same rules.
7. **Benign gaming is acceptable.** If a project adds real controls and evidence to improve an assessment result, that is improvement, not benchmark abuse.

## Reproducibility requirements

A published assessment must include enough information for another assessor to reproduce the conclusion:

- methodology version;
- target repository and SHA;
- evidence citation using path@SHA or platform evidence identifier;
- evidence class;
- observability class;
- result state;
- confidence for PASS/PARTIAL;
- concise reasoning;
- explicit assumptions/limitations.

Where platform/API evidence is transient, record the observation date and stable identifier or captured evidence where publication rights permit.

## Named third-party assessment policy

Methodology v0.1 is intended to minimize reputational and fairness risk.

Before publishing a named assessment of an external repository:

1. Notify maintainers using a reasonable public contact route.
2. Provide a **7 calendar-day right-of-reply window**.
3. Provide the intended findings or enough detail for factual correction.
4. State that non-response does not imply agreement.
5. Incorporate factual corrections supported by repository/platform evidence and record the correction.
6. Record material methodological disputes rather than silently rewriting history.
7. If a dispute reveals that the methodology cannot distinguish a material implemented control from unavailable evidence, withhold or de-name the affected result until the method is corrected.
8. Do not extend engagement indefinitely for abusive or non-substantive responses.

If a named assessment cannot be supported confidently within these rules, publish the methodological lesson without naming the repository.

## Corrections log

Published studies using this methodology should maintain a corrections section containing:

- date;
- affected assessment;
- original finding;
- corrected finding;
- evidence supporting the correction;
- whether the methodology changed.

Corrections are evidence that the methodology is being calibrated; they must not be hidden merely to preserve a prior result.

## Comparative-study rules

When multiple repositories are assessed together:

- do not produce an overall ranking;
- do not claim a winner;
- compare property-by-property evidence only;
- label sponsor-owned repositories as conflicts of interest;
- link sponsor-owned rows to their independently published self-assessments;
- include at least one substantial non-Nornyx implementation capable of receiving genuine PASS findings;
- avoid selecting small/unmanaged projects merely to create weak comparison rows;
- distinguish governance of the repository itself from governance capabilities the repository's software may provide to users.

## Assessment record template

```text
ASSESSMENT
Methodology: Governance Evidence Assessment v0.1
Repository: <owner/repo>
Target SHA: <sha>
Date: <YYYY-MM-DD>
Assessor: <name>
Observation surfaces: <O1/O2/O3/...>

FINDING
Dimension: <D1..D7>
Property: <specific property>
Result: PASS | PARTIAL | FAIL | NOT PRESENT | NOT ASSESSED | UNVERIFIABLE | OUT OF SCOPE
Evidence: <path@SHA / platform evidence identifier>
Evidence class: E1 | E2 | E3 | E4 | E5
Observability: O1 | O2 | O3 | O4 | O5
Confidence: HIGH | MEDIUM | LOW   # required for PASS/PARTIAL
Reasoning: <bounded explanation>
Assumptions/limits: <explicit limitations>
```

## Current limitation

This document defines an experimental methodology only. Nornyx Forge does not currently provide a general governance-assessment engine, hosted scanning service, certification program, public ranking or automated remediation system.

The next allowed validation step is sponsor self-assessment before any named external comparative study.
