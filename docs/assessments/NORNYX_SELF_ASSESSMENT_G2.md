# Governance Evidence Assessment — Nornyx Sponsor Self-Assessment

**Status:** G2 sponsor self-assessment under Governance Evidence Assessment v0.1  
**Conflict of interest:** sponsor-owned subject; no preferential treatment is permitted  
**Methodology:** `docs/GOVERNANCE_EVIDENCE_ASSESSMENT.md` v0.1  
**Assessment date:** 2026-08-21  
**Assessor:** project-sponsor self-assessment, prepared from public repository/API evidence  
**Repository:** `mazinmarji/nornyx`  
**Target commit:** `8729b5bdf1740e656c2cd0c3a8a0a99454ed973a`  
**Observation surfaces:** O1 repository content; O2 GitHub branch/platform state available to the assessor; O3 GitHub Actions execution metadata  

## Scope and limits

This assessment measures governance evidence of the **Nornyx repository itself**. It does not award credit merely because Nornyx software can model or assess a governance property for other repositories.

The assessment does not establish production safety, regulatory compliance, independent runtime assurance, or that hidden platform controls exist when they are not observable. Platform observations are dated 2026-08-21.

A passing finding applies only to the named property and evidence surface. No aggregate score, grade, ranking, or whole-repository certification is produced.

## Summary

| Dimension | Result | Confidence | Main reason |
|---|---|---:|---|
| D1 — Governance source of truth | **PASS** | HIGH | Repository authority and role guidance are explicit and versioned; public positioning and documentation authority are named. |
| D2 — Change and approval control | **PARTIAL** | HIGH | `main` is protected and a required status check is visible, but required human-review enforcement is not established by the available platform evidence and no `.github/CODEOWNERS` file is present. |
| D3 — Revision binding and drift detection | **PASS** | HIGH | CI checks an exact candidate SHA; Nornyx has deterministic lock/drift semantics and explicit revision-bound assurance rules. |
| D4 — Agent/tool authority and capability control | **PARTIAL** | HIGH | `AGENTS.md` defines agent roles and review duties, but repository-specific agent authority is mainly guidance; no independent machine-enforced repository capability boundary was established for arbitrary AI-assisted changes. |
| D5 — Evidence integrity and provenance | **PARTIAL** | HIGH | Structured revision-bound evidence semantics are strong, but Nornyx explicitly does not authenticate runtime-event producers, verify `signature_ref`, or prove supplied runtime truth. |
| D6 — CI/CD and supply-chain governance | **PARTIAL** | HIGH | Broad exact-candidate CI and wheel checks exist and a recent PR candidate completed CI successfully; the visible branch requirement names `adapter-conformance`, not the entire CI surface. |
| D7 — Enforcement-claim honesty and coverage | **PASS** | HIGH | Public docs explicitly separate design-time governance, cooperative adapter enforcement, and independent assurance; bypass and evidence limitations are named. |

**Non-PASS findings:** D2, D4, D5, D6. This satisfies G2's requirement for at least three honest non-PASS findings on a sponsor-owned subject.

---

## D1 — Governance source of truth

**Result:** PASS  
**Confidence:** HIGH  
**Evidence class / observability:** E2 / O1

### Evidence

- `AGENTS.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` states that current documentation authority and public positioning are defined by `docs/README.md` and `docs/48_NORNYX_POSITIONING.md`, and defines Architect, Builder, Reviewer, and Security Agent duties.
- `README.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` describes Nornyx's governed-source model, generated artifacts, locks, drift checks, and external enforcement boundary.
- Repository governance/architecture decisions are versioned as ADRs and roadmap/positioning records rather than being left only in prose outside version control.

### Reasoning

For the assessed repository, authoritative documentation and role guidance are discoverable and versioned. The repository also distinguishes product semantics, positioning, ADR decisions, and derived/generated artifacts rather than presenting every document as equally authoritative.

### Limits

This PASS does not mean the repository itself is governed by one root `.nyx` file, nor does it mean every historical document is current authority. The finding is limited to explicit, versioned discoverability of the repository's governance/documentation authority.

---

## D2 — Change and approval control

**Result:** PARTIAL  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E4 / O1 + O2

### Evidence

- GitHub branch observation for `main` on 2026-08-21 reports `protected: true` and a required status-check context `adapter-conformance`.
- `.github/workflows/ci.yml@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` runs on pull requests to `main`, verifies the exact candidate identity, tests the package and adapter surfaces, builds distributions, and checks installed wheels.
- `AGENTS.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` assigns Reviewer Agent duties and says meaningful patches should report whether approval is required.
- `.github/CODEOWNERS` was not present at the assessed commit.

### Reasoning

There is real platform-level change control: the main branch is protected and at least one status check is required. The repository also has explicit review expectations. However, the available observation surface does not establish that human reviews are platform-required for every consequential change, and there is no CODEOWNERS rule encoding review ownership. That is sufficient for PARTIAL, not PASS.

### Improvement that would change the result

A future assessment could move this toward PASS if platform evidence demonstrates required human review/approval policy for the relevant changes and the ownership/review boundary is explicit and reproducible.

---

## D3 — Revision binding and drift detection

**Result:** PASS  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E3 / O1 + O3

### Evidence

- `.github/workflows/ci.yml@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` checks out the exact PR candidate, verifies `git rev-parse HEAD` equals the PR head SHA, and builds/tests distributions from that candidate.
- `README.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` documents content-addressed lock/revision binding and `nornyx drift`, which exits non-zero when generated artifacts diverge.
- `docs/decisions/ADR-0040-governance-assurance-tiers.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` requires exact subject-revision binding and distinguishes lock/content binding from runtime truth.
- PR #95 candidate `fa73d72731435ed41c58f92dcf9a35a2ed43be08`, which was merged into the assessed `main` commit, has GitHub Actions CI run `32189377444` with conclusion `success`.

### Reasoning

Exact-candidate identity is enforced in CI and the product/repository semantics make revision and drift boundaries explicit. The latest merged candidate was also observed to complete the declared CI successfully.

### Limits

The observed CI execution is attached to the PR head that became part of the target merge, not a separately observed post-merge run on `8729b5...`. This does not weaken the exact-candidate property but is recorded as an observation limitation.

---

## D4 — Agent/tool authority and capability control

**Result:** PARTIAL  
**Confidence:** HIGH  
**Evidence class / observability:** E1 + E2 / O1

### Evidence

- `AGENTS.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` defines Architect, Builder, Reviewer, and Security Agent responsibilities and tells reviewers to reject changes that weaken policy, evidence, or approval semantics.
- `README.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` documents Nornyx's agent identity/capability/authorization model and external enforcement boundary.
- `docs/decisions/ADR-0040-governance-assurance-tiers.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` explicitly says cooperative adapters cover only declared wrapped surfaces and can be bypassed by avoiding those surfaces.

### Reasoning

Agent responsibilities are explicit and the software contains sophisticated authority semantics, but the assessment is of repository governance, not feature breadth. The available evidence does not establish a mandatory repository-level machine-enforced capability boundary for every AI-assisted change or tool invocation. Guidance and cooperative integration are real controls but do not justify a repository-wide PASS.

### Improvement that would change the result

Demonstrable, repository-scoped deny paths tied to the actual development execution surface, with explicit coverage and bypass boundaries, could support a stronger result.

---

## D5 — Evidence integrity and provenance

**Result:** PARTIAL  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E3 / O1

### Evidence

- `README.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` states that supplied runtime evidence is validated against the governed revision and explicitly says Nornyx does not independently attest that supplied runtime events actually occurred.
- `docs/decisions/ADR-0040-governance-assurance-tiers.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` records that runtime events bind `network_id`, `contract_digest`, `network_lock_digest`, and `subject_revision`, but Nornyx does not authenticate the producer, verify `signature_ref`, prove payload digests correspond to actual runtime payloads, or establish protected capture.
- The same ADR prohibits treating `external_runtime` metadata or `signature_ref` alone as independent assurance.

### Reasoning

Nornyx demonstrates strong integrity and revision-binding semantics and unusually explicit provenance limits. It cannot receive PASS for independent evidence provenance because its own canonical assurance record says producer authentication, protected capture, and cryptographic verification are not provided by Nornyx alone.

### Improvement that would change the result

An independently controlled evidence path with authenticated producer identity, verified attestation/signatures, and protected capture for the assessed claim would be needed for a stronger finding.

---

## D6 — CI/CD and supply-chain governance

**Result:** PARTIAL  
**Confidence:** HIGH  
**Evidence class / observability:** E2 + E3 + E4 / O1 + O2 + O3

### Evidence

- `.github/workflows/ci.yml@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` tests Python 3.10–3.13, verifies exact candidate identity, runs tests, checks diff hygiene, builds distributions, runs Twine checks, performs installed-wheel no-network smoke tests, and exercises adapter conformance/native framework paths.
- GitHub reports `main` is protected and requires `adapter-conformance`.
- PR #95 head `fa73d72731435ed41c58f92dcf9a35a2ed43be08` completed CI run `32189377444` successfully.

### Reasoning

The declared and demonstrated CI surface is substantial. The available platform evidence, however, exposes only `adapter-conformance` as a required branch status context, while the workflow contains many additional jobs. Without evidence that the full governance/security CI surface is required before merge, the platform-enforcement portion remains incomplete.

### Improvement that would change the result

Platform evidence showing the intended critical CI checks are required by branch/ruleset policy at the assessed revision would support PASS.

---

## D7 — Enforcement-claim honesty and coverage

**Result:** PASS  
**Confidence:** HIGH  
**Evidence class / observability:** E2 / O1

### Evidence

- `README.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` says external PEPs/runtimes/platform controls own enforcement and execution and that Nornyx validates supplied evidence rather than independently attesting runtime truth.
- `docs/decisions/ADR-0040-governance-assurance-tiers.md@8729b5bdf1740e656c2cd0c3a8a0a99454ed973a` distinguishes Tier 1 design-time governance, Tier 2 cooperative wrapped-surface enforcement, and Tier 3 independent assurance not supplied by Nornyx alone.
- The ADR explicitly states that bypassing a cooperative adapter bypasses enforcement and may leave no Nornyx-generated trace, and prohibits whole-application or independent-enforcement claims from a wrapped subset.

### Reasoning

The repository does not merely advertise governance controls; it publishes concrete prohibited claims and coverage limits. The wording matches the evidence model and explicitly prevents cooperative control from being described as independent enforcement.

---

## G2 sponsor-self-assessment conclusion

Nornyx shows strong revision discipline and claim-boundary honesty, but this methodology intentionally does not convert product sophistication into a whole-repository governance PASS. The main gaps found are repository-change approval evidence, repository-level machine-enforced agent authority, independent evidence provenance, and proof that the complete CI governance surface is platform-required.

These findings are not a request to expand the Nornyx roadmap. Under the governing Arsoryn strategy, any remediation is separately evidence-gated and may be unnecessary if the repository's current operating boundary is deliberate.