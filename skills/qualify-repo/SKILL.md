---
name: qualify-repo
description: Qualify one public or local repository before Nornyx Forge modifies it.
argument-hint: "<repository URL or path> [BRD path]"
allowed-tools: Read, Glob, Grep, Bash, WebSearch
---

# Repository qualification

Evaluate business fit, architecture fit, delivery readiness, Nornyx harness compatibility, agentic runtime fit, security posture, license, and adaptation effort.

Output one verdict: GO, CONDITIONAL_GO, REBASE_RECOMMENDED, NO_GO, or INSUFFICIENT_EVIDENCE. Hard legal/security stops override weighted scores.
