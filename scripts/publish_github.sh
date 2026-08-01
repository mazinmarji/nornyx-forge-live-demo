#!/usr/bin/env bash
set -euo pipefail

repo="${1:-mazinmarji/nornyx-forge-live-demo}"
if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required." >&2
  exit 127
fi
gh auth status >/dev/null
gh repo create "$repo" \
  --public \
  --source . \
  --remote origin \
  --push \
  --description "One-prompt Nornyx-governed BRD-to-running CrewAI application demonstration"
