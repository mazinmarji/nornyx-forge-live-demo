"""Generate and verify the runtime network lock.

The lock is only reachable once a human approval exists, so it is an
approval-bound operation and is gated on the same proof as every other one: that
the governed tree still holds the content the approval covers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from nornyx_forge.nornyx_runtime import prepare_runtime_contract

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "scripts"))
from refresh_governance_evidence import require_approval_matches_head  # noqa: E402

# Raises before the lock is written when an approval exists and the tree has
# drifted from it. Returns None, changing nothing, when no approval exists.
require_approval_matches_head()

results = prepare_runtime_contract(ROOT)
print(json.dumps([item.__dict__ for item in results], indent=2, default=list))
raise SystemExit(0 if results and all(item.passed for item in results) else 2)
