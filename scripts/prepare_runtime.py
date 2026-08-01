from __future__ import annotations

import json
from pathlib import Path

from nornyx_forge.nornyx_runtime import prepare_runtime_contract

ROOT = Path(__file__).resolve().parents[1]
results = prepare_runtime_contract(ROOT)
print(json.dumps([item.__dict__ for item in results], indent=2, default=list))
raise SystemExit(0 if results and all(item.passed for item in results) else 2)
