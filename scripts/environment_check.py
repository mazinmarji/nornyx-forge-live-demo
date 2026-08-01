from __future__ import annotations

import json
import shutil
import sys

required = {"git": shutil.which("git"), "python": sys.executable}
optional = {"docker": shutil.which("docker"), "claude": shutil.which("claude"), "nornyx": shutil.which("nornyx")}
print(json.dumps({"required": required, "optional": optional}, indent=2))
if not all(required.values()):
    raise SystemExit(2)
