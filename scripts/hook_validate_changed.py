from __future__ import annotations

import subprocess
import sys

raise SystemExit(subprocess.call([sys.executable, "scripts/validate_repository.py", "--quick"]))
