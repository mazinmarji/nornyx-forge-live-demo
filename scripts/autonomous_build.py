from __future__ import annotations

import subprocess
import sys

raise SystemExit(subprocess.call([sys.executable, "scripts/bootstrap.py", "--autonomous", "--worker-mode", "claude-code"]))
