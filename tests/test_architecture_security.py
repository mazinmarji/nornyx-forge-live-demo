import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_architecture_gate():
    assert subprocess.run([sys.executable, "scripts/check_architecture.py"], cwd=ROOT).returncode == 0


def test_security_gate():
    assert subprocess.run([sys.executable, "scripts/check_security.py"], cwd=ROOT).returncode == 0
