import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_repository_validator():
    result = subprocess.run([sys.executable, "scripts/validate_repository.py"], cwd=ROOT, check=False)
    assert result.returncode == 0
