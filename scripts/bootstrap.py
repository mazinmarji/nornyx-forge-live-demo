from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], *, check: bool = True) -> int:
    print("+", " ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, check=False)
    if check and result.returncode:
        raise SystemExit(result.returncode)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--autonomous", action="store_true")
    parser.add_argument("--worker-mode", choices=("deterministic", "claude-code", "in-session"), default="deterministic")
    parser.add_argument("--skip-install", action="store_true")
    parser.add_argument("--no-launch", action="store_true")
    args = parser.parse_args()

    run([sys.executable, "scripts/environment_check.py"])
    venv = ROOT / ".venv"
    if not args.skip_install:
        if not venv.exists():
            run([sys.executable, "-m", "venv", str(venv)])
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
        run([str(python), "-m", "pip", "install", "-e", ".[demo,dev]"])
    else:
        python = Path(sys.executable)

    run([str(python), "scripts/validate_repository.py"])
    run([str(python), "-m", "pytest", "-q"])
    run([str(python), "-m", "nornyx_forge.cli", "build", "--worker-mode", args.worker_mode])
    demo_command = [str(python), "-m", "nornyx_forge.cli", "demo", "--offline"]
    if not args.skip_install:
        demo_command.append("--strict-nornyx")
    run(demo_command)

    if args.no_launch:
        return 0
    if shutil.which("docker"):
        run(["docker", "compose", "up", "--build", "-d"])
        print("Application: http://localhost:8000")
        print("Dashboard:   http://localhost:8000/dashboard")
        print("API docs:    http://localhost:8000/docs")
        return 0
    print("Docker is unavailable. Launch manually with:")
    print(f"  {python} -m uvicorn demo_app.main:app --host 0.0.0.0 --port 8000")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
