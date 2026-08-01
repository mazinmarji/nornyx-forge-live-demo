from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request(url: str, *, method: str = "GET", timeout: float = 5.0) -> bytes:
    request = urllib.request.Request(url, data=b"" if method == "POST" else None, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def main() -> int:
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    strict = os.getenv("FORGE_SMOKE_STRICT", "false").lower() == "true"
    env = {
        **os.environ,
        "FORGE_ROOT": str(ROOT),
        "FORGE_WORKER_MODE": "deterministic",
        "FORGE_ALLOW_POLICY_FALLBACK": "false" if strict else "true",
        "FORGE_STRICT_CREWAI": "true" if strict else "false",
    }
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "demo_app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 30
        health: dict[str, object] | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                output = process.stdout.read() if process.stdout else ""
                raise RuntimeError(f"application exited before startup:\n{output}")
            try:
                health = json.loads(_request(base + "/api/health", timeout=1))
                break
            except Exception:
                time.sleep(0.2)
        if not health or health.get("status") != "ok":
            raise RuntimeError("health endpoint did not become ready")

        demo = json.loads(_request(base + "/api/demo/run", method="POST", timeout=20))
        dashboard = _request(base + "/dashboard", timeout=5).decode("utf-8")
        checks = {
            "health": health.get("status") == "ok",
            "demo": demo.get("status") == "pass",
            "low_risk": demo.get("low_risk", {}).get("status") == "completed",
            "high_risk": demo.get("high_risk", {}).get("status") == "prevented",
            "dashboard": "Nornyx Forge" in dashboard,
        }
        print(json.dumps({"status": "pass" if all(checks.values()) else "fail", "checks": checks}, indent=2))
        return 0 if all(checks.values()) else 2
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
