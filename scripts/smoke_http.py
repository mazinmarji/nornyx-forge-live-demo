from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
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
    # FORGE_ROOT, FORGE_ALLOW_POLICY_FALLBACK and FORGE_STRICT_CREWAI were set
    # here and read by nothing: the application derives its root structurally and
    # takes its backends from RuntimeAuthorityConfig. Setting them made this look
    # like it selected a strict configuration when the strict and non-strict runs
    # were materially identical, so they are gone rather than left as decoration
    # a reader would trust.
    #
    # FORGE_SMOKE_STRICT was read here and used nowhere else, so the "strict"
    # and ordinary smoke runs were materially identical. Removing the three env
    # vars above made that visible: the flag had no remaining effect to lose.
    # Strict governance IS exercised, by `nornyx-forge demo --offline
    # --strict-nornyx` and by scripts/prepare_runtime.py -- neither of which is
    # this script.
    # No FORGE_WORKER_MODE: nothing reads it. See app_launcher.
    env = {**os.environ}
    # The server's output must go to a file, not an unread PIPE. CrewAI prints a
    # large flow trace per case; with subprocess.PIPE and no reader the OS pipe
    # buffer fills, the server blocks on write, and every request then times out.
    log = tempfile.NamedTemporaryFile(  # noqa: SIM115 - closed in the finally block
        mode="w+", prefix="forge-smoke-", suffix=".log", delete=False
    )
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
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )

    def _server_output() -> str:
        log.flush()
        return Path(log.name).read_text(encoding="utf-8", errors="replace")[-4000:]

    try:
        # The CrewAI dependency tree can take well over 30s to import on a cold
        # start, so the readiness budget is generous and overridable.
        startup_timeout = float(os.getenv("FORGE_SMOKE_STARTUP_TIMEOUT", "180"))
        deadline = time.monotonic() + startup_timeout
        health: dict[str, object] | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"application exited before startup:\n{_server_output()}"
                )
            try:
                health = json.loads(_request(base + "/api/health", timeout=1))
                break
            except Exception:
                time.sleep(0.2)
        if not health or health.get("status") != "ok":
            raise RuntimeError(
                f"health endpoint did not become ready within {startup_timeout:g}s"
            )

        # Two full CrewAI Flow kickoffs run behind this call on a cold process.
        demo_timeout = float(os.getenv("FORGE_SMOKE_DEMO_TIMEOUT", "600"))
        demo = json.loads(
            _request(base + "/api/demo/run", method="POST", timeout=demo_timeout)
        )
        dashboard = _request(base + "/dashboard", timeout=60).decode("utf-8")
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
        log.close()
        try:
            Path(log.name).unlink(missing_ok=True)
        except OSError:
            # Windows can still hold the handle briefly after terminate().
            pass


if __name__ == "__main__":
    raise SystemExit(main())
