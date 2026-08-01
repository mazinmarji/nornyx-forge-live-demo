"""Coverage for the BRD-005 criterion `docker compose up --build`.

The static checks always run and need neither Docker nor a network. The live
launch is opt-in via FORGE_DOCKER_TESTS=1 because building the image downloads
packages, which BRD-004 forbids for the default offline test run.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
DOCKERFILE = ROOT / "Dockerfile"


def _docker_cli() -> str | None:
    return shutil.which("docker")


def test_compose_declares_the_documented_application_port():
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    service = compose["services"]["app"]
    assert "8000:8000" in service["ports"], service["ports"]
    assert service["build"] == "."


def test_compose_defaults_to_fail_closed_governance():
    """The declared compose default must not silently permit the fallback."""
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    environment = compose["services"]["app"]["environment"]
    assert environment["FORGE_ALLOW_POLICY_FALLBACK"] == "false"


def test_dockerfile_copies_the_governance_contracts():
    """The image must carry the contracts, or the runtime cannot authorize."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY .nornyx" in text
    assert "demo_app.main:app" in text
    assert "8000" in text


def test_dockerignore_excludes_the_virtualenv():
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert ".venv/" in ignored


@pytest.mark.skipif(_docker_cli() is None, reason="docker CLI is not installed")
def test_compose_file_is_valid_for_docker():
    completed = subprocess.run(
        [_docker_cli(), "compose", "-f", str(COMPOSE), "config"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.skipif(
    os.getenv("FORGE_DOCKER_TESTS") != "1" or _docker_cli() is None,
    reason="set FORGE_DOCKER_TESTS=1 with Docker running to build and launch the image",
)
def test_compose_up_build_starts_the_application():
    docker = _docker_cli()
    project = "nornyx-forge-test"
    up = subprocess.run(
        [docker, "compose", "-p", project, "up", "--build", "-d"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    try:
        assert up.returncode == 0, up.stderr
        deadline = time.monotonic() + 300
        payload: dict[str, object] | None = None
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:8000/api/health", timeout=5
                ) as response:
                    payload = json.loads(response.read())
                break
            except Exception:
                time.sleep(3)
        assert payload is not None, "health endpoint never became ready"
        assert payload["status"] == "ok"
        assert payload["human_review"] == "not_performed"
        assert payload["production_approval"] == "not_granted"
    finally:
        subprocess.run(
            [docker, "compose", "-p", project, "down", "-v"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
