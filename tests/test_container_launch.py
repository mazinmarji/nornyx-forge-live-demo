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


def _run(*command: str, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    """Run a Docker command, decoding its output as what it actually emits.

    `text=True` on its own decodes with the locale encoding. Docker's BuildKit
    progress output is UTF-8, so on a Windows console (cp1252) the reader thread
    dies on the first box-drawing glyph and the whole launch looks like a
    failure of the application rather than of how the test read its output.
    """
    return subprocess.run(
        list(command),
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def test_compose_declares_the_documented_application_port():
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    service = compose["services"]["app"]
    assert "8000:8000" in service["ports"], service["ports"]
    assert service["build"] == "."


def test_the_compose_default_does_not_claim_a_governance_mode():
    """The governance mode is not in the deployment, and must not appear to be.

    This test used to assert `FORGE_ALLOW_POLICY_FALLBACK == "false"` and was
    named for the property it believed that proved -- a fail-closed default.
    The variable had been retired; nothing read it; the effective default was
    the permissive backend. So the suite was requiring the presence of a key
    that controlled nothing, and reporting a posture the application did not
    have. The false claim was encoded as required behaviour, which is the
    failure mode that makes a test worse than no test.

    What is asserted now is the real arrangement: the mode lives in
    `RuntimeAuthorityConfig.policy_backend`, bound into the governed subject, so
    the deployment cannot select it at all. Changing it is a code change that
    moves the subject digest -- which is what makes the mode something an
    approval can cover.
    """
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    environment = compose["services"]["app"]["environment"]

    assert "FORGE_ALLOW_POLICY_FALLBACK" not in environment
    assert "FORGE_STRICT_CREWAI" not in environment

    from nornyx_forge.governed_subject import RuntimeAuthorityConfig  # noqa: PLC0415

    #: The mode is part of authority identity, not of the environment.
    assert "policy_backend" in RuntimeAuthorityConfig.__dataclass_fields__
    subject_fields = RuntimeAuthorityConfig(
        policy_backend="nornyx", execution_backend="sequential"
    )
    permissive = RuntimeAuthorityConfig(
        policy_backend="deterministic_demo", execution_backend="sequential"
    )
    assert subject_fields != permissive, (
        "the two governance modes are indistinguishable, so an approval of one "
        "would cover the other"
    )


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
    completed = _run(str(_docker_cli()), "compose", "-f", str(COMPOSE), "config")
    assert completed.returncode == 0, completed.stderr


@pytest.mark.skipif(
    os.getenv("FORGE_DOCKER_TESTS") != "1" or _docker_cli() is None,
    reason="set FORGE_DOCKER_TESTS=1 with Docker running to build and launch the image",
)
def test_compose_up_build_starts_the_application():
    docker = _docker_cli()
    project = "nornyx-forge-test"
    up = _run(
        str(docker), "compose", "-p", project, "up", "--build", "-d", timeout=1800
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

        # The packaged image ships no approver trust store, so it must say that
        # consequential authority is unavailable rather than merely unexercised.
        # This is the deployment-behaviour check unit tests cannot give: the real
        # image, started for real, reporting what it can actually do.
        assert payload["trusted_approvers_loaded"] is False
        assert payload["action_approval_authentication"] == "unavailable"
        assert payload["consequential_authority"] == "unavailable"

        # And it must not disclose where trust would come from.
        body = json.dumps(payload)
        for leak in ("trusted_approvers.json", "/root", "/app/.nornyx", "public_key"):
            assert leak not in body, f"health disclosed {leak}"
    finally:
        _run(str(docker), "compose", "-p", project, "down", "-v")
