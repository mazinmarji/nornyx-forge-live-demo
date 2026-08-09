"""The deployed image must be able to say what it is, from inside itself.

Model B: consequential authority binds the *packaged* authority surface, not the
repository's. Those legitimately differ — the image carries no `scripts/` — so
this must never be inferred from the Dockerfile. A static reading of the build
file proves what someone intended to ship; only running the verifier inside the
built image proves what shipped.

It also guards a packaging assumption the resolver depends on. `resolve_packaged_root`
walks a fixed relationship from the installed package, which holds because the
image installs editable and the package sits at `/app/src/nornyx_forge/`. A
switch to a wheel would move `__file__` into site-packages and silently break
that, while leaving the image otherwise valid — this is the test that would
catch it.

Requires a working Docker daemon, so it is opt-in locally and mandatory in the
container-launch CI job.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap

import pytest

IMAGE = "nornyx-forge-subject-probe:test"

needs_docker = pytest.mark.skipif(
    shutil.which("docker") is None
    or subprocess.run(
        ["docker", "info"], capture_output=True, text=True
    ).returncode
    != 0,
    reason="requires a running Docker daemon; proved in the container-launch CI job",
)

#: Run inside the image. Uses the production bootstrap, not a reimplementation:
#: a probe that computed the subject its own way would prove nothing about what
#: the application does.
PROBE = textwrap.dedent(
    """
    import json
    from pathlib import Path
    from nornyx_forge.governed_subject import RUNTIME_IMAGE_SCOPE, RuntimeAuthorityConfig
    from nornyx_forge.subject_bootstrap import establish_subject, resolve_packaged_root

    resolved = resolve_packaged_root()
    subject = establish_subject(
        resolved,
        scope=RUNTIME_IMAGE_SCOPE,
        config=RuntimeAuthorityConfig("nornyx", "crewai"),
    )
    print(json.dumps({
        "resolved_root": str(resolved),
        "scope_id": subject.scope_id,
        "verified": subject.subject_verified,
        "reason": subject.unavailable_reason,
        "subject_digest": subject.governed_subject_digest,
        "revision_digest": subject.governed_revision_digest,
        "source_commit": subject.source_commit,
        "git_present": Path("/app/.git").exists(),
    }))
    """
)


def _build() -> None:
    completed = subprocess.run(
        ["docker", "build", "-t", IMAGE, "."],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert completed.returncode == 0, completed.stdout[-3000:] + completed.stderr[-3000:]


def _probe() -> dict:
    completed = subprocess.run(
        ["docker", "run", "--rm", "-i", IMAGE, "python", "-"],
        input=PROBE,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


@needs_docker
def test_the_built_image_establishes_its_own_subject():
    """The decisive R1-F proof: run the real verifier inside the real image."""
    _build()
    result = _probe()

    assert result["verified"] is True, result["reason"]
    assert result["scope_id"] == "forge.runtime-image.v1"
    assert result["resolved_root"] == "/app"
    assert result["subject_digest"].startswith("sha256:")
    assert result["revision_digest"].startswith("sha256:")


@needs_docker
def test_the_image_needs_no_git_to_know_what_it_is():
    """Authority is content. Provenance is simply absent here, and that is fine."""
    _build()
    result = _probe()

    assert result["git_present"] is False
    assert result["source_commit"] is None
    # Absent provenance does not weaken the subject.
    assert result["verified"] is True
    assert result["subject_digest"].startswith("sha256:")


@needs_docker
def test_the_packaged_subject_is_not_assumed_equal_to_the_repository_subject():
    """They cover different surfaces, and the image is the one that executes.

    Asserting equality would be claiming the build ships the repository, which
    it does not — `scripts/` is deliberately absent so the issuer-side signing
    utility is outside the runtime trust boundary.
    """
    from pathlib import Path

    from nornyx_forge.governed_subject import (
        REPOSITORY_SCOPE,
        RUNTIME_IMAGE_SCOPE,
        RuntimeAuthorityConfig,
    )
    from nornyx_forge.subject_bootstrap import establish_subject

    _build()
    packaged = _probe()

    here = establish_subject(
        Path(__file__).resolve().parents[1],
        scope=REPOSITORY_SCOPE,
        config=RuntimeAuthorityConfig("nornyx", "crewai"),
    )
    assert packaged["scope_id"] != REPOSITORY_SCOPE.scope_id
    assert packaged["subject_digest"] != here.governed_subject_digest
    assert RUNTIME_IMAGE_SCOPE.scope_id == packaged["scope_id"]


@needs_docker
def test_a_missing_required_contract_in_the_image_refuses():
    """Packaging that drops a governance contract must not verify.

    This is the failure the scope model exists for: a build silently omitting a
    contract would otherwise compute a smaller subject and report itself
    verified, because nothing said what complete meant.
    """
    _build()
    stripped = subprocess.run(
        [
            "docker", "run", "--rm", "-i", IMAGE, "sh", "-c",
            "rm /app/.nornyx/contracts/runtime_network.nyx && python -",
        ],
        input=PROBE,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert stripped.returncode == 0, stripped.stdout + stripped.stderr
    result = json.loads(stripped.stdout.strip().splitlines()[-1])

    assert result["verified"] is False
    assert "SUBJECT_SCOPE_INCOMPLETE" in (result["reason"] or "")
    assert result["subject_digest"] == ""


def test_the_dockerfile_still_omits_the_issuer_tooling():
    """Runs everywhere: the trust-boundary assumption the runtime scope encodes.

    `scripts/` holds the signing utility. It is outside the runtime scope
    *because* it is outside the image; if the build started copying it, the
    scope would be describing a surface that no longer matches what ships.
    """
    from pathlib import Path

    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(
        encoding="utf-8"
    )
    copied = [
        line.split()[1]
        for line in dockerfile.splitlines()
        if line.startswith("COPY ") and len(line.split()) > 2
    ]
    assert "scripts" not in copied, (
        "the image now ships scripts/; the runtime scope and the trust boundary "
        "both need revisiting"
    )
