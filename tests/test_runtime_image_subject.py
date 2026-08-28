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

def _daemon_reachable() -> bool:
    """Whether a Docker daemon answers RIGHT NOW.

    `shutil.which` alone would answer a different question -- whether the CLI is
    installed -- and a client with no daemon behind it reports every build as a
    failure of whatever was being built.
    """
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(  # noqa: S603, S607
            ["docker", "info"], capture_output=True, text=True
        ).returncode
        == 0
    )


needs_docker = pytest.mark.skipif(
    not _daemon_reachable(),
    reason="requires a running Docker daemon; proved in the container-launch CI job",
)


def _refuse_or_skip(completed) -> None:
    """A failed build is a failure. A vanished daemon is not.

    Collection happens once and the daemon is checked there, so a workstation
    that stops Docker mid-run makes every remaining case fail with an assertion
    about the image -- a governance gate reporting FAIL for a reason that has
    nothing to do with the repository, which is a verdict nobody can act on.

    The distinction is RE-VERIFIED rather than pattern-matched out of the error
    text: the daemon is asked again, and only its absence buys a skip. A build
    that fails while the daemon is answering is a real failure and stays one --
    laundering those would be exactly the false green this suite exists to stop.
    The skip is declared in the census, and CI's container-launch job runs these
    with a daemon guaranteed, where a skip fails that job instead.
    """
    if completed.returncode == 0:
        return
    if not _daemon_reachable():
        pytest.skip(
            "the Docker daemon became unreachable during the run, so the image "
            "was never built; this is unavailability, not a failed property"
        )
    raise AssertionError(completed.stdout[-3000:] + completed.stderr[-3000:])

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
    _refuse_or_skip(completed)


def _probe() -> dict:
    completed = subprocess.run(
        ["docker", "run", "--rm", "-i", IMAGE, "python", "-"],
        input=PROBE,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    _refuse_or_skip(completed)
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
    import sys
    from pathlib import Path

    ROOT = Path(__file__).resolve().parents[1]
    # One parser, shared. This was three verbatim copies of a guard that
    # inspected only the first source argument of each COPY, matched by
    # exact string, and ignored ADD and lowercase -- so seven ways of
    # shipping the signer passed it. See tests/dockerfile_surface.py.
    sys.path.insert(0, str(ROOT / 'tests'))
    from dockerfile_surface import assert_image_excludes  # noqa: PLC0415

    assert_image_excludes('scripts', root=ROOT)



# --------------------------------------------------------------------------
# The unavailability/failure discrimination itself, which needs no daemon.
# --------------------------------------------------------------------------


class _Completed:
    def __init__(self, code: int) -> None:
        self.returncode = code
        self.stdout = "the image is wrong"
        self.stderr = ""


def test_a_build_failure_with_a_live_daemon_is_still_a_failure(monkeypatch):
    """The half that must NOT become a skip.

    An exemption that swallowed real build failures would be strictly worse
    than the flake it was written for: the daemon check is re-run, and a daemon
    that answers means the failure is about the image.
    """
    monkeypatch.setattr(
        "test_runtime_image_subject._daemon_reachable", lambda: True
    )
    with pytest.raises(AssertionError, match="the image is wrong"):
        _refuse_or_skip(_Completed(1))


def test_a_vanished_daemon_is_unavailability_not_a_failed_property(monkeypatch):
    """The half that must. Same failing process, opposite verdict, and the only
    thing that differs is whether a daemon answered when asked again.

    `pytest.skip` raises `Skipped`, which derives from BaseException -- so
    `pytest.raises(Exception)` does not catch it and this test SKIPS itself
    while appearing to assert. Caught by the skip census, which is what it is
    for, but it is worth naming: a test that silently becomes a skip proves
    exactly nothing, which is the defect this whole gate exists to find.
    """
    monkeypatch.setattr(
        "test_runtime_image_subject._daemon_reachable", lambda: False
    )
    with pytest.raises(
        pytest.skip.Exception, match="unavailability, not a failed property"
    ):
        _refuse_or_skip(_Completed(1))


def test_a_successful_build_is_neither(monkeypatch):
    """And success must not consult the daemon at all."""
    monkeypatch.setattr(
        "test_runtime_image_subject._daemon_reachable",
        lambda: pytest.fail("success re-probed the daemon"),
    )
    _refuse_or_skip(_Completed(0))
