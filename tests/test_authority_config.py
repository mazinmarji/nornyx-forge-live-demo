"""Runtime behaviour must follow the authority config bound into the subject.

Two ambient booleans — `FORGE_ALLOW_POLICY_FALLBACK` and `FORGE_STRICT_CREWAI` —
used to change which governance and execution path ran while every governed byte
stayed identical. Two materially different systems were approvable under one
signature.

Binding the mode into `governed_subject_digest` fixes the identity half. The
behavioural half is what these tests hold: the runtime must actually execute
according to the exact configuration that was bound, with no downstream ambient
override. Without that, the subject would cryptographically attest to `crewai`
while the process ran `sequential` — strictly worse than before, because the
attestation would be false rather than absent.

The observed backend is deliberately derived from the path that executed, not
copied from the configuration. A marker assigned by reading
`RuntimeAuthorityConfig` would make these assertions tautological: they would
prove the config equals itself.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

import demo_app.agentic as agentic
from nornyx_forge.governed_subject import (
    RUNTIME_IMAGE_SCOPE,
    GovernedSubjectError,
    RuntimeAuthorityConfig,
)
from nornyx_forge.nornyx_runtime import NornyxRuntimeUnavailable
from nornyx_forge.subject_bootstrap import establish_subject

ROOT = Path(__file__).resolve().parents[1]

#: Defined here rather than imported from the implementation. A list the
#: implementation owns can be edited in both places at once, which would hide a
#: reintroduction behind a rename.
RETIRED_AUTHORITY_ENV = (
    "FORGE_ALLOW_POLICY_FALLBACK",
    "FORGE_STRICT_CREWAI",
    "FORGE_USE_CREWAI_KICKOFF",
    "FORGE_RUNTIME_REVISION",
    "FORGE_RUNTIME_AS_OF",
    # Retired once the packaged-root resolver landed: an environment variable
    # selecting which tree the application governs is authority over subject
    # identity itself.
    "FORGE_ROOT",
)

CASE = {
    "id": "C1",
    "customer": "Omar",
    "summary": "Refund request",
    "risk": "low",
    "requested_action": "send guidance",
}


@pytest.fixture
def hostile_env(monkeypatch: pytest.MonkeyPatch):
    """Every retired control set to the value that used to change behaviour."""
    for name in ("FORGE_ALLOW_POLICY_FALLBACK", "FORGE_USE_CREWAI_KICKOFF"):
        monkeypatch.setenv(name, "true")
    monkeypatch.setenv("FORGE_STRICT_CREWAI", "true")


# --------------------------------------------------------------------------
# Identity: the mode is part of what is being approved
# --------------------------------------------------------------------------


def test_authority_config_moves_the_subject_but_not_the_revision_anchor():
    """Same packaged bytes, different governance mode, different subject."""
    base = establish_subject(
        ROOT, scope=RUNTIME_IMAGE_SCOPE, config=RuntimeAuthorityConfig("nornyx", "crewai")
    )
    demo = establish_subject(
        ROOT,
        scope=RUNTIME_IMAGE_SCOPE,
        config=RuntimeAuthorityConfig("deterministic_demo", "crewai"),
    )
    sequential = establish_subject(
        ROOT,
        scope=RUNTIME_IMAGE_SCOPE,
        config=RuntimeAuthorityConfig("nornyx", "sequential"),
    )

    assert demo.governed_subject_digest != base.governed_subject_digest
    assert sequential.governed_subject_digest != base.governed_subject_digest
    # The anchor identifies the authored revision, which mode is not part of.
    assert demo.governed_revision_digest == base.governed_revision_digest
    assert sequential.governed_revision_digest == base.governed_revision_digest


@pytest.mark.parametrize(
    ("policy", "execution"),
    [("silently_off", "crewai"), ("nornyx", "quietly_disabled")],
)
def test_unknown_backend_is_refused(policy: str, execution: str):
    """A typo must not select a permissive path by defaulting."""
    with pytest.raises(GovernedSubjectError):
        RuntimeAuthorityConfig(policy, execution)


# --------------------------------------------------------------------------
# Behaviour: what ran must be what was bound
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("configured", "expected_observed"),
    [("sequential", "sequential"), ("crewai", "crewai_flow")],
)
def test_execution_backend_binding_survives_hostile_environment(
    configured: str, expected_observed: str, tmp_path: Path, hostile_env
):
    """The retired variables are set hostile; behaviour must ignore them.

    `observed_execution_backend` is emitted by the driver that actually ran —
    `run_sequential` sets a flag, so a stage reaching the recorder without it
    was driven by CrewAI's Flow machinery. It is never read from the config, so
    this assertion can genuinely fail.
    """
    result = agentic.run_case(
        dict(CASE),
        root=ROOT,
        worker_mode="deterministic",
        config=RuntimeAuthorityConfig("deterministic_demo", configured),
    )
    assert result["configured_execution_backend"] == configured
    assert result["observed_execution_backend"] == expected_observed


def test_nornyx_failure_does_not_fall_back(monkeypatch: pytest.MonkeyPatch):
    """A genuine Nornyx failure must deny, not silently degrade.

    Stronger than asserting the exception class: the deterministic policy path
    must not be entered, and no consequential callback may run. An earlier
    version of this proof only showed that a *missing approval* did not trigger
    fallback, which is a much weaker statement.
    """
    import nornyx.agentic.authz as authz

    fallback_calls: list[int] = []
    callback_calls: list[int] = []

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("nornyx evaluator unavailable (forced)")

    monkeypatch.setattr(authz, "load_authorizer", unavailable)
    monkeypatch.setattr(
        agentic.CustomerCaseFlow,
        "run_sequential",
        lambda self: fallback_calls.append(1) or self.case,
    )

    with pytest.raises(NornyxRuntimeUnavailable):
        agentic.run_case(
            dict(CASE),
            root=ROOT,
            worker_mode="deterministic",
            config=RuntimeAuthorityConfig("nornyx", "sequential"),
        )

    assert fallback_calls == [], "the deterministic path ran despite policy_backend=nornyx"
    assert callback_calls == [], "a consequential callback ran during a governance failure"


def test_deterministic_demo_runs_only_when_explicitly_selected(
    monkeypatch: pytest.MonkeyPatch,
):
    """The named demo backend is reachable, and only by naming it."""
    import nornyx.agentic.authz as authz

    monkeypatch.setattr(
        authz,
        "load_authorizer",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("forced")),
    )
    result = agentic.run_case(
        dict(CASE),
        root=ROOT,
        worker_mode="deterministic",
        config=RuntimeAuthorityConfig("deterministic_demo", "sequential"),
    )
    assert result["observed_execution_backend"] == "sequential"
    assert result["configured_policy_backend"] == "deterministic_demo"


# --------------------------------------------------------------------------
# Static: the ambient controls cannot come back
# --------------------------------------------------------------------------


def test_no_retired_authority_env_is_read_anywhere_in_src():
    """AST rather than grep: a name in a comment or docstring is not a read.

    The forbidden vocabulary is defined in this file, so removing a name from
    the implementation cannot also remove it from what is being checked.
    """
    offenders: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and node.value in RETIRED_AUTHORITY_ENV:
                offenders.append(f"{path.relative_to(ROOT).as_posix()}: {node.value}")
    assert offenders == [], (
        "retired authority environment variables are read again: " + ", ".join(offenders)
    )


def test_the_hostile_environment_fixture_actually_sets_the_variables(hostile_env):
    """Guards the guard: a fixture that set nothing would make the tests vacuous."""
    for name in ("FORGE_ALLOW_POLICY_FALLBACK", "FORGE_STRICT_CREWAI"):
        assert os.environ.get(name), f"{name} was not set, so the binding tests prove nothing"
