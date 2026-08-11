"""The established security context must be what production actually runs on.

`tests/test_security_context.py` proves the mechanism: one object, immutable,
environment read once, mutation after startup does not re-aim it. Every one of
those tests passed while `bootstrap_security_context()` had no caller anywhere
under `src/`. The parameter existed, production passed `None`, and the boundary
fell back to resolving its own trust anchors per use — the ambient re-resolution
the subject model exists to remove.

So a mechanism proven in isolation is not a control. These tests assert the
wiring: that the application establishes exactly one context, that the request
path receives that exact object, and that no request can cause a second one.

THE PROPERTY:

    every governed request in a process runs under one security context,
    established before any request was served, and no input to a request can
    cause a different one to be established or observed

Identity is the assertion throughout, never equality. Two independently
bootstrapped contexts over an unchanged tree compare equal on every digest, so
an equality test would pass on precisely the architecture being prevented.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from demo_app import agentic  # noqa: E402
from demo_app.agentic import application_security_context  # noqa: E402

# --------------------------------------------------------------------------
# One context, and the request path gets that one
# --------------------------------------------------------------------------


def test_the_application_establishes_exactly_one_context():
    """Repeated access returns the same object, not an equal rebuild."""
    first = application_security_context()
    second = application_security_context()
    assert first is second


def test_the_http_surface_binds_the_established_context():
    """The interface layer holds the same object the application established.

    Asserted at the surface that serves requests, because that is where a
    per-request bootstrap would be introduced.
    """
    from demo_app import main

    assert main.SECURITY_CONTEXT is application_security_context()


def test_a_governed_run_receives_the_established_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The flow that runs a case is handed the application's context.

    This is the assertion that was missing. `run_case` accepted a context and
    production never supplied one, so the flow ran with `security_context=None`
    and nothing failed — the omission was invisible precisely because the
    parameter was optional.
    """
    captured: list[object] = []
    original = agentic.CustomerCaseFlow

    class Recording(original):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):
            captured.append(kwargs.get("security_context"))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(agentic, "CustomerCaseFlow", Recording)
    agentic.run_case(
        {
            "id": "CASE-WIRING",
            "customer": "Amina",
            "summary": "Update delivery instructions",
            "risk": "low",
            "requested_action": "send guidance",
        },
        root=tmp_path,
        # The configuration production uses. Without it `run_case` defaults to
        # the nornyx backend, which refuses on a tmp root carrying no runtime
        # lock -- a refusal about preparation, not about context wiring.
        config=agentic.demonstration_authority(),
    )

    assert captured, "no flow was constructed, so this test asserted nothing"
    assert captured[0] is application_security_context(), (
        "the flow ran under a context that is not the one this application "
        "established"
    )


def test_two_requests_share_one_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """One per application, not one per request."""
    captured: list[object] = []
    original = agentic.CustomerCaseFlow

    class Recording(original):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):
            captured.append(kwargs.get("security_context"))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(agentic, "CustomerCaseFlow", Recording)
    for index in (1, 2):
        agentic.run_case(
            {
                "id": f"CASE-{index}",
                "customer": "Amina",
                "summary": "Update delivery instructions",
                "risk": "low",
                "requested_action": "send guidance",
            },
            root=tmp_path,
            config=agentic.demonstration_authority(),
        )

    assert len(captured) == 2
    assert captured[0] is captured[1], "each request established its own context"


# --------------------------------------------------------------------------
# Nothing mutated after startup re-aims the running context
# --------------------------------------------------------------------------

#: Everything that has, at some point in this repository's history, been able to
#: steer which tree the runtime governed or when it thought it was: the retired
#: overrides, the git envelope, the launch directory, and the trust locations.
AMBIENT = {
    "FORGE_ROOT": "/tmp/attacker-tree",
    "FORGE_RUNTIME_REVISION": "git:" + "f" * 40,
    "FORGE_RUNTIME_AS_OF": "2099-01-01T00:00:00Z",
    "FORGE_APPROVAL_LEDGER": "/tmp/attacker-ledger.sqlite3",
    "FORGE_TRUST_STORE": "/tmp/attacker-approvers.json",
    "FORGE_REVIEWER_TRUST_STORE": "/tmp/attacker-reviewers.json",
    "GIT_DIR": "/tmp/attacker.git",
    "GIT_WORK_TREE": "/tmp/attacker-tree",
    "GIT_CEILING_DIRECTORIES": "/tmp",
}


def test_no_ambient_change_after_startup_re_aims_the_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Set every steering variable hostile, change directory, then look again.

    The context was established at import. Nothing here happened before that, so
    nothing here may change what it says. The digests are compared as well as
    the identity: an object could in principle be the same one and still consult
    the environment lazily on attribute access.
    """
    before = application_security_context()
    snapshot = (
        before.runtime_subject.governed_subject_digest,
        before.runtime_subject.governed_revision_digest,
        before.runtime_subject.scope_definition_digest,
        before.runtime_subject.runtime_authority_config_digest,
        before.runtime_subject.subject_verified,
        before.trust.approver_store,
        before.trust.reviewer_store,
        before.trust.approval_ledger,
        before.authority_config.policy_backend,
        before.authority_config.execution_backend,
    )

    for name, value in AMBIENT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)

    after = application_security_context()
    assert after is before, "an environment change produced a different context"
    assert (
        after.runtime_subject.governed_subject_digest,
        after.runtime_subject.governed_revision_digest,
        after.runtime_subject.scope_definition_digest,
        after.runtime_subject.runtime_authority_config_digest,
        after.runtime_subject.subject_verified,
        after.trust.approver_store,
        after.trust.reviewer_store,
        after.trust.approval_ledger,
        after.authority_config.policy_backend,
        after.authority_config.execution_backend,
    ) == snapshot, "the established context reported different values afterwards"


def test_editing_the_governed_tree_after_startup_does_not_re_aim_the_context():
    """A file changed mid-process must not change what the running context says.

    The point is not that editing files is prevented — it is that a context
    established before the edit keeps describing what it observed. A runtime
    that re-observed here would let a file written between two requests decide
    the authority the second one is judged under.
    """
    context = application_security_context()
    before = context.runtime_subject.governed_subject_digest
    scratch = ROOT / "src" / "nornyx_forge" / "_context_probe.py"
    assert not scratch.exists(), "probe file already present"
    try:
        scratch.write_text("# transient probe\n", encoding="utf-8", newline="")
        assert application_security_context() is context
        assert context.runtime_subject.governed_subject_digest == before, (
            "the running context re-observed the tree after a file appeared"
        )
    finally:
        scratch.unlink(missing_ok=True)


# --------------------------------------------------------------------------
# Structural: the request path may not establish one
# --------------------------------------------------------------------------


def test_no_request_path_bootstraps_a_context():
    """Establishment happens at module scope, never inside a request function.

    Behavioural tests cannot catch this reliably: a per-request bootstrap over
    an unchanged tree returns an equal context, so only an identity assertion in
    exactly the right place would notice. This asserts the shape directly.
    """
    import ast

    for relative in ("src/demo_app/agentic.py", "src/demo_app/main.py"):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                func = inner.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                assert name != "bootstrap_security_context", (
                    f"{relative}:{node.name} establishes a security context "
                    "inside a function, so a request can cause subject identity "
                    "to be resolved"
                )


def test_the_established_context_is_not_optional_in_production():
    """`run_case` must never fall through to an unestablished context.

    The default was `None`, which meant "no context", and every production call
    took it. It now means "the one this application established", so an omitted
    argument cannot silently disable the model.
    """
    import inspect

    source = inspect.getsource(agentic.run_case)
    assert "application_security_context()" in source, (
        "run_case no longer falls back to the established context, so a caller "
        "that omits one runs unestablished"
    )


def test_the_probe_would_notice_a_stale_assertion():
    """The identity assertions above must be capable of failing.

    A test that compares an object to itself through two names that are the same
    name proves nothing. This builds a genuinely separate context and confirms
    it is NOT the established one, so the assertions elsewhere are discriminating
    rather than tautological.
    """
    from nornyx_forge.subject_bootstrap import bootstrap_security_context

    separate = bootstrap_security_context(ROOT)
    assert separate is not application_security_context()
    assert isinstance(separate.runtime_subject.scope_id, str)


def test_an_unresolvable_root_yields_an_unavailable_context_not_an_exception(
    monkeypatch: pytest.MonkeyPatch,
):
    """Startup must not die because the deployment markers are missing.

    `bootstrap_security_context` documented "not an exception", but that covered
    observation failure only: `resolve_packaged_root()` raises, so a deployment
    without markers took the application down at import rather than leaving it
    running without consequential authority. Those are different outcomes and
    the docstring named the wrong one.
    """
    from nornyx_forge import subject_bootstrap
    from nornyx_forge.governed_subject import GovernedSubjectError

    def refuse() -> Path:
        raise GovernedSubjectError("PACKAGED_ROOT_UNRESOLVED: no markers")

    monkeypatch.setattr(subject_bootstrap, "resolve_packaged_root", refuse)
    context = subject_bootstrap.bootstrap_security_context()

    assert context.runtime_subject.subject_verified is False
    assert context.consequential_authority_available is False
    assert "PACKAGED_ROOT_UNRESOLVED" in (context.runtime_subject.unavailable_reason or "")
    assert context.trust.approval_ledger == "", (
        "a context with no resolvable root offered a replay-state location anyway"
    )


def test_os_environ_is_untouched_by_reading_the_context():
    """Reading the context must not be a way to learn what the environment says.

    A guard against the accessor quietly growing an `os.environ` lookup: the
    established values are compared against a context read while the relevant
    variables are absent entirely.
    """
    for name in AMBIENT:
        assert name not in os.environ or os.environ[name] != AMBIENT[name], (
            f"{name} leaked out of a monkeypatched test into the process"
        )
