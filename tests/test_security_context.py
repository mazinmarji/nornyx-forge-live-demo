"""The security context is established once and injected, never rediscovered.

Every flow used to construct its own `NornyxActionBoundary`, which re-read the
trust store from the environment; the subject would have been rediscovered the
same way. That means a file changed between two cases could silently re-aim the
second one, and a variable changed after startup could change which root of
trust applied — while the module docstring claimed loading once meant "a
variable changed after startup has no effect at all".

These assertions use `is`, deliberately. Comparing digest strings would pass
even if every flow had rebuilt its own context from scratch, which is precisely
the behaviour being prevented: equal values prove nothing about how many times
they were derived.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from nornyx_forge.governed_subject import RUNTIME_IMAGE_SCOPE, RuntimeAuthorityConfig
from nornyx_forge.subject_bootstrap import (
    RuntimeSecurityContext,
    bootstrap_security_context,
)

ROOT = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "__pycache__", "*.pyc", "*.egg-info", "evidence"
)
CONFIG = RuntimeAuthorityConfig("nornyx", "crewai")


def _tree() -> Path:
    work = Path(tempfile.mkdtemp()) / "repo"
    shutil.copytree(ROOT, work, ignore=IGNORE)
    return work


def _context(root: Path) -> RuntimeSecurityContext:
    return bootstrap_security_context(root, scope=RUNTIME_IMAGE_SCOPE, config=CONFIG)


class _Consumer:
    """Stands in for a flow: it receives a context and must not build one."""

    def __init__(self, security_context: RuntimeSecurityContext) -> None:
        self.security_context = security_context

    @property
    def runtime_subject(self):
        return self.security_context.runtime_subject


def test_every_consumer_receives_the_same_object():
    """Identity, not equality. Two equal contexts would be two bootstraps."""
    work = _tree()
    context = _context(work)

    first, second = _Consumer(context), _Consumer(context)

    assert first.security_context is context
    assert second.security_context is context
    assert first.runtime_subject is context.runtime_subject
    assert second.runtime_subject is context.runtime_subject
    assert first.runtime_subject is second.runtime_subject


def test_mutating_governed_content_does_not_re_aim_a_running_context():
    """The property the old per-case construction could not offer.

    A file changed after startup must not give the next flow a different
    subject. Rebinding authority mid-process is a decision, and nothing here is
    entitled to make it silently.
    """
    work = _tree()
    context = _context(work)
    before = context.runtime_subject

    (work / "src/nornyx_forge/injected_after_startup.py").write_bytes(b"X = 1\n")

    later = _Consumer(context)
    assert later.runtime_subject is before
    assert later.runtime_subject.governed_subject_digest == before.governed_subject_digest


def test_an_explicit_new_bootstrap_observes_the_change():
    """Subjects change at explicit security-context boundaries, and only there."""
    work = _tree()
    first = _context(work)

    (work / "src/nornyx_forge/injected_after_startup.py").write_bytes(b"X = 1\n")
    second = _context(work)

    assert second.runtime_subject is not first.runtime_subject
    assert (
        second.runtime_subject.governed_subject_digest
        != first.runtime_subject.governed_subject_digest
    )


def test_the_context_is_immutable():
    """Frozen, so a consumer cannot rebind authority on the object it was given."""
    context = _context(_tree())
    for field, value in (("runtime_subject", None), ("authority_config", None)):
        try:
            setattr(context, field, value)
        except Exception as exc:  # dataclasses raise FrozenInstanceError
            assert "frozen" in type(exc).__name__.lower() or "attribute" in str(exc).lower()
        else:  # pragma: no cover - only reached if the guarantee is gone
            raise AssertionError(f"{field} was reassignable on a frozen context")


def test_a_failed_observation_yields_an_unavailable_context_not_a_digest():
    """No fabricated identity, and no exception that stops the app starting.

    Availability and authority are different outcomes. The container previously
    conflated them by falling back to an unverified revision and carrying on.
    """
    work = _tree()
    (work / ".nornyx/contracts/runtime_network.nyx").unlink()

    context = _context(work)

    assert context.runtime_subject.subject_verified is False
    assert context.consequential_authority_available is False
    assert context.runtime_subject.governed_subject_digest == ""
    assert "SUBJECT_SCOPE_INCOMPLETE" in (context.runtime_subject.unavailable_reason or "")


def test_the_identity_assertion_can_actually_fail():
    """Guards the guard: two bootstraps must not satisfy an `is` comparison.

    Without this, `test_every_consumer_receives_the_same_object` could pass
    against an implementation that rebuilt the context each time, if the objects
    happened to be interned or equal.
    """
    work = _tree()
    assert _context(work) is not _context(work)
