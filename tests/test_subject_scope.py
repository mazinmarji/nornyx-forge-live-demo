"""What `subject_verified=True` is allowed to mean.

Not "the observer hashed whatever happened to exist". That is the same defect as
an architecture gate that checks whatever happens to be declared: omission
becomes the cheapest way to pass. A container whose build silently dropped a
contract would compute a smaller subject and report itself verified, because
nothing said what "complete" was.

So the scope is a code-owned, versioned domain value, and verification means:
the complete declared authority surface was present, canonical, observable, and
hashed — with nothing authority-capable left outside it.

Two directions, both enforced:

    completeness   every required root/file present, or SUBJECT_SCOPE_INCOMPLETE
    closure        nothing authority-capable outside it, or SUBJECT_SCOPE_ESCAPE

Every case asserts an exact structured code. A boolean collapsing "digest moved"
and "observation refused" would pass for either, which is how a refusal comes to
wear a success's clothes.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from nornyx_forge.governed_subject import (
    RUNTIME_IMAGE_SCOPE,
    RuntimeAuthorityConfig,
    SubjectScope,
)
from nornyx_forge.subject_bootstrap import establish_subject

ROOT = Path(__file__).resolve().parents[1]
IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "__pycache__", "*.pyc", "*.egg-info", "evidence"
)
CONFIG = RuntimeAuthorityConfig("nornyx", "crewai")


def _tree() -> Path:
    work = Path(tempfile.mkdtemp()) / "repo"
    shutil.copytree(ROOT, work, ignore=IGNORE)
    return work


def _subject(root: Path, scope: SubjectScope = RUNTIME_IMAGE_SCOPE):
    return establish_subject(root, scope=scope, config=CONFIG)


def _baseline() -> str:
    subject = _subject(_tree())
    assert subject.subject_verified, subject.unavailable_reason
    return subject.governed_subject_digest


# --------------------------------------------------------------------------
# Completeness: what is declared must be there
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "remove"),
    [
        ("required contract", ".nornyx/contracts/runtime_network.nyx"),
        ("required package root", "src/demo_app"),
    ],
)
def test_missing_declared_content_refuses_rather_than_shrinking(label: str, remove: str):
    work = _tree()
    target = work / remove
    shutil.rmtree(target) if target.is_dir() else target.unlink()

    subject = _subject(work)
    assert subject.subject_verified is False, label
    assert "SUBJECT_SCOPE_INCOMPLETE" in (subject.unavailable_reason or ""), label
    # No fabricated identity for content that could not be described.
    assert subject.governed_subject_digest == ""


# --------------------------------------------------------------------------
# Closure: nothing authority-capable may sit outside the subject
# --------------------------------------------------------------------------


def test_a_new_module_under_a_covered_root_moves_the_subject():
    """Structural universe: a file is inside it the moment it exists.

    No second hand-maintained list of "authority files" — forgetting a new
    module from both lists would otherwise still pass.
    """
    baseline = _baseline()
    work = _tree()
    (work / "src/nornyx_forge/added_after_the_fact.py").write_bytes(b"X = 1\n")

    subject = _subject(work)
    assert subject.subject_verified, subject.unavailable_reason
    assert subject.governed_subject_digest != baseline


@pytest.mark.parametrize(
    ("label", "path", "content"),
    [
        ("contract outside required_contracts", ".nornyx/contracts/rogue.nyx", b'nornyx: "0.2"\n'),
        ("module outside the covered roots", "src/elsewhere/mod.py", b"X = 1\n"),
    ],
)
def test_authority_capable_content_outside_the_subject_is_refused(
    label: str, path: str, content: bytes
):
    work = _tree()
    target = work / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)

    subject = _subject(work)
    assert subject.subject_verified is False, label
    assert "SUBJECT_SCOPE_ESCAPE" in (subject.unavailable_reason or ""), label


def test_gitignore_cannot_remove_a_file_from_the_subject():
    """`.gitignore` is not an authority boundary: an ignored file still runs."""
    baseline = _baseline()
    work = _tree()
    (work / "src/nornyx_forge/hidden.py").write_bytes(b"X = 1\n")
    (work / ".gitignore").write_bytes(
        (work / ".gitignore").read_bytes() + b"\nsrc/nornyx_forge/hidden.py\n"
    )

    subject = _subject(work)
    assert subject.subject_verified, subject.unavailable_reason
    assert subject.governed_subject_digest != baseline


# --------------------------------------------------------------------------
# The scope definition is itself bound
# --------------------------------------------------------------------------


def test_narrowing_a_scope_moves_the_subject_even_with_an_identical_id():
    """Scope *meaning* is bound, not just its label.

    Relying on the fact that shrinking a scope happens to move the digest —
    because the module declaring it is itself governed content — is indirect and
    holds only while that stays true.
    """
    work = _tree()
    honest = _subject(work, RUNTIME_IMAGE_SCOPE)
    narrowed = SubjectScope(
        scope_id=RUNTIME_IMAGE_SCOPE.scope_id,  # identical label
        required_roots=("src/nornyx_forge",),  # demo_app dropped
        required_files=RUNTIME_IMAGE_SCOPE.required_files,
        required_contracts=RUNTIME_IMAGE_SCOPE.required_contracts,
        authority_universe=RUNTIME_IMAGE_SCOPE.authority_universe,
        non_authoritative=RUNTIME_IMAGE_SCOPE.non_authoritative,
    )
    quiet = _subject(work, narrowed)

    assert quiet.scope_id == honest.scope_id
    assert quiet.scope_definition_digest != honest.scope_definition_digest
    # Dropping demo_app leaves its modules authority-capable but uncovered.
    assert quiet.subject_verified is False
    assert "SUBJECT_SCOPE_ESCAPE" in (quiet.unavailable_reason or "")


def test_the_two_scopes_describe_different_surfaces():
    """They are meant to differ; a shared digest would mean one is mislabelled."""
    from nornyx_forge.governed_subject import REPOSITORY_SCOPE

    work = _tree()
    repository, runtime = _subject(work, REPOSITORY_SCOPE), _subject(work, RUNTIME_IMAGE_SCOPE)
    assert repository.subject_verified and runtime.subject_verified
    assert repository.governed_subject_digest != runtime.governed_subject_digest
    assert repository.scope_definition_digest != runtime.scope_definition_digest


def test_the_manifest_cannot_define_what_is_observed():
    """Scope flows code -> observer -> manifest, never the reverse.

    A manifest able to declare its own `required_roots` would make forging it a
    way to shrink the subject.
    """
    from nornyx_forge.subject_bootstrap import build_subject_manifest

    work = _tree()
    manifest = build_subject_manifest(work, scope=RUNTIME_IMAGE_SCOPE, config=CONFIG)
    assert "required_roots" not in manifest
    assert manifest["subject_scope_id"] == RUNTIME_IMAGE_SCOPE.scope_id
    # It reports the digest; it is not consulted to produce one.
    assert manifest["governed_subject_digest"] == _subject(work).governed_subject_digest


def test_no_governed_file_escapes_the_canonical_text_rule():
    """An extension allowlist drifts; this is what notices.

    CI found three governed files — app.js, index.html, styles.css — outside
    `CANONICAL_TEXT_SUFFIXES`. Being undeclared, they were hashed raw and
    carried CR bytes on a Windows checkout, so the same commit digested
    differently on Linux. The control covered everything it enumerated and
    silently exempted the rest.

    Binary content is legitimately undeclared, so this does not demand that
    every file be text: it demands that an undeclared governed file actually be
    binary, rather than text nobody added to the list.
    """
    from nornyx_forge.governed_subject import REPOSITORY_SCOPE, is_declared_text
    from nornyx_forge.subject_observer import observe_governed_paths

    undeclared_text: list[str] = []
    for relative in observe_governed_paths(ROOT, REPOSITORY_SCOPE):
        if is_declared_text(relative):
            continue
        blob = (ROOT / relative).read_bytes()
        if bytes([0]) not in blob:  # no NUL: it is text, whatever the extension
            undeclared_text.append(relative)

    assert undeclared_text == [], (
        "governed text outside CANONICAL_TEXT_SUFFIXES is hashed raw, so its "
        "digest depends on the checkout's line endings: " + ", ".join(undeclared_text)
    )


def test_a_narrowed_scope_moves_the_governed_subject_digest():
    """The binding itself, asserted directly.

    `test_narrowing_a_scope_moves_the_subject_even_with_an_identical_id` claims
    this in its name and proves something else: it asserts
    `scope_definition_digest` differs — a different function, computed from the
    scope alone — and that SUBJECT_SCOPE_ESCAPE fires. Neither touches
    `governed_subject_digest`.

    An independent review deleted `scope_definition_digest` from the subject
    digest's inputs and the whole of six test files stayed green, then showed a
    scope with an identical id and `authority_universe=()` — closure enforcement
    entirely removed — producing a byte-identical subject digest to the honest
    scope. `governed_subject_digest` is the `subject_revision` an approval binds
    to, so two different authority surfaces became indistinguishable to every
    grant.

    A scope that covers less must be a different subject, and this asserts that
    and nothing else.
    """
    work = _tree()
    honest = _subject(work, RUNTIME_IMAGE_SCOPE)
    assert honest.subject_verified, honest.unavailable_reason

    # Same id, same declared surface, closure enforcement removed. The only way
    # this can produce a different digest is if the scope definition is bound in.
    unguarded = SubjectScope(
        scope_id=RUNTIME_IMAGE_SCOPE.scope_id,
        required_roots=RUNTIME_IMAGE_SCOPE.required_roots,
        required_files=RUNTIME_IMAGE_SCOPE.required_files,
        required_contracts=RUNTIME_IMAGE_SCOPE.required_contracts,
        authority_universe=(),
        non_authoritative=RUNTIME_IMAGE_SCOPE.non_authoritative,
    )
    weakened = _subject(work, unguarded)

    assert weakened.scope_id == honest.scope_id
    assert weakened.subject_verified, weakened.unavailable_reason
    assert weakened.governed_subject_digest != honest.governed_subject_digest, (
        "a scope with closure enforcement removed produced the same subject "
        "digest as the honest scope, so an approval bound to one authorizes the "
        "other"
    )


def test_the_authority_config_also_moves_the_subject_digest():
    """The sibling binding, asserted the same way.

    Kept adjacent deliberately: these two are the inputs a subject digest must
    cover beyond content, and the review found one of them provable and the
    other not. Proving them side by side makes the asymmetry visible if it
    returns.
    """
    from nornyx_forge.governed_subject import RuntimeAuthorityConfig

    work = _tree()
    governed = _subject(work, RUNTIME_IMAGE_SCOPE)
    demo = establish_subject(
        work,
        scope=RUNTIME_IMAGE_SCOPE,
        config=RuntimeAuthorityConfig("deterministic_demo", "sequential"),
    )
    assert governed.subject_verified and demo.subject_verified
    assert demo.governed_subject_digest != governed.governed_subject_digest


def test_an_exclusion_cannot_make_a_module_downstream_by_sitting_above_it():
    """A stated reason covers what it describes, not whatever lands beneath it.

    `.nornyx/contracts/evidence` is excluded because generated evidence is
    downstream of the subject. That reason is about JSON. The exclusion is a path
    prefix, so it also swallowed `.py`, and a module dropped there left the
    subject entirely -- carrying an exclusion reason written about something
    else. It ships in the runtime image via `COPY .nornyx`.
    """
    work = _tree()
    smuggled = work / ".nornyx/contracts/evidence/smuggled.py"
    smuggled.parent.mkdir(parents=True, exist_ok=True)
    smuggled.write_bytes(("def reach():" + chr(10) + "    return 1" + chr(10)).encode())

    subject = _subject(work, RUNTIME_IMAGE_SCOPE)
    assert subject.subject_verified is False
    assert "SUBJECT_SCOPE_ESCAPE" in (subject.unavailable_reason or "")
    assert "non-authoritative exclusion" in (subject.unavailable_reason or "")


def test_the_exclusion_still_covers_what_it_was_written_for():
    """Generated evidence must stay excluded, or the digest self-references.

    The narrowing must not turn into "exclusions do not work". Evidence JSON is
    downstream of the subject by construction: folding it in would make the
    input depend on something derived from it.
    """
    work = _tree()
    generated = work / ".nornyx/contracts/evidence/probe_report.json"
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_bytes(('{"status": "pass"}' + chr(10)).encode())

    subject = _subject(work, RUNTIME_IMAGE_SCOPE)
    assert subject.subject_verified, subject.unavailable_reason
