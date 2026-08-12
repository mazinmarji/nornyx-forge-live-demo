"""Required evidence being absent is not a successful empty verification.

Four defects in this repository have shared one root cause:

    missing contracts directory  -> empty result   -> intact
    empty contracts directory    -> empty result   -> intact
    missing review_binding.json  -> loop skipped   -> intact
    git binary unreachable       -> empty path set -> clean tree

Each was fixed where it was found. Four instances of one class is not four
bugs, so this is the class written down as a control:

    PRESENT + VERIFIED        -> intact / authenticated / available
    PRESENT + INVALID         -> compromised / unauthenticated
    REQUIRED BUT ABSENT       -> unavailable / incomplete
    OPTIONAL AND ABSENT       -> explicitly not-applicable

never

    absent -> empty collection -> no problems -> success

The behavioural half asserts each known instance still fails closed. The
structural half is the part that generalises: a scan for the constructs that
produced them, so a FIFTH one has to be classified deliberately instead of
appearing by accident.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from nornyx_forge.governed_subject import INTEGRITY_UNAVAILABLE  # noqa: E402
from nornyx_forge.subject_observer import observe_governance_integrity  # noqa: E402

#: Modules where absence can change an authority answer.
SURFACES = (
    "src/nornyx_forge/approval_trust.py",
    "src/nornyx_forge/reviewer_trust.py",
    "src/nornyx_forge/governed_subject.py",
    "src/nornyx_forge/subject_observer.py",
    "src/nornyx_forge/subject_bootstrap.py",
    "src/nornyx_forge/nornyx_runtime.py",
    "scripts/refresh_governance_evidence.py",
    "scripts/governed_content.py",
)

#: Handlers that may return an empty collection, each with the reason absence
#: cannot increase authority there. Classifying one is a decision someone makes
#: in writing; the scan below fails on anything not listed.
#:
#: Keyed by "<relative>:<function>" so moving a construct into a new function is
#: a new decision rather than an inherited exemption.
CLASSIFIED_EMPTY_RETURNS: dict[str, str] = {
    # Empty, and that is the current truth rather than an oversight: after the
    # dirty-tree fix there is no handler in these modules that turns a failure
    # into an empty collection. Two entries were written here from memory and
    # named functions that do not exist, which
    # `test_every_classification_still_names_a_real_site` caught -- an
    # exemption for a site that is not there is cover for whatever later takes
    # the name.
    #
    # An entry belongs here only with a reason beginning OPTIONAL. or
    # CONDITIONAL. that says why absence at that site cannot increase authority.
}


def _empty_return_sites(relative: str) -> list[tuple[str, int]]:
    """Every `except ...: return <empty>` in a module, with its function."""
    source = (ROOT / relative).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=relative)
    found: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.ExceptHandler):
                continue
            for statement in inner.body:
                if not isinstance(statement, ast.Return) or statement.value is None:
                    continue
                value = statement.value
                empty = (
                    isinstance(value, ast.List) and not value.elts
                ) or (
                    isinstance(value, ast.Dict) and not value.keys
                ) or (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id in {"list", "dict", "set", "tuple"}
                    and not value.args
                )
                if empty:
                    found.append((node.name, statement.lineno))
    return found


def test_every_empty_return_from_a_handler_is_classified():
    """A swallowed failure must be a decision, not a default.

    `except Exception: return []` is how the dirty-tree gate came to report a
    clean tree when git could not be run at all. The construct is not banned --
    some absences genuinely are optional -- but each one has to say which, and
    an unclassified one fails here rather than being read as harmless.
    """
    unclassified: list[str] = []
    for relative in SURFACES:
        for function, lineno in _empty_return_sites(relative):
            key = f"{relative}:{function}"
            if key not in CLASSIFIED_EMPTY_RETURNS:
                unclassified.append(f"{key} (line {lineno})")

    assert unclassified == [], (
        "these handlers turn a failure into an empty result with no stated "
        "reason why absence cannot increase authority. Classify each in "
        "CLASSIFIED_EMPTY_RETURNS or make it fail closed: " + str(unclassified)
    )


def test_every_classification_still_names_a_real_site():
    """A stale exemption is a hole nobody is watching.

    Moving or deleting one of these would otherwise leave its entry standing as
    cover for whatever later takes the name.
    """
    live = {
        f"{relative}:{function}"
        for relative in SURFACES
        for function, _ in _empty_return_sites(relative)
    }
    stale = sorted(set(CLASSIFIED_EMPTY_RETURNS) - live)
    assert stale == [], f"these classifications name sites that no longer exist: {stale}"


def test_each_classification_states_a_reason():
    """An allowlist without reasons becomes a place to hide things."""
    for key, reason in CLASSIFIED_EMPTY_RETURNS.items():
        assert reason.startswith(("OPTIONAL.", "CONDITIONAL.")), key
        assert len(reason) > 80, f"{key} is exempted without a real explanation"


# --------------------------------------------------------------------------
# The four known instances, each still failing closed
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "location"),
    [
        ("a missing contracts directory", "no/such/directory"),
        ("a contracts directory holding none", "tests"),
    ],
)
def test_an_unobservable_governance_surface_is_unavailable(label: str, location: str):
    state = observe_governance_integrity(ROOT / location)
    assert state.status == INTEGRITY_UNAVAILABLE, label
    assert state.authorizes_consequential_action is False, label


def test_an_unrunnable_git_is_not_a_clean_tree(monkeypatch: pytest.MonkeyPatch):
    """The fourth instance, reproduced exactly.

    `_git_lines` raises SystemExit on a non-zero exit and SystemExit is not an
    Exception, so that path was already fail-closed. What the handler caught was
    git being unreachable -- and it answered "no unstaged paths", which reads as
    a clean governed tree and lets an approval be honoured over content nobody
    could prove was unchanged.
    """
    import refresh_governance_evidence as refresh  # noqa: PLC0415

    real = subprocess.run

    def unreachable(args, **kwargs):
        if args and args[0] == "git":
            raise FileNotFoundError(2, "not found", "git")
        return real(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", unreachable)
    with pytest.raises(SystemExit) as refusal:
        refresh._unstaged_governed_paths()
    assert "clean governed tree cannot be proven" in str(refusal.value)


def test_a_missing_review_binding_is_not_a_passing_verification(tmp_path: Path):
    """The third instance, at the tool's own boundary.

    Deleting the artifact that carries the claims verification recomputes must
    not be the way to pass verification.
    """
    work = tmp_path / "repo"
    work.mkdir()
    archive = tmp_path / "tree.tar"
    subprocess.run(["git", "-C", str(ROOT), "archive", "-o", str(archive), "HEAD"], check=True)
    shutil.unpack_archive(str(archive), str(work), format="tar")
    for command in (["init", "-q"], ["config", "user.email", "a@b.invalid"],
                    ["config", "user.name", "a"], ["add", "-A"],
                    ["commit", "-qm", "fixture"]):
        subprocess.run(["git", "-C", str(work), *command], capture_output=True, check=True)

    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    for step in (["--as-of", "2026-08-11T00:00:00Z"], ["--sync-contracts"],
                 ["--review-binding"]):
        assert subprocess.run(
            [sys.executable, "scripts/refresh_governance_evidence.py", *step],
            cwd=work, capture_output=True, env=env,
        ).returncode == 0

    (work / ".nornyx/contracts/evidence/review_binding.json").unlink()
    completed = subprocess.run(
        [sys.executable, "scripts/refresh_governance_evidence.py", "--verify"],
        cwd=work, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env,
    )
    report = json.loads(completed.stdout[completed.stdout.find("{"):])["verification"]
    assert report["integrity_state"] != "intact"
    assert any("review binding is absent" in problem for problem in report["problems"])
