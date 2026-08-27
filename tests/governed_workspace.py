"""Build a fixture workspace the repository scope considers complete.

Seven fixtures each carried their own hardcoded list of files to copy:

    for item in ("pyproject.toml", ".gitignore", "BRD.md", "Dockerfile", ...):

Every one of them broke the moment `REPOSITORY_SCOPE` gained a required file,
with `SUBJECT_SCOPE_INCOMPLETE` — which is the scope refusing to compute a
smaller subject and call it verified, so the refusal was correct and the fixtures
were wrong. It has happened twice now: once when the scope model was introduced,
and again when `.dockerignore` and `CLAUDE.md` joined it.

A hardcoded list is a second definition of what the repository consists of, kept
in seven places, none of which the scope knows about. This derives the list from
the scope itself, so widening the scope updates every fixture at once and the
class of breakage disappears rather than being repaired again.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from nornyx_forge.governed_subject import REPOSITORY_SCOPE, SubjectScope

ROOT = Path(__file__).resolve().parents[1]

#: Copied in addition to whatever the scope requires. `.nornyx` carries the
#: contracts and evidence a governance fixture works on; `README.md` is not
#: scope-required but several fixtures read it.
ALWAYS = (".nornyx", "README.md")

IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info", ".venv", ".git")


def copy_governed_workspace(
    destination: Path, *, scope: SubjectScope = REPOSITORY_SCOPE, source: Path = ROOT
) -> Path:
    """Copy everything `scope` requires, plus the governance tree.

    Missing sources are skipped rather than raising: a scope may legitimately
    name something this checkout does not have, and the resulting
    SUBJECT_SCOPE_INCOMPLETE is a more informative failure than a copy error.
    """
    destination.mkdir(parents=True, exist_ok=True)

    for name in (*scope.required_roots, *ALWAYS):
        origin = source / name
        if not origin.exists():
            continue
        target = destination / name
        if origin.is_dir():
            shutil.copytree(origin, target, ignore=IGNORE, dirs_exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origin, target)

    for name in scope.required_files:
        origin = source / name
        if not origin.exists():
            continue
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, target)

    return destination
