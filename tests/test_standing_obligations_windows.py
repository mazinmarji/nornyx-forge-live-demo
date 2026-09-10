r"""Standing-obligation admission on Windows: the overlay refused, the public cycle admitted.

Runs in the windows-runtime CI job, where every test must execute -- that job
refuses a skip -- and is a declared skip in the Linux census. A directory
junction needs no privilege on Windows, unlike a symlink, so these fixtures
build on any Windows host; `tests/test_windows_runtime.py` builds its own the
same way.

What is held here, measured on the platform it concerns. Windows has no
`openat`, no `O_NOFOLLOW` and no `scandir` on a handle in `os`, so no
handle-based judgment of an overlay path exists there, and a pathname
inspected and then used again is a race an external review measured against
the checker. Rather than admit a private overlay over that race, the checker
refuses `--overlay` outright on this platform -- with one sentence that names
the platform and nothing else, whatever the path's shape: a plain external
file, a junction chain through the repository, a junction inside it, a
junction that never touches it, a `\\?\` spelling -- until a separately
reviewed HANDLE-based backend exists. Public-registry admission stays
available: init, complete, check, with the disposition created exclusively
by pathname. The symlink shapes and the held-descriptor properties are proved
on POSIX in `tests/test_standing_development_obligations.py`; nothing here
claims that any link was followed, because none is.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest
from test_standing_development_obligations import (
    RUNTIME,
    SENTINEL_DIR,
    _assert_no_leak,
    _complete,
    _load_module,
    _overlay_document,
    _refusal,
    _run,
    _runtime_disposition,
    _write_overlay,
)

windows_only = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows is the subject: these measure the checker where no handle-based "
           "backend exists, and three of them need a junction to do it; the "
           "windows-runtime CI job runs them all",
)

#: The one sentence every private overlay is refused with on this platform.
PLATFORM_REFUSAL = "private overlay is not admitted on this platform without a handle-based backend"


@pytest.fixture
def module():
    return _load_module()


def _junction(target: Path, link: Path) -> None:
    """A directory junction: the unprivileged Windows link."""
    import _winapi  # noqa: PLC0415 - Windows only, by the marker above

    _winapi.CreateJunction(str(target), str(link))


def _remove_junction(link: Path) -> None:
    if link.exists() or link.is_symlink():
        os.rmdir(link)


def _refused_on_this_platform(module, given: Path, *paths: Path) -> None:
    """The one platform sentence, in the API and on stderr, with no path in either."""
    assert module.HANDLE_BACKEND is False, "Windows has no handle backend in os"
    message = _refusal(module, lambda: module.load_registries(given))
    assert message == PLATFORM_REFUSAL
    _assert_no_leak(message, given, *paths)
    completed = _run("--overlay", str(given))
    assert completed.returncode == 2 and completed.stdout == ""
    assert completed.stderr == f"REFUSE: {PLATFORM_REFUSAL}\n"
    _assert_no_leak(completed.stdout + completed.stderr, given, *paths)


@windows_only
def test_a_plain_external_overlay_is_refused_on_this_platform(module, tmp_path):
    """The shape that USED to be admitted here: refused now, until a handle backend exists."""
    overlay = _write_overlay(tmp_path)
    _refused_on_this_platform(module, overlay)


@windows_only
def test_a_junction_chain_through_the_repository_is_refused(module, tmp_path):
    """`outside/a -> repo/.nornyx/runtime/j -> outside/final`: the same sentence, nothing followed.

    Measured by the Codex review on an earlier head: ACCEPTED by the
    pathname walk, because neither junction is a symlink to
    `Path.is_symlink()` and the final resolution was outside. Nothing walks
    this path now; the refusal precedes it and names no shape.
    """
    final = tmp_path / "final"
    final.mkdir()
    (final / "overlay.json").write_text(
        json.dumps(_overlay_document()), encoding="utf-8", newline="\n"
    )
    RUNTIME.mkdir(parents=True, exist_ok=True)
    middle = RUNTIME / f"junction-{uuid.uuid4().hex}"
    outside = tmp_path / SENTINEL_DIR
    outside.mkdir()
    first = outside / "a"
    try:
        _junction(final, middle)
        _junction(middle, first)
        given = first / "overlay.json"
        assert given.is_file(), "the chain resolves for an ordinary open"
        _refused_on_this_platform(module, given, middle, final)
    finally:
        _remove_junction(first)
        _remove_junction(middle)


@windows_only
def test_a_junction_inside_the_repository_pointing_outside_is_refused(module, tmp_path):
    outside = _write_overlay(tmp_path).parent
    RUNTIME.mkdir(parents=True, exist_ok=True)
    link = RUNTIME / f"junction-{uuid.uuid4().hex}"
    try:
        _junction(outside, link)
        _refused_on_this_platform(module, link / "overlay.json", outside)
    finally:
        _remove_junction(link)


@windows_only
def test_a_junction_that_never_touches_the_repository_is_still_refused(module, tmp_path):
    final = tmp_path / "final"
    final.mkdir()
    (final / "overlay.json").write_text(
        json.dumps(_overlay_document()), encoding="utf-8", newline="\n"
    )
    outside = tmp_path / SENTINEL_DIR
    outside.mkdir()
    link = outside / "j"
    try:
        _junction(final, link)
        _refused_on_this_platform(module, link / "overlay.json", final)
    finally:
        _remove_junction(link)


@windows_only
def test_a_namespace_spelling_of_an_in_repository_path_is_refused(module):
    r"""`\\?\D:\...\repo\.nornyx\runtime\x.json`: the same sentence, the spelling never judged."""
    RUNTIME.mkdir(parents=True, exist_ok=True)
    decoy = RUNTIME / f"decoy-{uuid.uuid4().hex}.json"
    decoy.write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
    try:
        _refused_on_this_platform(module, Path("\\\\?\\" + str(decoy)), decoy)
    finally:
        decoy.unlink()


@windows_only
def test_public_registry_admission_runs_on_this_platform(module):
    """Init, complete, check without an overlay: PASS; a second init refuses; the file is exclusive."""
    with _runtime_disposition() as path:
        completed = _run("--init", str(path), "--cycle-id", "WIN-1")
        assert completed.returncode == 0, completed.stderr
        completed = _run("--init", str(path), "--cycle-id", "WIN-1")
        assert completed.returncode == 2
        assert "already exists" in completed.stderr
        _complete(path, module, module.load_registries(None))
        completed = _run("--check-disposition", str(path))
        assert completed.returncode == 0, completed.stderr
        assert "PASS" in completed.stdout and module.ADMISSION_BOUNDARY in completed.stdout
        assert "overlay" not in completed.stdout.lower()


def test_the_windows_runtime_job_runs_this_module_and_refuses_a_skip():
    """Runs everywhere: the proofs above prove nothing unless a job runs them.

    Every other test here is a declared skip off Windows, so the census would
    count this module as present and proving nothing were this not held: the
    windows-runtime job names this module in its one pytest command, and that
    job exits non-zero on any skip, so the six run on the platform they
    concern or the job is red.
    """
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml")
    text = workflow.read_text(encoding="utf-8")
    job = text[text.index("windows-runtime:"):]
    commands = [line for line in job.splitlines() if "python -m pytest" in line]
    assert len(commands) == 1, commands
    assert "tests/test_standing_obligations_windows.py" in commands[0].split()
    assert "if skipped:" in job and "sys.exit(1)" in job
