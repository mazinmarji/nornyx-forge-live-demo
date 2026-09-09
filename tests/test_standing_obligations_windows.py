r"""Standing-obligation overlay confinement on Windows: junctions and spellings.

Runs in the windows-runtime CI job, where every test must execute -- that job
refuses a skip -- and is a declared skip in the Linux census. A directory
junction needs no privilege on Windows, unlike a symlink, so these fixtures
build on any Windows host; `tests/test_windows_runtime.py` builds its own the
same way.

What is held here, measured on the platform it concerns. A directory
junction anywhere in an overlay's path is refused rather than followed:
outside the tree, inside it, or in a chain that hops through it -- the shape
the Codex review of the PR head measured as ACCEPTED, because
`Path.is_symlink()` reports a junction as a plain directory. A plain
external path is admitted through the whole init-and-check cycle on
Windows, and a `\\?\` spelling of an in-repository path is still the
repository. The symlink chains are proved on POSIX in
`tests/test_standing_development_obligations.py`; nothing here claims that a
Windows symlink was followed, because none is built.
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
    reason="directory junctions exist only on Windows; the windows-runtime CI job runs these",
)


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


@windows_only
def test_a_real_junction_is_an_unsupported_link_and_a_plain_directory_is_not(module, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "junction"
    _junction(target, link)
    try:
        assert not link.is_symlink(), "a junction reads as a plain directory to is_symlink()"
        assert module._link_kind(os.lstat(link)) == module.UNSUPPORTED_LINK
        assert module._link_kind(os.lstat(target)) == module.PLAIN
        (target / "file.json").write_text("{}", encoding="utf-8", newline="\n")
        assert module._link_kind(os.lstat(target / "file.json")) == module.PLAIN
    finally:
        _remove_junction(link)


@windows_only
def test_a_junction_chain_through_the_repository_is_refused(module, tmp_path):
    """`outside/a -> repo/.nornyx/runtime/j -> outside/final`, given `outside/a/overlay.json`.

    Measured by the Codex review on the PR head: ACCEPTED, because neither
    junction is a symlink to `Path.is_symlink()` and the final resolution is
    outside. The walk refuses at the first junction it meets.
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
        message = _refusal(module, lambda: module.load_registries(given))
        assert message == "private overlay path crosses a link that is not followed"
        _assert_no_leak(message, given, middle, final)
        completed = _run("--overlay", str(given))
        assert completed.returncode == 2 and completed.stdout == ""
        _assert_no_leak(completed.stdout + completed.stderr, given, middle, final)
    finally:
        _remove_junction(first)
        _remove_junction(middle)


@windows_only
def test_a_junction_inside_the_repository_pointing_outside_is_refused(module, tmp_path):
    """The path as GIVEN is inside the tree, whatever the junction leads to."""
    outside = _write_overlay(tmp_path).parent
    RUNTIME.mkdir(parents=True, exist_ok=True)
    link = RUNTIME / f"junction-{uuid.uuid4().hex}"
    try:
        _junction(outside, link)
        given = link / "overlay.json"
        message = _refusal(module, lambda: module.load_registries(given))
        assert message == "private overlay must remain outside the Forge repository"
        _assert_no_leak(message, given, outside)
    finally:
        _remove_junction(link)


@windows_only
def test_a_junction_that_never_touches_the_repository_is_still_refused(module, tmp_path):
    """Fail closed: the checker does not follow a junction, wherever it leads."""
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
        message = _refusal(module, lambda: module.load_registries(link / "overlay.json"))
        assert message == "private overlay path crosses a link that is not followed"
        _assert_no_leak(message, link, final)
    finally:
        _remove_junction(link)


@windows_only
def test_a_namespace_spelling_of_an_in_repository_path_is_refused(module):
    r"""`\\?\D:\...\repo\.nornyx\runtime\x.json` is the repository under another anchor.

    Lexically it is not under the root, whose spelling has no prefix; by
    identity an ancestor of it IS the root.
    """
    RUNTIME.mkdir(parents=True, exist_ok=True)
    decoy = RUNTIME / f"decoy-{uuid.uuid4().hex}.json"
    decoy.write_text(json.dumps(_overlay_document()), encoding="utf-8", newline="\n")
    spelled = Path("\\\\?\\" + str(decoy))
    try:
        message = _refusal(module, lambda: module.load_registries(spelled))
        assert message == "private overlay must remain outside the Forge repository"
        completed = _run("--overlay", str(spelled))
        assert completed.returncode == 2
        _assert_no_leak(completed.stdout + completed.stderr, decoy)
    finally:
        decoy.unlink()


@windows_only
def test_a_plain_external_overlay_is_admitted_through_the_whole_cycle(module, tmp_path):
    """Registries, init, check: PASS on Windows, nothing from the overlay emitted."""
    overlay = _write_overlay(tmp_path)
    completed = _run("--overlay", str(overlay))
    assert completed.returncode == 0, completed.stderr
    with _runtime_disposition() as path:
        completed = _run("--overlay", str(overlay), "--init", str(path), "--cycle-id", "WIN-1")
        assert completed.returncode == 0, completed.stderr
        _complete(path, module, module.load_registries(overlay))
        completed = _run("--overlay", str(overlay), "--check-disposition", str(path))
        assert completed.returncode == 0, completed.stderr
        assert "PASS" in completed.stdout and module.OVERLAY_NOTICE in completed.stdout
        _assert_no_leak(completed.stdout + completed.stderr, overlay)


def test_the_windows_runtime_job_runs_this_module_and_refuses_a_skip():
    """Runs everywhere: the junction proofs above prove nothing unless a job runs them.

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
