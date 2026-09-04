"""The Windows bundle builder: the container's layout, provably mirrored.

THE ANTI-DRIFT PIN is the first test: the bundle's copy set is compared
against the Dockerfile's COPY sources, parsed from the Dockerfile itself,
so the two deployment surfaces cannot diverge silently. The rest holds
the builder to the packaging doctrine: the built tree carries every
structural marker `resolve_packaged_root` demands, the interpreter path
file puts `src` before the dependency library (source shadows any
installed copy) and admits no site-packages, the project's own packages
are pruned from that library, an unverified interpreter is refused, an
archive that is not the embeddable distribution is refused, nothing
developer-local rides into a bundle, and -- PR-18 -- the two kinds of
bundle carry a marker naming which they are and a launcher that says so:
the self-contained launcher runs the carried interpreter and nothing else,
the developer launcher runs an installed Python with the bundle's own code
first, and neither passes the launch directory as anything.

Everything here is cross-platform deterministic evidence: synthetic zips
stand in for the operator's embeddable archive, and a synthetic
`python.exe` is a file, not an interpreter. The real embedded-interpreter
run is the operator's act (A-017), measured by `--smoke` when they run it.

THE SMOKE VERDICT (N1 of the independent PR-18 review): `--smoke` said
`pass` whenever a stopped record existed, while the statuses it read, the
instance token it compared and the stop outcome were recorded and never
judged. The tests at the end hold `result` to the conjunction of the
recorded observations -- launcher, ready record, the three routes with the
token compared against the record's, the stop, the stopped record -- and
they need no interpreter: the verdict is judged over scripted observations,
and the smoke's own recording is driven over a scripted launcher and
listener, so the real operator run stays exactly what it was, unperformed.
"""

from __future__ import annotations

import hashlib
import http.client
import inspect
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_windows_bundle as builder  # noqa: E402
from build_windows_bundle import (  # noqa: E402
    BUNDLE_MARKER,
    BUNDLE_SCHEMA,
    DEVELOPER,
    DEVELOPER_BOOTSTRAP,
    DEVELOPER_LAUNCHER,
    EMBED_EXECUTABLES,
    LAUNCHERS,
    PTH_LINES,
    RUNTIME_SCHEMA,
    SELF_CONTAINED,
    SELF_CONTAINED_LAUNCHER,
    SMOKE_ACTOR,
    SMOKE_REQUIRED,
    SMOKE_SCHEMA,
    BundleError,
    bundle_manifest,
    copy_tree,
    evaluate_smoke_observations,
    install_python,
    smoke_bundle,
    write_bundle_marker,
    write_launcher,
)


def _embed_zip(path: Path, *executables: str, pth: str = "python313.zip\nimport site\n") -> str:
    """A synthetic embeddable archive. The executables are FILES, not
    interpreters; what is tested is the builder's handling of the archive."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("python313._pth", pth)
        for name in executables:
            archive.writestr(name, "not a real interpreter")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_bundle_copies_exactly_what_the_dockerfile_copies():
    """Parsed from the Dockerfile, not restated beside it."""
    docker_sources: set[str] = set()
    for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
        if line.startswith("COPY "):
            docker_sources.update(line.split()[1:-1])
    assert docker_sources, "the Dockerfile parse found no COPY lines"
    assert set(bundle_manifest()) == docker_sources, (
        "the bundle and the container no longer deploy the same tree"
    )


def test_the_built_tree_carries_the_resolvers_markers(tmp_path: Path):
    dist = tmp_path / "dist"
    copy_tree(ROOT, dist)
    for marker in ("src/nornyx_forge", "src/demo_app", ".nornyx/contracts"):
        assert (dist / marker).is_dir(), (
            f"the bundle lacks {marker}; resolve_packaged_root would refuse it"
        )
    assert (dist / "src" / "nornyx_forge" / "windows_launch.py").is_file()
    assert (dist / "src" / "nornyx_forge" / "windows_runtime.py").is_file()


def test_developer_state_never_rides_into_a_bundle(tmp_path: Path):
    dist = tmp_path / "dist"
    copy_tree(ROOT, dist)
    strays = [path for path in dist.rglob("__pycache__")] + [
        path for path in dist.rglob(".venv")
    ]
    assert strays == [], f"developer state was bundled: {strays[:3]}"


def test_a_nonempty_dist_is_refused(tmp_path: Path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "leftover.txt").write_text("old", encoding="utf-8", newline="")
    with pytest.raises(BundleError, match="built fresh"):
        copy_tree(ROOT, dist)


# ---------------------------------------------------------------------------
# W13  the interpreter is accepted only with the exact expected digest
# ---------------------------------------------------------------------------

def test_an_unverified_interpreter_is_refused(tmp_path: Path):
    fake_zip = tmp_path / "python-embed.zip"
    _embed_zip(fake_zip, *EMBED_EXECUTABLES)
    with pytest.raises(BundleError, match="does not match its declared sha256"):
        install_python(tmp_path / "dist", fake_zip, "0" * 64)
    assert not (tmp_path / "dist" / "python").exists(), "a mismatch must extract nothing"


def test_a_digest_that_differs_by_one_byte_is_a_mismatch_not_a_warning(tmp_path: Path):
    fake_zip = tmp_path / "python-embed.zip"
    digest = _embed_zip(fake_zip, *EMBED_EXECUTABLES)
    original = fake_zip.read_bytes()
    fake_zip.write_bytes(original[:-1] + bytes([original[-1] ^ 0x01]))
    with pytest.raises(BundleError, match="does not match"):
        install_python(tmp_path / "dist", fake_zip, digest)
    assert not (tmp_path / "dist" / "python").exists()


def test_the_path_file_puts_source_before_the_library_and_admits_no_site(tmp_path: Path):
    """THE SHADOWING PIN: `..\\src` resolves before `..\\pylib`, so the
    shipped source is the single import truth even if a project copy
    survives in the dependency library -- and no `import site` line, so
    nothing installed anywhere else on the machine is on the path at all."""
    fake_zip = tmp_path / "python-embed.zip"
    digest = _embed_zip(fake_zip, *EMBED_EXECUTABLES)
    dist = tmp_path / "dist"
    install_python(dist, fake_zip, digest)
    lines = (dist / "python" / "python313._pth").read_text(
        encoding="utf-8"
    ).splitlines()
    assert lines == list(PTH_LINES)
    assert lines.index("..\\src") < lines.index("..\\pylib")
    assert not any(line.startswith("import") for line in lines)


def test_an_embed_zip_with_ambiguous_path_files_is_refused(tmp_path: Path):
    fake_zip = tmp_path / "python-embed.zip"
    with zipfile.ZipFile(fake_zip, "w") as archive:
        archive.writestr("python313._pth", "a\n")
        archive.writestr("python314._pth", "b\n")
    digest = hashlib.sha256(fake_zip.read_bytes()).hexdigest()
    with pytest.raises(BundleError, match="exactly one"):
        install_python(tmp_path / "dist", fake_zip, digest)


def test_an_archive_without_the_launchers_interpreter_is_refused(tmp_path: Path):
    """The launcher runs `pythonw.exe`; an archive that lacks it is not the
    embeddable distribution, whatever its digest was declared to be."""
    fake_zip = tmp_path / "python-embed.zip"
    digest = _embed_zip(fake_zip, "python.exe")
    with pytest.raises(BundleError, match="lacks pythonw.exe"):
        install_python(tmp_path / "dist", fake_zip, digest)


# ---------------------------------------------------------------------------
# The marker: which kind of folder this is, and nothing more
# ---------------------------------------------------------------------------

def test_the_marker_names_the_mode_and_ties_it_to_the_interpreter_digest(tmp_path: Path):
    write_bundle_marker(tmp_path, mode=DEVELOPER, interpreter_sha256=None)
    marker = json.loads((tmp_path / BUNDLE_MARKER).read_text(encoding="utf-8"))
    assert marker["schema"] == BUNDLE_SCHEMA and marker["mode"] == DEVELOPER
    assert marker["interpreter"] is None
    write_bundle_marker(tmp_path, mode=SELF_CONTAINED, interpreter_sha256="AB" * 32,
                        source_commit="abc123")
    marker = json.loads((tmp_path / BUNDLE_MARKER).read_text(encoding="utf-8"))
    assert marker["mode"] == SELF_CONTAINED
    assert marker["interpreter"] == {"source": "operator-supplied", "sha256": "ab" * 32}
    assert marker["source_commit"] == "abc123"
    for forbidden in ("approv", "experience", "eligib", "inspect", "verified"):
        assert forbidden not in json.dumps(marker).lower(), forbidden


def test_the_marker_cannot_claim_a_mode_its_interpreter_does_not_support(tmp_path: Path):
    with pytest.raises(BundleError, match="cannot say otherwise"):
        write_bundle_marker(tmp_path, mode=SELF_CONTAINED, interpreter_sha256=None)
    with pytest.raises(BundleError, match="cannot say otherwise"):
        write_bundle_marker(tmp_path, mode=DEVELOPER, interpreter_sha256="ab" * 32)
    with pytest.raises(BundleError, match="unknown bundle mode"):
        write_bundle_marker(tmp_path, mode="portable", interpreter_sha256=None)
    with pytest.raises(BundleError, match="unknown bundle mode"):
        write_launcher(tmp_path, "portable")


# ---------------------------------------------------------------------------
# W4 / W14  the two launchers
# ---------------------------------------------------------------------------

def test_the_self_contained_launcher_runs_the_carried_interpreter_and_nothing_else(tmp_path: Path):
    """W4: the person types nothing -- the bundle root is the launcher's own
    folder, the project is the profile's, the port is Forge's. W14: the only
    interpreter the launcher names is the one under `python\\`; there is no
    `py`, no `python` on PATH, no fallback branch."""
    write_launcher(tmp_path, SELF_CONTAINED)
    launcher = (tmp_path / "Forge.cmd").read_text(encoding="utf-8")
    assert launcher == SELF_CONTAINED_LAUNCHER
    assert "nornyx_forge.windows_launch" in launcher
    assert '--bundle-root "%~dp0."' in launcher, "the root is the launcher's own folder"
    assert '--project-dir "%USERPROFILE%\\ForgeProject"' in launcher
    assert "%~dp0python\\pythonw.exe" in launcher
    assert set(re.findall(r"[\w\\%~.]+\.exe", launcher)) == {
        "%~dp0python\\pythonw.exe", "python\\pythonw.exe",
    }, "the self-contained launcher may name exactly one interpreter: the carried one"
    for fallback in ("pyw", " py ", "where ", "%PATH%", "python -", "python.exe"):
        assert fallback not in launcher, f"a fallback path exists: {fallback!r}"
    assert "exit /b 2" in launcher and "not a complete self-contained bundle" in launcher
    assert "--port" not in launcher, "the person chooses no port"
    assert str(ROOT) not in launcher, "a build-machine path leaked into the launcher"
    assert "%CD%" not in launcher and "cd " not in launcher.lower()


def test_the_developer_launcher_is_a_different_launcher_and_says_so(tmp_path: Path):
    write_launcher(tmp_path, DEVELOPER)
    launcher = (tmp_path / "Forge.cmd").read_text(encoding="utf-8")
    assert launcher == DEVELOPER_LAUNCHER
    assert "DEVELOPER" in launcher and "NO interpreter" in launcher
    assert "%~dp0python" not in launcher, "a developer bundle claims no carried interpreter"
    assert "pyw -3 -I -c" in launcher, "an installed Python, isolated"
    bootstrap = DEVELOPER_BOOTSTRAP.format(src="%~dp0src", pylib="%~dp0pylib")
    assert bootstrap in launcher
    assert bootstrap.index("%~dp0src") < bootstrap.index("%~dp0pylib"), "the bundle's src first"
    assert "sys.path[:0]" in bootstrap, "FIRST on the path, not appended behind site-packages"
    assert "nornyx_forge.windows_launch" in bootstrap
    assert '--bundle-root "%~dp0."' in launcher
    assert '--project-dir "%USERPROFILE%\\ForgeProject"' in launcher
    assert str(ROOT) not in launcher
    assert set(LAUNCHERS) == {SELF_CONTAINED, DEVELOPER}
    assert LAUNCHERS[SELF_CONTAINED] != LAUNCHERS[DEVELOPER]


def test_neither_launcher_passes_the_launch_directory_as_anything():
    for launcher in LAUNCHERS.values():
        assert "%CD%" not in launcher
        assert "%~dp0" in launcher, "the launcher derives the root from its own location"
        for line in launcher.splitlines():
            if line.lower().startswith("start "):
                assert "--bundle-root" in line and "--project-dir" in line
                assert "%*" in line, "operator arguments pass through explicitly"


def test_the_launchers_never_resolve_a_command_from_the_launch_directory():
    """cmd.exe looks in the current directory before PATH unless told not
    to. Measured under review: a `pyw.cmd` planted in the working directory
    ran in place of the Python launcher. The first thing either launcher
    does is turn that lookup off, before any bare command (`where`, `pyw`,
    `timeout`) is named."""
    for launcher in LAUNCHERS.values():
        lines = launcher.splitlines()
        assert lines[0] == "@echo off"
        assert lines[1] == "set NoDefaultCurrentDirectoryInExePath=1"
        bare = [line for line in lines[2:]
                if line.strip() and not line.startswith("rem ")
                and any(line.strip().startswith(command) for command in ("where ", "start ", "timeout "))]
        assert bare, "the launcher runs no command at all?"


def test_the_installer_is_probed_not_assumed(monkeypatch: pytest.MonkeyPatch):
    """A uv-managed environment ships no pip module -- measured on this
    repository's own venv. The builder probes and falls back to uv."""
    import build_windows_bundle as builder

    class NoPip:
        returncode = 1
        stdout = stderr = "No module named pip"

    monkeypatch.setattr(builder.subprocess, "run", lambda *a, **k: NoPip())
    monkeypatch.setattr(builder.shutil, "which",
                        lambda name: r"C:\tools\uv.exe" if name == "uv" else None)
    command = builder._installer_command("python.exe")
    assert command[:3] == [r"C:\tools\uv.exe", "pip", "install"]
    assert "--python" in command

    monkeypatch.setattr(builder.shutil, "which", lambda name: None)
    with pytest.raises(BundleError, match="no installer is available"):
        builder._installer_command("python.exe")


def test_the_manifest_is_a_closed_declaration():
    manifest = bundle_manifest()
    assert isinstance(manifest, tuple)
    assert "src" in manifest and ".nornyx" in manifest
    assert ".env" not in manifest and ".venv" not in manifest


def test_the_builder_never_fetches_an_interpreter_or_code():
    """W15 at build time: the builder verifies what the operator supplies
    and downloads nothing itself."""
    source = (ROOT / "scripts" / "build_windows_bundle.py").read_text(encoding="utf-8")
    for absent in ("urllib", "urlopen", "urlretrieve", "requests.", "httpx", "https://",
                   "python.org", "curl ", "wget ", "Invoke-WebRequest"):
        assert absent not in source, absent
    assert source.count('HTTPConnection("127.0.0.1"') == 1, (
        "the smoke's one loopback exchange helper is the builder's only HTTP"
    )


# ---------------------------------------------------------------------------
# The smoke verdict (N1): `pass` is the conjunction of the recorded observations
# ---------------------------------------------------------------------------

TOKEN = "0123456789abcdef0123456789abcdef"
OTHER_TOKEN = "fedcba9876543210fedcba9876543210"
_ABSENT = object()


def _ready_record(**changes) -> dict:
    return {"schema": RUNTIME_SCHEMA, "instance": TOKEN, "status": "ready", "port": 8710,
            "url": "http://127.0.0.1:8710/", **changes}


def _canonical() -> dict[str, dict]:
    """The passing observation set, one entry per required observation, keyed
    by a short name. A test names the one observation it disturbs and every
    other stays correct, so a red result is attributable to one fact."""
    return {
        "launcher": {"step": "launcher", "returncode": 0, "stdout": "", "stderr": ""},
        "record": {"step": "runtime_record", "record": _ready_record()},
        "runtime": {"step": "get", "path": "/api/runtime", "status": 200, "bytes": 320,
                    "content_type": "application/json", "json": "object",
                    "schema": RUNTIME_SCHEMA, "instance": TOKEN},
        "state": {"step": "get", "path": "/api/state", "status": 200, "bytes": 56,
                  "content_type": "application/json", "json": "object", "initialized": False},
        "page": {"step": "get", "path": "/", "status": 200, "bytes": 30000,
                 "content_type": "text/html; charset=utf-8"},
        "stop": {"step": "stop", "status": 200, "json": "object", "stopping": True,
                 "instance": TOKEN, "body": "{\"stopping\": true}"},
        "stopped": {"step": "stopped", "record": _ready_record(status="stopped")},
    }


def _observations(**changes) -> list[dict]:
    """The canonical set with named observations changed: a dict of facts is
    merged over the canonical ones (`_ABSENT` removes a fact); None drops the
    observation altogether."""
    steps = []
    for short, canonical in _canonical().items():
        if short in changes and changes[short] is None:
            continue
        facts = dict(canonical)
        for key, value in (changes.get(short) or {}).items():
            if value is _ABSENT:
                facts.pop(key, None)
            else:
                facts[key] = value
        steps.append(facts)
    return steps


def _failed(steps: list[dict]) -> list[str]:
    verdict = evaluate_smoke_observations(steps)
    assert verdict["result"] == ("pass" if not verdict["failed"] else "fail")
    return verdict["failed"]


def _names(steps: list[dict]) -> list[str]:
    return [entry.split(":", 1)[0] for entry in _failed(steps)]


def test_s1_every_required_observation_correct_is_a_pass():
    verdict = evaluate_smoke_observations(_observations())
    assert verdict["result"] == "pass" and verdict["failed"] == []
    assert verdict["required"] == list(SMOKE_REQUIRED) == [
        "launcher", "runtime_record", "get /api/runtime", "get /api/state", "get /",
        "stop", "stopped"]
    assert set(builder._SMOKE_CHECKS) == set(SMOKE_REQUIRED), "one judge per required observation"


def test_s2_a_non_success_status_on_the_runtime_route_is_not_a_pass():
    assert _names(_observations(runtime={"status": 500})) == ["get /api/runtime"]
    assert _names(_observations(runtime={"status": 404})) == ["get /api/runtime"]
    unreachable = {"status": None, "error": "ConnectionRefusedError: [WinError 10061]",
                   "json": _ABSENT, "schema": _ABSENT, "instance": _ABSENT}
    assert _failed(_observations(runtime=unreachable)) == [
        "get /api/runtime: HTTP None, not 200 (ConnectionRefusedError: [WinError 10061])"]
    assert "HTTP 500, not 200" in _failed(_observations(runtime={"status": 500}))[0]


def test_s3_the_expected_schema_with_the_wrong_instance_is_not_a_pass():
    """A Forge-shaped answer from some other runtime, a schema-only answer
    with no token, and any listener at all: none of them is THIS runtime."""
    assert _names(_observations(runtime={"instance": OTHER_TOKEN})) == ["get /api/runtime"]
    assert _names(_observations(runtime={"instance": None})) == ["get /api/runtime"]
    assert _names(_observations(runtime={"instance": _ABSENT})) == ["get /api/runtime"]
    assert _names(_observations(runtime={"schema": "nornyx.forge.other.v1"})) == ["get /api/runtime"]
    assert _names(_observations(runtime={"schema": None, "instance": None})) == ["get /api/runtime"]
    reason = _failed(_observations(runtime={"instance": OTHER_TOKEN}))[0]
    assert reason.endswith("is not the recorded runtime's")


def test_s4_invalid_json_on_the_runtime_route_is_not_a_pass():
    garbage = {"json": "invalid", "schema": _ABSENT, "instance": _ABSENT}
    assert _names(_observations(runtime=garbage)) == ["get /api/runtime"]
    not_object = {"json": "not an object", "schema": _ABSENT, "instance": _ABSENT}
    assert _names(_observations(runtime=not_object)) == ["get /api/runtime"]


def test_s5_a_failed_or_unusable_state_response_is_not_a_pass():
    assert _names(_observations(state={"status": 500, "json": "invalid",
                                       "initialized": _ABSENT})) == ["get /api/state"]
    assert _names(_observations(state={"status": 404})) == ["get /api/state"]
    assert _names(_observations(state={"json": "invalid", "initialized": _ABSENT})) == ["get /api/state"]
    assert _names(_observations(state={"initialized": "yes"})) == ["get /api/state"]
    assert _names(_observations(state={"initialized": _ABSENT})) == ["get /api/state"]
    # The smoke asks whether the state answer is usable, not what it says:
    # an initialized project and an uninitialized one both pass.
    assert _failed(_observations(state={"initialized": True})) == []


def test_s6_a_failed_or_missing_root_page_is_not_a_pass():
    assert _names(_observations(page={"status": 404})) == ["get /"]
    assert _names(_observations(page={"status": 500})) == ["get /"]
    assert _names(_observations(page={"content_type": "application/json"})) == ["get /"]
    assert _names(_observations(page={"bytes": 0})) == ["get /"]
    assert _failed(_observations(page=None)) == ["get /: not observed"]


def test_s7_a_failed_stop_request_is_not_a_pass():
    refused = {"status": 409, "stopping": None, "instance": None}
    assert _names(_observations(stop=refused)) == ["stop"]
    assert _names(_observations(stop={**refused, "status": 422})) == ["stop"]
    assert _names(_observations(stop={**refused, "status": 500, "json": "invalid"})) == ["stop"]
    assert _names(_observations(stop={"stopping": False})) == ["stop"]
    assert _names(_observations(stop={"json": "invalid", "stopping": True})) == ["stop"]
    assert _names(_observations(stop={"instance": OTHER_TOKEN})) == ["stop"]
    unreachable = {"status": None, "error": "ConnectionResetError", "json": _ABSENT,
                   "stopping": _ABSENT, "instance": _ABSENT}
    assert _names(_observations(stop=unreachable)) == ["stop"]


def test_s8_a_runtime_that_never_reaches_stopped_is_not_a_pass():
    assert _failed(_observations(stopped={"record": None})) == [
        "stopped: no stopped record within the wait"]
    assert _names(_observations(stopped={"record": _ready_record()})) == ["stopped"]
    assert _names(_observations(stopped={"record": _ready_record(status="failed")})) == ["stopped"]
    another = _ready_record(status="stopped", instance=OTHER_TOKEN)
    assert _names(_observations(stopped={"record": another})) == ["stopped"]
    foreign = _ready_record(status="stopped", schema="nornyx.forge.other.v1")
    assert _failed(_observations(stopped={"record": foreign}))[0].startswith(
        "stopped: record schema 'nornyx.forge.other.v1', not ")
    assert _names(_observations(stopped=None)) == ["stopped"]


def test_s9_a_stopped_record_alone_is_insufficient():
    """The base defect: every other observation failed and the record still
    reached stopped -- v1 called that a pass."""
    steps = _observations(
        launcher={"returncode": 7},
        runtime={"status": 500, "schema": None, "instance": OTHER_TOKEN},
        state={"status": 500, "json": "invalid", "initialized": _ABSENT},
        page={"status": 500},
        stop={"status": 500, "json": "invalid", "stopping": None, "instance": None},
    )
    verdict = evaluate_smoke_observations(steps)
    assert verdict["result"] == "fail"
    assert [entry.split(":", 1)[0] for entry in verdict["failed"]] == [
        "launcher", "get /api/runtime", "get /api/state", "get /", "stop"]
    only_stopped = [step for step in _observations() if step["step"] == "stopped"]
    verdict = evaluate_smoke_observations(only_stopped)
    assert verdict["result"] == "fail"
    assert verdict["failed"][:2] == ["launcher: not observed", "runtime_record: not observed"]
    assert verdict["failed"][-1] == "stopped: no recorded instance token to compare against"


def test_the_launcher_and_the_ready_record_are_required_too():
    assert _names(_observations(launcher={"returncode": 2})) == ["launcher"]
    assert _failed(_observations(launcher={"returncode": None, "timed_out": True})) == [
        "launcher: the launcher did not return within its timeout"]
    assert _names(_observations(launcher=None)) == ["launcher"]
    failed = _ready_record(status="failed", reason="git was not found")
    assert _names(_observations(record={"record": failed})) == ["runtime_record"]
    assert _names(_observations(record={"record": _ready_record(status="starting")})) == ["runtime_record"]
    # A record without a usable shape leaves every token comparison with
    # nothing to compare against, and says so at each of them.
    for broken in (None, {"status": "ready"}, _ready_record(schema="other"),
                   _ready_record(instance=""), _ready_record(port="8710"),
                   _ready_record(port=70000), _ready_record(port=0), _ready_record(port=True)):
        failed = _failed(_observations(record={"record": broken}))
        assert [entry.split(":", 1)[0] for entry in failed] == [
            "runtime_record", "get /api/runtime", "stop", "stopped"], broken
        assert failed[1:] == [f"{name}: no recorded instance token to compare against"
                              for name in ("get /api/runtime", "stop", "stopped")], broken


def test_an_observation_made_twice_is_not_judged_as_either():
    steps = _observations() + [dict(_canonical()["runtime"])]
    assert _failed(steps) == [
        "get /api/runtime: observed 2 times, so there is no one observation to judge"]
    steps = _observations() + [{"step": "get", "path": "/api/runtime", "status": 500}]
    assert _names(steps) == ["get /api/runtime"]


# The smoke's own recording, over a scripted launcher and listener. No child
# process and no interpreter exist; what runs is the smoke's recording and
# its judging, which is what these tests are about.

_DEFAULT = object()


def _scripted_runtime(monkeypatch: pytest.MonkeyPatch, *, returncode: int = 0,
                      record=_DEFAULT, answers: dict | None = None,
                      stop: tuple | None = None, stops: bool = True,
                      run_raises: BaseException | None = None,
                      get_raises: dict | None = None,
                      post_raises: BaseException | None = None) -> dict:
    state: dict = {}
    if record is _DEFAULT:
        record = _ready_record()
    answers = answers or {
        "/api/runtime": (200, json.dumps({"schema": RUNTIME_SCHEMA, "instance": TOKEN,
                                          "port": 8710}).encode("utf-8"), "application/json"),
        "/api/state": (200, b"{\"initialized\": false, \"providers\": [\"claude\", \"codex\"]}",
                       "application/json"),
        "/": (200, b"<title>Nornyx Forge</title>", "text/html; charset=utf-8"),
    }
    # Longer than the bounds the report applies, so the bounds are measured;
    # multi-byte padding, so a cut in bytes and a cut in characters differ.
    stop = stop or (200, json.dumps({"stopping": True, "instance": TOKEN,
                                     "padding": "\u00f8" * 300},
                                    ensure_ascii=False).encode("utf-8"))
    state["stop_body"] = stop[1]
    launcher_output = "x" * (builder.OUTPUT_LIMIT + 100)

    def run(argv, **kwargs):
        assert argv[:2] == ["cmd.exe", "/c"] and argv[2].endswith("Forge.cmd")
        assert "--no-browser" in argv and argv[argv.index("--port") + 1] == "0"
        runtime_dir = Path(argv[argv.index("--runtime-dir") + 1])
        runtime_dir.mkdir(parents=True)
        state["record"] = runtime_dir / "project.json"
        if record is not None:
            state["record"].write_text(json.dumps(record), encoding="utf-8")
        state["env"] = kwargs["env"]
        state["cwd"] = kwargs["cwd"]
        if run_raises is not None:
            raise run_raises
        return subprocess.CompletedProcess(argv, returncode, launcher_output, "")

    def get(port, path, timeout=5.0):
        state.setdefault("gets", []).append((port, path))
        if get_raises and path in get_raises:
            raise get_raises[path]
        return answers[path]

    def post(port, path, payload, timeout=5.0):
        state["stop"] = (port, path, payload)
        if post_raises is not None:
            raise post_raises
        if stops:
            current = json.loads(state["record"].read_text(encoding="utf-8"))
            current["status"] = "stopped"
            state["record"].write_text(json.dumps(current), encoding="utf-8")
        return stop

    monkeypatch.setattr(builder.subprocess, "run", run)
    monkeypatch.setattr(builder, "_get", get)
    monkeypatch.setattr(builder, "_post_json", post)
    return state


def test_the_smoke_records_every_observation_and_derives_its_result_from_them(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    state = _scripted_runtime(monkeypatch)
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert report["schema"] == SMOKE_SCHEMA and report["launcher"] == "Forge.cmd"
    assert report["result"] == "pass" == report["verdict"]["result"]
    assert report["verdict"]["failed"] == []
    assert report["result"] == evaluate_smoke_observations(report["steps"])["result"]
    assert [builder._identity(step) for step in report["steps"]] == list(SMOKE_REQUIRED)
    assert state["stop"][1:] == ("/api/runtime/stop", {"actor": SMOKE_ACTOR})
    assert state["gets"] == [(8710, "/api/runtime"), (8710, "/api/state"), (8710, "/")]
    assert state["env"]["USERPROFILE"] == state["env"]["HOME"] != os.environ.get("USERPROFILE")
    runtime_step = report["steps"][2]
    assert runtime_step["schema"] == RUNTIME_SCHEMA and runtime_step["instance"] == TOKEN
    assert report["steps"][3]["initialized"] is False
    assert report["steps"][4]["content_type"].startswith("text/html")
    assert report["steps"][5]["stopping"] is True and report["steps"][5]["instance"] == TOKEN
    assert report["steps"][6]["record"]["status"] == "stopped"
    assert not Path(state["cwd"]).exists(), "the scratch is removed after the run"
    assert report["steps"][0]["timed_out"] is False, "the judged fact is recorded on both branches"
    # The bounds, measured: launcher output and the stop body are cut.
    assert len(report["steps"][0]["stdout"]) == builder.OUTPUT_LIMIT
    # The stop body is cut in BYTES before it is decoded, so a 1 MiB body is
    # never decoded whole: the recorded string is the first FACT_LIMIT bytes
    # decoded, a split multi-byte character replaced, not the first
    # FACT_LIMIT characters (measured under inspection: only a multi-byte
    # body tells the two apart).
    raw = state["stop_body"]
    assert report["steps"][5]["body"] == raw[:builder.FACT_LIMIT].decode("utf-8", "replace")
    assert len(raw[:builder.FACT_LIMIT].decode("utf-8", "replace")) < builder.FACT_LIMIT


def test_a_launcher_that_never_returns_is_recorded_as_timed_out(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    late = subprocess.TimeoutExpired(cmd=["cmd.exe"], timeout=120,
                                     output="late " * 200, stderr="")
    _scripted_runtime(monkeypatch, run_raises=late)
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    launcher = report["steps"][0]
    assert launcher["returncode"] is None and launcher["timed_out"] is True
    assert len(launcher["stdout"]) == builder.OUTPUT_LIMIT and launcher["stderr"] == ""
    assert report["result"] == "fail"
    assert report["verdict"]["failed"] == ["launcher: the launcher did not return within its timeout"]
    assert len(report["steps"]) == 7, "the runtime the launcher started is still observed"


def test_an_unreachable_route_is_recorded_and_the_remaining_routes_are_still_read(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    refused = ConnectionRefusedError("[WinError 10061] refused")
    state = _scripted_runtime(monkeypatch, get_raises={"/api/state": refused})
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert report["steps"][3] == {"step": "get", "path": "/api/state", "status": None,
                                  "error": "ConnectionRefusedError: [WinError 10061] refused"}
    assert [path for _, path in state["gets"]] == ["/api/runtime", "/api/state", "/"]
    assert report["result"] == "fail"
    assert report["verdict"]["failed"] == [
        "get /api/state: HTTP None, not 200 (ConnectionRefusedError: [WinError 10061] refused)"]


def test_a_stop_request_that_raises_is_recorded_and_the_stopped_wait_still_runs(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _scripted_runtime(monkeypatch, post_raises=ConnectionResetError("reset by the listener"))
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=0.6)
    assert report["steps"][5] == {"step": "stop", "status": None,
                                  "error": "ConnectionResetError: reset by the listener"}
    assert report["steps"][6] == {"step": "stopped", "record": None}
    assert report["result"] == "fail"
    assert report["verdict"]["failed"] == [
        "stop: HTTP None, not 200 (ConnectionResetError: reset by the listener)",
        "stopped: no stopped record within the wait"]


def test_s9_through_the_smoke_the_base_defect_no_longer_passes(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Measured at the base: launcher exit code 7, HTTP 500 on every route
    with a foreign instance token, a failed stop, and a record that reached
    stopped anyway -- and `result` was `pass`."""
    failing = {path: (500, b"{\"instance\": \"WRONG-token\"}", "application/json")
               for path in ("/api/runtime", "/api/state", "/")}
    _scripted_runtime(monkeypatch, returncode=7, answers=failing,
                      stop=(500, b"stop route failed"))
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert report["steps"][-1]["record"]["status"] == "stopped"
    assert report["result"] == "fail"
    assert [entry.split(":", 1)[0] for entry in report["verdict"]["failed"]] == [
        "launcher", "get /api/runtime", "get /api/state", "get /", "stop"]


def test_s4_through_the_smoke_a_body_that_is_not_json_is_recorded_not_raised(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    answers = {"/api/runtime": (200, b"<html>not json at all", "text/html"),
               "/api/state": (200, b"[1, 2]", "application/json"),
               "/": (200, b"<title>x</title>", "text/html")}
    _scripted_runtime(monkeypatch, answers=answers)
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert report["result"] == "fail"
    assert report["steps"][2]["json"] == "invalid" and "instance" not in report["steps"][2]
    assert report["steps"][3]["json"] == "not an object"
    assert report["verdict"]["failed"] == [
        "get /api/runtime: body is 'invalid', not a JSON object",
        "get /api/state: body is 'not an object', not a JSON object"]


def test_s8_through_the_smoke_a_runtime_that_never_stops_is_not_a_pass(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _scripted_runtime(monkeypatch, stops=False)
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=0.6)
    assert report["result"] == "fail"
    assert report["steps"][-1] == {"step": "stopped", "record": None}
    assert report["verdict"]["failed"] == ["stopped: no stopped record within the wait"]


def test_a_record_that_never_says_ready_ends_the_smoke_with_the_rest_unobserved(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    failed = _ready_record(status="failed", reason="git was not found")
    state = _scripted_runtime(monkeypatch, record=failed)
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert report["result"] == "fail"
    assert "gets" not in state and "stop" not in state, "a runtime that is not ready is not asked"
    assert report["verdict"]["failed"][0] == "runtime_record: record status 'failed', not 'ready'"
    assert report["verdict"]["failed"][1:] == [f"{name}: not observed" for name in SMOKE_REQUIRED[2:]]
    _scripted_runtime(monkeypatch, record=None)
    report = smoke_bundle(tmp_path / "dist", timeout=1.2, stop_timeout=5)
    assert report["result"] == "fail"
    assert report["verdict"]["failed"][0] == "runtime_record: no runtime record was observed"


def test_a_recorded_fact_is_bounded_and_a_hostile_listener_is_not_this_runtime(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    huge = "x" * 5000
    answers = {"/api/runtime": (200, json.dumps({"schema": RUNTIME_SCHEMA, "instance": huge,
                                                 "port": 8710}).encode("utf-8"), "application/json"),
               "/api/state": (200, b"{\"initialized\": {\"nested\": true}}", "application/json"),
               "/": (200, b"<title>x</title>", "text/html")}
    _scripted_runtime(monkeypatch, answers=answers)
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert len(report["steps"][2]["instance"]) == builder.FACT_LIMIT + 3
    assert report["steps"][3]["initialized"] == "dict"
    assert report["result"] == "fail"
    assert report["verdict"]["failed"][0].startswith("get /api/runtime: instance 'xxx")
    assert report["verdict"]["failed"][1] == (
        "get /api/state: no boolean 'initialized': not usable as the onboarding state response")


def test_the_result_has_one_source_and_the_smoke_shares_the_runtimes_schema():
    """`result` is assigned once, from the verdict; the smoke's idea of a
    runtime record is the runtime's own; and the verdict speaks no
    governance vocabulary -- it is operator evidence about a bundle."""
    from nornyx_forge import windows_runtime

    source = inspect.getsource(smoke_bundle)
    assert source.count('report["result"]') == 1
    assert 'report["result"] = report["verdict"]["result"]' in source
    assert "stopped is not None" not in source
    assert RUNTIME_SCHEMA == windows_runtime.RUNTIME_SCHEMA
    assert SMOKE_SCHEMA == "nornyx.forge.windows_bundle_smoke.v2"
    assert SMOKE_ACTOR["kind"] == "human"
    rendered = json.dumps(evaluate_smoke_observations(_observations())).lower()
    for absent in ("approv", "ready_for", "eligib", "inspect", "verified", "confin"):
        assert absent not in rendered, absent


def test_main_refuses_a_non_pass_smoke_by_name_and_writes_the_report(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    for name in ("copy_tree", "install_dependencies", "write_bundle_marker",
                 "write_launcher", "verify_bundle"):
        monkeypatch.setattr(builder, name, lambda *a, **k: None)
    monkeypatch.setattr(builder, "_source_commit", lambda root: None)
    failing = {"schema": SMOKE_SCHEMA, "steps": [], "result": "fail",
               "verdict": {"failed": ["get /: HTTP 404, not 200", "stop: not observed"],
                           "result": "fail"}}
    monkeypatch.setattr(builder, "smoke_bundle", lambda dist: failing)
    dist = tmp_path / "forge-windows"
    expected = re.escape("did not pass: get /: HTTP 404, not 200; stop: not observed")
    with pytest.raises(BundleError, match=expected):
        builder.main(["--dist", str(dist), "--smoke"])
    written = json.loads((tmp_path / "forge-windows-smoke.json").read_text(encoding="utf-8"))
    assert written["result"] == "fail"


# The security inspection of this slice: what a hostile or malformed listener
# on the scratch port, or an oversized record, can and cannot do to the smoke.

def test_a_nested_body_or_record_is_invalid_not_a_raise(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    nested = b"[" * 200000
    assert builder._parse_object(nested) == (None, "invalid")
    (tmp_path / "nested.json").write_bytes(nested)
    assert builder._read_record(tmp_path / "nested.json") is None
    answers = {"/api/runtime": (200, nested, "application/json"),
               "/api/state": (200, b"{\"initialized\": false}", "application/json"),
               "/": (200, b"<title>x</title>", "text/html")}
    state = _scripted_runtime(monkeypatch, answers=answers)
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert report["result"] == "fail" and report["steps"][2]["json"] == "invalid"
    assert not Path(state["cwd"]).exists()


def test_the_scratch_does_not_outlive_a_raise(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    state = _scripted_runtime(monkeypatch)

    def exploding(port, path, timeout=5.0):
        raise RuntimeError("listener exploded")

    monkeypatch.setattr(builder, "_get", exploding)
    with pytest.raises(RuntimeError, match="listener exploded"):
        smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert not Path(state["cwd"]).exists(), "a raise left the scratch behind"


def test_the_record_is_kept_as_five_bounded_fields_not_archived(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    oversized = _ready_record(reason="r" * 5000, blob="b" * 100000, pid=4242)
    _scripted_runtime(monkeypatch, record=oversized)
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert report["result"] == "pass"
    kept = report["steps"][1]["record"]
    assert set(kept) <= set(builder.RECORD_FACTS) and "blob" not in kept and "pid" not in kept
    assert len(kept["reason"]) == builder.FACT_LIMIT + 3
    assert len(json.dumps(report)) < 4000, "the report explains; it does not archive"
    assert set(report["steps"][6]["record"]) <= set(builder.RECORD_FACTS)


def test_a_token_longer_than_the_fact_bound_is_not_a_forge_record(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Recorded facts are cut at FACT_LIMIT; a longer token could only ever be
    compared truncated, so it is refused at the record instead."""
    assert builder._record_shape(_ready_record(instance="t" * builder.FACT_LIMIT)) is None
    reason = builder._record_shape(_ready_record(instance="t" * (builder.FACT_LIMIT + 1)))
    assert reason == "record instance token is longer than the recorded-fact bound"
    long_token = "t" * 5000
    assert _names(_observations(record={"record": _ready_record(instance=long_token)})) == [
        "runtime_record", "get /api/runtime", "stop", "stopped"]
    answers = {"/api/runtime": (200, json.dumps({"schema": RUNTIME_SCHEMA, "instance": long_token,
                                                 "port": 8710}).encode("utf-8"), "application/json")}
    state = _scripted_runtime(monkeypatch, record=_ready_record(instance=long_token),
                              answers=answers)
    report = smoke_bundle(tmp_path / "dist", timeout=5, stop_timeout=5)
    assert report["result"] == "fail" and "gets" not in state
    assert report["verdict"]["failed"][0] == (
        "runtime_record: record instance token is longer than the recorded-fact bound")


def _listener(script) -> int:
    """A real loopback listener running `script(connection)` for one client.
    Each script reads the request before it answers."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve() -> None:
        connection, _ = server.accept()
        try:
            script(connection)
        except OSError:
            pass
        finally:
            connection.close()
            server.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def test_a_trickling_listener_cannot_hold_the_smoke_past_its_budget():
    """A REAL loopback listener, not a fake reader: measured under
    inspection, a fake that returned after one byte proved nothing, because
    a real `read` loops receives internally and a trickling body held the
    smoke open for the body's length. Now the whole exchange ends within
    twice the budget, whether the listener trickles its body or its
    headers, and a whole answer still arrives intact."""
    def trickle_body(connection: socket.socket) -> None:
        connection.recv(65536)
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                           b"Content-Length: 100000\r\n\r\n")
        for _ in range(100):
            connection.sendall(b"x")
            time.sleep(0.25)

    def trickle_headers(connection: socket.socket) -> None:
        connection.recv(65536)
        connection.sendall(b"HTTP/1.1 200 OK\r\n")
        for _ in range(100):
            connection.sendall(b"X-Slow: a\r\n")
            time.sleep(0.25)

    port = _listener(trickle_body)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="time budget"):
        builder._get(port, "/", timeout=1.0)
    assert time.monotonic() - started < 3.0
    # Trickled HEADERS end the same way -- unless the host ends them first:
    # measured on the development workstation, an HTTP-aware filter aborts a
    # loopback connection whose response headers arrive incomplete (WinError
    # 10053) before the watchdog fires. Either way the exchange is over
    # within the budget and is an OSError the smoke records as a failure.
    port = _listener(trickle_headers)
    started = time.monotonic()
    with pytest.raises(OSError) as ended:
        builder._get(port, "/", timeout=1.0)
    assert time.monotonic() - started < 3.0
    assert isinstance(ended.value, TimeoutError) or isinstance(ended.value, ConnectionError)

    # A trickle SLOWER than the budget: the watchdog's shutdown does not wake
    # a receive already pending (measured, Windows), so the exchange ends at
    # that receive's own timeout instead -- within twice the budget, never
    # at the trickle's pace.
    def slow_trickle(connection: socket.socket) -> None:
        connection.recv(65536)
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                           b"Content-Length: 100000\r\n\r\n")
        for _ in range(10):
            time.sleep(1.5)
            connection.sendall(b"x")

    port = _listener(slow_trickle)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        builder._get(port, "/", timeout=1.0)
    assert time.monotonic() - started < 2.0 + 1.0

    def whole(connection: socket.socket) -> None:
        # Read the request first: a listener that closes with the request
        # unread provokes a reset, which is not the property under test.
        connection.recv(65536)
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                           b"Content-Length: 6\r\n\r\nabcdef")

    assert builder._get(_listener(whole), "/", timeout=2.0) == (200, b"abcdef", "text/html")

    # Short of what it declared, a body is a broken answer, not the answer
    # (measured under inspection: an early close delivered it without an
    # IncompleteRead, and the page predicate would have accepted it).
    def short(connection: socket.socket) -> None:
        connection.recv(65536)
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                           b"Content-Length: 100000\r\n\r\n<html>hi")

    with pytest.raises(http.client.IncompleteRead):
        builder._get(_listener(short), "/", timeout=2.0)

    # A declared length above the read bound is compared against the bound,
    # and a Content-Length http.client cannot parse is no length at all --
    # never a parse of our own that could raise (measured under inspection:
    # a one-byte latin-1 header and a 5000-digit one each raised ValueError
    # out of the smoke).
    def short_oversize(connection: socket.socket) -> None:
        connection.recv(65536)
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                           b"Content-Length: 2097152\r\n\r\n<html>hi")

    with pytest.raises(http.client.IncompleteRead):
        builder._get(_listener(short_oversize), "/", timeout=2.0)
    for header in (b"\xb2", b"9" * 5000):
        def unparseable(connection: socket.socket, header: bytes = header) -> None:
            connection.recv(65536)
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                               b"Content-Length: " + header + b"\r\n\r\n<html>hi")

        assert builder._get(_listener(unparseable), "/", timeout=2.0) == (
            200, b"<html>hi", "text/html")
    source = inspect.getsource(builder._get) + inspect.getsource(builder._post_json)
    assert source.count("_exchange(") == 2 and "HTTPConnection" not in source
