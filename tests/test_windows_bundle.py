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
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_windows_bundle import (  # noqa: E402
    BUNDLE_MARKER,
    BUNDLE_SCHEMA,
    DEVELOPER,
    DEVELOPER_BOOTSTRAP,
    DEVELOPER_LAUNCHER,
    EMBED_EXECUTABLES,
    LAUNCHERS,
    PTH_LINES,
    SELF_CONTAINED,
    SELF_CONTAINED_LAUNCHER,
    BundleError,
    bundle_manifest,
    copy_tree,
    install_python,
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
    assert source.count('HTTPConnection("127.0.0.1"') == 2, (
        "the smoke's two loopback connections are the builder's only HTTP"
    )
