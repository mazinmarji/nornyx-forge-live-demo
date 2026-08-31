"""The Windows bundle builder: the container's layout, provably mirrored.

THE ANTI-DRIFT PIN is the first test: the bundle's copy set is compared
against the Dockerfile's COPY sources, parsed from the Dockerfile itself,
so the two deployment surfaces cannot diverge silently. The rest holds
the builder to the packaging doctrine: the built tree carries every
structural marker `resolve_packaged_root` demands, the interpreter path
file puts `src` before the dependency library (source shadows any
installed copy), the project's own packages are pruned from that library,
an unverified interpreter is refused, and nothing developer-local rides
into a bundle.
"""

from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_windows_bundle import (  # noqa: E402
    PTH_LINES,
    BundleError,
    bundle_manifest,
    copy_tree,
    install_python,
    write_launcher,
)


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


def test_an_unverified_interpreter_is_refused(tmp_path: Path):
    fake_zip = tmp_path / "python-embed.zip"
    with zipfile.ZipFile(fake_zip, "w") as archive:
        archive.writestr("python313._pth", "python313.zip\n")
    with pytest.raises(BundleError, match="does not match its declared sha256"):
        install_python(tmp_path / "dist", fake_zip, "0" * 64)


def test_the_path_file_puts_source_before_the_library(tmp_path: Path):
    """THE SHADOWING PIN: `..\\src` resolves before `..\\pylib`, so the
    shipped source is the single import truth even if a project copy
    survives in the dependency library."""
    fake_zip = tmp_path / "python-embed.zip"
    with zipfile.ZipFile(fake_zip, "w") as archive:
        archive.writestr("python313._pth", "python313.zip\nimport site\n")
        archive.writestr("python.exe", "not a real interpreter")
    digest = hashlib.sha256(fake_zip.read_bytes()).hexdigest()
    dist = tmp_path / "dist"
    install_python(dist, fake_zip, digest)
    lines = (dist / "python" / "python313._pth").read_text(
        encoding="utf-8"
    ).splitlines()
    assert lines == list(PTH_LINES)
    assert lines.index("..\\src") < lines.index("..\\pylib")


def test_an_embed_zip_with_ambiguous_path_files_is_refused(tmp_path: Path):
    fake_zip = tmp_path / "python-embed.zip"
    with zipfile.ZipFile(fake_zip, "w") as archive:
        archive.writestr("python313._pth", "a\n")
        archive.writestr("python314._pth", "b\n")
    digest = hashlib.sha256(fake_zip.read_bytes()).hexdigest()
    with pytest.raises(BundleError, match="exactly one"):
        install_python(tmp_path / "dist", fake_zip, digest)


def test_the_launcher_opens_onboarding_with_an_explicit_project(tmp_path: Path):
    write_launcher(tmp_path)
    launcher = (tmp_path / "Forge.cmd").read_text(encoding="utf-8")
    assert "onboard" in launcher
    assert "--project-dir" in launcher, "the launch must pass the project explicitly"
    assert "%USERPROFILE%" in launcher
    assert "python\\python.exe" in launcher
    assert str(ROOT) not in launcher, "a build-machine path leaked into the launcher"


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
