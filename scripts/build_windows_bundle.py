"""Build the Windows bundle: the container's install pattern, in a folder.

THE PACKAGING DIRECTION IS THE REPOSITORY'S OWN. `resolve_packaged_root`
pins the deployment assumption -- the package sits at `<root>/src/...`
with the governance tree beside it, exactly what the Dockerfile builds --
and refuses any layout that breaks it. A frozen-executable bundle would
move `__file__` into a private archive and be refused by design. So the
Windows bundle IS the incumbent layout: the same tree the Dockerfile
copies, a private dependency library, and an embedded CPython whose path
file puts `src` FIRST -- source shadows any installed copy, the same
order the development environment proves daily.

The bundle layout:

    <dist>/
      pyproject.toml README.md BRD.md     (the Dockerfile's copy set)
      src/                                (imported directly, shadows pylib)
      .nornyx/                            (contracts and evidence)
      pylib/                              (dependency closure, project pruned)
      python/                             (embedded CPython, when supplied)
      Forge.cmd                           (opens the onboarding surface)

The embedded interpreter is supplied by the builder as a zip WITH its
expected sha256 -- this script verifies and refuses a mismatch rather
than downloading anything itself. Without one, the build is a developer
bundle that runs on a system Python; the launcher and layout are
identical either way.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The copy set, and nothing else. A test compares this against the
#: Dockerfile's COPY sources so the two deployment surfaces cannot drift
#: apart silently.
BUNDLE_TREE = ("pyproject.toml", "README.md", "src", ".nornyx", "BRD.md")

#: Never carried into a bundle: developer state, caches, local machinery.
EXCLUDED_NAMES = {"__pycache__", ".venv", ".git", "node_modules"}

#: The interpreter path file, in resolution order. `..\\src` before
#: `..\\pylib` is load-bearing: the shipped source must shadow any copy of
#: the project that dependency installation dragged into the library.
PTH_LINES = ("python313.zip", ".", "..\\src", "..\\pylib")

LAUNCHER = """@echo off
rem Forge: open the onboarding surface for the default project.
rem The project directory is passed EXPLICITLY -- the launch directory
rem selects nothing, per the FORGE_ROOT doctrine.
"%~dp0python\\python.exe" -c "from nornyx_forge.cli import app; app()" onboard --project-dir "%USERPROFILE%\\ForgeProject" %*
"""


class BundleError(Exception):
    """A build input or state this script refuses."""


def bundle_manifest() -> tuple[str, ...]:
    """What the bundle carries: the Dockerfile's copy set, verbatim."""
    return BUNDLE_TREE


def _copy_filter(directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in EXCLUDED_NAMES}


def copy_tree(repo_root: Path, dist: Path) -> None:
    if dist.exists() and any(dist.iterdir()):
        raise BundleError(
            f"{dist} already contains files; a bundle is built fresh, never "
            "layered over an old one"
        )
    dist.mkdir(parents=True, exist_ok=True)
    for entry in bundle_manifest():
        source = repo_root / entry
        target = dist / entry
        if source.is_dir():
            shutil.copytree(source, target, ignore=_copy_filter)
        else:
            shutil.copy2(source, target)


def _installer_command(python_exe: str) -> list[str]:
    """The installer that actually exists here, probed rather than assumed.

    A uv-managed environment ships no pip module -- measured on this
    repository's own venv, where `python -m pip` answers `No module named
    pip`. The probe asks; the fallback is uv's pip interface pointed at the
    same interpreter; and an environment with neither is refused by name
    instead of failing three layers down.
    """
    probe = subprocess.run(
        [python_exe, "-m", "pip", "--version"],
        capture_output=True, text=True,
    )
    if probe.returncode == 0:
        return [python_exe, "-m", "pip", "install", "--quiet"]
    uv = shutil.which("uv")
    if uv is not None:
        # --native-tls: trust the system certificate store, which is where a
        # Windows machine behind TLS inspection keeps the issuer uv needs.
        return [uv, "pip", "install", "--quiet", "--native-tls",
                "--python", python_exe]
    raise BundleError(
        "no installer is available: the interpreter has no pip module and "
        "uv is not on PATH"
    )


def install_dependencies(dist: Path, python_exe: str) -> None:
    """The dependency closure into pylib, with the project itself pruned.

    Installing `.[demo]` also installs a non-editable copy of this project;
    left in place it would sit on the import path behind `src` -- dormant
    under the pinned path order, but a second copy of the code is a second
    place to read it wrong, so it is removed.
    """
    subprocess.run(
        [*_installer_command(python_exe),
         "--target", str(dist / "pylib"), f"{dist}[demo]"],
        check=True,
    )
    for own in ("nornyx_forge", "demo_app"):
        installed = dist / "pylib" / own
        if installed.is_dir():
            shutil.rmtree(installed)
    # Building the project sdist from the dist tree leaves a setuptools
    # `build/` directory beside it -- measured on the first real build. It
    # is a build byproduct, not bundle content.
    leftover = dist / "build"
    if leftover.is_dir():
        shutil.rmtree(leftover)


def install_python(dist: Path, embed_zip: Path, expected_sha256: str) -> None:
    digest = hashlib.sha256(embed_zip.read_bytes()).hexdigest()
    if digest != expected_sha256.lower():
        raise BundleError(
            "the embedded interpreter zip does not match its declared "
            f"sha256: expected {expected_sha256.lower()}, measured {digest}"
        )
    target = dist / "python"
    with zipfile.ZipFile(embed_zip) as archive:
        archive.extractall(target)
    pth_files = list(target.glob("python*._pth"))
    if len(pth_files) != 1:
        raise BundleError(
            f"expected exactly one python*._pth in the embed zip; found "
            f"{len(pth_files)}"
        )
    zip_name = pth_files[0].name.replace("._pth", ".zip")
    lines = (zip_name, *PTH_LINES[1:])
    pth_files[0].write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")


def write_launcher(dist: Path) -> None:
    (dist / "Forge.cmd").write_text(LAUNCHER, encoding="utf-8", newline="")


def verify_bundle(dist: Path) -> None:
    """The bundle proves itself: its own interpreter resolves its own root."""
    python = dist / "python" / "python.exe"
    if not python.exists():
        return  # developer bundle: verified by the system interpreter's tests
    completed = subprocess.run(
        [str(python), "-c",
         "import nornyx_forge.cli, demo_app.main; "
         "from nornyx_forge.subject_bootstrap import resolve_packaged_root; "
         "print(resolve_packaged_root())"],
        capture_output=True, text=True,
    )
    if completed.returncode != 0:
        raise BundleError(
            f"the built bundle cannot resolve itself:\n{completed.stderr}"
        )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist" / "forge-windows")
    parser.add_argument("--python-embed", type=Path, default=None,
                        help="CPython embeddable zip, supplied by the builder")
    parser.add_argument("--python-embed-sha256", default=None,
                        help="Expected sha256 of the embed zip; required with it")
    arguments = parser.parse_args(argv)
    if (arguments.python_embed is None) != (arguments.python_embed_sha256 is None):
        raise BundleError(
            "--python-embed and --python-embed-sha256 travel together: an "
            "unverified interpreter is not bundled"
        )
    copy_tree(ROOT, arguments.dist)
    install_dependencies(arguments.dist, sys.executable)
    if arguments.python_embed is not None:
        install_python(arguments.dist, arguments.python_embed,
                       arguments.python_embed_sha256)
    write_launcher(arguments.dist)
    verify_bundle(arguments.dist)
    print(f"bundle built: {arguments.dist}")


if __name__ == "__main__":
    main()
