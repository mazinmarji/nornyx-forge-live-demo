"""A tiny, sealed payload for exercising the installer's refusals.

The real payload is hundreds of megabytes; the installer's refusals (a link, a
foreign folder, another version, a path too long, an elevated process) all
happen before any file is extracted, so they are exercised with installers
built from small payloads that are still REAL payloads: sealed by the same
`seal_payload`, tied to the same commit, pins and lock, and carrying the pinned
embeddable interpreter so the installer's own verification step can run.

What a synthetic payload is NOT: runnable. Its `windows_launch.py` is a
marker. It exists to be installed, refused or verified, never started.

    python synthetic_payload.py --dest D --embed-zip Z --label first
    python synthetic_payload.py --dest D --embed-zip Z --label other --version 0.0.2
    python synthetic_payload.py --dest D --embed-zip Z --label same-version-other-bytes \
        --same-version-as <real payload folder>
    python synthetic_payload.py --dest D --embed-zip Z --label long --long-version --long-path
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _path in (ROOT / "scripts", ROOT / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import build_windows_bundle as bundle  # noqa: E402

from nornyx_forge.windows_payload import PAYLOAD_MANIFEST, read_manifest  # noqa: E402

#: The longest version a manifest accepts: a 64-character token.
LONG_VERSION = "9." + "9" * 62
#: A path of 158 UTF-16 code units, under the payload rule's 160.
LONG_PATH = "pad/" + "x" * 150 + ".txt"


def make(dest: Path, *, embed_zip: Path, label: str, version: str,
         long_path: bool, repo_root: Path = ROOT) -> dict:
    """Build and seal the payload at `dest` (absent or empty); returns its
    manifest."""
    if dest.exists() and any(dest.iterdir()):
        raise bundle.BundleError(f"{dest} already holds files")
    commit = bundle.require_clean_commit(repo_root)
    pins = bundle.load_pins(repo_root, commit)
    lock = bundle.load_lock(repo_root, commit, pins)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "pyproject.toml").write_text(
        f'[project]\nname = "synthetic"\nversion = "{version}"\n', encoding="utf-8", newline="")
    package = dest / "src" / "nornyx_forge"
    package.mkdir(parents=True)
    for name in ("__init__.py", "windows_payload.py"):
        shutil.copyfile(repo_root / "src" / "nornyx_forge" / name, package / name)
    (package / "windows_launch.py").write_text(
        '"""A synthetic payload is installed, refused and verified, never started."""\n',
        encoding="utf-8", newline="")
    (dest / "synthetic-payload.txt").write_text(f"{label}\n", encoding="utf-8", newline="")
    if long_path:
        padded = dest.joinpath(*LONG_PATH.split("/"))
        padded.parent.mkdir(parents=True)
        padded.write_text("pad\n", encoding="utf-8", newline="")
    bundle.install_python(dest, embed_zip, pins["interpreter"]["archive_sha256"],
                          pins["target"]["abi"])
    bundle.write_bundle_marker(dest, mode=bundle.SELF_CONTAINED,
                               interpreter_sha256=pins["interpreter"]["archive_sha256"],
                               source_commit=commit)
    bundle.write_launcher(dest, bundle.SELF_CONTAINED)
    return bundle.seal_payload(dest, pins=pins, lock=lock, commit=commit,
                               epoch=bundle.source_date_epoch(repo_root, commit))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dest", type=Path, required=True)
    parser.add_argument("--embed-zip", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--version", default="0.0.1")
    parser.add_argument("--long-version", action="store_true")
    parser.add_argument("--long-path", action="store_true")
    parser.add_argument("--same-version-as", type=Path, default=None,
                        help="take the version of this sealed payload folder")
    arguments = parser.parse_args(argv)
    version = arguments.version
    if arguments.long_version:
        version = LONG_VERSION
    if arguments.same_version_as is not None:
        version = read_manifest(arguments.same_version_as)["version"]
    manifest = make(arguments.dest, embed_zip=arguments.embed_zip, label=arguments.label,
                    version=version, long_path=arguments.long_path)
    print(json.dumps({"payload_sha256": manifest["payload_sha256"],
                      "version": manifest["version"], "manifest": PAYLOAD_MANIFEST}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
