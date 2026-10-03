"""Resolve the packages the NSIS build installs, from a dated archive snapshot.

This is the tool that WROTE `nsis-build-debs.json`; CI never runs it. CI reads
the lock it wrote, fetches every package the lock names, and refuses any whose
size or SHA-256 differs. The tool is kept so the lock can be renewed on
purpose, and so the way it was made is reviewable and tested.

WHAT IT DOES. Given the snapshot, the suites and components, the packages to
install and the dpkg status of the pinned image, it

* fetches each suite's `InRelease` and checks its OpenPGP signature with
  `gpgv` against a keyring you name, accepting only the Ubuntu archive signing
  keys listed in `ARCHIVE_KEY_FINGERPRINTS`;
* fetches each `Packages.xz` the signed `InRelease` lists and refuses one
  whose size or SHA-256 differs from that list;
* resolves the dependency closure of the requested packages over the packages
  the image already holds (Depends and Pre-Depends; never Recommends), and
  writes each package to install with its URL, size and SHA-256 as the signed
  index states them.

WHAT IT IS NOT. It is not `apt`. It reads the same indexes and applies the
same rules for the cases the closure meets, but it is a smaller program with
its own bugs, so its output is a CANDIDATE: the install inside the container
(`build-inside.sh`) is the check that the set installs, and it compares the
installed set with the lock afterwards. Where the closure meets a choice it
cannot make without guessing (a virtual package with several providers and no
installed one), it stops and says so; the answer is to name the package in
`container.install`. It resolves for one architecture, amd64, plus `all`.

WHAT IS TRUSTED. The keyring you pass is the trust root: the tool cannot say
where that file came from. The signature chain is `InRelease` -> `Packages.xz`
-> each package's size and SHA-256 -> the lock. The `.deb` files carry no
signature of their own that this tool checks.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

SNAPSHOT_HOST = "https://snapshot.ubuntu.com/ubuntu"
#: Ubuntu Archive Automatic Signing Key (2012) and (2018), as the distribution's
#: `ubuntu-keyring` package lists them.
ARCHIVE_KEY_FINGERPRINTS = frozenset({
    "790BC7277767219C42C86F933B4FE6ACC0B21F32",
    "F6ECB3762474EDA9D21B7022871920D1991BC93C",
})
_FIELD = re.compile(r"^([A-Za-z0-9-]+):[ \t]*(.*)$")
_ALT = re.compile(r"^\s*([a-z0-9][a-z0-9+.-]*)(?::(?:any|native))?\s*(?:\(\s*(<<|<=|=|>=|>>|<|>)\s*([^)\s]+)\s*\))?\s*$")
#: dpkg reads the deprecated `<` as `<=` and `>` as `>=`; the strict forms are `<<` and `>>`.
_OPS = {"<<": lambda c: c < 0, "<": lambda c: c <= 0, "<=": lambda c: c <= 0, "=": lambda c: c == 0,
        ">=": lambda c: c >= 0, ">>": lambda c: c > 0, ">": lambda c: c >= 0}


class ResolveError(Exception):
    """An input this tool refuses, or a closure it cannot decide."""


# ---------------------------------------------------------------------------
# Debian versions and control data
# ---------------------------------------------------------------------------

def _order(char: str) -> int:
    if char == "":
        return 0
    if char == "~":
        return -1
    if char in "0123456789":
        return 0
    if char.isascii() and char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(left: str, right: str) -> int:
    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and left[i] not in "0123456789") or (
                j < len(right) and right[j] not in "0123456789"):
            difference = _order(left[i] if i < len(left) else "") - _order(
                right[j] if j < len(right) else "")
            if difference:
                return difference
            i += 1
            j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        first = 0
        while i < len(left) and left[i] in "0123456789" and j < len(right) and right[j] in "0123456789":
            first = first or ord(left[i]) - ord(right[j])
            i += 1
            j += 1
        if i < len(left) and left[i] in "0123456789":
            return 1
        if j < len(right) and right[j] in "0123456789":
            return -1
        if first:
            return first
    return 0


def _split_version(version: str) -> tuple[int, str, str]:
    epoch, colon, rest = version.partition(":")
    if not colon:
        epoch, rest = "0", version
    upstream, dash, revision = rest.rpartition("-")
    if not dash:
        upstream, revision = rest, "0"
    return int(epoch), upstream, revision


def compare_versions(left: str, right: str) -> int:
    """dpkg's version order: negative, zero or positive."""
    (epoch_l, upstream_l, revision_l), (epoch_r, upstream_r, revision_r) = (
        _split_version(left), _split_version(right))
    if epoch_l != epoch_r:
        return epoch_l - epoch_r
    return _compare_part(upstream_l, upstream_r) or _compare_part(revision_l, revision_r)


def parse_stanzas(text: str) -> list[dict[str, str]]:
    """Control-file paragraphs as dictionaries (continuation lines are joined)."""
    stanzas, current, last = [], {}, None
    for line in text.splitlines():
        if not line.strip():
            if current:
                stanzas.append(current)
            current, last = {}, None
        elif line[0] in " \t":
            if last is None:
                raise ResolveError(f"a continuation line with no field: {line[:60]!r}")
            current[last] += "\n" + line.strip()
        else:
            match = _FIELD.match(line)
            if match is None:
                raise ResolveError(f"not a control field: {line[:60]!r}")
            last = match.group(1)
            current[last] = match.group(2)
    if current:
        stanzas.append(current)
    return stanzas


def parse_relation(field: str) -> list[list[tuple[str, str | None, str | None]]]:
    """`a (>= 1), b | c` as groups of alternatives (name, operator, version).
    The grammar here has no place for an architecture or profile restriction, so
    one is refused as "not a relationship" and never ignored."""
    groups = []
    for part in field.replace("\n", " ").split(","):
        if not part.strip():
            continue
        alternatives = []
        for text in part.split("|"):
            match = _ALT.match(text)
            if match is None:
                raise ResolveError(f"not a relationship: {text.strip()!r}")
            alternatives.append((match.group(1), match.group(2), match.group(3)))
        groups.append(alternatives)
    return groups


def _provides(stanza: dict[str, str]) -> list[tuple[str, str | None]]:
    provided = []
    for group in parse_relation(stanza.get("Provides", "")):
        for name, operator, version in group:
            provided.append((name, version if operator == "=" else None))
    return provided


def _meets(operator: str | None, wanted: str | None, actual: str | None) -> bool:
    if operator is None:
        return True
    return actual is not None and _OPS[operator](compare_versions(actual, wanted))


def satisfied_by(alternative: tuple, stanza: dict[str, str]) -> bool:
    """Does this package (by its name or by what it provides) meet one alternative?"""
    name, operator, wanted = alternative
    if stanza["Package"] == name and _meets(operator, wanted, stanza["Version"]):
        return True
    return any(provided == name and _meets(operator, wanted, version)
               for provided, version in _provides(stanza))


# ---------------------------------------------------------------------------
# Resolving
# ---------------------------------------------------------------------------

class Archive:
    """The packages the snapshot offers: every version of every name."""

    def __init__(self, stanzas: list[dict[str, str]]) -> None:
        self.versions: dict[str, dict[str, dict[str, str]]] = {}
        for stanza in stanzas:
            known = self.versions.setdefault(stanza["Package"], {})
            previous = known.get(stanza["Version"])
            if previous is not None and previous.get("SHA256") != stanza.get("SHA256"):
                raise ResolveError(f"{stanza['Package']} {stanza['Version']} is listed with "
                                   "two different SHA-256 values")
            known[stanza["Version"]] = stanza

    def best(self, alternative: tuple) -> dict[str, str] | None:
        """The highest version of the named package that meets the alternative."""
        name, operator, wanted = alternative
        fits = [stanza for version, stanza in self.versions.get(name, {}).items()
                if _meets(operator, wanted, version)]
        if not fits:
            return None
        return max(fits, key=_VersionKey)

    def providers(self, alternative: tuple) -> list[dict[str, str]]:
        """The highest version of each package that provides what is named."""
        found = {}
        for name, versions in sorted(self.versions.items()):
            for stanza in versions.values():
                if name != alternative[0] and satisfied_by(alternative, stanza):
                    if name not in found or compare_versions(
                            stanza["Version"], found[name]["Version"]) > 0:
                        found[name] = stanza
        return list(found.values())


class _VersionKey:
    def __init__(self, stanza: dict[str, str]) -> None:
        self.version = stanza["Version"]

    def __lt__(self, other: "_VersionKey") -> bool:
        return compare_versions(self.version, other.version) < 0


def _depends(stanza: dict[str, str]) -> list[list[tuple]]:
    return parse_relation(stanza.get("Pre-Depends", "")) + parse_relation(stanza.get("Depends", ""))


def resolve(archive: Archive, installed: dict[str, dict[str, str]],
            requested: list[str]) -> dict[str, dict[str, str]]:
    """The packages to install: the requested ones at their highest version, then
    whatever their dependencies need that the state does not already meet,
    until every Depends and Pre-Depends of the final state is met and no
    Breaks or Conflicts is violated. Returns name -> the archive's stanza."""
    state = dict(installed)
    chosen: dict[str, dict[str, str]] = {}
    for name in requested:
        stanza = archive.best((name, None, None))
        if stanza is None:
            raise ResolveError(f"the snapshot offers no package named {name}")
        if name in installed and installed[name]["Version"] == stanza["Version"]:
            continue
        state[name] = chosen[name] = stanza
    for _ in range(10_000):
        for name in sorted(state):
            missing = next((group for group in _depends(state[name])
                            if not any(satisfied_by(alt, other) for alt in group
                                       for other in state.values())), None)
            if missing is not None:
                stanza = _choose(archive, state, name, missing)
                state[stanza["Package"]] = chosen[stanza["Package"]] = stanza
                break
        else:
            _check_conflicts(state)
            return chosen
    raise ResolveError("the closure did not settle")


def _choose(archive: Archive, state: dict, owner: str, group: list[tuple]) -> dict[str, str]:
    for alternative in group:
        stanza = archive.best(alternative)
        if stanza is not None:
            return stanza
    for alternative in group:
        providers = archive.providers(alternative)
        if len(providers) == 1:
            return providers[0]
        if providers:
            raise ResolveError(f"{owner} needs {alternative[0]}, which "
                               f"{sorted(p['Package'] for p in providers)} all provide: name one "
                               "in container.install")
    raise ResolveError(f"{owner} needs {' | '.join(a[0] for a in group)}, which the snapshot "
                       "does not offer")


def _check_conflicts(state: dict[str, dict[str, str]]) -> None:
    for name, stanza in state.items():
        for field in ("Breaks", "Conflicts"):
            for group in parse_relation(stanza.get(field, "")):
                for alternative in group:
                    for other_name, other in state.items():
                        if other_name != name and satisfied_by(alternative, other):
                            raise ResolveError(f"{name} {field.lower()} {other_name} "
                                               f"{other['Version']}")


def installed_from_status(text: str) -> dict[str, dict[str, str]]:
    """Packages a dpkg status file holds as installed, by name."""
    return {s["Package"]: s for s in parse_stanzas(text)
            if s.get("Status", "").endswith(" installed")}


# ---------------------------------------------------------------------------
# The signed indexes
# ---------------------------------------------------------------------------

def parse_gpgv_status(status: str) -> set[str]:
    """Fingerprints of valid signatures in gpgv's status output."""
    return {line.split()[2].upper() for line in status.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG ")}


def verify_inrelease(path: Path, keyring: Path, gpgv: list[str] | None = None) -> str:
    """The cleartext of an InRelease file, once gpgv accepts its signature and
    the signing key is one of the archive's. gpgv's status lines go to a file
    descriptor of their own, not into the stream its human-readable messages share."""
    with tempfile.TemporaryFile() as status_file:
        descriptor = status_file.fileno()
        completed = subprocess.run(
            [*(gpgv or ["gpgv"]), "--status-fd", str(descriptor), "--keyring", str(keyring),
             "--output", "-", str(path)],
            capture_output=True, timeout=120, check=False, pass_fds=(descriptor,))
        status_file.seek(0)
        status = status_file.read().decode("utf-8", "replace")
    if completed.returncode != 0:
        raise ResolveError(f"gpgv refused {path.name}: "
                           f"{(status + completed.stderr.decode('utf-8', 'replace'))[-300:]}")
    cleartext = completed.stdout.decode("utf-8")
    signers = parse_gpgv_status(status)
    if not signers or not signers <= ARCHIVE_KEY_FINGERPRINTS:
        raise ResolveError(f"{path.name} is signed by {sorted(signers)}, which are not all "
                           "Ubuntu archive keys")
    return cleartext


def release_hashes(cleartext: str) -> dict[str, tuple[int, str]]:
    """path -> (size, sha256) from the SHA256 section of a Release file."""
    found, inside = {}, False
    for line in cleartext.splitlines():
        if line.startswith("SHA256:"):
            inside = True
        elif inside and line.startswith(" "):
            digest, size, name = line.split()
            found[name] = (int(size), digest)
        elif inside:
            inside = False
    if not found:
        raise ResolveError("no SHA256 section in the Release file")
    return found


def check_release_identity(cleartext: str, *, suite: str, codename: str, snapshot: str) -> str:
    """A signed Release file must be the one that was asked for: the suite, the
    codename, and a date no later than the snapshot. A genuine, signed file for
    another suite (or for a later day) is otherwise accepted by its signature alone.
    Returns the Date line."""
    fields = dict(re.findall(r"^(Suite|Codename|Date): (.+)$", cleartext, re.MULTILINE))
    if fields.get("Suite") != suite or fields.get("Codename") != codename:
        raise ResolveError(f"the Release file is for {fields.get('Suite')!r} / "
                           f"{fields.get('Codename')!r}, not {suite!r} / {codename!r}")
    try:
        issued = parsedate_to_datetime(fields["Date"])
    except (KeyError, TypeError, ValueError):
        raise ResolveError("the Release file has no readable Date") from None
    taken = datetime.strptime(snapshot, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    if issued > taken:
        raise ResolveError(f"the Release file is dated {fields['Date']}, after the snapshot")
    return fields["Date"]


def checked_index(data: bytes, name: str, listed: dict[str, tuple[int, str]]) -> bytes:
    """An index's bytes, refused unless the signed list states exactly this size and hash."""
    if name not in listed:
        raise ResolveError(f"{name} is not in the signed Release file")
    size, digest = listed[name]
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ResolveError(f"{name} is not the file the signed Release file lists")
    return data


def _get(url: str, limit: int = 1 << 28) -> bytes:
    with urllib.request.urlopen(url, timeout=300) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ResolveError(f"{url} is larger than {limit} bytes")
    return data


def fetch_archive(snapshot: str, suites: list[str], components: list[str], keyring: Path,
                  workdir: Path, gpgv: list[str] | None = None) -> tuple[Archive, dict]:
    """Every package the named suites and components list for amd64, through the
    signed chain, and a record of that chain (the digest of each InRelease and the
    size and hash of each index it listed) so the lock can show what it came from.
    The raw InRelease files are kept in `workdir`."""
    stanzas, record = [], {}
    for suite in suites:
        base = f"{SNAPSHOT_HOST}/{snapshot}/dists/{suite}"
        release = workdir / f"InRelease-{suite}"
        raw = _get(f"{base}/InRelease")
        release.write_bytes(raw)
        cleartext = verify_inrelease(release, keyring, gpgv)
        date = check_release_identity(cleartext, suite=suite, codename=suites[0],
                                      snapshot=snapshot)
        listed = release_hashes(cleartext)
        record[suite] = {"inrelease_sha256": hashlib.sha256(raw).hexdigest(), "date": date,
                         "indexes": {}}
        for component in components:
            name = f"{component}/binary-amd64/Packages.xz"
            data = checked_index(_get(f"{base}/{name}"), name, listed)
            record[suite]["indexes"][name] = {"size": len(data),
                                              "sha256": hashlib.sha256(data).hexdigest()}
            stanzas.extend(parse_stanzas(lzma.decompress(data).decode("utf-8")))
    return Archive(stanzas), record


def fetch_image_status(image: str) -> str:
    """dpkg's status file from the image's layers (a registry read; nothing is run).
    Every read is bounded."""
    name, _, digest = image.partition("@")
    repository = f"library/{name}"
    auth = json.loads(_get(
        f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull",
        1 << 20))
    headers = {"Authorization": f"Bearer {auth['token']}"}

    def blob(kind: str, reference: str, limit: int) -> bytes:
        request = urllib.request.Request(
            f"https://registry-1.docker.io/v2/{repository}/{kind}/{reference}",
            headers={**headers, "Accept": "application/vnd.oci.image.manifest.v1+json"})
        with urllib.request.urlopen(request, timeout=300) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ResolveError(f"{kind}/{reference} is larger than {limit} bytes")
        return data

    manifest_bytes = blob("manifests", digest, 1 << 20)
    if "sha256:" + hashlib.sha256(manifest_bytes).hexdigest() != digest:
        raise ResolveError("the manifest does not hash to the image digest")
    status = None
    for layer in json.loads(manifest_bytes)["layers"]:
        data = blob("blobs", layer["digest"], 1 << 28)
        if "sha256:" + hashlib.sha256(data).hexdigest() != layer["digest"]:
            raise ResolveError(f"layer {layer['digest']} does not hash to its digest")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for member in archive:
                if member.name.lstrip("./") == "var/lib/dpkg/status":
                    status = archive.extractfile(member).read(1 << 24).decode("utf-8")
    if status is None:
        raise ResolveError("the image holds no dpkg status")
    return status


# ---------------------------------------------------------------------------
# The lock
# ---------------------------------------------------------------------------

LOCK_SCHEMA = "nornyx.forge.nsis_build_debs.v1"
LOCK_NOTE = (
    "Every package the NSIS build installs over the pinned image, with the size and SHA-256 the "
    "signed snapshot index states. Written by resolve_nsis_debs.py, which resolved the closure "
    "itself (it is not apt): the install inside the container is the check that the set installs, "
    "and it must leave exactly this set installed. CI downloads each URL, refuses any size or "
    "SHA-256 that differs, and never runs apt-get update. The base list is the image's own dpkg "
    "status at the pinned digest.")


def build_lock(pins: dict, chosen: dict[str, dict[str, str]],
               installed: dict[str, dict[str, str]], signed: dict | None = None) -> dict:
    """The lock document: what the image holds, what is added, with each hash, and
    the signed indexes it was resolved from."""
    container = pins["container"]
    base = {n: s for n, s in installed.items()}
    packages = []
    for name in sorted(chosen):
        stanza = chosen[name]
        packages.append({
            "name": name, "architecture": stanza["Architecture"], "version": stanza["Version"],
            "url": f"{SNAPSHOT_HOST}/{container['snapshot']}/{stanza['Filename']}",
            "size": int(stanza["Size"]), "sha256": stanza["SHA256"]})
    return {
        "schema": LOCK_SCHEMA,
        "note": LOCK_NOTE,
        "image": container["image"],
        "snapshot": container["snapshot"],
        "install": list(container["install"]),
        "signed_indexes": signed or {},
        "base": sorted(f"{n} {s['Architecture']} {s['Version']}" for n, s in base.items()),
        "packages": packages,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--pins", type=Path, required=True, help="nsis-toolchain.json")
    parser.add_argument("--keyring", type=Path, required=True,
                        help="the archive keyring gpgv trusts (the trust root of this run)")
    parser.add_argument("--workdir", type=Path, required=True, help="where InRelease files are kept")
    parser.add_argument("--write", type=Path, required=True, help="the lock file to write")
    arguments = parser.parse_args(argv)
    pins = json.loads(arguments.pins.read_text(encoding="utf-8"))
    container = pins["container"]
    arguments.workdir.mkdir(parents=True, exist_ok=True)
    try:
        installed = installed_from_status(fetch_image_status(container["image"]))
        archive, signed = fetch_archive(container["snapshot"], container["suites"],
                                        container["components"], arguments.keyring,
                                        arguments.workdir)
        chosen = resolve(archive, installed, list(container["install"]))
    except ResolveError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1
    lock = build_lock(pins, chosen, installed, signed)
    arguments.write.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="")
    print(f"{len(lock['packages'])} packages to install over {len(lock['base'])} in the image")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
