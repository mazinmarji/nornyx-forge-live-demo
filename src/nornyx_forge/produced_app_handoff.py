"""Issuing the Produced Application Manifest, and the "Open application" gate.

TWO ACTS, BOTH FORGE'S AND NEITHER THE PROVIDER'S (A-051).

`issue_manifest` runs inside the build thread's post-build critical section --
under the store lock, after the store matched the seal Forge took when the
build began -- and renders the manifest from Forge's own records only: the
trusted verifier record the flow returned in memory (never
`.nornyx/runs/build-summary.json`, which is in the provider's workspace), the
capsule document and lifecycle Forge sealed at BUILD, the Provider Contract's
own eligibility row, and the produced files as Forge itself reads them now.
It issues nothing unless Forge's read reproduces the subject digest the
verifier accepted, the BRD it read is the BRD the scope confirmation bound,
and the static entry-point and import check finds nothing. A build it issues
nothing for is recorded exactly as before: READY is unchanged by this module.

`assess_readiness` is the separate handoff gate. It loads the manifest only
from a store that has passed `assert_sealed()` and carries a seal, takes the
manifest from the seal (whose recorded `pam/<sha256>` reference `sealed()`
holds to its bytes), validates it, re-reads and re-hashes every produced file
and re-runs the static check, and offers "Open application" only when the
Provider Contract's UNCHANGED `governed_build_eligibility` says the build's
provider is eligible -- both in the row the manifest recorded at issue and
asked again now. The row at issue is the contract's, not the verdict the
build route was handed, so a build made under a test's injected verdict
records an ineligible row and is never offered. Today no provider is
eligible, so it is never offered at all. `open_application_readiness` is the
only production entry and passes the contract's own decision; the injectable
`eligibility` exists for unit tests and nothing else.

NO PRODUCED CODE IS EXECUTED. Nothing here starts a process, imports a
produced module or compiles one to code; the checks are `ast` over bytes.
Every produced file is read through ONE descriptor, judged by what that
descriptor is -- a regular file, the very one inspected, within its bound,
unchanged while it was read -- and never by reopening its path (the
`_read_inspected_file` precedent, and the lesson of P1 4356060742). What
stays is disclosed rather than closed: a same-user process can swap a file
around Forge's read, so a digest here is only as good as that read.

`layer.application`: it composes the store adapter, the manifest domain, the
Provider Contract and the journey's scope reading; it starts no process.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .capsule import CapsuleError, CapsuleValidationError
from .capsule_store import CapsuleStore
from .contract_generator import generate_brd_contract, render_runtime_contract
from .experience_journey import scope_binding
from .gates import GREENFIELD_PROFILE_DIGEST, GREENFIELD_PROFILE_ID, GREENFIELD_VERIFIER_ID
from .produced_app_manifest import (
    application_files,
    pam_reference,
    render_pam,
    static_findings,
    subject_digest,
    validate_pam,
)
from .provider_contract import GovernedEligibility, governed_build_eligibility
from .requirements import parse_brd

#: The standard library of the interpreter Forge runs on, read once here so
#: the domain check receives it as data.
STDLIB = frozenset(sys.stdlib_module_names)

#: The trusted verifier's collection rule, copied: directories it never
#: inspects and the bounds it inspects within. `greenfield_verifier` is
#: executed by path and is not imported by Forge's application layer;
#: `test_the_handoff_collects_the_subject_by_the_verifiers_own_rule` holds
#: these equal to the verifier's own.
IGNORED_DIRECTORIES = frozenset({
    ".git", ".hg", ".mypy_cache", ".nornyx", ".pytest_cache", ".ruff_cache", ".svn",
    ".tox", ".venv", "__pycache__", "build", "dist", "node_modules", "venv",
})
MAX_FILES = 2000
MAX_FILE_BYTES = 500_000
MAX_TOTAL_BYTES = 10_000_000

_VERIFIER_PROVENANCE_SCHEMA = "nornyx.forge.verifier_provenance.v1"
_VERIFIER_TRUST = "structural-origin-and-digest"


# ---------------------------------------------------------------------------
# Reading the produced files: one descriptor each, never a path reopened
# ---------------------------------------------------------------------------

def _reparse_point(status: os.stat_result) -> bool:
    return bool(getattr(status, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _linklike_directory(path: Path) -> bool:
    """A symlink, junction or other reparse point where a directory is."""
    try:
        status = os.lstat(path)
    except OSError:
        return True
    return stat.S_ISLNK(status.st_mode) or _reparse_point(status) or not stat.S_ISDIR(status.st_mode)


def read_held(path: Path, limit: int = MAX_FILE_BYTES) -> tuple[bytes | None, str]:
    """The bytes of the regular file at `path`, read through one descriptor.

    The name is inspected with `lstat`, then opened without following a link
    where the platform can refuse one and without blocking where it could open
    a pipe; what is judged is the DESCRIPTOR -- a regular file, the device and
    inode that were inspected, within `limit` -- and the bytes come from it
    alone. `fstat` after the read must agree with `fstat` before it, and with
    the length read, or the file changed while it was read. Windows has
    neither open flag; the identity comparison is what refuses a substitution
    there. Returns the bytes and an empty reason, or `None` and the reason.
    """
    try:
        inspected = os.lstat(path)
    except OSError as error:
        return None, f"cannot be inspected ({error.strerror or error})"
    if not stat.S_ISREG(inspected.st_mode) or _reparse_point(inspected):
        return None, "is not a regular file"
    if inspected.st_size > limit:
        return None, f"is larger than {limit} bytes"
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_BINARY", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        return None, f"cannot be opened as a regular file ({error.strerror or error})"
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            return None, "is not a regular file"
        if (opened.st_dev, opened.st_ino) != (inspected.st_dev, inspected.st_ino):
            return None, "changed while it was inspected: the file opened is not the one inspected"
        if opened.st_size > limit:
            return None, f"is larger than {limit} bytes"
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1 << 16, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                return None, f"is larger than {limit} bytes"
        after = os.fstat(descriptor)
    except OSError as error:
        return None, f"cannot be read ({error.strerror or error})"
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns) or (
            len(data) != after.st_size):
        return None, "changed while it was read"
    return data, ""


def read_subject(project_root: Path) -> tuple[dict[str, bytes], list[str]]:
    """Every file the trusted verifier would inspect under `project_root`, by
    its own directory rule and bounds, each read by `read_held`.

    Returns the bytes by relative POSIX path, and the problems: a linked or
    reparse directory, a file that is not a plain readable file, or a bound
    exceeded. A non-empty problem list means the collection is not the subject.
    """
    root = Path(project_root).resolve(strict=True)
    files: dict[str, bytes] = {}
    problems: list[str] = []
    total = 0
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        here = Path(current)
        kept: list[str] = []
        for name in sorted(directories):
            if name in IGNORED_DIRECTORIES:
                continue
            if _linklike_directory(here / name):
                problems.append("a linked or reparse directory is in the subject: "
                                f"{(here / name).relative_to(root).as_posix()}")
                continue
            kept.append(name)
        directories[:] = kept
        for name in sorted(names):
            relative = (here / name).relative_to(root).as_posix()
            data, problem = read_held(here / name)
            if data is None:
                problems.append(f"{relative} {problem}")
                continue
            files[relative] = data
            total += len(data)
            if len(files) > MAX_FILES:
                problems.append(f"the subject exceeds the {MAX_FILES}-file bound")
                return files, problems
            if total > MAX_TOTAL_BYTES:
                problems.append(f"the subject exceeds the {MAX_TOTAL_BYTES}-byte bound")
                return files, problems
    return files, problems


def _digests(files: Mapping[str, bytes]) -> dict[str, str]:
    return {path: "sha256:" + hashlib.sha256(data).hexdigest() for path, data in files.items()}


# ---------------------------------------------------------------------------
# Issuing the manifest
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ManifestIssue:
    """What issuance produced: the manifest text, or nothing and why."""

    text: str | None
    findings: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "manifest": None if self.text is None else pam_reference(self.text),
            "findings": list(self.findings),
        }


def brd_text_digest(data: bytes) -> str | None:
    """The BRD digest by the scope binding's convention: the decoded text with
    universal newlines, as `Path.read_text` gives it, hashed as UTF-8."""
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return None
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def rendered_contract_digest(brd: bytes) -> str:
    """The digest of the contract the development flow generates from these
    BRD bytes, rendered by Forge into a private temporary directory with the
    flow's own parser and generator, and never read from the workspace."""
    with tempfile.TemporaryDirectory(prefix="nornyx-forge-pam-") as scratch:
        root = Path(scratch)
        (root / "BRD.md").write_bytes(brd)
        target = generate_brd_contract(root, parse_brd(root / "BRD.md"))
        return "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()


def rendered_runtime_contract_digest(brd: bytes) -> str:
    """The digest of the runtime operation contract (A-053) the development
    flow renders from these BRD bytes -- the flow declares no operation, so
    the empty closed table -- parsed by the flow's own parser in a private
    temporary directory, rendered as text and never read from the workspace
    (A-055). It names which contract was declared; it says nothing about
    whether the application obeys it when run."""
    with tempfile.TemporaryDirectory(prefix="nornyx-forge-pam-") as scratch:
        root = Path(scratch)
        (root / "BRD.md").write_bytes(brd)
        text = render_runtime_contract(parse_brd(root / "BRD.md"))
        return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _verifier_record(result: Any, project_root: Path) -> tuple[Mapping[str, Any] | None, list[str]]:
    """The trusted verifier record the flow returned in memory, or why not.

    Every field the manifest takes from it is checked here against Forge's own
    constants; anything else in it is not read.
    """
    if not isinstance(result, Mapping) or result.get("accepted") is not True:
        return None, ["the build was not accepted"]
    record = result.get("acceptance_provenance")
    if not isinstance(record, Mapping):
        return None, ["the build carries no trusted verifier record"]
    problems: list[str] = []
    verifier = record.get("verifier")
    profile = record.get("gate_profile")
    subject = record.get("subject")
    if (record.get("schema") != _VERIFIER_PROVENANCE_SCHEMA
            or record.get("trust") != _VERIFIER_TRUST):
        problems.append("the verifier record is not a trusted structural record")
    if not isinstance(verifier, Mapping) or verifier.get("id") != GREENFIELD_VERIFIER_ID:
        problems.append("the verifier record names another verifier")
    if (not isinstance(profile, Mapping) or profile.get("id") != GREENFIELD_PROFILE_ID
            or profile.get("digest") != GREENFIELD_PROFILE_DIGEST):
        problems.append("the verifier record names another gate profile")
    if (not isinstance(subject, Mapping)
            or subject.get("root") != str(Path(project_root).resolve())
            or not isinstance(subject.get("digest"), str)
            or not isinstance(subject.get("file_count"), int)
            or isinstance(subject.get("file_count"), bool)):
        problems.append("the verifier record does not describe this project's subject")
    return (None, problems) if problems else (record, [])


def issue_manifest(
    *,
    project_root: Path,
    store_root: Path,
    result: Any,
    document: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    sealed_revision: str,
    platform: str,
) -> ManifestIssue:
    """Render the manifest for an accepted build, or say why none is issued.

    `document` and `lifecycle` are the capsule and lifecycle Forge sealed when
    the build began, and the caller has just found the store matching that
    seal; `result` is the flow's in-memory return. Nothing here writes: the
    caller persists the text with `CapsuleStore.save_produced_application`.
    """
    project = Path(project_root).resolve()
    store_directory = Path(store_root).resolve().name
    if Path(store_root).resolve().parent != project:
        return ManifestIssue(None, ("the capsule store is not a directory of the project",))
    record, findings = _verifier_record(result, project)
    if record is None:
        return ManifestIssue(None, tuple(findings))
    files, problems = read_subject(project)
    if problems:
        return ManifestIssue(None, tuple(f"Forge could not read the subject: {p}" for p in problems))
    digests = _digests(files)
    accepted = record["subject"]
    if subject_digest(digests) != accepted["digest"] or len(digests) != accepted["file_count"]:
        return ManifestIssue(None, (
            "the files Forge read are not the subject the verifier accepted; something "
            "changed them after verification",))

    findings = static_findings(files, store_directory=store_directory, stdlib=STDLIB)
    brd = files.get("BRD.md")
    bound = scope_binding(lifecycle, "BUILD")
    chain = document.get("digest_chain") if isinstance(document, Mapping) else None
    tip = chain[-1] if isinstance(chain, list) and chain else None
    if brd is None:
        findings.append("BRD.md is not in the accepted subject")
    if bound is None:
        findings.append("the lifecycle records no scope binding for this build")
    elif bound[0] != tip:
        findings.append("the scope binding names another capsule than the one sealed")
    elif brd is not None and brd_text_digest(brd) != bound[1]:
        findings.append("the BRD the verifier accepted is not the BRD the scope "
                        "confirmation bound")
    provider = (document.get("authoritative", {}).get("provider") or {}).get("name") \
        if isinstance(document, Mapping) else None
    if not isinstance(provider, str):
        findings.append("the sealed capsule names no confirmed provider")
    if findings:
        return ManifestIssue(None, tuple(findings))

    try:
        contract = rendered_contract_digest(brd)
        runtime_contract = rendered_runtime_contract_digest(brd)
    except (OSError, UnicodeError, ValueError) as error:
        return ManifestIssue(None, (f"Forge could not render the generated contract: {error}",))
    verifier = record["verifier"]
    try:
        text = render_pam(
            files=digests,
            accepted_subject_digest=accepted["digest"],
            store_directory=store_directory,
            generated_contract_digest=contract,
            brd_scope_binding=f"capsule/{bound[0]}/brd/{bound[1]}",
            capsule_chain_tip=tip,
            sealed_revision=sealed_revision,
            provider=provider,
            # THE CONTRACT'S ROW, never the verdict the build route was given:
            # a verdict injected into a test composition does not reach here.
            eligibility=governed_build_eligibility(provider, platform).as_dict(),
            verifier_digest=verifier.get("digest"),
            gate_profile={"id": GREENFIELD_PROFILE_ID, "digest": GREENFIELD_PROFILE_DIGEST},
            forge_version=verifier.get("forge_version"),
            forge_revision=verifier.get("forge_revision"),
            runtime_contract_digest=runtime_contract,
            # A build in Forge's own workspace did not cross the run-act gate.
            gate_provenance=None,
        )
    except CapsuleValidationError as error:
        return ManifestIssue(None, (str(error),))
    return ManifestIssue(text, ())


# ---------------------------------------------------------------------------
# The handoff gate
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Readiness:
    """Whether "Open application" may be offered, and every reason it is not."""

    offered: bool
    reasons: tuple[str, ...]
    manifest: str | None

    def as_dict(self) -> dict[str, Any]:
        return {"offered": self.offered, "reasons": list(self.reasons),
                "manifest": self.manifest}


def _not_offered(reasons: list[str], manifest: str | None = None) -> Readiness:
    return Readiness(False, tuple(reasons), manifest)


def assess_readiness(
    store: CapsuleStore,
    project_root: Path,
    *,
    platform: str,
    eligibility: Callable[[str, str], GovernedEligibility],
) -> Readiness:
    """The handoff gate's judgement. Unit tests inject `eligibility`; the one
    production entry, `open_application_readiness`, passes the Provider
    Contract's own decision and nothing else."""
    try:
        store.assert_sealed()
        snapshot = store.sealed()
    except CapsuleError as error:
        return _not_offered([f"the authority store is not trusted: {str(error)[:300]}"])
    if snapshot is None:
        return _not_offered(["the store carries no seal; a manifest is read only from a "
                             "store Forge has sealed"])
    text = snapshot.files.get("pam.json")
    if text is None:
        return _not_offered(["no produced-application manifest is sealed for this project"])
    reference = pam_reference(text)
    try:
        manifest = validate_pam(text)
    except CapsuleValidationError as error:
        return _not_offered([str(error)], reference)

    reasons: list[str] = []
    if manifest["gate_provenance"] is not None:
        # A GATED BUILD IS NEVER OFFERED HERE (A-055): its verification was
        # static only and its tests were not run, and what it may be offered
        # on is an execution measured by an observer, which Forge holds none of.
        reasons.append("the build crossed the run-act gate and was verified statically "
                       "only; its tests were not run, so nothing is offered for it")
    project = Path(project_root).resolve()
    if (Path(store.root).resolve().parent != project
            or Path(store.root).resolve().name != manifest["store_directory"]):
        reasons.append("the manifest's store is not this project's capsule store")
    name = manifest["provider"]["name"]
    row = manifest["provider"]["eligibility"]
    if row["eligible"] is not True:
        reasons.append(f"the build's provider {name} was not eligible when the manifest was "
                       f"issued ({row['reason'][:200]}); a build made under any other verdict "
                       "is never offered")
    if row["platform"] != platform:
        reasons.append(f"the manifest was issued for platform {row['platform'][:80]}, not "
                       f"{platform[:80]}; an eligibility row for one platform says nothing "
                       "about another")
    verdict = eligibility(name, platform)
    if not verdict.eligible or verdict.provider != name or verdict.platform != platform:
        reasons.append(f"the build's provider {name} is not eligible for the governed build: "
                       f"{verdict.reason[:200]}")

    files, problems = read_subject(project)
    reasons.extend(f"Forge could not read the application: {p}" for p in problems)
    current = _digests({path: data for path, data in files.items()
                        if path in application_files(files, manifest["store_directory"])})
    listed = {path: manifest["subject"]["files"][path] for path in manifest["application"]["files"]}
    for path in sorted(set(listed) - set(current)):
        reasons.append(f"{path} is listed in the manifest and is missing")
    for path in sorted(set(current) - set(listed)):
        reasons.append(f"{path} is not listed in the manifest")
    for path in sorted(set(listed) & set(current)):
        if listed[path] != current[path]:
            reasons.append(f"{path} has changed since the manifest was issued")
    reasons.extend(static_findings(files, store_directory=manifest["store_directory"],
                                   stdlib=STDLIB))
    return Readiness(not reasons, tuple(reasons), reference)


def open_application_readiness(store: CapsuleStore, project_root: Path, platform: str) -> Readiness:
    """The handoff gate as production asks it: eligibility is the Provider
    Contract's unchanged `governed_build_eligibility`, and there is no other
    way to supply one."""
    return assess_readiness(store, project_root, platform=platform,
                            eligibility=governed_build_eligibility)


__all__ = [
    "IGNORED_DIRECTORIES",
    "MAX_FILES",
    "MAX_FILE_BYTES",
    "MAX_TOTAL_BYTES",
    "STDLIB",
    "ManifestIssue",
    "Readiness",
    "assess_readiness",
    "brd_text_digest",
    "issue_manifest",
    "open_application_readiness",
    "read_held",
    "read_subject",
    "rendered_contract_digest",
    "rendered_runtime_contract_digest",
]
