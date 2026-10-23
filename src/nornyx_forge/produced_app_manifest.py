"""The Produced Application Manifest (PAM): what an accepted build produced.

WHAT IT IS. After a governed build is accepted, Forge -- never the provider,
and never the development flow -- renders one manifest naming the bytes that
passed: the trusted verifier's subject digest and every file's SHA-256, the
entry point, the dependency declaration, the digest of the contract Forge
renders from the accepted BRD, the BRD's scope binding and the capsule's chain
tip, the provider and the Provider Contract's eligibility row for it, the
verifier's identity, and Forge's version and revision. The capsule store keeps
it as an authority file, so its exact bytes are sealed outside the project
(A-051).

THIS MODULE IS PURE. `layer.domain`: data in, text out, no filesystem, no
clock, no process and no interpreter state. `render_pam` is a function of its
arguments, so the manifest's digest is computed from the text Forge rendered,
never read back from a path. `static_findings` judges produced sources as
BYTES with `ast` and never imports, compiles or executes them; the standard
library's module names arrive as data from the caller.

WHAT `validate_pam` CHECKS, AND WHAT IT DOES NOT. Shape, closed values and
internal consistency: the exact key set at every level, the canonical
encoding, every digest's form, the subject digest recomputed from the listed
files, the application file list derived from them, the BRD's file digest
against the listed one, and the scope binding's capsule tip against the
recorded one. It cannot check a claim against the world: whether the verifier
really accepted this subject, whether the eligibility row is the contract's,
and whether the files on disk still have these digests are decided where the
world is visible -- by the issuer in `produced_app_handoff`, which compares
each with Forge's own records, and by the handoff gate, which re-reads the
files and asks the Provider Contract again. A valid manifest is a well-formed
claim, not a true one.

WHAT IT DOES NOT ESTABLISH (A-051). The manifest detects accidental change,
and change by a writer confined to the provider's workspace, of the files it
lists and of itself. It does not resist a process running as the same
operating-system user, which can rewrite the store and its seal together or
race Forge's read; currency stays `not_independently_anchored`. A file digest
here is only as good as Forge's read of that file.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import tokenize
from typing import Any, Collection, Mapping

from .capsule import PROVIDERS, CapsuleValidationError, canonical_json

PAM_SCHEMA = "nornyx.forge.produced_application_manifest.v1"

#: `pam/<64 hex>`: the SHA-256 of the manifest's exact text. Anchored `\A...\Z`
#: for the reason `experience_build` gives for its own formats.
PAM_REF = re.compile(r"\Apam/([0-9a-f]{64})\Z")

#: The one entry point version 1 knows: a package `app/` run as `python -m app`.
#: Nothing here runs it; it is checked only for being present and parsing.
ENTRY_POINT = "app/__main__.py"

#: Version 1 permits the Python standard library and nothing else.
DEPENDENCIES: Mapping[str, Any] = {"policy": "python_standard_library_only", "declared": []}

#: Where the development flow writes the generated build contract, and what the
#: manifest's digest of it is: the contract Forge renders from the BRD bytes the
#: verifier accepted, not bytes read back from that workspace path.
GENERATED_CONTRACT_PATH = ".nornyx/generated/brd_contract.nyx"
GENERATED_CONTRACT_BASIS = "rendered_by_forge_from_the_accepted_brd"

#: The trusted verifier's identity, as `gates.GREENFIELD_VERIFIER_ID` names it.
#: Copied rather than imported because this module is domain and `gates` is an
#: adapter; `test_the_manifest_pins_the_gates_own_verifier_identity` holds the
#: two equal.
VERIFIER_ID = "nornyx_forge.greenfield_verifier"

#: What the manifest's protection is and is not, carried in every manifest so
#: no reader of one has to find A-051 to learn its bound.
TRUST: Mapping[str, str] = {
    "basis": "rendered_by_forge_and_sealed_outside_the_project",
    "detects": "accidental_change_and_change_by_a_writer_confined_to_the_workspace",
    "does_not_resist": "a_process_running_as_the_same_operating_system_user",
    "currency": "not_independently_anchored",
}

#: The scope binding's shape, `capsule/<tip>/brd/<digest>`. Its owner is
#: `experience_build.SCOPE_REF`, an application module this domain module may
#: not import; `test_the_manifest_reads_the_scope_binding_its_owner_writes`
#: holds the two patterns equal so they cannot drift.
SCOPE_REF = re.compile(r"\Acapsule/([0-9a-f]{64})/brd/([0-9a-f]{64})\Z")

_SHA256 = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_REVISION = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_FORGE_REVISION = re.compile(r"\A(?:git:[0-9a-f]{40}|package:[^\s]{1,80})\Z")
_SEGMENT = re.compile(r"\A[A-Za-z0-9._-]{1,100}\Z")
#: One relative POSIX path of printable characters, no backslash, colon or
#: control character; `..` and empty segments are refused separately.
_PATH = re.compile(r"\A[^\\:\x00-\x1f\x7f]{1,400}\Z")
_TEXT_LIMIT = 4_000_000
_FILE_LIMIT = 2000
_REASON_LIMIT = 2000

_TOP_KEYS = frozenset({
    "schema", "subject", "store_directory", "application", "generated_contract",
    "brd", "capsule", "provider", "verifier", "forge", "trust",
})


def pam_digest(text: str) -> str:
    """`sha256:<hex>` of the manifest's exact text, encoded as written."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def pam_reference(text: str) -> str:
    """`pam/<hex>`: the reference that names one manifest by its bytes."""
    return "pam/" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def subject_digest(files: Mapping[str, str]) -> str:
    """The trusted verifier's subject digest over `files` (path -> digest).

    A copy of `greenfield_verifier._subject_digest`, which this module may not
    import: the verifier is executed by path and imports nothing of Forge's.
    `test_the_manifest_computes_the_verifiers_own_subject_digest` holds the two
    equal on the same input, the `brd_requirement_identity` precedent.
    """
    encoded = json.dumps({"files": sorted(files.items())}, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def application_files(files: Collection[str], store_directory: str) -> list[str]:
    """The subject files that are the produced application: every one outside
    the capsule store's directory, which is Forge's authority and not product."""
    prefix = store_directory + "/"
    return sorted(path for path in files if not path.startswith(prefix))


def render_pam(
    *,
    files: Mapping[str, str],
    accepted_subject_digest: str,
    store_directory: str,
    generated_contract_digest: str,
    brd_scope_binding: str,
    capsule_chain_tip: str,
    sealed_revision: str,
    provider: str,
    eligibility: Mapping[str, Any],
    verifier_digest: str,
    gate_profile: Mapping[str, Any],
    forge_version: str,
    forge_revision: str,
) -> str:
    """The manifest's one rendering: canonical JSON and a final newline.

    Pure, and it refuses to render what it would refuse to read: the text is
    put through `validate_pam` before it is returned, so a manifest that
    exists has passed the same checks as a manifest that is loaded.
    """
    document = {
        "schema": PAM_SCHEMA,
        "subject": {
            "digest": accepted_subject_digest,
            "file_count": len(files),
            "files": dict(files),
        },
        "store_directory": store_directory,
        "application": {
            "entry_point": ENTRY_POINT,
            "dependencies": dict(DEPENDENCIES),
            "files": application_files(files, store_directory),
        },
        "generated_contract": {
            "path": GENERATED_CONTRACT_PATH,
            "digest": generated_contract_digest,
            "basis": GENERATED_CONTRACT_BASIS,
        },
        "brd": {
            "path": "BRD.md",
            "file_digest": files.get("BRD.md"),
            "scope_binding": brd_scope_binding,
        },
        "capsule": {"chain_tip": capsule_chain_tip, "sealed_revision": sealed_revision},
        "provider": {"name": provider, "eligibility": dict(eligibility)},
        "verifier": {"id": VERIFIER_ID, "digest": verifier_digest,
                     "gate_profile": dict(gate_profile)},
        "forge": {"version": forge_version, "revision": forge_revision},
        "trust": dict(TRUST),
    }
    text = canonical_json(document) + "\n"
    validate_pam(text)
    return text


def _refuse(reason: str) -> CapsuleValidationError:
    return CapsuleValidationError(f"produced-application manifest: {reason}")


def _keys(value: Any, expected: Collection[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _refuse(f"{where} must be an object")
    if set(value) != set(expected):
        raise _refuse(f"{where} must carry exactly {sorted(expected)}, not {sorted(value)}")
    return value


def _text(value: Any, where: str, limit: int = 200) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise _refuse(f"{where} must be a non-empty string of at most {limit} characters")
    return value


def _relative_path(path: Any) -> str:
    if (
        not isinstance(path, str)
        or not _PATH.match(path)
        or path.startswith("/")
        or any(segment in ("", ".", "..") for segment in path.split("/"))
    ):
        raise _refuse(f"listed path {str(path)[:80]!r} is not a relative POSIX path")
    return path


def validate_pam(text: Any) -> dict[str, Any]:
    """The manifest's checks, failing closed; returns the parsed document.

    See the module docstring for the line between what this checks and what
    only the issuer and the gate can.
    """
    if not isinstance(text, str) or len(text) > _TEXT_LIMIT:
        raise _refuse(f"the manifest must be text of at most {_TEXT_LIMIT} characters")
    try:
        document = json.loads(text)
    except ValueError as error:
        raise _refuse(f"the manifest is not JSON: {error}") from error
    _keys(document, _TOP_KEYS, "the manifest")
    if canonical_json(document) + "\n" != text:
        raise _refuse("the manifest is not in its canonical encoding, so its digest "
                      "would not name its content")
    if document["schema"] != PAM_SCHEMA:
        raise _refuse(f"schema must be {PAM_SCHEMA}")

    subject = _keys(document["subject"], ("digest", "file_count", "files"), "subject")
    files = subject["files"]
    if not isinstance(files, dict) or not files or len(files) > _FILE_LIMIT:
        raise _refuse(f"subject files must list between 1 and {_FILE_LIMIT} files")
    for path, digest in files.items():
        _relative_path(path)
        if not isinstance(digest, str) or not _SHA256.match(digest):
            raise _refuse(f"the digest of {path!r} is not sha256:<64 hex>")
    if subject["digest"] != subject_digest(files):
        raise _refuse("the subject digest is not the digest of the listed files")
    if subject["file_count"] != len(files) or isinstance(subject["file_count"], bool):
        raise _refuse("the subject file count is not the number of listed files")

    store_directory = document["store_directory"]
    if (not isinstance(store_directory, str) or not _SEGMENT.match(store_directory)
            or store_directory in (".", "..")):
        raise _refuse("store_directory must be one directory name")

    application = _keys(document["application"], ("entry_point", "dependencies", "files"),
                        "application")
    if application["entry_point"] != ENTRY_POINT:
        raise _refuse(f"the entry point must be {ENTRY_POINT}")
    if application["dependencies"] != DEPENDENCIES:
        raise _refuse("version 1 declares the Python standard library and nothing else")
    if application["files"] != application_files(files, store_directory):
        raise _refuse("the application files are not the listed files outside the store")
    if ENTRY_POINT not in application["files"]:
        raise _refuse(f"the entry point {ENTRY_POINT} is not a listed application file")

    contract = _keys(document["generated_contract"], ("path", "digest", "basis"),
                     "generated_contract")
    if (contract["path"] != GENERATED_CONTRACT_PATH
            or contract["basis"] != GENERATED_CONTRACT_BASIS
            or not isinstance(contract["digest"], str) or not _SHA256.match(contract["digest"])):
        raise _refuse("generated_contract must name the generated contract, its basis "
                      "and a sha256 digest")

    brd = _keys(document["brd"], ("path", "file_digest", "scope_binding"), "brd")
    capsule = _keys(document["capsule"], ("chain_tip", "sealed_revision"), "capsule")
    if brd["path"] != "BRD.md" or brd["file_digest"] != files.get("BRD.md"):
        raise _refuse("brd must name BRD.md with the digest the subject lists for it")
    scope = SCOPE_REF.match(brd["scope_binding"]) if isinstance(brd["scope_binding"], str) else None
    if scope is None:
        raise _refuse("brd scope_binding is not capsule/<64 hex>/brd/<64 hex>")
    if not isinstance(capsule["chain_tip"], str) or not _HEX64.match(capsule["chain_tip"]):
        raise _refuse("capsule chain_tip is not 64 hex")
    if scope.group(1) != capsule["chain_tip"]:
        raise _refuse("the scope binding names another capsule tip than the one recorded")
    if not isinstance(capsule["sealed_revision"], str) or not _REVISION.match(capsule["sealed_revision"]):
        raise _refuse("capsule sealed_revision is not a full commit")

    provider = _keys(document["provider"], ("name", "eligibility"), "provider")
    if provider["name"] not in PROVIDERS:
        raise _refuse(f"provider name must be one of {PROVIDERS}")
    row = _keys(provider["eligibility"],
                ("provider", "platform", "eligible", "confinement", "reason"),
                "provider eligibility")
    if row["provider"] != provider["name"]:
        raise _refuse("the eligibility row is for another provider")
    _text(row["platform"], "eligibility platform", 80)
    _text(row["confinement"], "eligibility confinement", 80)
    _text(row["reason"], "eligibility reason", _REASON_LIMIT)
    if not isinstance(row["eligible"], bool):
        raise _refuse("eligibility eligible must be a bool")

    verifier = _keys(document["verifier"], ("id", "digest", "gate_profile"), "verifier")
    if verifier["id"] != VERIFIER_ID:
        raise _refuse(f"verifier id must be {VERIFIER_ID}")
    if not isinstance(verifier["digest"], str) or not _SHA256.match(verifier["digest"]):
        raise _refuse("verifier digest is not sha256:<64 hex>")
    profile = _keys(verifier["gate_profile"], ("id", "digest"), "verifier gate_profile")
    _text(profile["id"], "gate profile id", 80)
    if not isinstance(profile["digest"], str) or not _SHA256.match(profile["digest"]):
        raise _refuse("gate profile digest is not sha256:<64 hex>")

    forge = _keys(document["forge"], ("version", "revision"), "forge")
    _text(forge["version"], "forge version", 80)
    if not isinstance(forge["revision"], str) or not _FORGE_REVISION.match(forge["revision"]):
        raise _refuse("forge revision is not git:<40 hex> or package:<version>")

    if document["trust"] != TRUST:
        raise _refuse("trust must state the manifest's bound exactly")
    return document


# ---------------------------------------------------------------------------
# The static entry-point and import check: bytes in, findings out
# ---------------------------------------------------------------------------

#: Test modules may also import the runner the trusted verifier runs them with.
_TEST_ONLY_IMPORTS = frozenset({"pytest"})
_FORGE_PACKAGE = "nornyx_forge"

#: THE DYNAMIC PRIMITIVES, REFUSED BY ANY REFERENCE. A produced file may not
#: mention them at all: not call them, load them, bind them, import them, take
#: them as an attribute or name them in a `getattr` literal. The rule does not
#: follow where a name ends up -- an alias map did, and an annotated binding
#: walked straight past it (Codex P2 4361814368 on 86f3ba4, after P2 4359780685
#: on afa35eb) -- so there is no binding form, statement order or scope for it
#: to miss. It is conservative on purpose: a local that merely shares one of
#: these names is refused too.
#:
#: Names: `__import__`, `eval`, `exec`, `compile`, `__builtins__`, and the two
#: modules `importlib` and `builtins`, refused wherever they appear as a name.
#: Imports: any import of `importlib` or `builtins` (a submodule included, and
#: under any alias), and any imported name or alias spelling a primitive.
#: Attributes: `.__import__` and `.import_module` on anything. Bindings that are
#: not names in the tree -- a function, class or parameter name, a `global` or
#: `nonlocal`, an exception or pattern capture -- spelling a primitive. And a
#: `getattr` whose member is a string literal spelling one.
_PRIMITIVE_NAMES = frozenset({
    "__import__", "eval", "exec", "compile", "__builtins__", "importlib", "builtins",
})
_PRIMITIVE_MODULES = frozenset({"importlib", "builtins"})
_PRIMITIVE_MEMBERS = frozenset({"__import__", "import_module"})
_PRIMITIVE_SPELLINGS = _PRIMITIVE_NAMES | _PRIMITIVE_MEMBERS


def _primitive_references(path: str, tree: ast.AST) -> list[str]:
    """Every reference in one parsed file to a dynamic primitive, one finding per
    line and spelling, in line order."""
    found: set[tuple[int, str]] = set()

    def spelled(node: ast.AST, *names: str | None) -> None:
        for name in names:
            if name in _PRIMITIVE_SPELLINGS:
                found.add((getattr(node, "lineno", 0), str(name)))

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id in _PRIMITIVE_NAMES:
                found.add((node.lineno, node.id))
        elif isinstance(node, ast.Attribute):
            if node.attr in _PRIMITIVE_MEMBERS:
                found.add((node.lineno, "." + node.attr))
        elif isinstance(node, ast.Import):
            for item in node.names:
                if item.name.split(".")[0] in _PRIMITIVE_MODULES:
                    found.add((node.lineno, item.name))
                spelled(node, item.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module and (
                    node.module.split(".")[0] in _PRIMITIVE_MODULES):
                found.add((node.lineno, node.module))
            for item in node.names:
                spelled(node, item.name, item.asname)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            spelled(node, node.name)
        elif isinstance(node, ast.arg):
            spelled(node, node.arg)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            spelled(node, *node.names)
        elif isinstance(node, ast.ExceptHandler):
            spelled(node, node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            spelled(node, node.name)
        elif isinstance(node, ast.MatchMapping):
            spelled(node, node.rest)
        elif isinstance(node, ast.Call):
            called = node.func
            callee = (called.id if isinstance(called, ast.Name)
                      else called.attr if isinstance(called, ast.Attribute) else "")
            if callee == "getattr" and len(node.args) > 1 and isinstance(
                    node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                spelled(node, node.args[1].value)
    return [f"{path}:{line} refers to {name}, a dynamic import or execution primitive, "
            "which a static check cannot follow" for line, name in sorted(found)]


def _module_name(segment: str) -> str:
    return segment[:-3] if segment.endswith(".py") else segment


def _local_modules(python_files: Collection[str]) -> set[str]:
    """The top-level names the application's own files can be imported as: the
    first segment of each path, and under `src/` the second as well."""
    local: set[str] = set()
    for path in python_files:
        parts = path.split("/")
        local.add(_module_name(parts[0]))
        if parts[0] == "src" and len(parts) > 1:
            local.add(_module_name(parts[1]))
    return local


def _parsed(path: str, data: bytes) -> tuple[ast.AST | None, str | None]:
    """Parse one source as the verifier reads one: its declared encoding, then
    `ast.parse`. Nothing is compiled to code and nothing runs."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        return ast.parse(data.decode(encoding), filename=path), None
    except (LookupError, SyntaxError, UnicodeError, ValueError, MemoryError, RecursionError) as error:
        return None, f"{path} does not parse: {type(error).__name__}: {error}"


def static_findings(
    sources: Mapping[str, bytes],
    *,
    store_directory: str,
    stdlib: Collection[str],
) -> list[str]:
    """Everything that keeps these produced files from being a version-1
    application, by static inspection alone. Empty means none was found.

    `sources` maps relative POSIX paths to bytes; files under `store_directory`
    are Forge's and are not inspected. The checks: `ENTRY_POINT` is present
    and parses; every Python file parses; no file imports `nornyx_forge`, and
    no produced file is named so as to shadow it; outside `tests/` every
    import is the standard library (`stdlib`, supplied by the caller) or the
    application's own module, and in `tests/` the same plus `pytest`; and no
    file refers to a dynamic import or execution primitive in any of the forms
    `_PRIMITIVE_NAMES` lists, whether or not it is called. A relative import is
    the application's own by construction.

    A STATIC CHECK OVER THE FORMS LISTED, AND NO MORE (A-051). It is not a
    guarantee that produced code cannot reach Forge: what code computes at run
    time -- a name built from pieces and looked up some other way (a computed
    `getattr`, `globals()`, `sys.modules`), a code object, an encoded string --
    is beyond any static scan. That the
    application runs without Forge is established only by running it from a
    copy in which Forge is not importable, which this change does not do: it
    executes nothing.

    BYTES ONLY. Nothing here imports, compiles or executes a produced file.
    """
    prefix = store_directory + "/"
    produced = {path: data for path, data in sources.items() if not path.startswith(prefix)}
    python_files = sorted(path for path in produced if path.endswith(".py"))
    local = _local_modules(python_files)
    allowed = frozenset(stdlib) | local
    findings: list[str] = []
    if ENTRY_POINT not in produced:
        findings.append(f"the entry point {ENTRY_POINT} is missing")
    if _FORGE_PACKAGE in local:
        findings.append(f"a produced file is named {_FORGE_PACKAGE}, which would shadow Forge")
    for path in python_files:
        tree, problem = _parsed(path, produced[path])
        if tree is None:
            findings.append(problem or f"{path} does not parse")
            continue
        in_tests = path.split("/")[0] == "tests"
        permitted = allowed | _TEST_ONLY_IMPORTS if in_tests else allowed
        findings.extend(_primitive_references(path, tree))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            for name in names:
                top = name.split(".")[0]
                if top == _FORGE_PACKAGE:
                    findings.append(f"{path}:{node.lineno} imports {name}; a produced "
                                    "application must not depend on Forge")
                elif top not in permitted:
                    findings.append(
                        f"{path}:{node.lineno} imports {name}, which is neither the Python "
                        "standard library nor the application's own module"
                        + (" nor pytest" if in_tests else ""))
    return findings


__all__ = [
    "DEPENDENCIES",
    "ENTRY_POINT",
    "GENERATED_CONTRACT_BASIS",
    "GENERATED_CONTRACT_PATH",
    "PAM_REF",
    "PAM_SCHEMA",
    "SCOPE_REF",
    "TRUST",
    "VERIFIER_ID",
    "application_files",
    "pam_digest",
    "pam_reference",
    "render_pam",
    "static_findings",
    "subject_digest",
    "validate_pam",
]
