"""The Produced Application Manifest's domain: rendering, validation and the
static entry-point and import check (A-051).

WHAT WOULD FALSIFY IT: a manifest whose digest is not computed from the text
Forge rendered; a manifest that validates while its subject digest, file
count, application list, BRD digest or scope tip disagree with what it lists;
a validator that accepts a field it does not check; a static check that
passes a produced application with no entry point, a third-party import or an
import of Forge -- or that runs any of it. Everything here is pure: bytes and
mappings in, text and findings out.
"""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

import pytest

from nornyx_forge import experience_build, gates, greenfield_verifier
from nornyx_forge.capsule import CapsuleValidationError, canonical_json

try:
    from nornyx_forge import produced_app_manifest as pam
except ImportError as missing:  # red first: on a parent without the module
    _ABSENT = str(missing)

    class _Missing:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"the manifest module does not exist here: {_ABSENT}")

    pam = _Missing()  # type: ignore[assignment]

STDLIB = frozenset(sys.stdlib_module_names)
TIP = "a" * 64
BRD_TEXT_DIGEST = "b" * 64
ROW = {"provider": "codex", "platform": "linux", "eligible": False,
       "confinement": "declared", "reason": "the contract's row, for this unit test"}


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


FILES = {
    "BRD.md": _digest(b"# BRD\n"),
    "app/__main__.py": _digest(b"print('x')\n"),
    "app/cases.py": _digest(b"X = 1\n"),
    "tests/test_cases.py": _digest(b"def test_x():\n    assert True\n"),
    "capsule/capsule.json": _digest(b"{}\n"),
}


def _arguments(**overrides: Any) -> dict[str, Any]:
    files = overrides.pop("files", FILES)
    arguments = {
        "files": files,
        "accepted_subject_digest": pam.subject_digest(files),
        "store_directory": "capsule",
        "generated_contract_digest": "sha256:" + "c" * 64,
        "brd_scope_binding": f"capsule/{TIP}/brd/{BRD_TEXT_DIGEST}",
        "capsule_chain_tip": TIP,
        "sealed_revision": "d" * 40,
        "provider": "codex",
        "eligibility": ROW,
        "verifier_digest": "sha256:" + "e" * 64,
        "gate_profile": {"id": gates.GREENFIELD_PROFILE_ID,
                         "digest": gates.GREENFIELD_PROFILE_DIGEST},
        "forge_version": "0.1.0",
        "forge_revision": "git:" + "f" * 40,
    }
    arguments.update(overrides)
    return arguments


def _rewritten(text: str, change) -> str:
    """The manifest with one field changed and re-encoded canonically, so the
    refusal measured is the field's and not the encoding's."""
    document = json.loads(text)
    change(document)
    return canonical_json(document) + "\n"


# ---------------------------------------------------------------------------
# Rendering and the reference
# ---------------------------------------------------------------------------

def test_the_manifest_is_rendered_canonically_and_named_by_its_own_text():
    text = pam.render_pam(**_arguments())
    document = pam.validate_pam(text)
    assert text == canonical_json(document) + "\n"
    assert document["schema"] == pam.PAM_SCHEMA
    assert pam.pam_reference(text) == "pam/" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert pam.PAM_REF.match(pam.pam_reference(text))
    assert pam.pam_digest(text) == "sha256:" + pam.pam_reference(text)[4:]
    # Pure: the same arguments render the same bytes.
    assert pam.render_pam(**_arguments()) == text
    assert document["application"] == {
        "entry_point": "app/__main__.py",
        "dependencies": {"policy": "python_standard_library_only", "declared": []},
        "files": ["BRD.md", "app/__main__.py", "app/cases.py", "tests/test_cases.py"],
    }
    assert document["trust"]["currency"] == "not_independently_anchored"
    assert document["trust"]["does_not_resist"] == "a_process_running_as_the_same_operating_system_user"
    assert document["brd"]["file_digest"] == FILES["BRD.md"]
    assert document["provider"] == {"name": "codex", "eligibility": ROW}


def test_the_renderer_refuses_what_the_validator_would_refuse():
    with pytest.raises(CapsuleValidationError, match="subject digest"):
        pam.render_pam(**_arguments(accepted_subject_digest="sha256:" + "0" * 64))
    with pytest.raises(CapsuleValidationError, match="entry point"):
        pam.render_pam(**_arguments(files={k: v for k, v in FILES.items()
                                           if k != "app/__main__.py"}))
    with pytest.raises(CapsuleValidationError, match="provider name"):
        pam.render_pam(**_arguments(provider="gemini",
                                    eligibility={**ROW, "provider": "gemini"}))


# ---------------------------------------------------------------------------
# Validation: every field it takes is a field it checks
# ---------------------------------------------------------------------------

def _set(path: tuple[str, ...], value: Any):
    def change(document: dict[str, Any]) -> None:
        target = document
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return change


def _drop(path: tuple[str, ...]):
    def change(document: dict[str, Any]) -> None:
        target = document
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]
    return change


REFUSALS = {
    "an unknown top-level key": (lambda d: d.update(extra=1), "exactly"),
    "a missing top-level key": (_drop(("forge",)), "exactly"),
    "another schema": (_set(("schema",), "nornyx.forge.other.v1"), "schema"),
    "a file digest of another shape": (
        _set(("subject", "files", "app/cases.py"), "md5:00"), "sha256"),
    "a subject digest of other files": (
        _set(("subject", "digest"), "sha256:" + "0" * 64), "subject digest"),
    "a file count that is not the count": (_set(("subject", "file_count"), 4), "file count"),
    "a file count that is a bool": (_set(("subject", "file_count"), True), "file count"),
    "a path that climbs out": (lambda d: d["subject"]["files"].update({"../x": FILES["BRD.md"]}),
                               "relative POSIX path"),
    "an absolute path": (lambda d: d["subject"]["files"].update({"/etc/x": FILES["BRD.md"]}),
                         "relative POSIX path"),
    "a backslash path": (lambda d: d["subject"]["files"].update({"app\\x.py": FILES["BRD.md"]}),
                         "relative POSIX path"),
    "a store directory that is a path": (_set(("store_directory",), "a/b"), "store_directory"),
    "an application list that is not derived": (
        _set(("application", "files"), ["app/__main__.py"]), "application files"),
    "another entry point": (_set(("application", "entry_point"), "main.py"), "entry point"),
    "a declared dependency": (
        _set(("application", "dependencies"),
             {"policy": "python_standard_library_only", "declared": ["requests"]}),
        "standard library"),
    "a contract with another basis": (
        _set(("generated_contract", "basis"), "read_from_the_workspace"), "generated_contract"),
    "a BRD digest that is not the listed one": (
        _set(("brd", "file_digest"), "sha256:" + "0" * 64), "brd must name"),
    "a scope binding of another shape": (_set(("brd", "scope_binding"), "flow/x"), "scope_binding"),
    "a scope binding naming another capsule": (
        _set(("brd", "scope_binding"), f"capsule/{'9' * 64}/brd/{BRD_TEXT_DIGEST}"),
        "another capsule tip"),
    "a short sealed revision": (_set(("capsule", "sealed_revision"), "abc"), "full commit"),
    "an eligibility row for another provider": (
        _set(("provider", "eligibility", "provider"), "claude"), "another provider"),
    "an eligibility that is not a bool": (
        _set(("provider", "eligibility", "eligible"), "yes"), "bool"),
    "an eligibility row with an extra claim": (
        _set(("provider", "eligibility", "attested"), True), "exactly"),
    "another verifier": (_set(("verifier", "id"), "someone.else"), "verifier id"),
    "a verifier digest of another shape": (_set(("verifier", "digest"), "x"), "verifier digest"),
    "a forge revision of another shape": (_set(("forge", "revision"), "HEAD"), "forge revision"),
    "a softened trust statement": (
        _set(("trust", "does_not_resist"), "nothing"), "trust"),
}


@pytest.mark.parametrize("label", sorted(REFUSALS))
def test_the_validator_refuses(label: str):
    change, reason = REFUSALS[label]
    text = _rewritten(pam.render_pam(**_arguments()), change)
    with pytest.raises(CapsuleValidationError, match=reason):
        pam.validate_pam(text)


def test_the_validator_refuses_bytes_that_are_not_the_canonical_text():
    text = pam.render_pam(**_arguments())
    for label, other in (
        ("indented", json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"),
        ("no final newline", text[:-1]),
        ("not JSON", "{not json"),
        ("not text", text.encode("utf-8")),
        ("a list", "[]\n"),
    ):
        with pytest.raises(CapsuleValidationError):
            pam.validate_pam(other)
        assert label


# ---------------------------------------------------------------------------
# Equalities with the owners of the formats this module copies
# ---------------------------------------------------------------------------

def test_the_manifest_computes_the_verifiers_own_subject_digest():
    """The domain copy and the verifier's `_subject_digest` agree, on ordinary
    and non-ASCII paths in any insertion order."""
    for files in (FILES, {"é/ü.py": FILES["BRD.md"], "a.py": FILES["app/cases.py"]}, {}):
        reordered = dict(reversed(list(files.items())))
        assert pam.subject_digest(files) == greenfield_verifier._subject_digest(dict(files))
        assert pam.subject_digest(reordered) == pam.subject_digest(files)


def test_the_manifest_pins_the_gates_own_verifier_identity():
    assert pam.VERIFIER_ID == gates.GREENFIELD_VERIFIER_ID


def test_the_manifest_reads_the_scope_binding_its_owner_writes():
    assert pam.SCOPE_REF.pattern == experience_build.SCOPE_REF.pattern
    written = experience_build.scope_reference(TIP, BRD_TEXT_DIGEST)
    assert pam.SCOPE_REF.match(written).groups() == (TIP, BRD_TEXT_DIGEST)


# ---------------------------------------------------------------------------
# The static entry-point and import check
# ---------------------------------------------------------------------------

REFERENCE = {
    "BRD.md": b"# BRD\n",
    "app/__init__.py": b'"""The register."""\n',
    "app/__main__.py": (b"import argparse\nimport json\n\nfrom app.cases import Register\n"
                        b"from . import cases\n\n\ndef main():\n    return 0\n"),
    "app/cases.py": b"from __future__ import annotations\nimport dataclasses\n\nclass Register:\n    pass\n",
    "tests/test_cases.py": b"import pytest\n\nfrom app.cases import Register\n\n\ndef test_x():\n    assert Register\n",
    "capsule/capsule.json": b"{}\n",
}


def _with(path: str, data: bytes | None) -> list[str]:
    sources = dict(REFERENCE)
    if data is None:
        sources.pop(path)
    else:
        sources[path] = data
    return pam.static_findings(sources, store_directory="capsule", stdlib=STDLIB)


def test_the_reference_shape_has_no_finding():
    assert pam.static_findings(REFERENCE, store_directory="capsule", stdlib=STDLIB) == []


def test_a_missing_entry_point_is_a_finding():
    assert _with("app/__main__.py", None) == ["the entry point app/__main__.py is missing"]


def test_an_entry_point_that_does_not_parse_is_a_finding():
    findings = _with("app/__main__.py", b"def main(:\n")
    assert len(findings) == 1 and findings[0].startswith("app/__main__.py does not parse")


def test_a_third_party_import_in_the_application_is_a_finding():
    findings = _with("app/cases.py", b"import requests\nfrom yaml import safe_load\n")
    assert findings == [
        "app/cases.py:1 imports requests, which is neither the Python standard library "
        "nor the application's own module",
        "app/cases.py:2 imports yaml, which is neither the Python standard library "
        "nor the application's own module",
    ]


def test_pytest_is_a_test_dependency_and_not_an_application_one():
    assert _with("tests/test_cases.py", b"import pytest\n") == []
    assert _with("app/cases.py", b"import pytest\n") == [
        "app/cases.py:1 imports pytest, which is neither the Python standard library "
        "nor the application's own module"]
    assert _with("tests/test_cases.py", b"import hypothesis\n") == [
        "tests/test_cases.py:1 imports hypothesis, which is neither the Python standard "
        "library nor the application's own module nor pytest"]


@pytest.mark.parametrize("path, source", [
    ("app/cases.py", b"import nornyx_forge\n"),
    ("app/cases.py", b"from nornyx_forge.capsule import canonical_json\n"),
    ("app/__main__.py", b"import nornyx_forge.gates as g\n"),
    ("tests/test_cases.py", b"from nornyx_forge import capsule\n"),
    ("app/cases.py", b"def f():\n    import nornyx_forge\n"),
])
def test_an_import_of_forge_anywhere_is_a_finding(path: str, source: bytes):
    """The produced application must not depend on Forge, in its own
    modules or in its tests, at module level or inside a function."""
    findings = _with(path, source)
    assert any("must not depend on Forge" in finding for finding in findings), findings


def test_a_produced_module_that_would_shadow_forge_is_a_finding():
    findings = _with("nornyx_forge/__init__.py", b"")
    assert "a produced file is named nornyx_forge, which would shadow Forge" in findings


def test_a_dynamic_import_is_a_finding_because_a_static_check_cannot_see_it():
    for source in (b"m = __import__('json')\n", b"import importlib\nm = importlib.import_module('json')\n"):
        findings = _with("app/cases.py", source)
        assert any("imports dynamically" in finding for finding in findings), findings


#: The dynamic-import and dynamic-execution forms the static check refuses AS A
#: CLASS (Codex P2 4359780685 on afa35eb named the first). Each sits in the
#: application, and its target is never what decides: a literal argument is
#: refused as well as a computed one.
DYNAMIC_FORMS = {
    "an aliased import_module": (
        b"from importlib import import_module as m\nm('nornyx_forge')\n", "imports dynamically"),
    "an aliased importlib module": (
        b"import importlib as x\nx.import_module('json')\n", "imports dynamically"),
    "import_module bound by assignment": (
        b"from importlib import import_module\nload = import_module\nload('json')\n",
        "imports dynamically"),
    "__import__ bound by assignment": (b"imp = __import__\nimp('json')\n", "imports dynamically"),
    "__import__ with a computed target": (b"name = 'js' + 'on'\n__import__(name)\n",
                                          "imports dynamically"),
    "builtins.__import__": (b"import builtins\nbuiltins.__import__('json')\n",
                            "imports dynamically"),
    "importlib.__import__": (b"import importlib\nimportlib.__import__('json')\n",
                             "imports dynamically"),
    "an aliased builtins.__import__": (
        b"import builtins as b\nf = b.__import__\nf('json')\n", "imports dynamically"),
    "import_module reached by getattr": (
        b"import importlib\nf = getattr(importlib, 'import_module')\nf('json')\n",
        "by reflection"),
    "builtins reached by a computed getattr": (
        b"import builtins\nname = 'ex' + 'ec'\ngetattr(builtins, name)('x = 1')\n",
        "by reflection"),
    # Split literals, so the repository's own dynamic-execution scan
    # (scripts/check_security.py) does not read these specimens as calls.
    "eval": (b"ev" b"al('1')\n", "executes dynamically"),
    "exec": (b"ex" b"ec('x = 1')\n", "executes dynamically"),
    "compile": (b"compile('1', 'x', 'eval')\n", "executes dynamically"),
    "builtins.exec": (b"import builtins\nbuiltins.ex" b"ec('x = 1')\n", "executes dynamically"),
    "an aliased eval": (b"from builtins import eval as e\ne('1')\n", "executes dynamically"),
}


@pytest.mark.parametrize("label", sorted(DYNAMIC_FORMS))
def test_a_dynamic_import_or_execution_primitive_is_refused_however_it_is_bound(label: str):
    source, kind = DYNAMIC_FORMS[label]
    findings = _with("app/cases.py", source)
    assert any(kind in finding for finding in findings), (label, findings)


def test_the_check_resolves_names_by_the_verifiers_own_alias_rule():
    """The alias resolution is the trusted verifier's, copied because this
    module may not import an adapter, and held equal here on every form above."""
    import ast

    for source, _ in DYNAMIC_FORMS.values():
        tree = ast.parse(source.decode())
        assert pam._aliases(tree) == greenfield_verifier._aliases(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                assert pam._resolved_callable_name(node.func, pam._aliases(tree)) == (
                    greenfield_verifier._resolved_callable_name(
                        node.func, greenfield_verifier._aliases(tree)))


def test_the_store_is_not_inspected_and_relative_imports_are_the_applications_own():
    assert _with("capsule/anything.py", b"import requests\n") == []
    assert _with("app/cases.py", b"from . import sibling\nfrom .x import y\n") == []
    assert _with("src/helper.py", b"X = 1\n") == []
    assert _with("app/cases.py", b"import helper\n") == [
        "app/cases.py:1 imports helper, which is neither the Python standard library "
        "nor the application's own module"]
    sources = {**REFERENCE, "src/helper.py": b"X = 1\n", "app/cases.py": b"import helper\n"}
    assert pam.static_findings(sources, store_directory="capsule", stdlib=STDLIB) == []


def test_the_static_check_reads_bytes_and_runs_nothing(tmp_path, monkeypatch):
    """A produced source whose import would leave a mark leaves none: the check
    parses and never imports, compiles to code or executes."""
    marker = tmp_path / "ran"
    source = f"open({str(marker)!r}, 'w').write('ran')\n".encode()
    monkeypatch.setattr(sys, "path", [str(tmp_path), *sys.path])
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__main__.py").write_bytes(source)
    findings = pam.static_findings({**REFERENCE, "app/__main__.py": source},
                                   store_directory="capsule", stdlib=STDLIB)
    assert findings == [] and not marker.exists()
    assert "app.__main__" not in sys.modules
