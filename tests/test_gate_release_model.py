"""The run-act gate's boundary as data (A-055): path spellings, the credential
pattern as configurable data, the release manifest, the completeness list,
and the stage, import and provenance records.

WHAT WOULD FALSIFY IT: a released name that two spellings could reach, or
that lands outside the workspace or inside a directory that is never product,
accepted; a manifest line with an extra, missing or wrongly-typed field, a
repeated identifier or name, or a byte-order mark, CR or unterminated line,
accepted; a completeness list that names a file not released, misses one
released, or names itself, accepted; a credential pattern that cannot be
recorded, or a scan narrower than the gate's; a record or provenance that
validates with a field of the wrong kind. Everything here is pure.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest

from nornyx_forge import provider_gate

try:
    from nornyx_forge import gate_release_model as model
except ImportError as missing:  # red first: on a parent without the module
    _ABSENT = str(missing)

    class _Missing:
        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"the gate release model does not exist here: {_ABSENT}")

    model = _Missing()  # type: ignore[assignment]

KEY = "sk-" + "Fak3" * 6  # synthetic, 24 characters after the prefix


def _layout(**change: Any):
    values = {"manifest_name": "hold-manifest.jsonl", "workspace_prefix": "ws\\",
              "record_name": "release-record.json"}
    values.update(change)
    return model.ReleaseLayout(**values)


def _line(**fields: Any) -> str:
    row = {"id": "i0001", "name": "ws\\app\\x.py", "size": 3, "digest": "a" * 64}
    row.update(fields)
    return json.dumps(row, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Path spellings
# ---------------------------------------------------------------------------

ACCEPTED_PATHS = ["app/__main__.py", ".forge-tree.txt", "tests/test_cases.py", "a/b/c-d_e.f.txt",
                  ".gitignore", "README"]

REFUSED_PATHS = {
    "an empty path": "",
    "a leading slash": "/etc/passwd",
    "a climb": "app/../x.py",
    "a dot segment": "app/./x.py",
    "an empty segment": "app//x.py",
    "a trailing slash": "app/",
    "a backslash": "app\\x.py",
    "a drive": "C:/x.py",
    "a named stream": "app/x.py:evil",
    "a space": "app/my file.py",
    "a tilde (8.3 short name)": "PROGRA~1/x.py",
    "a trailing dot": "app/x.",
    "a dots-only segment": "app/.../x.py",
    "a device name": "app/CON",
    "a device name with an extension": "app/nul.txt",
    "a device name in lower case": "lpt1",
    "a non-ASCII letter": "app/caf\u00e9.py",
    "a full-width solidus": "app\uff0fx.py",
    "a control character": "app/x\x01.py",
    "git anywhere": "app/.git/config",
    "git in upper case": ".GIT/hooks/post-checkout",
    "forge's governance directory": ".nornyx/contracts/x.nyx",
    "a reserved directory the caller names": "__pycache__/x.pyc",
    "a too-long segment": "a" * 101,
    "too deep": "/".join(["d"] * 33),
}


@pytest.mark.parametrize("path", ACCEPTED_PATHS)
def test_a_plain_workspace_path_is_accepted(path: str):
    assert model.workspace_path_problem(path, {"__pycache__"}) is None


@pytest.mark.parametrize("label", sorted(REFUSED_PATHS))
def test_every_other_spelling_is_refused(label: str):
    assert model.workspace_path_problem(REFUSED_PATHS[label], {"__pycache__"}) is not None


def test_collisions_on_a_case_insensitive_file_system_are_named():
    assert model.collision_problems(["app/X.py", "app/x.py"])
    assert model.collision_problems(["App/x.py", "app/y.py", "APP"])
    assert model.collision_problems(["a", "a/b"])
    assert model.collision_problems(["a/b", "a/c", "b"]) == []


def test_a_released_name_is_read_only_in_the_gates_spelling():
    layout = _layout()
    assert model.workspace_path_of("ws\\app\\x.py", layout) == "app/x.py"
    assert model.workspace_path_of("gate-stdout.txt", layout) is None
    assert model.name_problem("ws\\app\\x.py", layout, ()) is None
    assert model.name_problem("gate-stdout.txt", layout, ()) is None
    for refused in ("ws\\app/x.py", "ws/app/x.py", "ws\\..\\x.py", "ws\\app\\x.py.",
                    "a\\b", "WS\\app\\x.py\\", "ws\\", "ws\\\\x.py", "ws\\CON"):
        assert model.name_problem(refused, layout, ()) is not None, refused


# ---------------------------------------------------------------------------
# The credential pattern, as data
# ---------------------------------------------------------------------------

def test_forge_holds_its_own_copy_of_the_gates_current_seed_pattern():
    assert model.GATE_SEED_PATTERN.expressions == (r"sk-[A-Za-z0-9_-]{20,}",)
    record = model.GATE_SEED_PATTERN.record()
    assert record["id"] == "d3g-seed-current"
    assert record["digest"] == "sha256:" + hashlib.sha256(json.dumps(
        {"expressions": list(record["expressions"]), "id": record["id"]},
        sort_keys=True, separators=(",", ":")).encode() + b"\n").hexdigest()


def test_the_current_pattern_hits_a_key_and_its_known_false_positive():
    """The known defect is recorded, not repaired here: "task-" followed by
    20 identifier characters is a hit under the gate's current pattern."""
    pattern = model.GATE_SEED_PATTERN
    assert model.credential_hits(f"key = {KEY}\n".encode(), pattern) == 1
    assert model.credential_hits(b"task-management-dashboard-v2\n", pattern) == 1
    assert model.credential_hits(b"plain text with sk-short\n", pattern) == 0


def test_the_import_pattern_is_the_gates_current_pattern_and_no_weaker():
    """Founder precaution (A-055): Forge-owned, never weaker than the gate's
    current `sk-[A-Za-z0-9_-]{20,}`; a record naming any other is refused."""
    assert model.IMPORT_PATTERN is model.GATE_SEED_PATTERN
    assert model.IMPORT_PATTERN.expressions == (r"sk-[A-Za-z0-9_-]{20,}",)
    assert model.validate_pattern_record(model.IMPORT_PATTERN.record())
    for other in (
        model.CredentialPattern("weaker", (r"sk-[A-Za-z0-9_-]{99,}",)),
        model.CredentialPattern(
            "left-bounded",
            (r"(?:(?<![A-Za-z0-9_-])|(?<=%[0-9A-Fa-f]{2}))sk-[A-Za-z0-9_-]{20,}",)),
        model.CredentialPattern("d3g-seed-current", (r"sk-[A-Za-z0-9_-]{21,}",)),
    ):
        with pytest.raises(model.GateReleaseRefused, match="other than Forge's import pattern"):
            model.validate_pattern_record(other.record())
    with pytest.raises(model.GateReleaseRefused):
        model.validate_pattern_record({"id": "empty", "expressions": [], "digest": "sha256:"})


def test_the_import_record_cannot_be_rendered_with_another_pattern():
    with pytest.raises(TypeError):
        _import_record(pattern=model.CredentialPattern("weaker", (r"sk-x{99,}",)))


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be", "latin-1"])
def test_the_scan_is_independent_of_the_encoding(encoding: str):
    data = f"prefix \u00e9 {KEY} suffix".encode(encoding)
    assert model.credential_hits(data, model.GATE_SEED_PATTERN) == 1


def test_the_scan_sees_a_key_in_bytes_that_are_not_valid_text():
    assert model.credential_hits(b"\xff\xfe\x00" + KEY.encode() + b"\x80",
                                 model.GATE_SEED_PATTERN) == 1


@pytest.mark.parametrize("expressions", [(), ("",), ("(",), ("a*",), ("\u00e9",), ["x"]])
def test_an_unusable_pattern_is_refused_when_built(expressions):
    with pytest.raises(model.GateReleaseRefused):
        model.CredentialPattern("p", expressions)


def test_a_pattern_id_is_one_plain_name():
    with pytest.raises(model.GateReleaseRefused):
        model.CredentialPattern("a b", ("x",))


# ---------------------------------------------------------------------------
# The release layout and manifest
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("change", [
    {"manifest_name": "a/b"}, {"manifest_name": "CON"}, {"manifest_name": ""},
    {"record_name": "HOLD-MANIFEST.jsonl"}, {"workspace_prefix": "ws"},
    {"workspace_prefix": "ws/"}, {"workspace_prefix": "a\\b\\"}, {"workspace_prefix": "\\"},
])
def test_an_unusable_layout_is_refused(change):
    with pytest.raises(model.GateReleaseRefused):
        _layout(**change)


def test_a_manifest_is_parsed_into_its_rows():
    text = _line() + "\n" + _line(id="i0002", name="gate-stdout.txt", size=0) + "\n"
    rows = model.parse_release_manifest(text.encode(), _layout())
    assert [row.id for row in rows] == ["i0001", "i0002"]
    assert rows[0] == model.ReleaseRow("i0001", "ws\\app\\x.py", 3, "a" * 64)
    assert model.parse_release_manifest(b"\n", _layout()) == []


MANIFEST_REFUSALS = {
    "a byte-order mark": b"\xef\xbb\xbf" + (_line() + "\n").encode(),
    "not UTF-8": b"\xff\n",
    "a CR": (_line() + "\r\n").encode(),
    "an unterminated last line": _line().encode(),
    "empty": b"",
    "an empty line": (_line() + "\n\n").encode(),
    "not JSON": b"{oops\n",
    "a list": b"[]\n",
    "an extra field": (_line()[:-1] + ',"owner":"x"}\n').encode(),
    "a missing field": b'{"id":"i0001","name":"ws\\\\a","size":1}\n',
    "a repeated key": (_line()[:-1] + ',"id":"i0009"}\n').encode(),
    "NaN as the size": _line(size=0).replace('"size":0', '"size":NaN').encode() + b"\n",
    "a bool as the size": (_line(size=True) + "\n").encode(),
    "a negative size": (_line(size=-1) + "\n").encode(),
    "a float size": (_line(size=1.0) + "\n").encode(),
    "an upper-case digest": (_line(digest="A" * 64) + "\n").encode(),
    "a prefixed digest": (_line(digest="sha256:" + "a" * 64) + "\n").encode(),
    "an id that is a path": (_line(id="..\\x") + "\n").encode(),
    "an id that is a device": (_line(id="NUL") + "\n").encode(),
    "an id that is the manifest's name": (_line(id="hold-manifest") + "\n").encode(),
    "a control character in a name": (_line(name="ws\\a\x00") + "\n").encode(),
    "a repeated id": (_line() + "\n" + _line(name="ws\\b") + "\n").encode(),
    "a repeated id in another case": (_line() + "\n" + _line(id="I0001", name="ws\\b")
                                      + "\n").encode(),
    "a repeated name": (_line() + "\n" + _line(id="i0002") + "\n").encode(),
    "a repeated name in another case": (_line() + "\n" + _line(id="i0002", name="WS\\APP\\X.PY")
                                        + "\n").encode(),
}


@pytest.mark.parametrize("label", sorted(MANIFEST_REFUSALS))
def test_the_manifest_is_refused(label: str):
    layout = _layout(manifest_name="hold-manifest")
    with pytest.raises(model.GateReleaseRefused):
        model.parse_release_manifest(MANIFEST_REFUSALS[label], layout)


def test_a_manifest_over_the_item_bound_is_refused():
    lines = "".join(_line(id=f"i{n:05d}", name=f"ws\\f{n}") + "\n" for n in range(2001))
    with pytest.raises(model.GateReleaseRefused, match="more than"):
        model.parse_release_manifest(lines.encode(), _layout())


# ---------------------------------------------------------------------------
# The completeness list
# ---------------------------------------------------------------------------

def test_the_list_names_exactly_the_other_files():
    listed = model.parse_completeness_list(b"app/__main__.py\nBRD.md\n")
    held = {"app/__main__.py", "BRD.md", model.COMPLETENESS_LIST}
    assert model.completeness_problems(listed, held) == []
    assert model.completeness_problems(listed, held | {"extra.py"}) == [
        "'extra.py' was released and is not listed"]
    assert model.completeness_problems(listed + ["gone.py"], held) == [
        "'gone.py' is listed and was not released"]


@pytest.mark.parametrize("data", [
    b"\xef\xbb\xbfa\n", b"a\r\n", b"a", b"a\n\nb\n", b"a\na\n", b"\xff\n",
    b".forge-tree.txt\n", b"\n",
])
def test_the_list_is_refused(data: bytes):
    with pytest.raises(model.GateReleaseRefused):
        model.parse_completeness_list(data)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

def _stage_manifest(**change: Any) -> str:
    arguments = {
        "role": "codex", "stage": "s" + "0" * 16,
        "files": {"BRD.md": (5, "sha256:" + "1" * 64)},
        "sources": {"brd": "sha256:" + "1" * 64, "generated_contract": "sha256:" + "2" * 64,
                    "runtime_contract": "sha256:" + "3" * 64,
                    "requirements": "sha256:" + "4" * 64,
                    "instructions": "sha256:" + "5" * 64, "verified_import": None},
    }
    arguments.update(change)
    return model.render_stage_manifest(**arguments)


def test_a_stage_manifest_round_trips_and_refuses_another_shape():
    text = _stage_manifest()
    assert model.validate_stage_manifest(text)["files"]["BRD.md"]["size"] == 5
    for bad in (text.replace('"codex"', '"co dex"'), text.replace("s000", "S000"),
                text[:-1], json.dumps(json.loads(text), indent=1)):
        with pytest.raises(model.GateReleaseRefused):
            model.validate_stage_manifest(bad)
    with pytest.raises(model.GateReleaseRefused):
        _stage_manifest(files={"a/../b": (1, "sha256:" + "1" * 64)})
    with pytest.raises(model.GateReleaseRefused):
        _stage_manifest(files={"A": (1, "sha256:" + "1" * 64), "a": (1, "sha256:" + "1" * 64)})


def _import_record(**change: Any) -> str:
    items = [
        {"id": "i0001", "name": "ws\\.forge-tree.txt", "kind": "workspace",
         "path": ".forge-tree.txt", "size": 0, "digest": "sha256:" + "1" * 64},
        {"id": "i0002", "name": "gate-stdout.txt", "kind": "gate_item", "path": "i0002",
         "size": 0, "digest": "sha256:" + "2" * 64},
    ]
    arguments = {"cycle_id": "c01", "release_manifest_digest": "sha256:" + "3" * 64,
                 "release_record_digest": None, "completeness_list_digest": "sha256:" + "4" * 64,
                 "items": items,
                 "workspace_subject_digest": "sha256:" + "5" * 64}
    arguments.update(change)
    return model.render_import_record(**arguments)


def _changed(text: str, change) -> str:
    document = json.loads(text)
    change(document)
    return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"


IMPORT_RECORD_REFUSALS = {
    "a state other than COMPLETE": lambda d: d.update(state="INCOMPLETE"),
    "hits": lambda d: d.update(credential_hits=1),
    "hits as a bool": lambda d: d.update(credential_hits=False),
    "an extra key": lambda d: d.update(extra=1),
    "a pattern whose digest is not its own": lambda d: d["credential_pattern"].update(
        digest="sha256:" + "0" * 64),
    "a pattern with another expression": lambda d: d["credential_pattern"].update(
        expressions=["x"]),
    "a gate item stored under another name": lambda d: d["items"][1].update(path="elsewhere"),
    "a workspace path that climbs": lambda d: d["items"][0].update(path="../x"),
    "no completeness list": lambda d: d["items"][0].update(path="other.txt"),
    "an unknown kind": lambda d: d["items"][0].update(kind="secret"),
    "items out of order": lambda d: d.update(items=list(reversed(d["items"]))),
    "a cycle id that is a path": lambda d: d.update(cycle_id="../c"),
}


@pytest.mark.parametrize("label", sorted(IMPORT_RECORD_REFUSALS))
def test_an_import_record_of_another_shape_is_refused(label: str):
    text = _import_record()
    assert model.validate_import_record(text)["state"] == "COMPLETE"
    with pytest.raises(model.GateReleaseRefused):
        model.validate_import_record(_changed(text, IMPORT_RECORD_REFUSALS[label]))


def _provenance(**change: Any) -> dict[str, Any]:
    arguments = {"cycle_id": "c01", "run_act_sha256": provider_gate.PINNED_RUN_ACT_SHA256,
                 "stage_manifest": "sha256:" + "1" * 64, "release_manifest": "sha256:" + "2" * 64,
                 "import_record": "sha256:" + "3" * 64, "completeness_list": "sha256:" + "4" * 64,
                 "check_d3g_result": "sha256:" + "5" * 64,
                 "credential_pattern": model.GATE_SEED_PATTERN.record()}
    arguments.update(change)
    return model.gate_provenance(**arguments)


def test_a_provenance_states_static_only_and_what_was_cited():
    value = _provenance()
    assert value["verification"] == "static_only" and value["test_execution"] == "not_run"
    assert value["basis"]["cited_by_the_act_not_verified"] == ["cycle_id", "check_d3g_result"]
    assert model.validate_gate_provenance(value) is value


@pytest.mark.parametrize("change", [
    {"verification": "full"}, {"test_execution": "passed"}, {"run_act_sha256": "A" * 64},
    {"stage_manifest": "1" * 64}, {"basis": {}}, {"extra": 1}, {"cycle_id": ""},
    {"credential_pattern": {"id": "x", "expressions": ["y"], "digest": "sha256:" + "0" * 64}},
])
def test_a_provenance_of_another_shape_is_refused(change):
    value = {**_provenance(), **change}
    with pytest.raises(model.GateReleaseRefused):
        model.validate_gate_provenance(value)


# ---------------------------------------------------------------------------
# Equalities with the owners of the values this module copies
# ---------------------------------------------------------------------------

def test_the_role_rule_is_the_gate_launchs_own():
    assert model.ROLE.pattern.removeprefix(r"\A").removesuffix(r"\Z") == \
        provider_gate._ROLE.pattern


def test_the_model_reads_no_ambient_state():
    """Pure: the module imports no filesystem, process or interpreter state."""
    source = model.__loader__.get_source(model.__name__)
    imported = set(re.findall(r"^(?:from|import) ([\w.]+)", source, re.MULTILINE))
    assert imported <= {"__future__", "hashlib", "json", "re", "dataclasses", "typing"}
