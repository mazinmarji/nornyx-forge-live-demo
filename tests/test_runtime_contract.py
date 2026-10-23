"""The runtime operation contract (A-053): declared operations, never inferred ones.

`contract_generator.render_runtime_contract` turns a BRD model and a mapping of
declared operations into a closed operation table. Every field it holds about
an operation comes from `nornyx_runtime.OPERATION_REGISTRY` (A-047); nothing
reads a requirement's words. An unregistered operation is refused; every
operation that needs an approval is refused by the application's boundary,
because no approval mechanism exists; and the validator accepts a contract
only if it is exactly what Forge renders. The development flow renders the
empty table -- it declares nothing -- and binds its digest.

What this does NOT establish: that any produced application honours the
table. Forge's own reference specimen does, as `test_capability_guard.py`
measures; a provider's application is not built or run here.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from nornyx_forge import contract_generator as generator
from nornyx_forge import nornyx_runtime
from nornyx_forge.requirements import RequirementsModel, parse_brd

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runtime_boundary_specimen import BRD, DECLARATIONS  # noqa: E402


def _model(tmp_path: Path, text: str = BRD) -> RequirementsModel:
    path = tmp_path / "BRD.md"
    path.write_text(text, encoding="utf-8", newline="")
    return parse_brd(path)


def _render(model: RequirementsModel, declarations: object = DECLARATIONS) -> str:
    return generator.render_runtime_contract(model, declarations)


def _entries(text: str) -> dict[str, dict[str, str]]:
    return {entry["operation"]: entry for entry in json.loads(text)["operations"]}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def test_the_contract_is_deterministic_canonical_and_sorted(tmp_path: Path) -> None:
    model = _model(tmp_path)
    reversed_declarations = dict(reversed(list(DECLARATIONS.items())))

    text = _render(model)

    assert text == _render(model) == _render(model, reversed_declarations)
    assert text.endswith("\n") and "\r" not in text
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"
    data = json.loads(text)
    assert data["schema"] == "nornyx.forge.runtime_contract.v1"
    assert data["brd"] == {"source": "BRD.md", "source_digest": model.source_digest}
    assert data["unlisted_operation"] == "refused"
    assert data["always_refused_consequences"] == [
        "destructive_bulk_deletion", "external_transmission"]
    assert [entry["operation"] for entry in data["operations"]] == sorted(DECLARATIONS)


def test_every_field_about_an_operation_comes_from_the_registry(tmp_path: Path) -> None:
    entries = _entries(_render(_model(tmp_path)))

    for operation, requirement in DECLARATIONS.items():
        registered = nornyx_runtime.OPERATION_REGISTRY[operation]
        assert entries[operation] == {
            "operation": operation,
            "consequence": registered.consequence,
            "risk": registered.risk,
            "capability": registered.capability,
            "requirement": requirement,
            "disposition": entries[operation]["disposition"],
        }
    assert entries["delete all service requests"]["consequence"] == "destructive_bulk_deletion"
    assert entries["send external email"]["consequence"] == "external_transmission"


def test_the_contract_binds_the_registry_it_was_classified_against(tmp_path: Path) -> None:
    registry = json.loads(_render(_model(tmp_path)))["operation_registry"]

    expected = "sha256:" + hashlib.sha256(json.dumps(
        [[entry.operation, entry.consequence, entry.risk, entry.capability]
         for _name, entry in sorted(nornyx_runtime.OPERATION_REGISTRY.items())],
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    assert registry == {
        "name": "nornyx_forge.nornyx_runtime.OPERATION_REGISTRY", "digest": expected}


def test_only_the_low_impact_operation_is_permitted(tmp_path: Path) -> None:
    model = _model(tmp_path, BRD)
    every = {operation: "BRD-F-001" for operation in nornyx_runtime.OPERATION_REGISTRY}

    entries = _entries(_render(model, every))

    assert {name for name, entry in entries.items()
            if entry["disposition"] == "permitted"} == {"send guidance"}
    for name, entry in entries.items():
        if name != "send guidance":
            assert entry["disposition"] == "refused_no_approval_mechanism", name
            assert entry["capability"] == "execute_high_risk_effect", name


def test_the_two_consequences_are_refused_even_were_they_registered_low(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A registry where both carried low risk would still not release them:
    # the disposition names the consequence before it reads the capability.
    relaxed = dict(nornyx_runtime.OPERATION_REGISTRY)
    for name in ("delete all service requests", "send external email"):
        entry = relaxed[name]
        relaxed[name] = nornyx_runtime.RegisteredOperation(
            entry.operation, entry.consequence, "low", "execute_low_risk_action")
    monkeypatch.setattr(generator, "OPERATION_REGISTRY", relaxed)

    entries = _entries(_render(_model(tmp_path)))

    assert entries["delete all service requests"]["disposition"] == "refused_no_approval_mechanism"
    assert entries["send external email"]["disposition"] == "refused_no_approval_mechanism"
    assert entries["send guidance"]["disposition"] == "permitted"


# ---------------------------------------------------------------------------
# Declared, never inferred
# ---------------------------------------------------------------------------

def test_a_row_declares_nothing_by_its_words(tmp_path: Path) -> None:
    # Every row here SAYS a consequential act; none declares one.
    loud = BRD.replace(
        "A team member records a short note in the notebook.",
        "Delete all service requests and send external email to everyone at once.",
    )

    assert json.loads(_render(_model(tmp_path, loud), {}))["operations"] == []
    assert json.loads(_render(_model(tmp_path, loud), None))["operations"] == []


def test_a_declaration_is_classified_by_the_registry_not_the_rows_words(tmp_path: Path) -> None:
    # The row's words describe a harmless note; the declaration names an
    # external send. The registry decides, so the send is what is recorded.
    entries = _entries(_render(_model(tmp_path), {"send external email": "BRD-F-001"}))

    assert entries["send external email"]["consequence"] == "external_transmission"
    assert entries["send external email"]["disposition"] == "refused_no_approval_mechanism"


def test_the_renderer_never_reads_a_requirements_words(tmp_path: Path) -> None:
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    one = _model(tmp_path / "one")
    reworded = BRD.replace("records a short note", "erases everything and mails it out")
    other = _model(tmp_path / "two", reworded)

    first, second = json.loads(_render(one)), json.loads(_render(other))

    assert first["operations"] == second["operations"]
    assert first["brd"]["source_digest"] != second["brd"]["source_digest"]


@pytest.mark.parametrize("operation", [
    "archive every note", "Send guidance", "send guidance ", " send guidance",
    "send  guidance", "SEND EXTERNAL EMAIL", "delete", "", "send guidance\n",
])
def test_an_unregistered_operation_is_refused(tmp_path: Path, operation: str) -> None:
    with pytest.raises(generator.RuntimeContractRefused) as refused:
        _render(_model(tmp_path), {operation: "BRD-F-001"})

    assert str(refused.value).startswith(nornyx_runtime.OPERATION_UNREGISTERED)


def test_a_string_subclass_is_not_a_registered_spelling(tmp_path: Path) -> None:
    class Lookalike(str):
        def __eq__(self, other: object) -> bool:
            return True

        def __hash__(self) -> int:
            return hash("send guidance")

    with pytest.raises(generator.RuntimeContractRefused):
        _render(_model(tmp_path), {Lookalike("anything"): "BRD-F-001"})


@pytest.mark.parametrize("declarations", [
    {"send guidance": "BRD-F-009"},     # not a requirement of this BRD
    {"send guidance": "BRD-002"},       # a section, which states nothing
    {"send guidance": "brd-f-001"},     # another spelling of a requirement
    {"send guidance": 1},
    {"send guidance": None},
    {1: "BRD-F-001"},
    {("send guidance",): "BRD-F-001"},
])
def test_a_declaration_naming_no_requirement_of_this_brd_is_refused(
    tmp_path: Path, declarations: dict
) -> None:
    with pytest.raises(generator.RuntimeContractRefused):
        _render(_model(tmp_path), declarations)


@pytest.mark.parametrize("declarations", [[("send guidance", "BRD-F-001")], "send guidance", 7])
def test_declarations_that_are_not_a_mapping_are_refused(
    tmp_path: Path, declarations: object
) -> None:
    with pytest.raises(generator.RuntimeContractRefused):
        _render(_model(tmp_path), declarations)


# ---------------------------------------------------------------------------
# Validation: exactly what Forge renders, or nothing
# ---------------------------------------------------------------------------

def test_the_rendered_contract_validates(tmp_path: Path) -> None:
    model = _model(tmp_path)
    text = _render(model)

    assert generator.validate_runtime_contract(text, model) == json.loads(text)
    empty = _render(model, {})
    assert generator.validate_runtime_contract(empty, model)["operations"] == []


def _edited(text: str, edit) -> str:
    data = json.loads(text)
    edit(data)
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _set_entry(name: str, key: str, value: object):
    def edit(data: dict) -> None:
        for entry in data["operations"]:
            if entry["operation"] == name:
                entry[key] = value
    return edit


_FORGERIES = {
    "permitted bulk deletion": _set_entry(
        "delete all service requests", "disposition", "permitted"),
    "permitted external send": _set_entry("send external email", "disposition", "permitted"),
    "lowered risk": _set_entry("send external email", "risk", "low"),
    "low capability": _set_entry(
        "send external email", "capability", "execute_low_risk_action"),
    "renamed consequence": _set_entry(
        "delete all service requests", "consequence", "local_guidance_note"),
    "unregistered operation": _set_entry("send guidance", "operation", "archive every note"),
    "other requirement": _set_entry("send guidance", "requirement", "BRD-F-009"),
    "extra entry key": _set_entry("send guidance", "approved_by", "nobody"),
    "missing entry key": lambda data: data["operations"][0].pop("risk"),
    "extra top key": lambda data: data.__setitem__("approval", "granted"),
    "missing top key": lambda data: data.pop("always_refused_consequences"),
    "always-refused emptied": lambda data: data.__setitem__("always_refused_consequences", []),
    "unlisted permitted": lambda data: data.__setitem__("unlisted_operation", "permitted"),
    "other schema": lambda data: data.__setitem__("schema", "nornyx.forge.runtime_contract.v0"),
    "other brd": lambda data: data["brd"].__setitem__("source_digest", "sha256:" + "0" * 64),
    "other registry": lambda data: data["operation_registry"].__setitem__(
        "digest", "sha256:" + "0" * 64),
    "duplicated entry": lambda data: data["operations"].append(dict(data["operations"][0])),
    "operations not a list": lambda data: data.__setitem__("operations", {}),
    "entry not an object": lambda data: data["operations"].__setitem__(0, "send guidance"),
    "non-text operation": _set_entry("send guidance", "operation", 7),
}


@pytest.mark.parametrize("label", sorted(_FORGERIES))
def test_a_contract_differing_from_the_rendering_is_refused(tmp_path: Path, label: str) -> None:
    model = _model(tmp_path)
    forged = _edited(_render(model), _FORGERIES[label])

    with pytest.raises(generator.RuntimeContractRefused):
        generator.validate_runtime_contract(forged, model)


def test_a_contract_with_an_entry_removed_is_only_stricter_and_its_digest_differs(
    tmp_path: Path,
) -> None:
    # The validator re-derives a contract from its own entries, so a table
    # with one declaration fewer is still a table Forge renders -- for fewer
    # declarations -- and the removed operation becomes unlisted, so refused.
    # What tells it apart from the build's table is the digest bound at
    # generation, never this validator.
    model = _model(tmp_path)
    text = _render(model)
    fewer = _edited(text, lambda data: data["operations"].pop())

    assert generator.validate_runtime_contract(fewer, model)
    assert len(json.loads(fewer)["operations"]) == len(DECLARATIONS) - 1
    assert hashlib.sha256(fewer.encode()).digest() != hashlib.sha256(text.encode()).digest()


def test_unsorted_reformatted_or_non_text_contracts_are_refused(tmp_path: Path) -> None:
    model = _model(tmp_path)
    text = _render(model)
    data = json.loads(text)
    data["operations"].reverse()
    variants = [
        json.dumps(data, indent=2, sort_keys=True) + "\n",       # unsorted entries
        json.dumps(json.loads(text), sort_keys=True),            # another layout
        text.replace("\n", "\r\n"),                               # another line ending
        text.rstrip("\n"),                                        # no final newline
        text.encode("utf-8"),                                     # bytes, not text
        None,
        "not json",
        "[]",
        text.replace('"schema"', '"schema": "x", "schema"', 1),   # a repeated key
        text.replace('"refused"', "NaN", 1),                      # a non-JSON constant
    ]
    for variant in variants:
        with pytest.raises(generator.RuntimeContractRefused):
            generator.validate_runtime_contract(variant, model)


def test_a_contract_for_another_brd_is_refused(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    model = _model(tmp_path / "a")
    other = _model(tmp_path / "b", BRD.replace("short team notes", "brief team notes"))

    with pytest.raises(generator.RuntimeContractRefused):
        generator.validate_runtime_contract(_render(other), model)


# ---------------------------------------------------------------------------
# Writing, and the build's binding
# ---------------------------------------------------------------------------

def test_generation_writes_exactly_the_rendered_bytes(tmp_path: Path) -> None:
    model = _model(tmp_path)

    target = generator.generate_runtime_contract(tmp_path, model, DECLARATIONS)

    assert target == tmp_path / ".nornyx/generated/runtime-contract.json"
    assert target.read_bytes() == _render(model).encode("utf-8")


def test_the_build_renders_the_empty_table_and_binds_its_digest(tmp_path: Path) -> None:
    from nornyx_forge.development_flow import DevelopmentFlow

    model = _model(tmp_path)
    flow = DevelopmentFlow(tmp_path, worker_mode="deterministic", repo_mode="greenfield")

    flow.requirements()

    written = (tmp_path / ".nornyx/generated/runtime-contract.json").read_bytes()
    expected = generator.render_runtime_contract(model)
    digest = "sha256:" + hashlib.sha256(expected.encode("utf-8")).hexdigest()
    assert written == expected.encode("utf-8")
    assert json.loads(expected)["operations"] == []
    assert flow.data["generated_runtime_contract"] == ".nornyx/generated/runtime-contract.json"
    assert flow.data["generated_runtime_contract_digest"] == digest
    events = [json.loads(line) for line in
              (tmp_path / ".nornyx/runs/build-events.jsonl").read_text(
                  encoding="utf-8").splitlines()]
    normalized = [event["fields"] for event in events
                  if event.get("event_type") == "requirements_normalized"]
    assert len(normalized) == 1
    assert normalized[0]["generated_runtime_contract_digest"] == digest
    assert normalized[0]["generated_runtime_contract"] == ".nornyx/generated/runtime-contract.json"
