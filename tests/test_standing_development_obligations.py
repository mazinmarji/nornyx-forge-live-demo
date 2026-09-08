from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_standing_development_obligations.py"
PUBLIC = ROOT / "docs" / "governance" / "STANDING_DEVELOPMENT_OBLIGATIONS.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("standing_obligations", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _overlay(tmp_path: Path, *, dedupe_key: str = "private-example") -> Path:
    path = tmp_path / "private-overlay.json"
    path.write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.private_standing_overlay.v1",
                "classification": "private",
                "items": [
                    {
                        "id": "PRIVATE-001",
                        "kind": "deferred_capability",
                        "dedupe_key": dedupe_key,
                        "status": "deferred",
                        "title": "SENTINEL PRIVATE TITLE",
                        "rule": "SENTINEL PRIVATE RULE",
                        "reopen_condition": "SENTINEL PRIVATE CONDITION",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_public_registry_is_valid_and_semantically_unique():
    module = _load_module()
    public_items, private_items = module.load_registries(None)
    assert private_items == []
    assert len(public_items) == len({item["id"] for item in public_items})
    assert len(public_items) == len({item["dedupe_key"] for item in public_items})


def test_duplicate_semantic_item_is_refused():
    module = _load_module()
    document = json.loads(PUBLIC.read_text(encoding="utf-8"))
    duplicate = dict(document["items"][0])
    duplicate["id"] = "FGR-SDO-DUPLICATE"
    document["items"].append(duplicate)
    try:
        module._validate_registry(
            document,
            schema=module.PUBLIC_SCHEMA,
            label="public registry",
        )
    except module.AdmissionError as exc:
        assert "duplicate semantic key" in str(exc)
    else:
        raise AssertionError("duplicate semantic obligation was accepted")


def test_private_overlay_cannot_duplicate_public_semantics(tmp_path):
    module = _load_module()
    public = json.loads(PUBLIC.read_text(encoding="utf-8"))
    overlay = _overlay(tmp_path, dedupe_key=public["items"][0]["dedupe_key"])
    try:
        module.load_registries(overlay)
    except module.AdmissionError as exc:
        assert "duplicate semantic keys" in str(exc)
    else:
        raise AssertionError("cross-registry semantic duplicate was accepted")


def test_cycle_disposition_is_runtime_only_and_pending_must_be_completed(tmp_path):
    module = _load_module()
    public_items, private_items = module.load_registries(None)

    outside = tmp_path / "disposition.json"
    try:
        module.initialize_disposition(
            outside,
            cycle_id="TEST",
            overlay_path=None,
            public_items=public_items,
            private_items=private_items,
        )
    except module.AdmissionError as exc:
        assert ".nornyx/runtime/" in str(exc)
    else:
        raise AssertionError("a disposition outside runtime was accepted")

    runtime = ROOT / ".nornyx" / "runtime" / "test-standing-disposition.json"
    try:
        module.initialize_disposition(
            runtime,
            cycle_id="TEST",
            overlay_path=None,
            public_items=public_items,
            private_items=private_items,
        )
        try:
            module.validate_disposition(
                runtime,
                overlay_path=None,
                public_items=public_items,
                private_items=private_items,
            )
        except module.AdmissionError as exc:
            assert "pending" in str(exc)
        else:
            raise AssertionError("pending disposition was accepted")

        record = json.loads(runtime.read_text(encoding="utf-8"))
        for row in record["items"]:
            row["disposition"] = "considered"
            row["reason"] = "Reviewed for the test cycle."
        runtime.write_text(json.dumps(record), encoding="utf-8")
        module.validate_disposition(
            runtime,
            overlay_path=None,
            public_items=public_items,
            private_items=private_items,
        )
    finally:
        runtime.unlink(missing_ok=True)


def test_requires_decision_blocks_admission():
    module = _load_module()
    public_items, private_items = module.load_registries(None)
    runtime = ROOT / ".nornyx" / "runtime" / "test-decision-disposition.json"
    try:
        module.initialize_disposition(
            runtime,
            cycle_id="TEST",
            overlay_path=None,
            public_items=public_items,
            private_items=private_items,
        )
        record = json.loads(runtime.read_text(encoding="utf-8"))
        for row in record["items"]:
            row["disposition"] = "considered"
            row["reason"] = "Reviewed."
        record["items"][0]["disposition"] = "requires_decision"
        record["items"][0]["reason"] = "Authority must decide."
        runtime.write_text(json.dumps(record), encoding="utf-8")
        try:
            module.validate_disposition(
                runtime,
                overlay_path=None,
                public_items=public_items,
                private_items=private_items,
            )
        except module.AdmissionError as exc:
            assert "requires_decision" in str(exc)
        else:
            raise AssertionError("requires_decision was accepted")
    finally:
        runtime.unlink(missing_ok=True)


def test_private_overlay_content_is_not_emitted(tmp_path):
    overlay = _overlay(tmp_path)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--overlay", str(overlay)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    combined = completed.stdout + completed.stderr
    assert completed.returncode == 0
    assert "SENTINEL PRIVATE TITLE" not in combined
    assert "SENTINEL PRIVATE RULE" not in combined
    assert str(overlay) not in combined


def test_public_entrypoints_require_standing_admission():
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    claude = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    skill = (ROOT / "skills" / "build-app" / "SKILL.md").read_text(encoding="utf-8")
    needle = "check_standing_development_obligations.py"
    assert needle in agents
    assert "AGENTS.md" in claude and needle in claude
    assert needle in skill


def test_runtime_disposition_directory_is_gitignored():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".nornyx/runtime/" in gitignore
