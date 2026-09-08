"""Validate and disposition cross-session Forge development obligations."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_REGISTRY = ROOT / "docs" / "governance" / "STANDING_DEVELOPMENT_OBLIGATIONS.json"
RUNTIME_ROOT = ROOT / ".nornyx" / "runtime"

PUBLIC_SCHEMA = "nornyx.forge.standing_development_obligations.v1"
OVERLAY_SCHEMA = "nornyx.forge.private_standing_overlay.v1"
DISPOSITION_SCHEMA = "nornyx.forge.development_cycle_disposition.v1"

ITEM_KINDS = {"invariant", "deferred_capability", "learning"}
ITEM_STATUSES = {"active", "deferred", "retired"}
RESOLVED_DISPOSITIONS = {"considered", "unchanged", "defer", "not_applicable"}
ALL_DISPOSITIONS = RESOLVED_DISPOSITIONS | {"pending", "requires_decision"}


class AdmissionError(ValueError):
    """A standing-obligation input or disposition is invalid."""


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError(f"{label} cannot be loaded as JSON") from exc
    if not isinstance(value, dict):
        raise AdmissionError(f"{label} must be a JSON object")
    return value


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _require_runtime_file(path: Path) -> None:
    if not _inside(path, RUNTIME_ROOT):
        raise AdmissionError("cycle disposition must be under .nornyx/runtime/")


def _validate_item(item: Any, *, label: str, index: int) -> tuple[str, str]:
    if not isinstance(item, dict):
        raise AdmissionError(f"{label} item {index} must be an object")
    item_id = item.get("id")
    dedupe_key = item.get("dedupe_key")
    if not isinstance(item_id, str) or not item_id.strip():
        raise AdmissionError(f"{label} item {index} has no valid id")
    if not isinstance(dedupe_key, str) or not dedupe_key.strip():
        raise AdmissionError(f"{label} item {index} has no valid dedupe_key")
    if dedupe_key != dedupe_key.lower():
        raise AdmissionError(f"{label} item {index} dedupe_key must be lowercase")
    if item.get("kind") not in ITEM_KINDS:
        raise AdmissionError(f"{label} item {index} has an invalid kind")
    if item.get("status") not in ITEM_STATUSES:
        raise AdmissionError(f"{label} item {index} has an invalid status")
    if not isinstance(item.get("title"), str) or not item["title"].strip():
        raise AdmissionError(f"{label} item {index} has no valid title")
    if not isinstance(item.get("rule"), str) or not item["rule"].strip():
        raise AdmissionError(f"{label} item {index} has no valid rule")
    if item.get("status") == "deferred":
        condition = item.get("reopen_condition")
        if not isinstance(condition, str) or not condition.strip():
            raise AdmissionError(
                f"{label} item {index} is deferred without a reopen_condition"
            )
    return item_id, dedupe_key


def _validate_registry(
    document: dict[str, Any],
    *,
    schema: str,
    label: str,
) -> list[dict[str, Any]]:
    if document.get("schema") != schema:
        raise AdmissionError(f"{label} has an unsupported schema")
    items = document.get("items")
    if not isinstance(items, list):
        raise AdmissionError(f"{label} items must be a list")

    ids: set[str] = set()
    keys: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        item_id, dedupe_key = _validate_item(item, label=label, index=index)
        if item_id in ids:
            raise AdmissionError(f"{label} contains a duplicate item id")
        if dedupe_key in keys:
            raise AdmissionError(f"{label} contains a duplicate semantic key")
        ids.add(item_id)
        keys.add(dedupe_key)
        validated.append(item)
    return validated


def load_registries(
    overlay_path: Path | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    public_doc = _load_json(PUBLIC_REGISTRY, label="public registry")
    if public_doc.get("visibility") != "public":
        raise AdmissionError("public registry must declare public visibility")
    public_items = _validate_registry(
        public_doc,
        schema=PUBLIC_SCHEMA,
        label="public registry",
    )

    private_items: list[dict[str, Any]] = []
    if overlay_path is not None:
        if _inside(overlay_path, ROOT):
            raise AdmissionError("private overlay must remain outside the Forge repository")
        overlay_doc = _load_json(overlay_path, label="private overlay")
        if overlay_doc.get("classification") != "private":
            raise AdmissionError("private overlay must declare private classification")
        private_items = _validate_registry(
            overlay_doc,
            schema=OVERLAY_SCHEMA,
            label="private overlay",
        )

        public_ids = {item["id"] for item in public_items}
        private_ids = {item["id"] for item in private_items}
        if public_ids & private_ids:
            raise AdmissionError("public registry and private overlay contain duplicate item ids")

        public_keys = {item["dedupe_key"] for item in public_items}
        private_keys = {item["dedupe_key"] for item in private_items}
        if public_keys & private_keys:
            raise AdmissionError(
                "public registry and private overlay contain duplicate semantic keys"
            )

    return public_items, private_items


def initialize_disposition(
    output: Path,
    *,
    cycle_id: str,
    overlay_path: Path | None,
    public_items: list[dict[str, Any]],
    private_items: list[dict[str, Any]],
) -> None:
    _require_runtime_file(output)
    if not cycle_id.strip():
        raise AdmissionError("--cycle-id must be non-empty")
    output.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": DISPOSITION_SCHEMA,
        "cycle_id": cycle_id,
        "public_registry_sha256": _digest(PUBLIC_REGISTRY),
        "private_overlay_sha256": _digest(overlay_path) if overlay_path else None,
        "items": [
            {
                "id": item["id"],
                "source": source,
                "disposition": "pending",
                "reason": "",
            }
            for source, items in (("public", public_items), ("private", private_items))
            for item in items
        ],
    }
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


def validate_disposition(
    path: Path,
    *,
    overlay_path: Path | None,
    public_items: list[dict[str, Any]],
    private_items: list[dict[str, Any]],
) -> None:
    _require_runtime_file(path)
    record = _load_json(path, label="cycle disposition")
    if record.get("schema") != DISPOSITION_SCHEMA:
        raise AdmissionError("cycle disposition has an unsupported schema")
    if record.get("public_registry_sha256") != _digest(PUBLIC_REGISTRY):
        raise AdmissionError("cycle disposition is stale against the public registry")

    expected_overlay = _digest(overlay_path) if overlay_path else None
    if record.get("private_overlay_sha256") != expected_overlay:
        raise AdmissionError("cycle disposition is stale against the supplied overlay")

    expected = {
        ("public", item["id"]) for item in public_items
    } | {
        ("private", item["id"]) for item in private_items
    }
    rows = record.get("items")
    if not isinstance(rows, list):
        raise AdmissionError("cycle disposition items must be a list")

    seen: set[tuple[str, str]] = set()
    blockers: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise AdmissionError(f"cycle disposition item {index} must be an object")
        source = row.get("source")
        item_id = row.get("id")
        if source not in {"public", "private"} or not isinstance(item_id, str):
            raise AdmissionError(f"cycle disposition item {index} has invalid identity")
        identity = (source, item_id)
        if identity in seen:
            raise AdmissionError("cycle disposition contains a duplicate obligation")
        seen.add(identity)

        disposition = row.get("disposition")
        if disposition not in ALL_DISPOSITIONS:
            raise AdmissionError(f"cycle disposition item {index} has an invalid disposition")
        reason = row.get("reason")
        if disposition != "pending" and (not isinstance(reason, str) or not reason.strip()):
            raise AdmissionError(f"cycle disposition item {index} needs a reason")
        if disposition == "pending":
            blockers.append(f"{item_id}: pending")
        elif disposition == "requires_decision":
            blockers.append(f"{item_id}: requires_decision")

    if seen != expected:
        raise AdmissionError("cycle disposition does not exactly cover loaded standing obligations")
    if blockers:
        raise AdmissionError("development admission refused: " + ", ".join(blockers))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and disposition Forge standing development obligations."
    )
    parser.add_argument(
        "--overlay",
        type=Path,
        help="Explicit external private overlay. It must resolve outside this repository.",
    )
    parser.add_argument("--init", type=Path, help="Initialize a gitignored cycle disposition.")
    parser.add_argument("--cycle-id", default="", help="Cycle identifier used with --init.")
    parser.add_argument(
        "--check-disposition",
        type=Path,
        help="Validate a completed gitignored cycle disposition.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        public_items, private_items = load_registries(args.overlay)
        if args.init and args.check_disposition:
            raise AdmissionError("--init and --check-disposition are mutually exclusive")
        if args.init:
            initialize_disposition(
                args.init,
                cycle_id=args.cycle_id,
                overlay_path=args.overlay,
                public_items=public_items,
                private_items=private_items,
            )
            print("Standing obligations validated; local cycle disposition initialized.")
            if args.overlay:
                print("Private overlay present and validated; its contents were not emitted.")
            return 0
        if args.check_disposition:
            validate_disposition(
                args.check_disposition,
                overlay_path=args.overlay,
                public_items=public_items,
                private_items=private_items,
            )
            print("Standing-obligation development admission: PASS.")
            if args.overlay:
                print("Private overlay present and validated; its contents were not emitted.")
            return 0

        print("Standing-obligation registries: PASS.")
        if args.overlay:
            print("Private overlay present and validated; its contents were not emitted.")
        return 0
    except (AdmissionError, OSError) as exc:
        print(f"REFUSE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
