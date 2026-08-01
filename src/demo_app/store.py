from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any


class JsonStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({"cases": {}})

    def _read(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, self.path)

    def list_cases(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._read()["cases"].values())

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._read()["cases"].get(case_id)

    def put_case(self, case: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            data = self._read()
            data["cases"][case["id"]] = case
            self._write(data)
            return case
