from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write_canonical_text(path: Path, text: str) -> None:
    """Write governed text in the repository's canonical form: LF, always.

    THE PROPERTY: content this repository declares canonical-LF is written that
    way on every platform, so its digest is a fact about the content rather than
    about the machine that produced it.

    `Path.write_text` translates LF to the platform separator, so on Windows
    every one of these writers emitted CRLF. The subject observer then refused
    the file it had just been handed -- `SUBJECT_NONCANONICAL_TEXT` -- because
    hashing it normalised would describe content the file does not hold. The
    repository enforced canonical-LF on READ while its own tooling violated it
    on WRITE, which is the same control verified where it was written and not
    where it was used.

    `newline=""` disables translation. Centralised rather than repeated, because
    a rule that has to be remembered at twelve call sites is a rule that will be
    missed at the thirteenth.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def write_json(path: Path, value: Any) -> None:
    write_canonical_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))
