"""Governed text is written canonical-LF, on every platform, by every writer.

THE PROPERTY:

    content this repository declares canonical-LF is WRITTEN that way wherever
    this system writes it, so a digest is a fact about the content rather than
    about the machine that produced it

The repository already enforced this on read: `CANONICAL_TEXT_SUFFIXES` names
the governed text types and the subject observer refuses CR bytes, because
hashing a CRLF file normalised would describe content the file does not hold.

Nothing enforced it on WRITE. `Path.write_text` translates LF to the platform
separator, so on Windows the contract generator, the requirements writer, the
JSON helper and both gate reports all emitted CRLF -- and the observer then
refused files this system had just produced. `SUBJECT_NONCANONICAL_TEXT` on
`src/demo_app/agentic.py` was reached exactly this way, which left the running
application unable to establish consequential authority.

Same control, verified where it was written and not where it was used.

Both halves are tested: behaviour, because that is what actually matters, and
structure, because a new writer added later would pass every behavioural test
here while carrying the same defect.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nornyx_forge.governed_subject import CANONICAL_TEXT_SUFFIXES  # noqa: E402
from nornyx_forge.util import write_canonical_text, write_json  # noqa: E402

#: Files whose writers must not translate line endings. Anything under `src/`
#: or `scripts/` that produces governed text belongs here.
AUDITED = ("src", "scripts")

#: `write_text` calls that legitimately need no `newline=""`, each with the
#: reason. Empty today, and deliberately present so that adding one is a
#: decision someone records rather than an omission nobody notices.
EXEMPT: dict[str, str] = {}


def test_the_canonical_writer_emits_lf(tmp_path: Path):
    """The behaviour, stated directly."""
    target = tmp_path / "sample.md"
    write_canonical_text(target, "first\nsecond\n")
    assert target.read_bytes() == b"first\nsecond\n"
    assert b"\r" not in target.read_bytes()


def test_write_json_emits_lf(tmp_path: Path):
    """Evidence JSON is digest-verified, so its bytes are the whole point."""
    target = tmp_path / "evidence.json"
    write_json(target, {"b": 1, "a": [1, 2]})
    raw = target.read_bytes()
    assert b"\r" not in raw, "write_json emitted CR bytes"
    assert json.loads(raw.decode("utf-8")) == {"b": 1, "a": [1, 2]}


def test_the_canonical_writer_creates_missing_parents(tmp_path: Path):
    """The benign control: it must remain usable, not merely correct."""
    target = tmp_path / "deep" / "nested" / "file.md"
    write_canonical_text(target, "content\n")
    assert target.read_text(encoding="utf-8") == "content\n"


def test_a_crlf_payload_is_written_through_unchanged(tmp_path: Path):
    """`newline=""` means no translation IN EITHER DIRECTION.

    The helper does not silently repair CRLF it was handed -- it writes exactly
    what the caller built. Normalising here would hide a caller that assembled
    the wrong bytes, and the observer is the place that refuses them.
    """
    target = tmp_path / "given.md"
    write_canonical_text(target, "one\r\ntwo\r\n")
    assert target.read_bytes() == b"one\r\ntwo\r\n"


def _write_text_calls(path: Path) -> list[tuple[int, bool]]:
    """(line, passes newline=) for every text-mode write opener in a file.

    Covers `.open(...)` as well as `.write_text(...)`. Checking only the latter
    would be the enumeration mistake this repository keeps finding: the evidence
    ledger appends through `path.open("a", encoding="utf-8")`, which translates
    line endings exactly as `write_text` does, and an audit that looked for one
    spelling reported it clean.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[int, bool]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr == "write_text":
            pass
        elif func.attr == "open":
            mode = node.args[0] if node.args else None
            literal = mode.value if isinstance(mode, ast.Constant) else ""
            written = isinstance(literal, str) and any(
                flag in literal for flag in ("w", "a", "+", "x")
            )
            binary = isinstance(literal, str) and "b" in literal
            if not written or binary:
                continue
        else:
            continue
        found.append(
            (node.lineno, any(kw.arg == "newline" for kw in node.keywords))
        )
    return found


@pytest.mark.parametrize("area", AUDITED)
def test_no_writer_leaves_line_endings_to_the_platform(area: str):
    """Structural, because behaviour cannot see a writer added tomorrow.

    A new `path.write_text(...)` without `newline=""` is a governed file that
    becomes CRLF on Windows and LF on Linux -- the same commit producing two
    different digests, which is precisely what content identity must not do.
    """
    offenders: list[str] = []
    for path in sorted((ROOT / area).rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = str(path.relative_to(ROOT)).replace("\\", "/")
        for line, has_newline in _write_text_calls(path):
            if has_newline or f"{relative}:{line}" in EXEMPT:
                continue
            offenders.append(f"{relative}:{line}")

    assert offenders == [], (
        "these calls let the platform choose line endings for governed text, so "
        "the same content digests differently on Windows and Linux: "
        + ", ".join(offenders)
    )


def test_every_exemption_still_points_at_a_real_call():
    """An exemption whose call is gone is a rule quietly widened."""
    live = set()
    for area in AUDITED:
        for path in sorted((ROOT / area).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            relative = str(path.relative_to(ROOT)).replace("\\", "/")
            live.update(f"{relative}:{line}" for line, _ in _write_text_calls(path))
    stale = sorted(set(EXEMPT) - live)
    assert stale == [], f"exemptions naming calls that no longer exist: {stale}"


def test_the_repository_carries_no_cr_bytes_in_canonical_text():
    """The end state the writers exist to preserve.

    Checked over the working tree rather than the index: the observer reads
    bytes on disk, so that is where the property has to hold. A checkout whose
    files carry CR bytes cannot establish a subject at all, however clean the
    repository content is.

    Scoped to what git TRACKS, and the scope matters as much as the bytes. This
    walked the whole tree behind a hand-written skip list, so it also read
    generated output that no subject contains: a JUnit report written to the
    gitignored `.nornyx/runs/` failed it, and pytest writes XML with CRLF on
    Windows. That is a real CR byte in a file that cannot break subject
    establishment, because the file is not part of the subject.

    Asking git removes the skip list too. Every future build artifact is
    excluded for the reason it should be -- the repository does not carry it --
    rather than because someone remembered to add its directory here.
    """
    tracked = subprocess.run(  # noqa: S603
        ["git", "ls-files", "-z"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=True, timeout=120,
    ).stdout.split("\0")

    carriers: list[str] = []
    for name in tracked:
        if not name:
            continue
        path = ROOT / name
        if path.suffix not in CANONICAL_TEXT_SUFFIXES or not path.is_file():
            continue
        try:
            if b"\r" in path.read_bytes():
                carriers.append(name)
        except OSError:
            continue
    assert carriers == [], (
        "canonical-LF content carries CR bytes, so the subject observer will "
        f"refuse it: {carriers[:10]}"
    )
