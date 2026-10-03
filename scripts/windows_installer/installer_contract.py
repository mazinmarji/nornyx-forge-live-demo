"""What ForgeSetup.exe promises, stated once and read by everything that checks it.

`forge-setup.nsi` is the installer; this module holds the parts of its contract
that are data, so the build, the tests and the Windows CI driver read ONE
statement instead of restating it:

* the exit-code table, read from the `!define EXIT_*` lines of the script;
* the install-receipt schema, the text the installer writes (rendered from the
  manifest at build time) and the checker that refuses a receipt naming
  anything the installer does not own;
* the file list the installer extracts (`files.nsh`), one `File` per manifest
  entry, in manifest order;
* the Start-menu shortcut the installer writes.

Standard library only: the Windows driver runs it with the runner's Python.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

NSI_NAME = "forge-setup.nsi"
SHORTCUT_NAME = "Nornyx Forge.lnk"
RECEIPT_NAME = "install-receipt.json"
RECEIPT_SCHEMA = "nornyx.forge.install_receipt.v1"
#: Where the installer puts everything, under %LOCALAPPDATA%.
INSTALL_ROOT_PARTS = ("Programs", "Nornyx Forge")
PARTIAL_SUFFIX = ".partial"

#: The receipt lists what the installer created and nothing else. By schema it
#: may not name any of the state classes an uninstall or a repair must never
#: touch: the person's project, Forge's runtime and seal directories, the trust
#: stores, CrewAI's storage and a provider's configuration home. A name is
#: refused wherever it appears in a path, whatever its letter case.
FORBIDDEN_RECEIPT_NAMES = (
    "ForgeProject", ".nornyx", ".nornyx-forge", ".config", "crewai", ".crewai",
    ".claude", ".codex", "capsule", "seals", "trusted_approvers", "forge_reviewer_trust",
)

#: The receipt's lines, with the two values only the installer's run knows.
GIT_TOKEN = "$GitState"
ROOT_TOKEN = "$RootCreated"

_EXIT = re.compile(r"^!define\s+(EXIT_[A-Z_]+)\s+(\d+)\s*$", re.M)
_SAFE_NSIS = re.compile(r"[^\x00-\x1f\x7f\"]*")


class ContractError(Exception):
    """An input the installer's contract refuses."""


def exit_codes(nsi_text: str) -> dict[str, int]:
    """The exit-code table, as the script defines it."""
    table = {name: int(code) for name, code in _EXIT.findall(nsi_text)}
    if not table or len(set(table.values())) != len(table):
        raise ContractError("the script defines no exit codes, or two names share a code")
    return table


def version_directory(manifest: dict) -> str:
    """`<version>+<commit12>`: the folder the payload is installed into."""
    return f"{manifest['version']}+{manifest['source_commit'][:12]}"


def nsis_text(value: str) -> str:
    """`value` as the inside of a double-quoted NSIS string: `$` is NSIS's
    escape character, and a double quote or a control character cannot be
    carried at all (the payload's name rule refuses both already). A backtick
    or a single quote is literal inside double quotes."""
    if not _SAFE_NSIS.fullmatch(value):
        raise ContractError(f"{value!r} cannot be written into an NSIS string")
    return value.replace("$", "$$")


def files_nsh(entries: list[list], payload_dir: Path, *, manifest_name: str) -> str:
    """The `File` instructions of the installer: every manifest entry in the
    manifest's own (byte) order, then the manifest. `SetOutPath` is issued
    whenever the directory changes. A source path is the payload's absolute
    path and must be plain; a destination is the entry's own relative path."""
    base = payload_dir.resolve().as_posix()
    if not re.fullmatch(r"[A-Za-z0-9_./+-]+", base):
        raise ContractError(f"the payload path {base!r} holds a character outside "
                            "[A-Za-z0-9_./+-]; build from a plainly named folder")
    lines: list[str] = []
    current: str | None = None

    def place(relative: str) -> None:
        nonlocal current
        directory = relative.rpartition("/")[0]
        if directory != current:
            target = "$Partial" + "".join("\\" + nsis_text(part) for part in directory.split("/")
                                          if part)
            lines.append(f'SetOutPath "{target}"')
            current = directory
        lines.append(f'File "{nsis_text(base)}/{nsis_text(relative)}"')

    for relative, _size, _digest in entries:
        place(relative)
    place(manifest_name)
    return "\n".join(lines) + "\n"


def receipt_lines(manifest: dict) -> list[str]:
    """The receipt as JSON text, one line each, with `$GitState` and
    `$RootCreated` standing for the two values the installer's run decides.
    Everything else is fixed by the payload."""
    directory = version_directory(manifest)
    return [
        "{",
        f'  "schema": "{RECEIPT_SCHEMA}",',
        '  "location": "local_application_data/' + "/".join(INSTALL_ROOT_PARTS) + '",',
        f'  "root_created": {ROOT_TOKEN},',
        '  "versions": [',
        "    {",
        f'      "directory": "{directory}",',
        f'      "version": "{manifest["version"]}",',
        f'      "source_commit": "{manifest["source_commit"]}",',
        f'      "payload_sha256": "{manifest["payload_sha256"]}"',
        "    }",
        "  ],",
        '  "created": [',
        f'    {{"kind": "directory", "path": "{directory}"}},',
        f'    {{"kind": "file", "path": "{RECEIPT_NAME}"}},',
        f'    {{"kind": "shortcut", "folder": "start_menu_programs", "name": "{SHORTCUT_NAME}"}}',
        "  ],",
        '  "registry": [],',
        f'  "prerequisites": {{"git": "{GIT_TOKEN}"}}',
        "}",
    ]


def receipt_nsh(manifest: dict) -> str:
    """The NSIS that writes the receipt: open, one `FileWrite` per line, close.
    Backtick-quoted, because the JSON carries double quotes."""
    lines = ['FileOpen $0 "$INSTDIR\\' + RECEIPT_NAME + '" w']
    for line in receipt_lines(manifest):
        if "`" in line:
            raise ContractError("a receipt line carries a backtick")
        lines.append(f"FileWrite $0 `{line}$\\n`")
    lines.append("FileClose $0")
    return "\n".join(lines) + "\n"


def render_receipt(manifest: dict, *, git: str, root_created: bool) -> str:
    """What the installer writes, for a run that found git as `git` and did or
    did not create the root folder."""
    if git not in ("found", "not found"):
        raise ContractError(f"git is {git!r}, not 'found' or 'not found'")
    text = "\n".join(receipt_lines(manifest)) + "\n"
    return text.replace(GIT_TOKEN, git).replace(ROOT_TOKEN, "true" if root_created else "false")


def check_receipt(text: str, manifest: dict | None = None) -> list[str]:
    """Every reason `text` is not a receipt this installer writes. With the
    payload's manifest, it must also name exactly that payload."""
    try:
        receipt = json.loads(text)
    except ValueError as error:
        return [f"not JSON: {error}"]
    fields = {"schema", "location", "root_created", "versions", "created", "registry",
              "prerequisites"}
    if not isinstance(receipt, dict) or set(receipt) != fields:
        return [f"the receipt's fields are not exactly {sorted(fields)}"]
    problems: list[str] = []
    if receipt["schema"] != RECEIPT_SCHEMA:
        problems.append(f"schema {receipt['schema']!r}")
    if receipt["location"] != "local_application_data/" + "/".join(INSTALL_ROOT_PARTS):
        problems.append(f"location {receipt['location']!r}")
    if not isinstance(receipt["root_created"], bool):
        problems.append("root_created is not a boolean")
    if receipt["registry"] != []:
        problems.append("the installer writes no registry value, and the receipt lists some")
    if receipt["prerequisites"].get("git") not in ("found", "not found") or set(
            receipt["prerequisites"]) != {"git"}:
        problems.append("prerequisites is not exactly the git advisory")
    versions = receipt["versions"]
    version_fields = {"directory", "version", "source_commit", "payload_sha256"}
    if not (isinstance(versions, list) and versions and all(
            isinstance(v, dict) and set(v) == version_fields for v in versions)):
        problems.append("versions is not a list of exact version entries")
        versions = []
    created = receipt["created"]
    paths: list[str] = []
    for item in created if isinstance(created, list) else []:
        if not isinstance(item, dict) or item.get("kind") not in ("directory", "file",
                                                                   "shortcut"):
            problems.append(f"an unknown created entry: {item!r:.100}")
            continue
        if item["kind"] == "shortcut":
            if item != {"kind": "shortcut", "folder": "start_menu_programs",
                        "name": SHORTCUT_NAME}:
                problems.append(f"the shortcut entry is not the installer's: {item!r:.100}")
            continue
        path = item.get("path")
        if set(item) != {"kind", "path"} or not isinstance(path, str):
            problems.append(f"a created entry is not a kind and a path: {item!r:.100}")
            continue
        paths.append(path)
        if path.startswith(("/", "\\")) or re.match(r"[A-Za-z]:", path) or ".." in path.split("/"):
            problems.append(f"{path!r} is not a path inside the install folder")
    strings = [receipt["location"], *paths, *(str(v) for entry in versions
                                              for v in entry.values())]
    for text_item in strings:
        folded = str(text_item).casefold()
        for name in FORBIDDEN_RECEIPT_NAMES:
            if name.casefold() in folded:
                problems.append(f"{text_item!r} names {name}, which the installer does not own")
    if manifest is not None:
        expected = {"directory": version_directory(manifest), "version": manifest["version"],
                    "source_commit": manifest["source_commit"],
                    "payload_sha256": manifest["payload_sha256"]}
        if versions != [expected]:
            problems.append("the receipt does not name exactly the installed payload")
        if sorted(paths) != sorted([expected["directory"], RECEIPT_NAME]):
            problems.append("the created paths are not exactly the version folder and the receipt")
    return problems


def shortcut_expectation(manifest: dict, *, install_root: str, profile: str) -> dict[str, str]:
    """The shortcut the installer writes, as the Windows shell reports it: the
    embedded interpreter, started without a console and without writing
    bytecode into the verified folder, in the install root."""
    folder = f"{install_root}\\{version_directory(manifest)}"
    return {
        "TargetPath": f"{folder}\\python\\pythonw.exe",
        "Arguments": f'-B -m nornyx_forge.windows_launch --bundle-root "{folder}" '
                     f'--project-dir "{profile}\\ForgeProject"',
        "WorkingDirectory": install_root,
    }


def nsi_text(path: Path | None = None) -> str:
    return (path or Path(__file__).with_name(NSI_NAME)).read_text(encoding="utf-8")
