"""ForgeSetup.exe: its script, its contract, its builder and the jobs that run it.

Six groups.

The SCRIPT (`forge-setup.nsi`) read as source. Nothing here compiles or runs
NSIS: the pinned compiler is built from source by CI (`nsis-toolchain`) and
runs only inside the pinned image, and a Windows installer runs only on
Windows. These tests therefore hold what can be held from the text, and
say so: that the exit-code table is defined once and used both ways, that every
variable is declared and used, that the elevation check comes first and reads
the token, that no instruction the installer must never use appears, that every
process it starts is the payload's own interpreter running the payload's
verifier against the identity baked in. A line that is present is not an effect;
the effects are the `windows-install` job's.

The CONTRACT (`installer_contract.py`): the file list the installer extracts
(one `File` per manifest entry, in manifest order, read back with a strict
parser), the receipt it writes (rendered, read back, and refused when it names
anything it does not own), the shortcut it expects.

The BUILDER over a synthetic repository, a sealed payload, a stand-in
compiler tree pinned by its digests, and a stand-in for `docker run` that maps
the mounts and runs the stand-in compiler: what it refuses before and after
compiling, the container the compiler is given (the same hardening as the
toolchain's own compile), and that the same inputs give the same bytes.

The DRIVER's pure parts (ACL, folder listings, PATH) and its coverage of the
exit codes.

The SHAPE of the `windows-installer` and `windows-install` jobs, read as
structure, and the TEXT of the docs about them.

What these tests cannot show: that the script compiles (CI's), that two builds
give the same bytes (CI's), and any behaviour of the installer on Windows.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "windows_installer"))

import build_nsis_toolchain as toolchain  # noqa: E402
import build_windows_bundle as bundle  # noqa: E402
import build_windows_installer as installer  # noqa: E402
import installer_contract as contract  # noqa: E402
import standard_user_checks as driver  # noqa: E402
import synthetic_payload  # noqa: E402

from nornyx_forge.windows_payload import (  # noqa: E402
    PAYLOAD_MANIFEST,
    build_manifest,
    check_name,
    render_manifest,
)

NSI = ROOT / "scripts" / "windows_installer" / contract.NSI_NAME
TOOLCHAIN = ROOT / "scripts" / "windows_installer" / "nsis-toolchain.json"
LOCK = ROOT / "scripts" / "windows_installer" / "nsis-build-debs.json"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
ASSUMPTIONS = ROOT / "docs" / "requirements" / "ASSUMPTIONS.md"
COMMITTED = 1767323045
COMMIT = "0123456789abcdef0123456789abcdef01234567"
MANIFEST_FIELDS = {
    "version": "1.2.3", "source_commit": COMMIT, "source_date_epoch": COMMITTED,
    "target": "cp313-win_amd64", "lock_sha256": "a" * 64,
    "installer": {"name": "uv", "version": "0.0.0"},
    "interpreter": {"version": "3.13.0", "archive_url": "https://example.invalid/e.zip",
                    "archive_sha256": "b" * 64}}


def _nsi() -> str:
    return NSI.read_text(encoding="utf-8")


def _code_lines(text: str) -> list[str]:
    """The script's instructions: comments and blank lines removed."""
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith((";", "#"))]


def _manifest_of(files: dict[str, bytes], tmp_path: Path, **override) -> dict:
    root = tmp_path / "manifest-source"
    for relative, data in files.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return build_manifest(root, **{**MANIFEST_FIELDS, **override})


# ---------------------------------------------------------------------------
# The script, read as source
# ---------------------------------------------------------------------------

def test_the_exit_codes_are_defined_once_and_used_both_ways():
    text = _nsi()
    table = contract.exit_codes(text)
    defined = set(table)
    used = set(re.findall(r"\$\{(EXIT_[A-Z_]+)\}", "\n".join(_code_lines(text))))
    assert used == defined, f"defined but unused {defined - used}; used but undefined {used - defined}"
    assert len(set(table.values())) == len(table), "two names share a code"
    assert all(10 <= code < 100 for code in table.values()), (
        "a code of 0, 1 or 2 would read as success or as NSIS's own abort")
    for line in _code_lines(text):
        assert "!insertmacro Refuse" not in line or re.search(
            r"!insertmacro Refuse \$\{EXIT_[A-Z_]+\} \"", line), (
            f"a refusal passes a literal code, not the table's: {line}")


def test_the_exit_code_reader_refuses_a_table_that_cannot_be_read():
    with pytest.raises(contract.ContractError):
        contract.exit_codes("; no table here\n")
    with pytest.raises(contract.ContractError):
        contract.exit_codes("!define EXIT_A 10\n!define EXIT_B 10\n")


def test_every_variable_is_declared_and_used_and_every_use_is_declared():
    text = "\n".join(_code_lines(_nsi()))
    declared = set(re.findall(r"^Var (\w+)$", text, re.M))
    builtins = {"0", "1", "2", "3", "4", "5", "6", "7", "INSTDIR", "LOCALAPPDATA", "PROFILE",
                "SMPROGRAMS", "OUTDIR", "R0"}
    # `$$`, `$\r` and `$\n` are NSIS escapes, not variables.
    without_escapes = re.sub(r"\$\$|\$\\[rnt\"]", "", text)
    used = set(re.findall(r"\$([A-Za-z_]\w*)", re.sub(r"^Var .*$", "", without_escapes,
                                                      flags=re.M)))
    assert declared, "the script declares no variable"
    assert not (declared - used), f"declared and never used: {sorted(declared - used)}"
    unknown = used - declared - builtins
    assert not unknown, f"used and never declared: {sorted(unknown)}"


def test_the_generated_includes_use_only_variables_the_script_declares():
    declared = set(re.findall(r"^Var (\w+)$", _nsi(), re.M)) | {"INSTDIR", "0"}
    manifest = {**MANIFEST_FIELDS, "payload_sha256": "c" * 64}
    for generated in (contract.receipt_nsh(manifest),
                      contract.files_nsh([["a/b.py", 1, "d" * 64]], "/tmp/payload",
                                         manifest_name=PAYLOAD_MANIFEST)):
        used = set(re.findall(r"\$(\w+)", re.sub(r"\$\$|\$\\n", "", generated)))
        assert used <= declared, sorted(used - declared)


def test_the_defines_the_script_reads_are_the_defines_the_builder_passes(tmp_path: Path):
    reads = set(re.findall(r"\$\{([A-Z0-9_]+)\}", "\n".join(_code_lines(_nsi()))))
    own = set(re.findall(r"^!define (\w+)", _nsi(), re.M))
    for parameters in re.findall(r"^!macro \w+ (.*)$", _nsi(), re.M):
        own |= set(parameters.split())
    needed = {name for name in reads - own if not name.startswith("EXIT_")}
    fixture = _Fixture(tmp_path)
    fixture.build()
    passed = set(fixture.capture()["defines"])
    assert passed == needed, f"passed but unread {passed - needed}; read but not passed {needed - passed}"


def test_the_elevation_check_comes_first_and_reads_the_token():
    text = _nsi()
    init = text[text.index("Function .onInit"):text.index("Function .onInstFailed")]
    calls = re.findall(r"^  Call (\w+)$", init, re.M)
    assert calls == ["RefuseElevated", "CheckLocation", "CheckPathBudget", "DecideExisting",
                     "CheckShortcutFree"], calls
    for instruction in ("CreateDirectory", "SetOutPath", "File ", "Rename", "CreateShortcut",
                        "FileOpen", "nsExec"):
        assert instruction not in init, f".onInit does {instruction} before the checks finish"
    body = text[text.index("Function RefuseElevated"):text.index("Function CheckNoLinks")]
    assert "OpenProcessToken" in body and "GetTokenInformation(p r1, i 20" in body
    assert "IsUserAnAdmin" in body
    assert body.count("${EXIT_ELEVATION_UNKNOWN}") == 2, "an unreadable token must fail closed"
    for failed in ("$2", "$5"):  # OpenProcessToken's and GetTokenInformation's results
        assert re.search(r"\$\{If\} " + re.escape(failed) + r" = 0\n\s+!insertmacro Refuse "
                         r"\$\{EXIT_ELEVATION_UNKNOWN\}", body), f"{failed} = 0 must refuse"
    assert re.search(r"\$\{If\} \$6 <> 0\n\s+\$\{OrIf\} \$7 <> 0\n\s+!insertmacro Refuse "
                     r"\$\{EXIT_ELEVATED\}", body), "an elevated token or an administrator refuses"
    assert "${EXIT_ELEVATED}" in body
    assert re.search(r"RequestExecutionLevel user\b", text)


def _function(name: str) -> str:
    """One function's or the section's instructions, comments removed."""
    code = "\n".join(_code_lines(_nsi()))
    start = code.index(name)
    ends = [end for end in (code.find(marker, start + 1) for marker in ("\nFunction ", "\nSection "))
            if end != -1]
    return code[start:min(ends)] if ends else code[start:]


def test_every_errors_test_follows_a_clear_and_one_straight_run_of_instructions():
    """CLASS: the error flag is sticky. FindNext sets it at the end of every
    listing, so an empty-folder listing left it set and the next `${If}
    ${Errors}` read it, which refused every install into an existing empty
    folder. Every test of the flag must be preceded by ClearErrors with only
    straight-line instructions between (no call, no branch, no other test)."""
    lines = _code_lines(_nsi())
    tests = [i for i, line in enumerate(lines) if "${Errors}" in line]
    assert len(tests) >= 5, "the script tests the error flag in several places"
    for index in tests:
        back = index - 1
        while back >= 0 and lines[back] != "ClearErrors":
            line = lines[back]
            straight = not (line.startswith("${") or line.startswith("Call ")
                            or line.startswith("Function ") or line.startswith("Section")
                            or line.startswith("!insertmacro")) or line.startswith("${GetOptions}")
            assert straight, f"line {index}: {lines[index]!r} reads a flag that {line!r} may have set"
            back -= 1
        assert back >= 0 and index - back <= 4, (
            f"{lines[index]!r} is not preceded by ClearErrors and at most two instructions")


def test_a_failure_callback_keeps_the_specific_exit_code():
    callback = _function("Function .onInstFailed")
    assert "GetErrorLevel $0" in callback and "${If} $0 = -1" in callback
    assert callback.index("${If} $0 = -1") < callback.index("SetErrorLevel ${EXIT_FAILED}")
    assert callback.count("SetErrorLevel") == 1, "17 only when none was set"


def test_the_unfinished_install_is_named_before_the_folder_is_judged_by_its_receipt():
    body = _function("Function DecideExisting")
    check = ('Push "$Partial"\nCall AttrOf\nPop $0\n${If} $0 <> -1\n'
             '!insertmacro Refuse ${EXIT_UNFINISHED}')
    assert body.count(check) == 1
    assert body.index(check) < body.index("FindFirst") < body.index("install-receipt.json"), (
        "a failed first install leaves a .partial folder and no receipt")
    listing = body[body.index("FindFirst"):body.index("${DoWhile}")]
    assert '${If} $3 == ""' in listing and "${EXIT_NOT_FORGE}" in listing, (
        "a folder that cannot be listed is a refusal, not an empty folder")
    assert "FindClose $2\nClearErrors" in body, "FindNext leaves the flag set at the end of a list"


def test_the_log_is_appended_to_not_overwritten():
    log = _function("Function WriteLog")
    assert log.index('FileOpen $1 "$LogPath" a') < log.index("FileSeek $1 0 END") < log.index(
        "FileWrite")


def test_a_shortcut_that_exists_is_refused_not_replaced():
    body = _function("Function CheckShortcutFree")
    assert body.startswith('Function CheckShortcutFree\nPush "$SMPROGRAMS\\Nornyx Forge.lnk"\n'
                           "Call AttrOf\nPop $0\n${If} $0 <> -1\n"), (
        "any kind of entry of that name, a folder included")
    assert "${EXIT_SHORTCUT_EXISTS}" in body
    section = _function("Section ")
    assert section.count("CreateShortcut") == 1
    assert 'CreateShortcut "$SMPROGRAMS\\Nornyx Forge.lnk" ' in section, (
        "the name checked is the name written")


def test_the_path_budget_counts_files_and_folders_by_their_own_limits():
    body = _function("Function CheckPathBudget")
    assert "${LONGEST_RELATIVE}" in body and "${LONGEST_DIRECTORY}" in body
    assert "\n${If} $0 > 259\n" in body and "\n${If} $1 > 247\n" in body, (
        "CreateDirectory refuses 248 characters, a file path 260")


def test_the_plugins_are_reserved_before_the_payload_and_the_payload_is_extracted_last():
    code = "\n".join(_code_lines(_nsi()))
    assert code.index("ReserveFile /plugin System.dll") < code.index("Section ")
    assert code.index("ReserveFile /plugin nsExec.dll") < code.index("Section ")
    assert code.count("!include \"${STAGE_DIR}/files.nsh\"") == 1
    section = code[code.index("Section "):]
    order = ["CreateDirectory", "Call CheckNoLinks", "files.nsh", "Call VerifyFolder", "Rename ",
             "CreateShortcut", "receipt.nsh"]
    positions = [section.index(item) for item in order]
    assert positions == sorted(positions), dict(zip(order, positions))


def test_the_installer_uses_none_of_what_it_must_never_use():
    code = "\n".join(_code_lines(_nsi()))
    for forbidden in ("WriteReg", "DeleteReg", "HKLM", "HKCU", "HKEY_", "SetShellVarContext all",
                      "$PROGRAMFILES", "$COMMONFILES", "$WINDIR", "$SYSDIR", "$APPDATA",
                      "$TEMP", "$DESKTOP", "WriteUninstaller", "Uninst", "RMDir", "Delete ",
                      "Exec ", "ExecWait", "ExecShell", "inetc", "NSISdl", "SetOverwrite on",
                      "RequestExecutionLevel admin", "RequestExecutionLevel highest",
                      "EnVar", "AddEnv", "$PATH", "SendMessage"):
        assert forbidden not in code, f"the script uses {forbidden}"
    for required in ("AllowSkipFiles off", "SetOverwrite off", "CRCCheck on", "Unicode true",
                     "SetShellVarContext current", "Target x86-unicode"):
        assert required in code, f"the script lacks {required}"
    assert code.index("Target x86-unicode") < code.index("Unicode true") < code.index("OutFile"), (
        "the target is selected before anything that depends on it")


def test_the_only_process_it_starts_is_the_payloads_own_verifier_against_the_baked_identity():
    code = _code_lines(_nsi())
    started = [line for line in code if "nsExec::" in line]
    assert len(started) == 1, started
    assert started[0].endswith(
        "'\"$0\\python\\python.exe\" -B -I -m nornyx_forge.windows_payload verify \"$0\" "
        "--expect ${PAYLOAD_SHA256}'"), started[0]
    assert sum("System::Call" in line for line in code) >= 6, "the token and attribute calls"


def test_no_line_of_the_script_ends_in_a_backslash():
    """NSIS continues a line, a comment included, that ends in one."""
    for number, line in enumerate(_nsi().splitlines(), 1):
        assert not line.rstrip("\r").endswith("\\"), f"line {number} ends in a backslash"


def test_the_installers_sources_are_under_the_canonical_text_rule_and_written_canonically():
    """CLASS (found by CI, not by the fast checks): a governed text file whose
    suffix the canonical rule does not name is hashed raw, so its digest depends
    on the checkout's line endings; and a writer that leaves line endings to the
    platform makes a file CRLF on Windows. Both are held for everything this
    change adds under scripts/."""
    from nornyx_forge.governed_subject import (  # noqa: PLC0415
        CANONICAL_TEXT_SUFFIXES,
        is_declared_text,
    )

    for suffix in (".nsi", ".nsh", ".ps1"):
        assert suffix in CANONICAL_TEXT_SUFFIXES, suffix
    added = sorted(path for path in (ROOT / "scripts" / "windows_installer").iterdir()
                   if path.is_file()) + [ROOT / "scripts" / "build_windows_installer.py"]
    assert len(added) >= 8
    for path in added:
        relative = path.relative_to(ROOT).as_posix()
        assert is_declared_text(relative) or b"\0" in path.read_bytes(), (
            f"{relative} is text outside the canonical text rule")
    import ast  # noqa: PLC0415

    for path in added:
        if path.suffix != ".py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            mode = node.args[0] if node.args else None
            literal = mode.value if isinstance(mode, ast.Constant) else ""
            opens_text_for_writing = (
                node.func.attr == "open" and isinstance(literal, str)
                and any(flag in literal for flag in "wax+") and "b" not in literal)
            if node.func.attr == "write_text" or opens_text_for_writing:
                assert any(keyword.arg == "newline" for keyword in node.keywords), (
                    f"{path.name}:{node.lineno} leaves line endings to the platform")


def test_the_new_canonical_suffixes_are_used_only_by_the_installers_own_sources():
    """The boundary touch of the canonical text rule (made with the compiler's
    pins) changes how a file of those suffixes is hashed. At that change's base no
    tracked file had one (A-042 gives the measurement); here, every tracked file
    that has one is the installer's own or the compiler's smoke script."""
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True,  # noqa: S603, S607
                             timeout=120, check=True).stdout.decode("utf-8").split("\0")
    users = sorted(name for name in tracked if name.endswith((".nsi", ".nsh", ".ps1")))
    assert users == ["scripts/windows_installer/forge-setup.nsi",
                     "scripts/windows_installer/nsis-smoke.nsi",
                     "scripts/windows_installer/run_as_standard_user.ps1"], users


def test_the_installer_files_are_lf_utf8_with_a_final_newline():
    for path in (NSI, ROOT / "scripts" / "windows_installer" / "installer_contract.py",
                 ROOT / "scripts" / "windows_installer" / "standard_user_checks.py",
                 ROOT / "scripts" / "windows_installer" / "synthetic_payload.py",
                 ROOT / "scripts" / "windows_installer" / "run_as_standard_user.ps1",
                 ROOT / "scripts" / "build_windows_installer.py"):
        data = path.read_bytes()
        data.decode("utf-8")
        assert b"\r" not in data and data.endswith(b"\n"), path.name


# ---------------------------------------------------------------------------
# The contract: the file list, the receipt, the shortcut
# ---------------------------------------------------------------------------

TRICKY = ["Forge.cmd", ".nornyx/contracts/a.nyx", "pylib/a b/c d.py", "pylib/a.b/x.py",
          "pylib/a/z.py", "pylib/$HOME/$$x.py", "pylib/ünï/çode.py", "src/x/y.py", "src/x/z.py",
          "src/x/w/v.py"]


def _parse_files_nsh(text: str, base: str) -> list[str]:
    """Read an include back with a strict parser of exactly what the emitter
    writes, refusing any other line: the destination of each `File`."""
    destinations, current = [], None
    for line in text.splitlines():
        out = re.fullmatch(r'SetOutPath "\$Partial((?:\\[^"\\]+)*)"', line)
        file_ = re.fullmatch(r'File "' + re.escape(base) + r'/([^"]+)"', line)
        if out:
            current = out.group(1).replace("\\", "/").lstrip("/")
        elif file_:
            assert current is not None, "a File before any SetOutPath"
            source = file_.group(1)
            destination = (current + "/" if current else "") + source.rpartition("/")[2]
            assert destination == source, (
                f"{source} would be extracted to {destination}, not to where it is read from")
            destinations.append(destination.replace("$$", "$"))
        else:
            raise AssertionError(f"a line the emitter does not write: {line!r}")
    return destinations


def test_the_file_list_extracts_every_manifest_entry_once_in_order_and_nothing_else(
        tmp_path: Path):
    manifest = _manifest_of({name: b"x" for name in TRICKY}, tmp_path)
    text = contract.files_nsh(manifest["files"], "/tmp/payload",
                              manifest_name=PAYLOAD_MANIFEST)
    destinations = _parse_files_nsh(text, "/tmp/payload")
    listed = [entry[0] for entry in manifest["files"]]
    assert destinations == listed + [PAYLOAD_MANIFEST], "a dead write or a phantom read"
    assert len(set(destinations)) == len(destinations)
    sources = re.findall(r'File "/tmp/payload/([^"]+)"', text)
    assert [s.replace("$$", "$") for s in sources] == listed + [PAYLOAD_MANIFEST]
    assert "$$HOME" in text and "$HOME" not in text.replace("$$", ""), "a `$` must be escaped"


def test_the_file_list_changes_directory_only_when_it_has_to(tmp_path: Path):
    manifest = _manifest_of({name: b"x" for name in TRICKY}, tmp_path)
    text = contract.files_nsh(manifest["files"], "/tmp/payload",
                              manifest_name=PAYLOAD_MANIFEST)
    outs = re.findall(r'SetOutPath "([^"]+)"', text)
    assert all(a != b for a, b in zip(outs, outs[1:])), "a repeated SetOutPath"
    assert outs[0] == "$Partial" or outs[0].startswith("$Partial\\")


@pytest.mark.parametrize("name", ['pylib/a"b.py', "pylib/a\nb.py", "pylib/a\x7fb.py"])
def test_a_name_an_nsis_string_cannot_carry_is_refused(name: str):
    with pytest.raises(contract.ContractError):
        contract.files_nsh([[name, 1, "d" * 64]], "/tmp/payload",
                           manifest_name=PAYLOAD_MANIFEST)


@pytest.mark.parametrize("base", ["/tmp/a payload", "/tmp/a$b", "/tmp/a\"b", "/tmp/ünï",
                                  "tmp/payload", "C:/payload", ""])
def test_a_payload_path_the_script_cannot_name_plainly_is_refused(base: str):
    """The builder passes the fixed place the container mounts the payload at;
    anything but a plain absolute POSIX path is refused all the same."""
    with pytest.raises(contract.ContractError):
        contract.files_nsh([["a.py", 1, "d" * 64]], base, manifest_name=PAYLOAD_MANIFEST)
    emitted = contract.files_nsh([["a.py", 1, "d" * 64]], installer.PAYLOAD_MOUNT,
                                 manifest_name=PAYLOAD_MANIFEST)
    assert emitted.endswith(f'File "/payload/a.py"\nFile "/payload/{PAYLOAD_MANIFEST}"\n')


def test_every_name_the_payload_rule_admits_the_installers_string_syntax_carries():
    """The rule that admits a name to the payload must also admit it to the
    installer's string syntax. A backtick was the character they disagreed on
    while `nsis_text` shared a refusal with the receipt's backtick-quoted
    strings; it is literal inside the double quotes the file list uses."""
    for codepoint in list(range(0x20, 0x7F)) + [0x7F, 0xE9, 0x4E2D, 0x1F600]:
        name = f"a{chr(codepoint)}b"
        if check_name(name) is None:
            assert contract.nsis_text(name) == name.replace("$", "$$"), hex(codepoint)
    assert check_name("a`b") is None and contract.nsis_text("a`b") == "a`b"


def _manifest(tmp_path: Path) -> dict:
    return _manifest_of({"Forge.cmd": b"@echo off\n", "src/x.py": b"x\n"}, tmp_path)


def test_the_receipt_the_installer_writes_is_the_receipt_the_checker_accepts(tmp_path: Path):
    manifest = _manifest(tmp_path)
    for git in ("found", "not found"):
        for created in (True, False):
            text = contract.render_receipt(manifest, git=git, root_created=created)
            assert contract.check_receipt(text, manifest) == []
            parsed = json.loads(text)
            assert parsed["prerequisites"] == {"git": git} and parsed["root_created"] is created
            assert parsed["versions"][0]["payload_sha256"] == manifest["payload_sha256"]
            assert parsed["versions"][0]["directory"] == f"1.2.3+{COMMIT[:12]}"
            assert parsed["registry"] == []


def test_the_nsis_that_writes_the_receipt_writes_exactly_its_lines(tmp_path: Path):
    manifest = _manifest(tmp_path)
    nsh = contract.receipt_nsh(manifest).splitlines()
    assert nsh[0] == 'FileOpen $0 "$INSTDIR\\install-receipt.json" w' and nsh[-1] == "FileClose $0"
    written = []
    for line in nsh[1:-1]:
        match = re.fullmatch(r"FileWrite \$0 `(.*)\$\\n`", line)
        assert match, f"a line the emitter does not write: {line!r}"
        written.append(match.group(1))
    assert written == contract.receipt_lines(manifest)
    for token in (contract.GIT_TOKEN, contract.ROOT_TOKEN):
        assert sum(line.count(token) for line in written) == 1


@pytest.mark.parametrize("name", contract.FORBIDDEN_RECEIPT_NAMES)
def test_a_receipt_that_names_a_state_class_it_does_not_own_is_refused(tmp_path: Path, name: str):
    manifest = _manifest(tmp_path)
    receipt = json.loads(contract.render_receipt(manifest, git="found", root_created=True))
    receipt["created"].append({"kind": "directory", "path": f"x/{name.upper()}/y"})
    problems = contract.check_receipt(json.dumps(receipt), manifest)
    assert any(name.casefold() in problem.casefold() for problem in problems), problems


@pytest.mark.parametrize("change, expect", [
    (lambda r: r.update(extra=1), "fields are not exactly"),
    (lambda r: r.update(schema="x"), "schema"),
    (lambda r: r.update(location="local_application_data/Elsewhere"), "location"),
    (lambda r: r.update(registry=[{"key": "HKCU\\x"}]), "registry"),
    (lambda r: r.update(root_created="yes"), "boolean"),
    (lambda r: r["prerequisites"].update(python="found"), "prerequisites"),
    (lambda r: r.update(prerequisites=["git"]), "prerequisites"),
    (lambda r: r.update(prerequisites="found"), "prerequisites"),
    (lambda r: r.update(prerequisites=None), "prerequisites"),
    (lambda r: r["prerequisites"].update(git=["found"]), "prerequisites"),
    (lambda r: r["created"].append({"kind": "file", "path": "/etc/x"}), "not a path inside"),
    (lambda r: r["created"].append({"kind": "file", "path": "C:/x"}), "not a path inside"),
    (lambda r: r["created"].append({"kind": "file", "path": "a/../../x"}), "not a path inside"),
    (lambda r: r["created"].append({"kind": "file", "path": "extra"}), "created paths"),
    (lambda r: r["created"].append({"kind": "key", "path": "x"}), "unknown created"),
    (lambda r: r["versions"][0].update(payload_sha256="e" * 64), "exactly the installed payload"),
    (lambda r: r["created"].__setitem__(2, {"kind": "shortcut", "folder": "desktop",
                                            "name": "x.lnk"}), "shortcut entry"),
])
def test_each_receipt_guard_refuses_by_name(tmp_path: Path, change, expect: str):
    manifest = _manifest(tmp_path)
    receipt = json.loads(contract.render_receipt(manifest, git="found", root_created=True))
    change(receipt)
    problems = contract.check_receipt(json.dumps(receipt), manifest)
    assert any(expect in problem for problem in problems), problems


def test_a_receipt_that_is_not_json_or_not_an_object_is_refused():
    assert contract.check_receipt("not json")[0].startswith("not JSON")
    assert contract.check_receipt("[]")[0].startswith("the receipt's fields")


def test_the_receipt_may_not_name_a_state_class_the_driver_also_watches():
    """The two lists are one fact seen twice; they must not drift."""
    watched = {name.casefold() for name in driver.STATE_NAMES}
    named = {name.casefold() for name in contract.FORBIDDEN_RECEIPT_NAMES}
    assert watched <= named | {"crewai"}, sorted(watched - named)


def test_the_shortcut_starts_the_embedded_interpreter_without_bytecode_in_the_install_root(
        tmp_path: Path):
    manifest = _manifest(tmp_path)
    expected = contract.shortcut_expectation(
        manifest, install_root="C:\\U\\AppData\\Local\\Programs\\Nornyx Forge",
        profile="C:\\U")
    folder = f"C:\\U\\AppData\\Local\\Programs\\Nornyx Forge\\1.2.3+{COMMIT[:12]}"
    assert expected == {
        "TargetPath": folder + "\\python\\pythonw.exe",
        "Arguments": f'-B -m nornyx_forge.windows_launch --bundle-root "{folder}" '
                     '--project-dir "C:\\U\\ForgeProject"',
        "WorkingDirectory": "C:\\U\\AppData\\Local\\Programs\\Nornyx Forge"}
    shortcut = [line for line in _code_lines(_nsi()) if line.startswith("CreateShortcut")]
    assert len(shortcut) == 1
    assert '"$INSTDIR\\$VerDir\\python\\pythonw.exe"' in shortcut[0]
    assert ("'-B -m nornyx_forge.windows_launch --bundle-root \"$INSTDIR\\$VerDir\" "
            "--project-dir \"$PROFILE\\ForgeProject\"'") in shortcut[0]
    assert contract.SHORTCUT_NAME in _nsi()


# ---------------------------------------------------------------------------
# The builder, over a synthetic repository, a sealed payload, a stand-in compiler
# tree and a stand-in for `docker run`
# ---------------------------------------------------------------------------

FAKE_MAKENSIS = """#!{python}
import hashlib, json, os, shutil, sys
args = sys.argv[1:]
config = json.load(open({config!r}))
if args == ["-VERSION"]:
    print(config.get("version", CONFIG_VERSION))
    raise SystemExit(0)
defines = dict(a[2:].split("=", 1) for a in args if a.startswith("-D"))
script = args[-1]
stage = os.path.dirname(script)
capture = config["capture"]
os.makedirs(capture, exist_ok=True)
for name in sorted(os.listdir(stage)):
    shutil.copyfile(os.path.join(stage, name), os.path.join(capture, name))
json.dump({{"args": args, "defines": defines, "environ": dict(os.environ), "cwd": os.getcwd()}},
          open(os.path.join(capture, "call.json"), "w"))
if config["mode"] in ("fail", "fail-with-file"):
    if config["mode"] == "fail-with-file":
        open(defines["OUT_FILE"], "wb").write(b"MZ")
    print("error: a stand-in failure", file=sys.stderr)
    raise SystemExit(1)
print("warning: a stand-in warning (x.nsi:1)")
print(config.get("say", ""))
import re
parts = []
for name in sorted(os.listdir(stage)):
    text = open(os.path.join(stage, name), "rb").read()
    if name == "files.nsh":
        sources = re.findall(rb'File "([^"]+)"', text)
        base = os.path.commonpath([os.path.dirname(s) for s in sources])
        text = text.replace(base, b"<payload>")
    parts.append(text)
digest = hashlib.sha256(b"".join(parts)).hexdigest()
manifest = '<requestedExecutionLevel level="asInvoker" uiAccess="false"/>'
body = b"MZ" + bytes(0x3A) + (0x80).to_bytes(4, "little") + bytes(0x80 - 0x40) + b"PE\\0\\0"
body += manifest.encode()
body += ("{{VERSION}}+{{COMMIT12}}".format(**defines)).encode("utf-16-le")
body += ("payload sha256 " + defines["PAYLOAD_SHA256"]).encode("utf-16-le")
body += digest.encode() + os.urandom(0)
for extra in config.get("append", []):
    body += extra.encode()
if config["mode"] == "bad-manifest":
    body = body.replace(b"asInvoker", b"requireAdministrator")
elif config["mode"] == "no-manifest":
    body = body.replace(b"asInvoker", b"none")
elif config["mode"] == "no-product-version":
    body = body.replace(("{{VERSION}}+{{COMMIT12}}".format(**defines)).encode("utf-16-le"), b"")
elif config["mode"] == "no-version":
    body = body.replace(("payload sha256 " + defines["PAYLOAD_SHA256"]).encode("utf-16-le"), b"")
elif config["mode"] == "not-pe":
    body = b"XX" + body[2:]
elif config["mode"] == "no-header":
    body = body.replace(b"PE\\0\\0", b"XX\\0\\0")
if config["mode"] == "link-output":
    elsewhere = os.path.join(capture, "elsewhere.exe")
    open(elsewhere, "wb").write(body)
    os.symlink(elsewhere, defines["OUT_FILE"])
    raise SystemExit(0)
open(defines["OUT_FILE"], "wb").write(body)
if config["mode"] == "extra-output":
    open(defines["OUT_FILE"] + ".extra", "wb").write(b"x")
"""


class _Docker:
    """Stands in for `docker run`: reads the options the builder passes, maps
    each `-v` mount back to its host path (in the command and in `-D` values),
    and runs the stand-in compiler there with exactly the `-e` environment and
    nothing of the caller's. Records every argv it is given."""

    VALUED = {"--pull", "--network", "--cap-drop", "--security-opt", "--user", "--tmpfs", "-e",
              "-v"}

    def __init__(self, image: str) -> None:
        self.image = image
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, timeout, capture_output=False, check=False, env=None):
        self.calls.append(list(argv))
        assert argv[:2] == ["docker", "run"] and env is None
        at = argv.index(self.image)
        options, command = argv[2:at], argv[at + 1:]
        mounts, environment, index = {}, {}, 0
        while index < len(options):
            if options[index] in self.VALUED:
                value = options[index + 1]
                if options[index] == "-v":
                    source, target = value.removesuffix(":ro").rsplit(":", 1)
                    mounts[target] = source
                elif options[index] == "-e":
                    key, _, setting = value.partition("=")
                    environment[key] = setting
                index += 2
            else:
                index += 1

        def host(value: str) -> str:
            for target in sorted(mounts, key=len, reverse=True):
                if value == target or value.startswith(target + "/"):
                    return mounts[target] + value[len(target):]
            return value

        translated = [f"{a.split('=', 1)[0]}={host(a.split('=', 1)[1])}"
                      if a.startswith("-D") and "=" in a else host(a) for a in command]
        return subprocess.run(translated, capture_output=capture_output, timeout=timeout,  # noqa: S603
                              env=environment, check=check)


class _Fixture:
    """A repository, a sealed payload, a stand-in compiler tree pinned by its
    digests in the repository's toolchain pins, and the stand-in docker:
    everything one `installer.build` needs."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.repo = tmp_path / "repo"
        files = {
            "pyproject.toml": b'[project]\nname = "x"\nversion = "1.2.3"\n',
            "src/nornyx_forge/__init__.py": b"", "src/nornyx_forge/windows_payload.py": b"# s\n",
            "src/nornyx_forge/windows_launch.py": b"#\n", "README.md": b"readme\n",
            "BRD.md": b"brd\n", ".nornyx/contracts/c.nyx": b"contract\n",
            "scripts/build_windows_bundle.py": b"# stand-in\n",
            "scripts/build_windows_installer.py": b"# stand-in\n",
            "scripts/windows_installer/installer_contract.py": b"# stand-in\n",
            "scripts/windows_installer/build_nsis_toolchain.py": b"# stand-in\n",
            "scripts/windows_installer/nsis-build-debs.json": LOCK.read_bytes(),
            "scripts/windows_installer/forge-setup.nsi": NSI.read_bytes(),
            "scripts/windows_installer/lock.txt": b"x==1 \\\n    --hash=sha256:" + b"0" * 64 + b"\n",
            "scripts/windows_installer/pins.json": json.dumps(self.pins()).encode("utf-8"),
        }
        for relative, data in files.items():
            path = self.repo.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.config = tmp_path / "fake-config.json"
        self.captured = tmp_path / "captured"
        self.tree = tmp_path / "nsis-tree"
        (self.tree / "Stubs").mkdir(parents=True)
        (self.tree / "Stubs" / "lzma").write_bytes(b"stub\n")
        self.makensis = self.tree / "Bin" / "makensis"
        self.makensis.parent.mkdir()
        self.makensis.write_text(FAKE_MAKENSIS.format(
            python=sys.executable, config=str(self.config)).replace(
            "CONFIG_VERSION", repr("v3.13")), encoding="utf-8", newline="\n")
        self.makensis.chmod(self.makensis.stat().st_mode | stat.S_IXUSR)
        self.docker = _Docker(json.loads(TOOLCHAIN.read_text(encoding="utf-8"))["container"]["image"])
        self.set_mode("ok")
        self.write_toolchain()
        self.commit()

    @staticmethod
    def pins() -> dict:
        return {"schema": bundle.PINS_SCHEMA, "lock": "lock.txt",
                "installer": {"name": "uv", "version": "0.0.0"},
                "target": {"python_version": "3.13", "python_platform": "x86_64-pc-windows-msvc",
                           "wheel_platform": "win_amd64", "abi": "cp313"},
                "interpreter": {"version": "3.13.0", "archive_url": "https://example.invalid/e.zip",
                                "archive_sha256": "b" * 64}}

    def set_mode(self, mode: str, **more) -> None:
        self.config.write_text(json.dumps({"mode": mode, "capture": str(self.captured), **more}),
                               encoding="utf-8")

    def toolchain_pins(self, **override) -> dict:
        """The committed toolchain pins, with the outputs those of the stand-in tree."""
        pins = json.loads(TOOLCHAIN.read_text(encoding="utf-8"))
        pins["outputs"] = {"makensis_sha256": installer._sha256(self.makensis),
                           "data_tree_sha256": toolchain.tree_digest(self.tree)}
        pins.update(override)
        return pins

    def write_toolchain(self, **override) -> None:
        (self.repo / "scripts/windows_installer/nsis-toolchain.json").write_text(
            json.dumps(self.toolchain_pins(**override), indent=2), encoding="utf-8")

    def git(self, *arguments: str) -> str:
        environment = {**os.environ, "GIT_AUTHOR_DATE": "2025-06-07T08:09:10Z",
                       "GIT_COMMITTER_DATE": "2026-01-02T03:04:05Z"}
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *arguments],
            cwd=str(self.repo), capture_output=True, check=True, env=environment,
            timeout=60).stdout.decode("utf-8")

    def commit(self) -> str:
        if not (self.repo / ".git").exists():
            self.git("init", "-q")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "fixture")
        return self.git("rev-parse", "HEAD").strip()

    def payload(self, name: str = "payload", *, version: str = "1.2.3", extra: dict | None = None,
                drop: tuple[str, ...] = (), **override) -> Path:
        """A sealed payload tied to this commit, its pins and its lock: the
        commit's own copy set (as the payload builder copies it) plus the
        interpreter, the launcher and the marker. `extra` adds or replaces a
        file; `drop` removes one."""
        commit = self.git("rev-parse", "HEAD").strip()
        lock = (self.repo / "scripts/windows_installer/lock.txt").read_bytes()
        root = self.tmp / name
        bundle.copy_tree(self.repo, root, commit)
        bundle.write_bundle_marker(root, mode=bundle.SELF_CONTAINED,
                                   interpreter_sha256="b" * 64, source_commit=commit)
        bundle.write_launcher(root, bundle.SELF_CONTAINED)
        files = {"python/python.exe": b"MZ", "python/pythonw.exe": b"MZ", **(extra or {})}
        for relative, data in files.items():
            path = root.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for relative in drop:
            (root / relative).unlink()
        fields = {"version": version, "source_commit": commit, "source_date_epoch": COMMITTED,
                  "target": "cp313-win_amd64", "lock_sha256": hashlib.sha256(lock).hexdigest(),
                  "installer": {"name": "uv", "version": "0.0.0"},
                  "interpreter": {"version": "3.13.0", "archive_url": "https://example.invalid/e.zip",
                                  "archive_sha256": "b" * 64}, **override}
        (root / PAYLOAD_MANIFEST).write_bytes(render_manifest(build_manifest(root, **fields)))
        bundle.normalize_mtimes(root, COMMITTED)
        return root

    def build(self, payload: Path | None = None, out: str = "out", **kwargs) -> dict:
        payload = payload or self.payload()
        return installer.build(self.repo, payload, self.tmp / out, nsis_tree=self.tree,
                               run=self.docker, **kwargs)

    def capture(self) -> dict:
        return json.loads((self.captured / "call.json").read_text(encoding="utf-8"))

    def compiles(self) -> list[list[str]]:
        """The docker calls that compiled, as opposed to asking the version."""
        return [call for call in self.docker.calls if call[-1] != "-VERSION"]


def test_the_builder_makes_exactly_the_executable_its_digest_and_its_record(tmp_path: Path):
    fixture = _Fixture(tmp_path)
    record = fixture.build()
    out = tmp_path / "out"
    assert sorted(path.name for path in out.iterdir()) == sorted(installer.OUTPUT_NAMES)
    data = (out / "ForgeSetup.exe").read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert (out / "ForgeSetup.exe.sha256").read_text() == f"{digest}  ForgeSetup.exe\n"
    on_disk = json.loads((out / "ForgeSetup.build.json").read_text(encoding="utf-8"))
    assert on_disk == record and record["installer"] == {"file": "ForgeSetup.exe",
                                                         "sha256": digest, "size": len(data)}
    sealed = json.loads((tmp_path / "payload" / PAYLOAD_MANIFEST).read_text(encoding="utf-8"))
    assert record["payload"]["sha256"] == sealed["payload_sha256"]
    assert record["payload"]["files"] == len(sealed["files"]) + 1
    assert record["tool"]["version_output"] == "v3.13" and record["makensis_warnings"] == 1
    pins = fixture.toolchain_pins()
    assert record["tool"]["makensis_sha256"] == pins["outputs"]["makensis_sha256"]
    assert record["tool"]["data_tree_sha256"] == pins["outputs"]["data_tree_sha256"]
    assert record["tool"]["image"] == pins["container"]["image"]
    assert record["tool"]["source"] == {"version": "3.13", "sha256": pins["source"]["sha256"]}
    assert set(record["inputs"]) == set(COMPARED_INSTALLER_FILES)
    assert "built_at" not in json.dumps(record) and str(tmp_path) not in json.dumps(record)


def _options(argv: list[str]) -> dict[str, list[str]]:
    """The values of each repeated option of a docker argv, in order."""
    found: dict[str, list[str]] = {}
    for index, value in enumerate(argv[:-1]):
        if value in _Docker.VALUED:
            found.setdefault(value, []).append(argv[index + 1])
    return found


def test_the_compiler_runs_in_the_pinned_image_with_fixed_mounts_command_and_environment(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FORGE_TEST_LEAK", "leaked")
    monkeypatch.setenv("UV_ANYTHING", "1")
    fixture = _Fixture(tmp_path)
    fixture.build()
    pins = fixture.toolchain_pins()
    image = pins["container"]["image"]
    version_call, compile_call = fixture.docker.calls
    for argv in (version_call, compile_call):
        assert argv[:2] == ["docker", "run"] and argv[argv.index("--network") + 1] == "none"
        assert argv[argv.index("--pull") + 1] == "never", "the image is pulled beforehand, never here"
        assert argv[argv.index("--tmpfs") + 1] == "/tmp", "the only writable place but the output"
        assert argv[argv.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}", (
            "the compiler runs as the invoking user, not as the image's root")
        assert argv[argv.index("--cap-drop") + 1] == "ALL" and "--read-only" in argv
        assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
        assert image in argv and "--privileged" not in argv
        assert not any("docker.sock" in value for value in argv)
    # ONE definition of the container for every consumer of the tree: the options
    # before the mounts are the toolchain's own smoke compile's, but for the epoch.
    smoke = toolchain.smoke_argv(pins, tree=fixture.tree, nsi=tmp_path / "x.nsi",
                                 out_dir=tmp_path, command=[])
    def without_epoch(argv: list[str]) -> list[str]:
        head = argv[:argv.index("-v")]
        return [v for i, v in enumerate(head) if not v.startswith("SOURCE_DATE_EPOCH=")
                and not (v == "-e" and head[i + 1].startswith("SOURCE_DATE_EPOCH="))]
    assert without_epoch(compile_call) == without_epoch(smoke)
    assert version_call[version_call.index(image) + 1:] == ["/nsis/Bin/makensis", "-VERSION"]
    assert _options(version_call)["-v"] == [f"{fixture.tree.resolve()}:/nsis:ro"]
    mounts = _options(compile_call)["-v"]
    assert [mount.split(":", 1)[1] for mount in mounts] == [
        "/nsis:ro", "/stage:ro", "/payload:ro", "/out"], "only the output folder is writable"
    assert mounts[0] == f"{fixture.tree.resolve()}:/nsis:ro"
    assert mounts[2] == f"{(tmp_path / 'payload').resolve()}:/payload:ro"
    environment = dict(value.split("=", 1) for value in _options(compile_call)["-e"])
    assert environment == {"HOME": "/tmp", "NSISDIR": "/nsis", "LC_ALL": "C.UTF-8", "TZ": "UTC",
                           "SOURCE_DATE_EPOCH": str(COMMITTED)}
    call = fixture.capture()
    assert call["environ"] == environment, "nothing of the caller's reaches the compiler"
    command = compile_call[compile_call.index(image) + 1:]
    assert command[:6] == ["/nsis/Bin/makensis", "-NOCONFIG", "-NOCD", "-INPUTCHARSET", "UTF8",
                           "-V2"]
    assert command[-1] == "/stage/" + contract.NSI_NAME
    assert "-DSTAGE_DIR=/stage" in command and "-DOUT_FILE=/out/ForgeSetup.exe" in command
    assert call["defines"]["VERSION"] == "1.2.3"
    assert call["defines"]["COMMIT12"] == fixture.git("rev-parse", "HEAD").strip()[:12]
    assert call["defines"]["VI_VERSION"] == "1.2.3.0"
    stage = fixture.captured
    assert (stage / contract.NSI_NAME).read_bytes() == NSI.read_bytes(), (
        "the compiled script is the committed one")
    sealed = json.loads((tmp_path / "payload" / PAYLOAD_MANIFEST).read_text(encoding="utf-8"))
    assert call["defines"]["PAYLOAD_SHA256"] == sealed["payload_sha256"]
    assert call["defines"]["LONGEST_RELATIVE"] == str(max(
        len(entry[0]) for entry in sealed["files"]))
    assert call["defines"]["LONGEST_DIRECTORY"] == str(max(
        len(entry[0].rpartition("/")[0]) for entry in sealed["files"]))
    assert (stage / "files.nsh").read_text(encoding="utf-8") == contract.files_nsh(
        sealed["files"], "/payload", manifest_name=PAYLOAD_MANIFEST)
    assert (stage / "receipt.nsh").read_text(encoding="utf-8") == contract.receipt_nsh(sealed)


def test_two_builds_from_different_places_and_clocks_are_the_same_bytes(tmp_path: Path):
    """The inputs fixed, the payload folder and the output folder moved, the
    wall clock moved between builds: the executable, its digest and its record
    are equal."""
    fixture = _Fixture(tmp_path)
    first = fixture.build(fixture.payload("payload-a"), "out-a")
    time.sleep(1.1)
    second = fixture.build(fixture.payload("payload-b"), "out-b")
    assert first == second
    for name in installer.OUTPUT_NAMES:
        assert (tmp_path / "out-a" / name).read_bytes() == (tmp_path / "out-b" / name).read_bytes()


@pytest.mark.parametrize("mutate, message", [
    (lambda p: (p / "README.md").write_bytes(b"changed\n"), "does not verify"),
    (lambda p: (p / "extra.txt").write_bytes(b"unlisted\n"), "does not verify"),
    (lambda p: os.utime(p / "README.md", (COMMITTED + 5, COMMITTED + 5)),
     "does not carry the commit's time"),
    (lambda p: os.utime(p / "src", (COMMITTED + 5, COMMITTED + 5)),
     "does not carry the commit's time"),
], ids=["changed-byte", "unlisted-file", "touched-file", "touched-folder"])
def test_a_payload_that_does_not_verify_or_was_touched_is_refused(tmp_path: Path, mutate, message):
    fixture = _Fixture(tmp_path)
    payload = fixture.payload()
    mutate(payload)
    with pytest.raises(installer.InstallerError, match=message):
        fixture.build(payload)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("override, field", [
    ({"source_commit": "f" * 40}, "source_commit"),
    ({"lock_sha256": "9" * 64}, "lock_sha256"),
    ({"installer": {"name": "uv", "version": "9.9.9"}}, "installer"),
    ({"interpreter": {"version": "3.13.1", "archive_url": "https://example.invalid/e.zip",
                      "archive_sha256": "b" * 64}}, "interpreter"),
    ({"interpreter": {"version": "3.13.0", "archive_url": "https://example.invalid/e.zip",
                      "archive_sha256": "c" * 64}}, "interpreter"),
    ({"target": "cp312-win_amd64"}, "target"),
    ({"source_date_epoch": COMMITTED + 1}, "source_date_epoch"),
], ids=["commit", "lock", "installer", "interpreter-version", "interpreter-digest", "target",
        "epoch"])
def test_a_payload_that_is_not_this_commits_is_refused_by_field(tmp_path: Path, override, field):
    """Sealed correctly, verifying, and still not this commit's payload."""
    fixture = _Fixture(tmp_path)
    payload = fixture.payload(**override)
    with pytest.raises(installer.InstallerError, match=f"payload's {field}"):
        fixture.build(payload)


@pytest.mark.parametrize("missing", installer.REQUIRED_ENTRIES)
def test_a_payload_without_what_the_installer_starts_and_verifies_with_is_refused(
        tmp_path: Path, missing: str):
    fixture = _Fixture(tmp_path)
    payload = fixture.payload(drop=(missing,))
    with pytest.raises(installer.InstallerError, match="lacks"):
        fixture.build(payload)


@pytest.mark.parametrize("change, message", [
    ({"src/nornyx_forge/windows_payload.py": b"# changed, and resealed\n"},
     r"changed: src/nornyx_forge/windows_payload.py"),
    ({"README.md": b"changed\n"}, r"changed: README.md"),
    ({".nornyx/contracts/c.nyx": b"another contract\n"}, r"changed: .nornyx/contracts/c.nyx"),
    ({"src/nornyx_forge/extra.py": b"print(1)\n"}, r"not in the commit: src/nornyx_forge/extra.py"),
    ({".nornyx/extra.txt": b"x\n"}, r"not in the commit: .nornyx/extra.txt"),
], ids=["source", "readme", "contract", "extra-source", "extra-contract"])
def test_a_payload_whose_copy_of_the_repository_is_not_the_commits_is_refused(
        tmp_path: Path, change: dict, message: str):
    """Sealed correctly, verifying, tied to this commit by every manifest field,
    and still not the commit's bytes: only the file comparison sees it."""
    fixture = _Fixture(tmp_path)
    with pytest.raises(installer.InstallerError, match=message):
        fixture.build(fixture.payload(extra=change))


def test_a_committed_file_missing_from_the_payload_or_a_version_of_another_commit_is_refused(
        tmp_path: Path):
    fixture = _Fixture(tmp_path)
    with pytest.raises(installer.InstallerError, match="missing: BRD.md"):
        fixture.build(fixture.payload("payload-missing", drop=("BRD.md",)))
    with pytest.raises(installer.InstallerError, match="version is '9.9.9'"):
        fixture.build(fixture.payload("payload-version", version="9.9.9"), "out-version")


def test_files_outside_the_copy_set_are_not_compared_and_the_record_says_so(tmp_path: Path):
    """`pylib/` and `python/` have no counterpart in the commit; the record
    lists them as not compared instead of implying they were."""
    fixture = _Fixture(tmp_path)
    record = fixture.build(fixture.payload(extra={"pylib/dep/__init__.py": b"x = 1\n"}))
    payload = record["payload"]
    assert payload["payload_kind"] == "commit-payload"
    assert "every copy-set file's bytes" in payload["compared_with_the_commit"]
    assert "version" in payload["compared_with_the_commit"]
    assert {"Forge.cmd", "forge-bundle.json"} <= set(payload["compared_with_the_commit"])
    assert payload["not_compared_with_the_commit"] == ["pylib", "python"]


@pytest.mark.parametrize("change, message", [
    ({"Forge.cmd": b"@echo off\r\nstart other.exe\r\n"}, "payload's Forge.cmd is not"),
    ({"forge-bundle.json": b'{"mode": "developer"}\n'}, "payload's forge-bundle.json is not"),
    ({"tools/extra.exe": b"MZ"}, r"holds \['tools'\] at its top"),
    ({"extra.txt": b"x\n"}, r"holds \['extra.txt'\] at its top"),
], ids=["launcher", "bundle-marker", "extra-top-level-folder", "extra-top-level-file"])
def test_a_file_outside_the_copy_set_is_compared_or_refused(tmp_path: Path, change, message):
    """A file outside the copy set is either one the payload builder writes,
    compared byte for byte with what the commit's builder writes, or under the
    declared `pylib/` and `python/`; anything else is refused, not passed over."""
    fixture = _Fixture(tmp_path)
    with pytest.raises(installer.InstallerError, match=message):
        fixture.build(fixture.payload(extra=change))
    assert not fixture.compiles()


@pytest.mark.parametrize("name", ["Forge.cmd", "forge-bundle.json"])
def test_a_synthetic_payload_s_generated_files_are_compared_too(tmp_path: Path, name: str):
    fixture = _Fixture(tmp_path)
    with pytest.raises(installer.InstallerError, match=f"payload's {name} is not"):
        fixture.build(fixture.payload("tiny", extra={name: b"other\n"}), synthetic=True)


def test_every_top_level_name_is_compared_or_declared_and_every_declared_name_exists(
        tmp_path: Path):
    """Two ways round, for both kinds of payload: no top-level name of the
    payload is neither compared nor declared, none is both, and the record
    declares no name the payload does not hold."""
    fixture = _Fixture(tmp_path)
    cases = [(False, fixture.payload("real", extra={"pylib/a.py": b"a = 1\n"})),
             (True, fixture.payload("tiny", extra={"README.md": b"other\n", "pad/x.txt": b"p\n"}))]
    for synthetic, payload in cases:
        record = fixture.build(payload, f"out-{payload.name}", synthetic=synthetic)
        sealed = json.loads((payload / PAYLOAD_MANIFEST).read_text(encoding="utf-8"))
        tops = {entry[0].split("/", 1)[0] for entry in sealed["files"]}
        declared = set(record["payload"]["not_compared_with_the_commit"])
        compared = set(installer.GENERATED_FILES) | (
            set() if synthetic else set(bundle.bundle_manifest()))
        assert declared <= tops, "a declared name the payload does not hold"
        assert not (declared & compared), "a name both compared and declared"
        assert tops <= declared | compared, sorted(tops - declared - compared)
    assert record["payload"]["not_compared_with_the_commit"] == [
        ".nornyx", "BRD.md", "README.md", "pad", "pyproject.toml", "python", "src"]


def test_the_synthetic_path_is_explicit_and_labelled_and_the_default_refuses_what_it_admits(
        tmp_path: Path):
    """A tiny test payload that is not a copy of the repository: refused by
    default, built through the test-only path, and labelled as such."""
    fixture = _Fixture(tmp_path)
    tiny = fixture.payload("tiny", extra={"README.md": b"not the commit's readme\n"})
    with pytest.raises(installer.InstallerError, match="not the commit's"):
        fixture.build(tiny)
    record = fixture.build(tiny, "out-synthetic", synthetic=True)
    assert record["payload"]["payload_kind"] == "synthetic-test-payload"
    assert record["payload"]["not_compared_with_the_commit"] == [
        ".nornyx", "BRD.md", "README.md", "pyproject.toml", "python", "src"]
    assert "every copy-set file's bytes" not in record["payload"]["compared_with_the_commit"]


def test_the_command_line_has_the_test_only_flag_and_it_reaches_the_build(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fixture = _Fixture(tmp_path)
    monkeypatch.setattr(installer, "ROOT", fixture.repo)
    tiny = fixture.payload("tiny", extra={"README.md": b"not the commit's readme\n"})
    monkeypatch.setattr(installer.toolchain, "_run_child", fixture.docker)
    common = ["--payload", str(tiny), "--nsis-tree", str(fixture.tree)]
    assert installer.main([*common, "--out", str(tmp_path / "out-a")]) == 1
    assert installer.main([*common, "--out", str(tmp_path / "out-b"),
                           "--test-only-synthetic"]) == 0


def test_the_longest_folder_is_counted_in_utf16_units_and_the_root_counts_as_zero(
        tmp_path: Path):
    flat = {"files": [["a.py", 1, "a" * 64]]}
    assert installer.longest_directory(flat) == 0
    deep = {"files": [["a.py", 1, "a" * 64], ["x/\U0001F600" * 3 + "/b.py", 1, "a" * 64]]}
    assert installer.longest_directory(deep) == 3 * (len("x/") + 2), "two units per astral character"
    assert installer.longest_directory({"files": [["d/e/f.py", 1, "a" * 64]]}) == len("d/e")


def test_a_host_path_docker_would_split_is_refused_and_any_other_name_is_mounted(tmp_path: Path):
    """The payload is mounted at one fixed place, so its own folder's name no
    longer reaches the script; only a `:`, which `docker -v` splits on, is refused."""
    fixture = _Fixture(tmp_path)
    with pytest.raises(installer.InstallerError, match="docker -v would split on"):
        fixture.build(fixture.payload("a:payload"))
    assert not fixture.compiles()
    record = fixture.build(fixture.payload("a payload"), "out-space")
    assert record["installer"]["size"] > 0


#: The files the build must hold to the commit's blobs, named here and not read
#: from the builder, so a name dropped from `INSTALLER_FILES` is seen.
COMPARED_INSTALLER_FILES = (
    "scripts/build_windows_installer.py", "scripts/windows_installer/forge-setup.nsi",
    "scripts/windows_installer/nsis-toolchain.json", "scripts/windows_installer/nsis-build-debs.json",
    "scripts/windows_installer/installer_contract.py",
    "scripts/windows_installer/build_nsis_toolchain.py")


@pytest.mark.parametrize("name", COMPARED_INSTALLER_FILES)
def test_each_file_the_build_runs_or_reads_is_held_to_the_commit_under_an_index_flag(
        tmp_path: Path, name: str):
    fixture = _Fixture(tmp_path)
    payload = fixture.payload()
    path = fixture.repo / name
    fixture.git("update-index", "--assume-unchanged", name)
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(installer.InstallerError, match="is not the file .* holds"):
        fixture.build(payload)
    assert not fixture.compiles()


def test_an_uncommitted_edit_to_the_script_or_the_pins_is_refused_even_under_an_index_flag(
        tmp_path: Path):
    fixture = _Fixture(tmp_path)
    payload = fixture.payload()
    nsi = fixture.repo / "scripts/windows_installer/forge-setup.nsi"
    nsi.write_bytes(nsi.read_bytes() + b"; edited\n")
    with pytest.raises(installer.InstallerError, match="working tree differs"):
        fixture.build(payload)
    fixture.git("update-index", "--assume-unchanged", "scripts/windows_installer/forge-setup.nsi")
    with pytest.raises(installer.InstallerError, match="is not the file .* holds"):
        fixture.build(payload)
    pins = fixture.repo / "scripts/windows_installer/nsis-toolchain.json"
    nsi.write_bytes(NSI.read_bytes())
    fixture.git("update-index", "--no-assume-unchanged", "scripts/windows_installer/forge-setup.nsi")
    fixture.git("update-index", "--skip-worktree", "scripts/windows_installer/nsis-toolchain.json")
    pins.write_text(json.dumps(fixture.toolchain_pins(outputs={
        "makensis_sha256": "0" * 64, "data_tree_sha256": "0" * 64})), encoding="utf-8")
    with pytest.raises(installer.InstallerError, match="is not the file .* holds"):
        fixture.build(payload)


def test_the_script_the_compiler_reads_is_the_commits_not_the_working_trees(tmp_path: Path):
    fixture = _Fixture(tmp_path)
    name = "scripts/windows_installer/forge-setup.nsi"
    fixture.git("config", "core.autocrlf", "true")
    (fixture.repo / name).unlink()
    fixture.git("-c", "core.autocrlf=true", "checkout", "--", name)
    assert (fixture.repo / name).read_bytes().endswith(b"\r\n"), "git wrote CRLF"
    fixture.build()  # a checkout that converts line endings still builds ...
    assert (fixture.captured / contract.NSI_NAME).read_bytes() == NSI.read_bytes(), (
        "... and the compiler is given the commit's bytes")


@pytest.mark.parametrize("breakage, message", [
    ("binary", "not the pinned one"), ("tree", "not the pinned one"),
    ("extra-file", "not the pinned one"), ("link", "not a regular file"),
    ("version", "makensis reports 'v3.12'"), ("version-suffix", "makensis reports 'v3.13-local'"),
    ("unpinned", "pins no outputs"),
], ids=["binary", "data-file", "extra-file", "link", "reported-version", "version-with-a-suffix",
        "unpinned-outputs"])
def test_a_compiler_tree_that_is_not_the_pinned_one_is_refused_before_anything_compiles(
        tmp_path: Path, breakage, message):
    fixture = _Fixture(tmp_path)
    if breakage == "binary":
        fixture.makensis.write_text(fixture.makensis.read_text() + "\n# changed\n")
    elif breakage == "tree":
        (fixture.tree / "Stubs" / "lzma").write_bytes(b"another stub\n")
    elif breakage == "extra-file":
        (fixture.tree / "Include").mkdir()
        (fixture.tree / "Include" / "x.nsh").write_bytes(b"!system 'id'\n")
    elif breakage == "link":
        (fixture.tree / "Stubs" / "link").symlink_to(fixture.tree / "Stubs" / "lzma")
    elif breakage == "version":
        fixture.set_mode("ok", version="v3.12")
    elif breakage == "version-suffix":
        fixture.set_mode("ok", version="v3.13-local")
    else:
        fixture.write_toolchain(outputs=None)
        fixture.commit()
    with pytest.raises(installer.InstallerError, match=message):
        fixture.build()
    assert not fixture.captured.exists(), "the compiler compiled although its pin failed"
    assert fixture.compiles() == []
    assert len(fixture.docker.calls) == (1 if breakage.startswith("version") else 0), (
        "the version is asked only of a tree whose digests passed")


@pytest.mark.parametrize("which", ["tree", "nsi", "out"])
def test_the_smoke_container_refuses_a_host_path_docker_would_split(tmp_path: Path, which: str):
    pins = json.loads(TOOLCHAIN.read_text(encoding="utf-8"))
    paths = {"tree": tmp_path / "t", "nsi": tmp_path / "s.nsi", "out": tmp_path / "o"}
    paths[which] = tmp_path / "a:b"
    with pytest.raises(toolchain.ToolchainError, match="docker -v would split on"):
        toolchain.smoke_argv(pins, tree=paths["tree"], nsi=paths["nsi"], out_dir=paths["out"],
                             command=[])


@pytest.mark.parametrize("which", ["tree", "mount"])
def test_a_relative_host_path_is_refused_for_every_mount_of_the_compiler_container(
        tmp_path: Path, which: str):
    """docker takes a relative `-v` source for a named volume, so the shared
    container definition refuses one for the tree and for each caller mount."""
    pins = json.loads(TOOLCHAIN.read_text(encoding="utf-8"))
    tree = Path("nsis") if which == "tree" else tmp_path
    mounts = [(Path("stage") if which == "mount" else tmp_path, "/stage", True)]
    with pytest.raises(toolchain.ToolchainError, match="not absolute"):
        toolchain.compiler_argv(pins, tree=tree, mounts=mounts, command=[], epoch=0)


@pytest.mark.parametrize("change, message", [
    (lambda pins, lock: pins.update(outputs=None), "pins no outputs"),
    (lambda pins, lock: pins["container"].update(lock="other.json"), "names the lock"),
    (lambda pins, lock: pins["outputs"].update(makensis_sha256="zz"), "is refused"),
    (lambda pins, lock: pins["build"].update(version_output="v3.09"), "is refused"),
    (lambda pins, lock: pins["container"].update(image="ubuntu:noble"), "is refused"),
    (lambda pins, lock: lock.update(snapshot="20990101T000000Z"), "is refused"),
    (lambda pins, lock: pins.update(schema="x"), "is refused"),
], ids=["unpinned", "lock-name", "output-digest", "version", "image-tag", "lock-snapshot",
        "schema"])
def test_toolchain_pins_that_are_incomplete_inconsistent_or_unpinned_are_refused(change, message):
    pins = json.loads(TOOLCHAIN.read_text(encoding="utf-8"))
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    change(pins, lock)
    with pytest.raises(installer.InstallerError, match=message):
        installer.load_toolchain_pins(json.dumps(pins).encode(), json.dumps(lock).encode())
    with pytest.raises(installer.InstallerError, match="is not JSON"):
        installer.load_toolchain_pins(b"{", LOCK.read_bytes())


def test_the_committed_toolchain_pins_load_and_the_installer_job_takes_the_verified_tree():
    pins = installer.load_toolchain_pins(TOOLCHAIN.read_bytes(), LOCK.read_bytes())
    assert pins["build"]["version_output"] == "v3.13" and pins["outputs"] is not None
    assert not (ROOT / "scripts" / "windows_installer" / "installer-tools.json").exists()
    job = _jobs()["windows-installer"]
    assert job["runs-on"] == "ubuntu-24.04" and job["needs"] == "nsis-toolchain-verify"
    downloads = [step for step in job["steps"]
                 if str(step.get("uses", "")).startswith("actions/download-artifact@")]
    assert [step["with"]["name"] for step in downloads] == ["nsis-toolchain-a"]
    steps = {step.get("name"): str(step.get("run", "")) for step in job["steps"]}
    tree = '"$RUNNER_TEMP/leg-a/nsis"'
    assert steps["Refuse a compiler tree that contradicts the pins"] == (
        f"python first/scripts/windows_installer/build_nsis_toolchain.py check-tree --tree {tree}")
    assert "--allow-unpinned" not in WORKFLOW.read_text(encoding="utf-8").split(
        "  windows-installer:")[1]
    assert steps["Make the checked compiler executable"] == f'chmod +x {tree[:-1]}/Bin/makensis"'
    assert "nsis-toolchain.json" in steps["Pull the pinned image"] and "docker pull" in steps[
        "Pull the pinned image"]
    for name in ("Build ForgeSetup.exe from the first payload",
                 "Build ForgeSetup.exe again from the second checkout and payload"):
        assert f"--nsis-tree {tree}" in steps[name], name
    variants = steps["Build the small installers that exercise the refusals"]
    assert f"--nsis-tree {tree}" in variants
    text = "\n".join(steps.values())
    assert "dpkg" not in text and "installer-tools.json" not in text and "apt" not in text


def test_a_non_empty_output_folder_is_refused_and_nothing_is_overwritten(tmp_path: Path):
    fixture = _Fixture(tmp_path)
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "ForgeSetup.exe").write_bytes(b"old")
    with pytest.raises(installer.InstallerError, match="empty folder"):
        fixture.build()
    assert (tmp_path / "out" / "ForgeSetup.exe").read_bytes() == b"old"


@pytest.mark.parametrize("mode", ["fail", "fail-with-file"])
def test_a_compiler_failure_is_a_refusal_that_carries_its_words(tmp_path: Path, mode: str):
    """Including a compiler that fails after leaving an output file behind."""
    fixture = _Fixture(tmp_path)
    fixture.set_mode(mode)
    with pytest.raises(installer.InstallerError, match="a stand-in failure"):
        fixture.build()
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("mode, message", [
    ("extra-output", "not exactly"), ("link-output", "not a regular file"),
], ids=["a-file-beside-it", "a-link"])
def test_what_the_container_wrote_is_read_as_untrusted(tmp_path: Path, mode: str, message: str):
    """The output folder is the container's one writable mount: it must hold
    the executable and nothing else, and the executable must be a regular file,
    not a link that would have the host read and copy any file it names."""
    fixture = _Fixture(tmp_path)
    fixture.set_mode(mode)
    with pytest.raises(installer.InstallerError, match=message):
        fixture.build()
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("mode, message", [
    ("bad-manifest", "asInvoker|requireAdministrator"), ("no-manifest", "asInvoker manifest"),
    ("no-version", "payload identity"), ("no-product-version", "its version"),
    ("not-pe", "does not start with MZ"), ("no-header", "no PE signature"),
])
def test_an_executable_that_would_ask_for_privilege_or_lacks_its_identity_is_refused(
        tmp_path: Path, mode: str, message: str):
    fixture = _Fixture(tmp_path)
    fixture.set_mode(mode)
    with pytest.raises(installer.InstallerError, match=message):
        fixture.build()
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("appended", ["highestAvailable", 'uiAccess="true"', "requireAdministrator"])
def test_any_privilege_request_anywhere_in_the_executable_is_refused(tmp_path: Path, appended):
    fixture = _Fixture(tmp_path)
    fixture.set_mode("ok", append=[appended])
    with pytest.raises(installer.InstallerError, match="contains"):
        fixture.build()


def test_an_installer_of_two_gibibytes_or_more_is_refused(tmp_path: Path,
                                                          monkeypatch: pytest.MonkeyPatch):
    exe = tmp_path / "x.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(installer, "MAX_INSTALLER_BYTES", 1)
    with pytest.raises(installer.InstallerError, match="under 2 GiB"):
        installer.check_executable(exe, {"version": "1", "source_commit": COMMIT,
                                         "payload_sha256": "a" * 64})


@pytest.mark.parametrize("version, expected", [
    ("0.3.0", "0.3.0.0"), ("1.2.3rc1", "1.2.3.0"), ("1.2", "0.0.0.0"), ("70000.1.1", "0.0.0.0"),
    ("v1.2.3", "0.0.0.0")])
def test_the_numeric_version_resource_is_the_first_three_numbers_or_zero(version, expected):
    assert installer.vi_version(version) == expected


def test_the_longest_path_is_counted_in_utf16_units_and_includes_the_manifest(tmp_path: Path):
    manifest = _manifest_of({"a/" + "ü" * 40 + ".py": b"x", "b.py": b"y"}, tmp_path)
    assert installer.longest_relative(manifest) == len("a/" + "ü" * 40 + ".py")
    emoji = {"files": [["x/" + "\U0001F600" * 12, 1, "a" * 64]]}
    assert installer.longest_relative(emoji) == len("x/") + 24, "two units per astral character"
    short = {"files": [["a.py", 1, "a" * 64]]}
    assert installer.longest_relative(short) == len(PAYLOAD_MANIFEST), "the manifest counts"


@pytest.mark.parametrize("text, count", [
    ("Processed 1 file\n", 0),
    ("warning: a (x.nsi:1)\n", 1),
    ("warning 6000: a (x.nsi:1)\n  Warning: b (x.nsi:2)\n", 2),
    ("warning 6000: a (x.nsi:1)\nwarning: b (x.nsi:2)\n\n2 warnings:\n  a (x.nsi:1)\n"
     "  b (x.nsi:2)\n", 2),
    ("\n3 warnings:\n  a\n  b\n  c\n", 3),
    ("\n1 warning:\n  a\n", 1),
    ("no warnings were treated as errors\n", 0),
], ids=["none", "one-inline", "two-inline", "inline-and-summary", "summary-only", "summary-one",
        "chatter"])
def test_each_warning_is_counted_once_whether_printed_inline_in_the_summary_or_both(text, count):
    assert installer.count_warnings(text) == count


@pytest.mark.parametrize("text, message", [
    ("warning: a\nwarning: b\n\n1 warning:\n  a\n", "summary says 1"),
    ("\n1 warning:\n  a\n\n2 warnings:\n  a\n  b\n", "2 warning summaries"),
], ids=["more-inline-than-the-summary", "two-summaries"])
def test_warning_output_that_cannot_be_read_one_way_is_refused(text, message):
    with pytest.raises(installer.InstallerError, match=message):
        installer.count_warnings(text)


def test_the_build_records_the_count_of_a_compiler_that_prints_both_forms(tmp_path: Path):
    fixture = _Fixture(tmp_path)
    fixture.set_mode("ok", say="warning 6000: two (x.nsi:2)\n\n2 warnings:\n  one\n  two\n")
    assert fixture.build()["makensis_warnings"] == 2


# ---------------------------------------------------------------------------
# The synthetic payloads the Windows job's refusals use
# ---------------------------------------------------------------------------

def test_the_long_variant_overflows_a_ci_profile_path_and_the_small_one_does_not():
    root = len("C:\\Users\\forgeci\\AppData\\Local\\Programs\\Nornyx Forge")
    def budget(version: str, longest: int) -> int:
        return root + 1 + len(f"{version}+{'0' * 12}") + len(contract.PARTIAL_SUFFIX) + 1 + longest
    assert check_name(synthetic_payload.LONG_PATH) is None
    assert len(synthetic_payload.LONG_PATH) <= 160
    assert budget(synthetic_payload.LONG_VERSION, len(synthetic_payload.LONG_PATH)) > 259
    assert budget("0.0.1", 60) <= 259
    assert budget("0.3.0", 160) <= 259, "even the longest legal path fits under a real version"


def test_a_synthetic_payload_is_a_real_sealed_payload_tied_to_the_commit(tmp_path: Path):
    fixture = _Fixture(tmp_path)
    archive = tmp_path / "embed.zip"
    import zipfile  # noqa: PLC0415
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("python313._pth", "python313.zip\nimport site\n")
        for name in ("python.exe", "pythonw.exe", "python313.zip"):
            handle.writestr(name, "stand-in " + name)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    pins = fixture.pins()
    pins["interpreter"]["archive_sha256"] = sha
    (fixture.repo / "scripts/windows_installer/pins.json").write_text(json.dumps(pins),
                                                                       encoding="utf-8")
    fixture.commit()
    for relative in ("src/nornyx_forge/__init__.py", "src/nornyx_forge/windows_payload.py"):
        assert (fixture.repo / relative).is_file()
    manifest = synthetic_payload.make(tmp_path / "synthetic", embed_zip=archive, label="t",
                                      version="0.0.1", long_path=True, repo_root=fixture.repo)
    from nornyx_forge.windows_payload import verify  # noqa: PLC0415
    verify(tmp_path / "synthetic", expected_payload_sha256=manifest["payload_sha256"])
    listed = {entry[0] for entry in manifest["files"]}
    assert set(installer.REQUIRED_ENTRIES) <= listed and synthetic_payload.LONG_PATH in listed
    assert manifest["source_commit"] == fixture.git("rev-parse", "HEAD").strip()


# ---------------------------------------------------------------------------
# The driver's pure parts, and its coverage of the exit codes
# ---------------------------------------------------------------------------

ICACLS = """C:\\Users\\forgeci\\AppData\\Local\\Programs\\Nornyx Forge NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)
                                                           BUILTIN\\Administrators:(I)(OI)(CI)(F)
                                                           RUNNER\\forgeci:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
"""


def test_the_acl_of_a_folder_the_installer_added_nothing_to_is_accepted():
    path = "C:\\Users\\forgeci\\AppData\\Local\\Programs\\Nornyx Forge"
    aces = driver.parse_icacls(ICACLS, path)
    assert aces == [("NT AUTHORITY\\SYSTEM", "(I)(OI)(CI)(F)"),
                    ("BUILTIN\\Administrators", "(I)(OI)(CI)(F)"),
                    ("RUNNER\\forgeci", "(I)(OI)(CI)(F)")]
    assert driver.acl_problems(aces, computer="RUNNER", user="forgeci") == []


@pytest.mark.parametrize("extra, expect", [
    ("BUILTIN\\Users:(I)(OI)(CI)(RX)", "BUILTIN\\Users"),
    ("Everyone:(OI)(CI)(F)", "Everyone"),
])
def test_a_principal_the_installer_would_have_granted_is_named(extra: str, expect: str):
    path = "C:\\x\\Nornyx Forge"
    aces = driver.parse_icacls(ICACLS.replace("C:\\Users\\forgeci\\AppData\\Local\\Programs\\"
                                              "Nornyx Forge", path) + "    " + extra + "\n", path)
    problems = driver.acl_problems(aces, computer="RUNNER", user="forgeci")
    assert any(expect in problem for problem in problems), problems
    assert driver.acl_problems([], computer="RUNNER", user="forgeci")


# What the CI run measured (windows-latest, a freshly created standard user): the
# folder the installer made, the file extracted into it and the root all showed
# SYSTEM, Administrators and the user with full control, (OI)(CI) on folders, and
# NO (I) mark. The first check read "no (I)" as "the installer added an ACE".
EXPLICIT_FOLDER = [("NT AUTHORITY\\SYSTEM", "(OI)(CI)(F)"), ("BUILTIN\\Administrators", "(OI)(CI)(F)"),
                   ("RUNNER\\forgeci", "(OI)(CI)(F)")]
INHERITED_FOLDER = [(who, "(I)" + flags) for who, flags in EXPLICIT_FOLDER]


def test_explicit_and_inherited_marks_on_the_same_access_are_one_access():
    """The invariant is the access an ACL grants, compared with a control made
    the plain way in the same parent: a control that shows the same explicit
    shape cannot make the installer's object differ from it."""
    assert driver.acl_problems(EXPLICIT_FOLDER, computer="RUNNER", user="forgeci") == []
    assert driver.acl_signature(EXPLICIT_FOLDER) == driver.acl_signature(INHERITED_FOLDER)
    assert driver.acl_differences(EXPLICIT_FOLDER, INHERITED_FOLDER) == []
    assert driver.acl_differences(EXPLICIT_FOLDER, EXPLICIT_FOLDER) == []


@pytest.mark.parametrize("planted, expect", [
    (EXPLICIT_FOLDER + [("BUILTIN\\Users", "(OI)(CI)(R)")], "only on the installer's object: "
                                                              "builtin\\users"),
    ([(who, "(OI)(CI)(M)" if who.endswith("forgeci") else flags)
      for who, flags in EXPLICIT_FOLDER], "only on the installer's object: runner\\forgeci"),
    (EXPLICIT_FOLDER[:2], "only on the control: runner\\forgeci"),
    ([(who, flags.replace("(OI)(CI)", "")) for who, flags in EXPLICIT_FOLDER],
     "only on the installer's object"),
], ids=["extra-principal", "other-rights", "missing-principal", "other-inheritance-flags"])
def test_a_planted_difference_from_the_control_is_found(planted, expect):
    differences = driver.acl_differences(planted, INHERITED_FOLDER)
    assert any(expect in found for found in differences), differences


def test_the_driver_proves_its_acl_check_can_fail_on_the_hosts_own_icacls():
    source = (ROOT / "scripts/windows_installer/standard_user_checks.py").read_text(encoding="utf-8")
    body = source[source.index("def planted_acl_problems"):source.index("def refused")]
    assert '"/grant", "BUILTIN\\\\Users:(OI)(CI)(R)"' in body
    assert "acl_differences(made, control)" in body and "acl_problems(made" in body
    assert "planted = planted_acl_problems(" in source and "expect(bool(planted)" in source
    check = source[source.index("def acl_check"):source.index("def planted_acl_problems")]
    assert "shutil.copyfile(path, control)" in check and "control.mkdir()" in check, (
        "a plain copy and a plain mkdir are the controls")
    assert "parent_raw" in check and "plain_raw" in check, "the raw ACLs are printed for diagnosis"
    assert "made, made_raw = aces_of(path)" in check and "plain, plain_raw = aces_of(control)" in check, (
        "the object is read from the object and the control from the control")


def test_the_watched_listings_name_what_an_install_may_add_and_refuse_the_rest():
    before = {folder: set() for folder in driver.WATCHED}
    after = {folder: set(names) for folder, names in driver.WATCHED.items()}
    assert driver.listing_problems(before, after) == []
    after["AppData/Local"] = {"Programs", "Microsoft", "Temp", "Packages"}
    after[""] = {"NTUSER.DAT{x}.TM.blf"}
    assert driver.listing_problems(before, after) == []
    stray = {folder: set(names) for folder, names in after.items()}
    stray["AppData/Local/Programs"].add("Other")
    assert any("gained ['Other']" in problem for problem in driver.listing_problems(before, stray))
    state = {folder: set(names) for folder, names in after.items()}
    state[""].add(".nornyx")
    problems = driver.listing_problems(before, state)
    assert any("gained ['.nornyx']" in p for p in problems)
    assert any("state-class" in p for p in problems)
    lost = {folder: set(names) for folder, names in after.items()}
    lost["AppData/Roaming"] = set()
    before2 = {folder: set(names) for folder, names in before.items()}
    before2["AppData/Roaming"] = {"Microsoft"}
    assert any("lost" in p for p in driver.listing_problems(before2, lost))


def test_the_tree_state_sees_a_changed_byte_a_new_file_and_a_touched_time(tmp_path: Path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a").write_bytes(b"1")
    base = driver.tree_state(tmp_path)
    (tmp_path / "d" / "a").write_bytes(b"2")
    assert driver.tree_state(tmp_path) != base
    (tmp_path / "d" / "a").write_bytes(b"1")
    os.utime(tmp_path / "d" / "a", ns=(1, 1))
    assert driver.tree_state(tmp_path) != base
    (tmp_path / "d" / "b").write_bytes(b"")
    assert len(driver.tree_state(tmp_path)) == 3, "the folder, and two files"


def test_an_empty_folder_that_appears_changes_the_tree_state(tmp_path: Path):
    """An empty `.partial` folder used to pass "nothing changes"."""
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "a").write_bytes(b"1")
    base = driver.tree_state(tmp_path)
    (tmp_path / "d" / "empty.partial").mkdir()
    assert driver.tree_state(tmp_path) != base
    assert "d/empty.partial/" in driver.tree_state(tmp_path)


@pytest.mark.parametrize("got, log, problem", [
    (0, "refused (14): x", "exit code 0, not 14"),
    (13, "refused (14): x", "exit code 13, not 14"),
    (14, "", "no 'refused (14):' line"),
    (14, "refused (13): x", "no 'refused (14):' line"),
    (14, "installed 1.2.3", "no 'refused (14):' line"),
])
def test_a_refusal_needs_both_the_exit_code_and_the_installers_own_line(got, log, problem):
    """An exit code alone is not a refusal: any program can exit 14, and a
    program that never ran the script leaves no line."""
    assert any(problem in found for found in driver.refusal_problems(got, log, 14))
    assert driver.refusal_problems(14, "refused (14): the folder is not Forge's", 14) == []


def test_a_registry_census_that_read_nothing_is_not_trusted():
    assert driver.registry_problems({"HKCU Environment": {"TEMP": "x"}, "HKLM PATH": "C:\\"}) == []
    assert driver.registry_problems({"HKCU Environment": {}, "HKLM PATH": "C:\\"})
    assert driver.registry_problems({"HKCU Environment": None, "HKLM PATH": "C:\\"})
    assert driver.registry_problems({"HKCU Environment": {"TEMP": "x"}, "HKLM PATH": None})


def test_the_registry_places_are_read_as_what_they_hold():
    """A `Run` entry is a VALUE; reading the key as subkeys saw none."""
    kinds = driver.REGISTRY_WATCH
    run = r"Software\Microsoft\Windows\CurrentVersion\Run"
    assert kinds[run] == "values" and kinds[run + "Once"] == "values"
    assert kinds["Environment"] == "values"
    assert kinds[r"Software\Microsoft\Windows\CurrentVersion\Uninstall"] == "subkeys"
    assert kinds[r"Software\Microsoft\Windows\CurrentVersion\App Paths"] == "subkeys"


def test_only_the_unreadable_token_is_left_unprovoked():
    assert set(driver.UNEXERCISED) == {"EXIT_ELEVATION_UNKNOWN"}


def test_the_driver_judges_the_acl_of_what_the_installer_made_not_of_what_it_made_itself():
    source = (ROOT / "scripts/windows_installer/standard_user_checks.py").read_text(encoding="utf-8")
    body = source[source.index("def check_install"):source.index("def launch_checks")]
    assert "judged = [folder, folder / \"forge-payload.json\"] + ([root] if root_created else [])" in body
    assert "acl_check(path" in body
    assert "root.mkdir()" not in body, "the driver's own folder is not the thing under test"


def test_the_path_without_git_or_python_keeps_everything_else(tmp_path: Path):
    git, py, other = tmp_path / "git", tmp_path / "py", tmp_path / "other"
    for folder, name in ((git, "git.exe"), (py, "python.exe"), (other, "tool.exe")):
        folder.mkdir()
        (folder / name).write_bytes(b"")
    joined = os.pathsep.join(map(str, (git, py, other, tmp_path / "missing")))
    assert driver.path_without(("git.exe", "python.exe"), joined) == os.pathsep.join(
        map(str, (other, tmp_path / "missing")))
    assert driver.path_without((), joined) == joined


def test_the_driver_asserts_every_exit_code_but_the_ones_it_declares_it_cannot_provoke():
    table = contract.exit_codes(_nsi())
    source = (ROOT / "scripts/windows_installer/standard_user_checks.py").read_text(encoding="utf-8")
    referenced = set(re.findall(r'codes\["(EXIT_[A-Z_]+)"\]', source))
    unexercised = set(driver.UNEXERCISED)
    assert unexercised <= set(table), "a declared exemption for a code the script does not define"
    assert all(len(reason) > 30 for reason in driver.UNEXERCISED.values())
    assert referenced == set(table) - unexercised, (
        f"unasserted {set(table) - unexercised - referenced}; phantom {referenced - set(table)}")


def test_the_driver_reads_the_receipt_and_the_shortcut_from_the_contract_not_from_literals():
    source = (ROOT / "scripts/windows_installer/standard_user_checks.py").read_text(encoding="utf-8")
    for needed in ("contract.check_receipt(", "contract.shortcut_expectation(",
                   "contract.version_directory(", "contract.RECEIPT_NAME", "contract.SHORTCUT_NAME"):
        assert needed in source, needed
    assert "install-receipt.json" not in source and "Nornyx Forge.lnk" not in source


def test_the_driver_does_not_import_windows_modules_at_load():
    """It imports and its pure parts run on any host; the Windows calls are
    reached only by `main`."""
    source = (ROOT / "scripts/windows_installer/standard_user_checks.py").read_text(encoding="utf-8")
    top = source.split("def expect", 1)[0]
    assert "import winreg" not in top and "ctypes.windll" not in top


# ---------------------------------------------------------------------------
# The jobs, read as structure
# ---------------------------------------------------------------------------

def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


@pytest.mark.parametrize("name", ["windows-installer", "windows-install"])
def test_the_installer_jobs_can_fail_and_nothing_in_them_is_optional(name: str):
    """A neutered job would still contain every command, so what is pinned is
    structure: no `continue-on-error` and no `if` on the job or a step, none of
    the escape spellings below in any step, every action pinned by commit, a
    time limit, and checkouts without credentials. It refuses those enumerated
    forms; it does not refuse every way a step could swallow a failure."""
    job = _jobs()[name]
    assert job.get("timeout-minutes")
    for holder in [job, *job["steps"]]:
        for key in ("continue-on-error", "if"):
            assert key not in holder, f"{key} on {holder.get('name', 'the job')}"
    for step in job["steps"]:
        script = str(step.get("run", ""))
        for escape in ("|| true", "|| :", "set +e", "|| exit 0", "; true", "2>/dev/null"):
            assert escape not in script, f"{escape!r} in {step.get('name')}"
    assert all(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", step["uses"])
               for step in job["steps"] if "uses" in step), "actions pinned by commit"
    for step in job["steps"]:
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


def test_the_build_job_builds_twice_compares_and_uploads_what_the_windows_job_downloads():
    jobs = _jobs()
    build, run = jobs["windows-installer"], jobs["windows-install"]
    assert build["runs-on"] == "ubuntu-24.04" and run["runs-on"] == "windows-latest"
    assert run["needs"] == "windows-installer"
    checkouts = [s for s in build["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert [s["with"]["path"] for s in checkouts] == ["first", "second"]
    names = [step.get("name") for step in build["steps"]]
    order = ["Refuse a compiler tree that contradicts the pins",
             "Make the checked compiler executable", "Pull the pinned image",
             "Install the pinned installer", "Fetch the pinned interpreter archive",
             "Build the payload from the first checkout",
             "Build the payload again from the second checkout",
             "Build ForgeSetup.exe from the first payload",
             "Build ForgeSetup.exe again from the second checkout and payload",
             "Compare the two installers byte for byte",
             "Build the small installers that exercise the refusals"]
    assert [n for n in names if n in order] == order
    steps = {step.get("name"): str(step.get("run", "")) for step in build["steps"]}
    assert build["needs"] == "nsis-toolchain-verify", (
        "the compiler is used only after its two builds were compared with the pins")
    compare = steps["Compare the two installers byte for byte"]
    for artifact in ("ForgeSetup.exe", "ForgeSetup.exe.sha256", "ForgeSetup.build.json"):
        assert f"cmp setup-first/{artifact} setup-second/{artifact}" in compare
    second = steps["Build ForgeSetup.exe again from the second checkout and payload"]
    assert "second-python/bin/python" in second and "second/scripts/build_windows_installer.py" in second
    assert '--payload "$RUNNER_TEMP/payload-second"' in second, "the second payload, not the first"
    assert '--out "$RUNNER_TEMP/setup-second"' in second
    assert '--dist "$RUNNER_TEMP/payload-second"' in steps[
        "Build the payload again from the second checkout"]
    assert 'second/scripts/build_windows_bundle.py' in steps[
        "Build the payload again from the second checkout"]
    first = steps["Build ForgeSetup.exe from the first payload"]
    assert '--payload "$RUNNER_TEMP/payload-first"' in first and "first/scripts/" in first
    uploads = [s for s in build["steps"] if str(s.get("uses", "")).startswith(
        "actions/upload-artifact@")]
    downloads = [s for s in run["steps"] if str(s.get("uses", "")).startswith(
        "actions/download-artifact@")]
    assert len(uploads) == len(downloads) == 1
    assert uploads[0]["with"]["name"] == downloads[0]["with"]["name"] == "forge-setup"
    assert build["permissions"] == run["permissions"] == {"contents": "read"}
    assert uploads[0]["with"]["if-no-files-found"] == "error"
    assert uploads[0]["with"]["retention-days"] <= 7
    variants = steps["Build the small installers that exercise the refusals"]
    for variant in ("small", "other --version 0.0.2", "same-version --same-version-as",
                    "long --long-version --long-path"):
        assert f"build_variant {variant}" in variants, variant
    assert '--out "$variants/$name" --test-only-synthetic' in variants, (
        "the small installers are labelled synthetic in their records")
    real = steps["Build ForgeSetup.exe from the first payload"]
    assert "--test-only-synthetic" not in real and "--test-only-synthetic" not in compare


def _artifact_check_script() -> str:
    step = next(step for step in _jobs()["windows-install"]["steps"]
                if step.get("name") == "The artifact is the one its build record names")
    text = step["run"]
    return text[text.index("<<'PY'\n") + len("<<'PY'\n"):text.rindex("\nPY")]


def _artifact(root: Path, count: int = 5) -> Path:
    names = ["forge-setup"] + [f"variants/v{index}" for index in range(count - 1)]
    for name in names:
        folder = root / "forge-setup-artifact" / name
        folder.mkdir(parents=True)
        data = name.encode()
        digest = hashlib.sha256(data).hexdigest()
        (folder / "ForgeSetup.exe").write_bytes(data)
        (folder / "ForgeSetup.exe.sha256").write_text(f"{digest}  ForgeSetup.exe\n", encoding="utf-8")
        (folder / "ForgeSetup.build.json").write_text(
            json.dumps({"installer": {"sha256": digest}}), encoding="utf-8")
    return root / "forge-setup-artifact"


@pytest.mark.parametrize("breakage", [None, "exe", "record", "listed", "missing-variant"])
def test_the_artifact_check_fails_on_any_digest_that_disagrees(tmp_path: Path, breakage):
    """The workflow's own check, run: an artifact whose executable, record or
    `.sha256` disagrees, or that lacks an installer, fails the step."""
    artifact = _artifact(tmp_path, 4 if breakage == "missing-variant" else 5)
    folder = artifact / "variants" / "v1"
    if breakage == "exe":
        (folder / "ForgeSetup.exe").write_bytes(b"other")
    elif breakage == "record":
        (folder / "ForgeSetup.build.json").write_text(
            json.dumps({"installer": {"sha256": "0" * 64}}), encoding="utf-8")
    elif breakage == "listed":
        (folder / "ForgeSetup.exe.sha256").write_text("0" * 64 + "  ForgeSetup.exe\n",
                                                      encoding="utf-8")
    completed = subprocess.run([sys.executable, "-"], input=_artifact_check_script(), text=True,
                               capture_output=True, timeout=60,
                               env={**os.environ, "RUNNER_TEMP": str(tmp_path)})
    assert (completed.returncode == 0) == (breakage is None), completed.stderr[-500:]


def test_the_windows_job_checks_the_artifact_then_refuses_elevated_then_runs_as_a_standard_user():
    run = _jobs()["windows-install"]
    steps = {step.get("name"): str(step.get("run", "")) for step in run["steps"]}
    names = [step.get("name") for step in run["steps"] if step.get("name")]
    assert names == ["The artifact is the one its build record names",
                     "An elevated run is refused",
                     "Install, launch, stop and reopen as a standard user"]
    assert "recorded[\"installer\"][\"sha256\"] == listed" in steps[names[0]]
    assert "assert len(folders) == 5" in steps[names[0]]
    assert "standard_user_checks.py elevated" in steps[names[1]]
    last = steps[names[2]]
    assert "run_as_standard_user.ps1" in last and "-Checkout \"$GITHUB_WORKSPACE\"" in last
    script = (ROOT / "scripts/windows_installer/run_as_standard_user.ps1").read_text(
        encoding="utf-8")
    assert "standard_user_checks.py" in script and "standard-user" in script
    assert 'Add-LocalGroupMember -Group "Users"' in script
    assert "is an administrator; the account must be a standard user" in script
    assert "exit $process.ExitCode" in script
    assert "SilentlyContinue" not in script and "-ErrorAction" not in script
    assert "-Wait" not in script, "Start-Process -Wait waits on the whole process tree"
    assert "WaitForExit($limitMilliseconds)" in script and "taskkill /T /F /PID" in script
    assert "exit 124" in script and "40 * 60 * 1000" in script


def test_the_standard_user_script_names_every_path_the_driver_reads():
    script = (ROOT / "scripts/windows_installer/run_as_standard_user.ps1").read_text(
        encoding="utf-8")
    import ast  # noqa: PLC0415

    def imports(path: Path) -> set[str]:
        found: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                found |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                found.add(node.module or "")
        return found

    driver_imports = imports(ROOT / "scripts/windows_installer/standard_user_checks.py")
    local = {name for name in driver_imports
             if name.split(".")[0] not in sys.stdlib_module_names}
    assert local == {"installer_contract", "build_windows_bundle"}, local
    bundle_local = {name for name in imports(ROOT / "scripts/build_windows_bundle.py")
                    if name.split(".")[0] not in sys.stdlib_module_names
                    and name.split(".")[0] not in {"tomli"}}
    assert {name for name in bundle_local if name.startswith("nornyx_forge")} == {
        "nornyx_forge.windows_payload"}, bundle_local
    # What the standard user can import: scripts\ and the two source files
    # (the package's __init__ and the verifier) the bundle builder imports.
    for copied in ('"$Checkout\\scripts"', "src\\nornyx_forge\\__init__.py",
                   "src\\nornyx_forge\\windows_payload.py"):
        assert copied in script, f"the standard user cannot import {copied}"


# ---------------------------------------------------------------------------
# The text about it
# ---------------------------------------------------------------------------

def _assumption(number: str) -> str:
    text = ASSUMPTIONS.read_text(encoding="utf-8")
    start = text.index(f"\n## {number} ") + 1
    end = text.find("\n## A-", start + 1)
    return text[start:end if end != -1 else len(text)]


def test_the_assumption_states_what_is_not_established_and_claims_none_of_what_it_denies():
    section = _assumption("A-043")
    lowered = " ".join(section.split()).casefold()
    for stated in ("unsigned", "not an msi", "per-user", "tamper-evident", "not established",
                   "smartscreen", "smart app control", "requireadministrator",
                   "test evidence only", "not a distributable and not a release candidate",
                   "3.11 and 3.12", "mitigation", "does not eliminate", "$pluginsdir",
                   "(typically downloads)", "dll", "$smprograms", "not a release channel",
                   "fork", "user shell folders", "token's profile path", "`..` spelling",
                   "pylib/", "--test-only-synthetic", "297",
                   "target x86-unicode", "v3.13", "nsis-toolchain-verify", "no network",
                   "check_tree", "compiler_argv", "trust-on-first-use", "blocking unknown",
                   "withheld until the `windows-installer` and `windows-install` jobs pass",
                   "not among the branch's required status checks", "--pull never",
                   "shares the runner's kernel", "generated_files", "uncompared_roots"):
        assert stated in lowered, stated
    # The compile with this compiler is unobserved, and that is not a footnote.
    assert "non-blocking" not in lowered and "never on the build machine" not in lowered
    for claim in (r"\bis signed\b", r"\bsigned installer\b(?<!unsigned installer)",
                  r"auto-?update(?!s? (?:is|are) not)", r"\bruns as a service\b",
                  r"tamper-proof(?!ing)"):
        for match in re.finditer(claim, lowered):
            window = lowered[max(0, match.start() - 40):match.start()]
            assert re.search(r"\b(no|not|nor|never|without|un)\b", window), (
                f"{match.group(0)!r} claimed in A-043: {lowered[match.start()-60:match.end()+40]!r}")
    for code in contract.exit_codes(_nsi()):
        assert code not in section, "the exit-code table lives in the script, once"


#: Sentences that were claims the code did not keep. Each is checked against
#: every text that speaks of the installer.
RETIRED_CLAIMS = ("overwrites nothing", "overwrites and deletes nothing",
                  "nothing is ever overwritten", "never overwrites", "never overwritten",
                  "its last step", "the build reads the exit", "paths of 260 characters",
                  "the driver cannot provoke them", "size and time are not measured",
                  "installed size and install time",
                  # The compiler the installer was first built with, and its pins.
                  "nsis 3.09", "3.09-4ubuntu1", "installer-tools.json", "dpkg -i")


def test_no_text_makes_a_claim_the_installer_does_not_keep():
    """The installer replaces nothing it has not checked for, deletes nothing, and
    appends to one named log; it does not claim more. These phrases were
    claims that the code or the measurements contradicted."""
    texts = {
        "README": (ROOT / "README.md").read_text(encoding="utf-8"),
        "CHANGELOG": (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").split("\n## 0.3.0")[0],
        "VALIDATION": (ROOT / "docs/VALIDATION.md").read_text(encoding="utf-8"),
        "A-043": _assumption("A-043"), "script": _nsi(),
        "builder": (ROOT / "scripts/build_windows_installer.py").read_text(encoding="utf-8"),
        "driver": (ROOT / "scripts/windows_installer/standard_user_checks.py").read_text(
            encoding="utf-8"),
        "workflow": WORKFLOW.read_text(encoding="utf-8"),
    }
    for name, text in texts.items():
        flat = " ".join(text.split()).casefold()
        for claim in RETIRED_CLAIMS:
            assert claim not in flat, f"{name} says {claim!r}"
    script = " ".join(_nsi().split())
    assert "the build, the tests and the CI driver read it" not in script


def test_the_readme_and_validation_no_longer_say_the_installer_does_not_exist():
    for path in (ROOT / "README.md", ROOT / "docs" / "VALIDATION.md"):
        text = path.read_text(encoding="utf-8")
        assert "does not exist yet" not in text.replace("\n", " "), path.name
        assert "A-043" in text, path.name
