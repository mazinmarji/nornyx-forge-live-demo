"""ForgeSetup.exe: its script, its contract, its builder and the jobs that run it.

Six groups.

The SCRIPT (`forge-setup.nsi`) read as source. Nothing here compiles or runs
NSIS: the pinned `makensis` is installed by CI, and a Windows installer runs
only on Windows. These tests therefore hold what can be held from the text, and
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

The BUILDER over a synthetic repository, a sealed payload and a stand-in
`makensis`: what it refuses before and after compiling, what the compiler is
given, and that the same inputs give the same bytes.

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
TOOLS = ROOT / "scripts" / "windows_installer" / "installer-tools.json"
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
                      contract.files_nsh([["a/b.py", 1, "d" * 64]], Path("/tmp/payload"),
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
                     "SetShellVarContext current"):
        assert required in code, f"the script lacks {required}"


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


def test_the_installer_files_are_lf_utf8_with_a_final_newline():
    for path in (NSI, TOOLS, ROOT / "scripts" / "windows_installer" / "installer_contract.py",
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
    text = contract.files_nsh(manifest["files"], Path("/tmp/payload"),
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
    text = contract.files_nsh(manifest["files"], Path("/tmp/payload"),
                              manifest_name=PAYLOAD_MANIFEST)
    outs = re.findall(r'SetOutPath "([^"]+)"', text)
    assert all(a != b for a, b in zip(outs, outs[1:])), "a repeated SetOutPath"
    assert outs[0] == "$Partial" or outs[0].startswith("$Partial\\")


@pytest.mark.parametrize("name", ['pylib/a"b.py', "pylib/a\nb.py", "pylib/a\x7fb.py"])
def test_a_name_an_nsis_string_cannot_carry_is_refused(name: str):
    with pytest.raises(contract.ContractError):
        contract.files_nsh([[name, 1, "d" * 64]], Path("/tmp/payload"),
                           manifest_name=PAYLOAD_MANIFEST)


@pytest.mark.parametrize("base", ["/tmp/a payload", "/tmp/a$b", "/tmp/a\"b", "/tmp/ünï"])
def test_a_payload_path_the_script_cannot_name_plainly_is_refused(base: str):
    with pytest.raises(contract.ContractError):
        contract.files_nsh([["a.py", 1, "d" * 64]], Path(base), manifest_name=PAYLOAD_MANIFEST)


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
# The builder, over a synthetic repository, a sealed payload and a stand-in makensis
# ---------------------------------------------------------------------------

FAKE_MAKENSIS = '''#!{python}
import hashlib, json, os, shutil, sys
args = sys.argv[1:]
if args == ["-VERSION"]:
    print(CONFIG_VERSION)
    raise SystemExit(0)
config = json.load(open({config!r}))
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
elif config["mode"] == "no-version":
    body = body.replace(("payload sha256 " + defines["PAYLOAD_SHA256"]).encode("utf-16-le"), b"")
elif config["mode"] == "not-pe":
    body = b"XX" + body[2:]
elif config["mode"] == "no-header":
    body = body.replace(b"PE\\0\\0", b"XX\\0\\0")
open(defines["OUT_FILE"], "wb").write(body)
'''


class _Fixture:
    """A repository, a sealed payload, a stand-in makensis (pinned by hash)
    and its data directory: everything one `installer.build` needs."""

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
        self.nsis_dir = tmp_path / "nsis"
        (self.nsis_dir / "Stubs").mkdir(parents=True)
        (self.nsis_dir / "Stubs" / "lzma").write_bytes(b"stub\n")
        self.makensis = tmp_path / "fake-bin" / "makensis"
        self.makensis.parent.mkdir()
        self.makensis.write_text(FAKE_MAKENSIS.format(
            python=sys.executable, config=str(self.config)).replace(
            "CONFIG_VERSION", repr("v3.09")), encoding="utf-8")
        self.makensis.chmod(self.makensis.stat().st_mode | stat.S_IXUSR)
        self.set_mode("ok")
        self.write_tools()
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

    def tools(self, **override) -> dict:
        tools = json.loads(TOOLS.read_text(encoding="utf-8"))
        tools["makensis"]["binary_sha256"] = installer._sha256(self.makensis)
        tools["makensis"]["data_tree_sha256"] = installer.tree_digest(self.nsis_dir)
        tools["makensis"].update(override)
        return tools

    def write_tools(self, **override) -> None:
        (self.repo / "scripts/windows_installer/installer-tools.json").write_text(
            json.dumps(self.tools(**override), indent=2), encoding="utf-8")

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
        files = {"python/python.exe": b"MZ", "python/pythonw.exe": b"MZ",
                 "forge-bundle.json": b"{}\n", "Forge.cmd": b"@echo off\n", **(extra or {})}
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
        return installer.build(self.repo, payload, self.tmp / out, makensis=str(self.makensis),
                               nsis_dir=self.nsis_dir, **kwargs)

    def capture(self) -> dict:
        return json.loads((self.captured / "call.json").read_text(encoding="utf-8"))


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
    assert record["tool"]["version_output"] == "v3.09" and record["makensis_warnings"] == 1
    assert set(record["inputs"]) == set(installer.INSTALLER_FILES)
    assert "built_at" not in json.dumps(record) and str(tmp_path) not in json.dumps(record)


def test_the_compiler_is_given_a_fixed_command_and_a_fixed_environment(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FORGE_TEST_LEAK", "leaked")
    monkeypatch.setenv("UV_ANYTHING", "1")
    fixture = _Fixture(tmp_path)
    fixture.build()
    call = fixture.capture()
    arguments = call["args"]
    assert arguments[:5] == ["-NOCONFIG", "-NOCD", "-INPUTCHARSET", "UTF8", "-V2"]
    assert arguments[-1].endswith("/stage/" + contract.NSI_NAME)
    assert set(call["environ"]) == {"PATH", "LC_ALL", "TZ", "HOME", "SOURCE_DATE_EPOCH"}
    assert call["environ"]["SOURCE_DATE_EPOCH"] == str(COMMITTED)
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
        sealed["files"], tmp_path / "payload", manifest_name=PAYLOAD_MANIFEST)
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
    assert payload["not_compared_with_the_commit"] == ["pylib", "python"]


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
    assert "the copy set" in record["payload"]["not_compared_with_the_commit"]
    assert "every copy-set file's bytes" not in record["payload"]["compared_with_the_commit"]


def test_the_command_line_has_the_test_only_flag_and_it_reaches_the_build(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fixture = _Fixture(tmp_path)
    monkeypatch.setattr(installer, "ROOT", fixture.repo)
    tiny = fixture.payload("tiny", extra={"README.md": b"not the commit's readme\n"})
    common = ["--payload", str(tiny), "--makensis", str(fixture.makensis),
              "--nsis-dir", str(fixture.nsis_dir)]
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


def test_a_payload_folder_the_script_cannot_name_plainly_is_refused(tmp_path: Path):
    fixture = _Fixture(tmp_path)
    payload = fixture.payload("a payload")
    with pytest.raises(installer.InstallerError, match="character outside"):
        fixture.build(payload)


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
    tools = fixture.repo / "scripts/windows_installer/installer-tools.json"
    nsi.write_bytes(NSI.read_bytes())
    fixture.git("update-index", "--no-assume-unchanged", "scripts/windows_installer/forge-setup.nsi")
    fixture.git("update-index", "--skip-worktree", "scripts/windows_installer/installer-tools.json")
    tools.write_text(json.dumps(fixture.tools(binary_sha256="0" * 64)), encoding="utf-8")
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
    ("binary", "has SHA-256"), ("tree", "tree digest"), ("version", "makensis reports"),
], ids=["binary", "data-directory", "reported-version"])
def test_a_makensis_that_is_not_the_pinned_one_is_refused(tmp_path: Path, breakage, message):
    fixture = _Fixture(tmp_path)
    if breakage == "binary":
        fixture.makensis.write_text(fixture.makensis.read_text() + "\n# changed\n")
    elif breakage == "tree":
        (fixture.nsis_dir / "Stubs" / "lzma").write_bytes(b"another stub\n")
    else:
        fixture.write_tools(version_output="v9.99")
        fixture.commit()
    with pytest.raises(installer.InstallerError, match=message):
        fixture.build()
    assert not fixture.captured.exists(), "the compiler ran although its pin failed"


def test_the_build_refuses_loose_tool_pins_before_it_compiles(tmp_path: Path):
    fixture = _Fixture(tmp_path)
    fixture.write_tools(packages=[])
    fixture.commit()
    with pytest.raises(installer.InstallerError, match="does not pin its packages"):
        fixture.build()
    assert not fixture.captured.exists()


def test_a_link_in_the_tools_data_directory_is_refused(tmp_path: Path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "real").write_bytes(b"x")
    (tmp_path / "data" / "link").symlink_to(tmp_path / "data" / "real")
    with pytest.raises(installer.InstallerError, match="not a regular file"):
        installer.tree_digest(tmp_path / "data")


def test_the_tree_digest_moves_with_a_name_a_byte_and_a_new_file(tmp_path: Path):
    root = tmp_path / "t"
    (root / "d").mkdir(parents=True)
    (root / "d" / "a").write_bytes(b"1")
    base = installer.tree_digest(root)
    (root / "d" / "a").write_bytes(b"2")
    assert installer.tree_digest(root) != base
    (root / "d" / "a").write_bytes(b"1")
    assert installer.tree_digest(root) == base
    (root / "d" / "a").rename(root / "d" / "b")
    assert installer.tree_digest(root) != base
    (root / "d" / "b").rename(root / "d" / "a")
    (root / "d" / "c").write_bytes(b"")
    assert installer.tree_digest(root) != base


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
    ("bad-manifest", "asInvoker|requireAdministrator"), ("no-manifest", "asInvoker manifest"),
    ("no-version", "payload identity"),
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


@pytest.mark.parametrize("change", [
    lambda t: t.pop("builder_image"),
    lambda t: t["makensis"].update(binary_sha256="zz"),
    lambda t: t["makensis"].update(data_tree_sha256="a" * 63),
    lambda t: t["makensis"]["packages"][0].update(sha256="x"),
    lambda t: t["makensis"]["packages"][0].update(size=0),
    lambda t: t["makensis"]["packages"][0].update(url="http://archive.ubuntu.com/x.deb"),
    lambda t: t["makensis"]["packages"][0].update(url="https://example.com/ubuntu/pool/x.deb"),
    lambda t: t["makensis"]["packages"][0].update(
        url="https://example.com/ubuntu/pool/universe/n/nsis/nsis_3.09-4ubuntu1_amd64.deb"),
    lambda t: t["makensis"]["packages"][0].update(
        url="https://archive.ubuntu.com/ubuntu/pool/universe/n/nsis/nsis_3.09-4ubuntu1_amd64.tar"),
    lambda t: t["makensis"]["packages"][0].update(name="other"),
    lambda t: t["makensis"]["packages"][0].pop("size"),
    lambda t: t["makensis"].update(packages=[]),
    lambda t: t.update(schema="x"),
])
def test_incomplete_or_loose_tool_pins_are_refused(change):
    tools = json.loads(TOOLS.read_text(encoding="utf-8"))
    change(tools)
    with pytest.raises(installer.InstallerError):
        installer.check_tools(tools)


def test_the_committed_tool_pins_are_complete_and_agree_with_the_workflow():
    tools = installer.check_tools(json.loads(TOOLS.read_text(encoding="utf-8")))
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert workflow["jobs"]["windows-installer"]["runs-on"] == tools["builder_image"]
    names = {package["name"] for package in tools["makensis"]["packages"]}
    assert names == {"nsis", "nsis-common"}
    assert {package["version"] for package in tools["makensis"]["packages"]} == {"3.09-4ubuntu1"}
    assert tools["makensis"]["version_output"] == "v3.09"


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
    ("RUNNER\\forgeci:(OI)(CI)(F)", "explicit"),
])
def test_an_ace_the_installer_would_have_added_is_named(extra: str, expect: str):
    path = "C:\\x\\Nornyx Forge"
    aces = driver.parse_icacls(ICACLS.replace("C:\\Users\\forgeci\\AppData\\Local\\Programs\\"
                                              "Nornyx Forge", path) + "    " + extra + "\n", path)
    problems = driver.acl_problems(aces, computer="RUNNER", user="forgeci")
    assert any(expect in problem for problem in problems), problems
    assert driver.acl_problems([], computer="RUNNER", user="forgeci")


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
    assert "icacls_problems(path" in body
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
    order = ["Install the pinned installer", "Fetch the pinned interpreter archive",
             "Fetch and install the pinned makensis packages",
             "Build the payload from the first checkout",
             "Build the payload again from the second checkout",
             "Build ForgeSetup.exe from the first payload",
             "Build ForgeSetup.exe again from the second checkout and payload",
             "Compare the two installers byte for byte",
             "Build the small installers that exercise the refusals"]
    assert [n for n in names if n in order] == order
    steps = {step.get("name"): str(step.get("run", "")) for step in build["steps"]}
    fetch = steps["Fetch and install the pinned makensis packages"]
    assert "not the pinned package" in fetch and "timeout=" in fetch
    assert 'if len(data) != package["size"] or digest != package["sha256"]:' in fetch, (
        "the refusal must be conditional on the size and the SHA-256, not merely present")
    assert 'subprocess.run(["sudo", "dpkg", "-i", *paths], check=True)' in fetch
    assert "installer-tools.json" in fetch
    compare = steps["Compare the two installers byte for byte"]
    for artifact in ("ForgeSetup.exe", "ForgeSetup.exe.sha256", "ForgeSetup.build.json"):
        assert f"cmp setup-first/{artifact} setup-second/{artifact}" in compare
    second = steps["Build ForgeSetup.exe again from the second checkout and payload"]
    assert "second-python/bin/python" in second and "second/scripts/build_windows_installer.py" in second
    uploads = [s for s in build["steps"] if str(s.get("uses", "")).startswith(
        "actions/upload-artifact@")]
    downloads = [s for s in run["steps"] if str(s.get("uses", "")).startswith(
        "actions/download-artifact@")]
    assert len(uploads) == len(downloads) == 1
    assert uploads[0]["with"]["name"] == downloads[0]["with"]["name"] == "forge-setup"
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
    section = _assumption("A-042")
    lowered = " ".join(section.split()).casefold()
    for stated in ("unsigned", "not an msi", "per-user", "tamper-evident", "not established",
                   "smartscreen", "smart app control", "requireadministrator",
                   "test evidence only", "not a distributable and not a release candidate",
                   "3.11 and 3.12", "mitigation", "does not eliminate", "$pluginsdir",
                   "(typically downloads)", "dll", "$smprograms", "not a release channel",
                   "fork", "user shell folders", "token's profile path", "`..` spelling",
                   "pylib/", "--test-only-synthetic", "297"):
        assert stated in lowered, stated
    for claim in (r"\bis signed\b", r"\bsigned installer\b(?<!unsigned installer)",
                  r"auto-?update(?!s? (?:is|are) not)", r"\bruns as a service\b",
                  r"tamper-proof(?!ing)"):
        for match in re.finditer(claim, lowered):
            window = lowered[max(0, match.start() - 40):match.start()]
            assert re.search(r"\b(no|not|nor|never|without|un)\b", window), (
                f"{match.group(0)!r} claimed in A-042: {lowered[match.start()-60:match.end()+40]!r}")
    for code in contract.exit_codes(_nsi()):
        assert code not in section, "the exit-code table lives in the script, once"


#: Sentences that were claims the code did not keep. Each is checked against
#: every text that speaks of the installer.
RETIRED_CLAIMS = ("overwrites nothing", "overwrites and deletes nothing",
                  "nothing is ever overwritten", "never overwrites", "never overwritten",
                  "its last step", "the build reads the exit", "paths of 260 characters",
                  "the driver cannot provoke them", "size and time are not measured",
                  "installed size and install time")


def test_no_text_makes_a_claim_the_installer_does_not_keep():
    """The installer replaces nothing it has not checked for, deletes nothing, and
    appends to one named log; it does not claim more. These phrases were
    claims that the code or the measurements contradicted."""
    texts = {
        "README": (ROOT / "README.md").read_text(encoding="utf-8"),
        "CHANGELOG": (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").split("\n## 0.3.0")[0],
        "VALIDATION": (ROOT / "docs/VALIDATION.md").read_text(encoding="utf-8"),
        "A-042": _assumption("A-042"), "script": _nsi(),
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
        assert "A-042" in text, path.name
