"""No uninstall or repair path silently destroys the person's state (A-044).

THE CLAIM, and what it rests on. The Windows install has no uninstaller and no
repair: `forge-setup.nsi` registers none, refuses another version, verifies the
same payload and leaves it, and says of every refusal that it deletes nothing.
The paths that DO exist are Setup run again, a refusal, and the removal a
refusal's message tells a person to make (the install folder, then Setup
again). The claim is therefore about a bounded set of paths, and it is held here from
four sides:

* the SCRIPT, read as source: a default-deny census (a tripwire over its text,
  not a proof) in which every instruction is of an inert verb or an exact entry
  of a reviewed table, plug-in calls and assignments to a destination variable
  included, so that a deletion, an uninstaller, a registry write or a variable
  pointed at state is a red test whatever its spelling. The
  older deny-list (`test_the_installer_uses_none_of_what_it_must_never_use`)
  refuses names; this census refuses anything it has not been shown, including
  a `System::Call` to `DeleteFileW`, which no name in a deny-list catches;
* the STATE SPECIMEN the Windows driver plants and compares, held two ways round
  against the locations the product itself names, so a location the product
  moves or adds is a red test here and not a silent gap in CI's scenario;
* the DRIVER's pure parts (what counts as a change, and that the scenario
  compares after every path it runs);
* the REFUSALS: every `Refuse` in the script is listed, and the scenario's replay
  of them with the specimen planted is held to exactly the ones listed as
  replayed, the rest saying why they are not;
* the PRODUCT's own reset paths: the capsule restoration rewrites its own seal and
  nothing else beside the capsule, and the operator's ledger reset runs only when
  asked, rewrites only the ledger and its mark, and says so.

WHAT THESE TESTS CANNOT SHOW. That the installer, run on Windows, leaves the
specimen alone is the `windows-install` job's to measure, per commit, on a
hosted image; nothing here runs NSIS or Windows. A line that is absent from the
script is not an effect, and the census says exactly that and no more. Nor do
these tests make the scenario cover every refusal: it replays the ones `REFUSALS`
marks as replayed, and the rest are named, with the reason, in A-044.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "windows_installer"))

import build_windows_bundle as bundle  # noqa: E402
import installer_contract as contract  # noqa: E402
import standard_user_checks as driver  # noqa: E402

from nornyx_forge.windows_payload import PAYLOAD_MANIFEST  # noqa: E402

NSI = ROOT / "scripts" / "windows_installer" / contract.NSI_NAME
DRIVER = ROOT / "scripts" / "windows_installer" / "standard_user_checks.py"
ASSUMPTIONS = ROOT / "docs" / "requirements" / "ASSUMPTIONS.md"
AT = "2026-09-03T09:00:00Z"

MANIFEST = {
    "version": "1.2.3", "source_commit": "0123456789abcdef" * 2 + "01234567",
    "payload_sha256": "c" * 64,
}


# ---------------------------------------------------------------------------
# The script: a default-deny census of what it can change
# ---------------------------------------------------------------------------

#: THE CENSUS IS A DEFAULT-DENY TRIPWIRE over the installer script's instructions,
#: not a proof about the product. An instruction is allowed in exactly one of two
#: ways: its verb is in INERT_VERBS, or its verb AND its arguments are an entry of
#: ALLOWED_INSTRUCTIONS, as many times as listed. There is no third category: no
#: verb is benign whatever its arguments, and a verb in neither place is refused.
#: Order and nesting are not part of it (see A-044 for what it cannot see).
#:
#: INERT_VERBS may appear with any arguments because they do none of: write a
#: variable, name a path or destination that is used at run time, branch, or act
#: on a file, the registry, a process or the machine. They are compile-time
#: metadata and declarations, and one pause. A compile-time conditional is NOT
#: inert, whatever it guards: it decides which instructions are compiled, so
#: `!ifndef`, `!error` and `!endif` are in the table, and `_depth_problems`
#: pins where they may stand.
INERT_VERBS = frozenset({
    "BrandingText", "CRCCheck", "Caption", "Name", "SetCompressor", "SetDatablockOptimize",
    "SetDetailsPrint", "Sleep", "Target", "Unicode", "VIAddVersionKey", "VIProductVersion",
    "Var", "XPStyle",
})
#: A sanity net for the list above, not a second census: verbs that write a
#: variable, name a path, branch, or act on the machine. None may be inert, and
#: neither may a plug-in call.
PATH_ALTERING_VERBS = frozenset({
    "StrCpy", "IntOp", "StrLen", "Push", "Pop", "Exch", "Call", "Goto", "Return", "Abort", "Quit",
    "MessageBox", "ClearErrors", "GetErrorLevel", "SetErrorLevel", "IfErrors", "IfFileExists",
    "StrCmp", "StrCmpS", "IntCmp", "ReadRegStr", "ReadRegDWORD", "ReadEnvStr", "ExpandEnvStrings",
    "GetFullPathName", "GetTempFileName", "GetDLLVersion", "SearchPath", "FindFirst", "FindNext",
    "FindClose", "FileOpen", "FileRead", "FileWrite", "FileSeek", "FileClose", "File", "SetOutPath",
    "SetOverwrite", "SetShellVarContext", "InstallDir", "InstallDirRegKey", "OutFile",
    "CreateDirectory", "CreateShortcut", "Rename", "Delete", "RMDir", "CopyFiles",
    "SetFileAttributes", "WriteINIStr", "WriteRegStr", "WriteRegExpandStr", "WriteRegDWORD",
    "WriteRegBin", "DeleteRegKey", "DeleteRegValue", "WriteUninstaller", "Exec", "ExecWait",
    "ExecShell", "ExecShellWait", "ExecDos", "RegDLL", "UnRegDLL", "CallInstDLL", "SendMessage",
    "Reboot", "SetRebootFlag", "Function", "FunctionEnd", "Section", "SectionEnd", "Page",
    "ReserveFile", "RequestExecutionLevel", "AllowSkipFiles", "GetFunctionAddress",
    "!define", "!macro", "!macroend", "!include", "!insertmacro", "!system", "!execute",
    "!ifdef", "!ifndef", "!if", "!ifmacrodef", "!ifmacrondef", "!else", "!endif", "!error",
    "!packhdr", "!finalize", "!tempfile", "!appendfile", "!delfile", "!cd", "!pragma",
    "!searchparse", "!undef",
})
#: The one command line the script runs: the payload's own standard-library
#: verifier, with the folder's interpreter, against the identity baked into the
#: installer.
VERIFIER = ("/TIMEOUT=900000 '\"$0\\python\\python.exe\" -B -I -m nornyx_forge.windows_payload "
            "verify \"$0\" --expect ${PAYLOAD_SHA256}'")
#: What an NSIS script can use to delete, move, copy, rewrite, register or run,
#: for the message that names a refused verb. The census does not depend on this
#: list being complete: it refuses every verb that is not allowed.
KNOWN_DESTRUCTIVE = frozenset({
    "Delete", "RMDir", "CopyFiles", "WriteINIStr", "DeleteINISec", "DeleteINIStr", "FlushINI",
    "WriteRegStr", "WriteRegExpandStr", "WriteRegDWORD", "WriteRegBin", "DeleteRegKey",
    "DeleteRegValue", "WriteUninstaller", "SetFileAttributes", "Exec", "ExecWait", "ExecShell",
    "ExecShellWait", "ExecDos", "RegDLL", "UnRegDLL", "CallInstDLL", "SendMessage",
    "SetRebootFlag", "Reboot", "FileWriteByte", "FileWriteWord", "FileWriteUTF16LE", "Uninst",
})
#: The Win32 functions `System::Call` may reach: the process token, the file
#: attributes of a path (a read), a handle's close. A second, independent check
#: beside the table: the table already pins every `System::Call` argument.
ALLOWED_WIN32 = frozenset({
    "kernel32::GetFileAttributesW", "kernel32::GetCurrentProcess",
    "advapi32::OpenProcessToken", "advapi32::GetTokenInformation", "kernel32::CloseHandle",
    "shell32::IsUserAnAdmin",
})

#: EVERY instruction of the script whose verb is not inert, as `<count> <verb>
#: <arguments>`: the instruction as `_instructions` reads it (whitespace runs
#: collapsed, the text of a message replaced by "…" because the refusals have
#: their own list below). It is a snapshot of the script that a person reviewed:
#: a change to any instruction in it is a red test until the change is read and
#: this table is edited in the same commit. The first group is what can change the
#: machine or the destination of a write; the second is the plumbing (variables,
#: the stack, branches); the third is declarations and build-time guards.
ALLOWED_INSTRUCTIONS_TABLE = r"""
# Can change the machine, or where a write goes: a mutating instruction, a setting, a
# plug-in call. Every System::Call argument is pinned here.
1 CreateDirectory "$INSTDIR"
1 CreateShortcut "$SMPROGRAMS\Nornyx Forge.lnk" "$INSTDIR\$VerDir\python\pythonw.exe" '-B -m nornyx_forge.windows_launch --bundle-root "$INSTDIR\$VerDir" --project-dir "$PROFILE\ForgeProject"' "" 0 SW_SHOWNORMAL "" "Start Nornyx Forge"
1 FileOpen $1 "$LogPath" a
1 FileWrite $1 "$0$\r$\n"
1 Rename "$Partial" "$INSTDIR\$VerDir"
3 SetOutPath "$INSTDIR"
1 SetOverwrite off
1 AllowSkipFiles off
1 SetShellVarContext current
1 RequestExecutionLevel user
1 InstallDir "$LOCALAPPDATA\Programs\Nornyx Forge"
1 OutFile "${OUT_FILE}"
1 ReserveFile /plugin System.dll
1 ReserveFile /plugin nsExec.dll
1 Page instfiles
1 System::Call '*$3(i .r6)'
1 System::Call '*(i 0) p .r3'
1 System::Call 'advapi32::GetTokenInformation(p r1, i 20, p r3, i 4, *i .r4) i .r5'
1 System::Call 'advapi32::OpenProcessToken(p r0, i 8, *p .r1) i .r2'
1 System::Call 'kernel32::CloseHandle(p r1)'
1 System::Call 'kernel32::GetCurrentProcess() p .r0'
1 System::Call 'kernel32::GetFileAttributesW(w r0) i .r0'
1 System::Call 'shell32::IsUserAnAdmin() i .r7'
1 System::Free $3
1 nsExec::ExecToStack /TIMEOUT=900000 '"$0\python\python.exe" -B -I -m nornyx_forge.windows_payload verify "$0" --expect ${PAYLOAD_SHA256}'
# Plumbing: variables, the stack, branches, the structure of functions and sections.
1 ${AndIf} $3 != ".."
2 ${Break}
1 ${DoWhile} $3 != ""
1 ${DoWhile} $LinkPos <= $LinkLen
1 ${Do}
2 ${Else}
39 ${EndIf}
1 ${GetOptions} $0 "/LOG=" $LogPath
1 ${GetParameters} $0
2 ${IfNot} ${Errors}
2 ${If} $0 != "0"
1 ${If} $0 != ":"
3 ${If} $0 <> -1
4 ${If} $0 = -1
1 ${If} $0 == "\\"
1 ${If} $0 > 259
1 ${If} $1 != "$PROFILE\"
1 ${If} $1 <> 0
1 ${If} $1 <> 0x10
1 ${If} $1 = 0
1 ${If} $1 == "0"
1 ${If} $1 > 247
1 ${If} $2 = 0
1 ${If} $3 != "."
1 ${If} $3 == ""
1 ${If} $5 = 0
1 ${If} $6 <> 0
1 ${If} $Attr <> -1
1 ${If} $Attr <> 0
1 ${If} $GitState == "not found"
1 ${If} $HasEntries = 0
1 ${If} $LinkChar == "\"
1 ${If} $LinkPos = $LinkLen
1 ${If} $LinkPrefix != ""
1 ${If} $LogPath != ""
1 ${If} $Tries >= 5
5 ${If} ${Errors}
3 ${Loop}
1 ${OrIf} $1 != "\"
1 ${OrIf} $7 <> 0
1 Abort
7 Call AttrOf
1 Call CheckLocation
2 Call CheckNoLinks
1 Call CheckPathBudget
1 Call CheckShortcutFree
1 Call DecideExisting
1 Call RefuseElevated
2 Call VerifyFolder
2 Call WriteLog
9 ClearErrors
5 Exch $0
1 FileClose $1
1 FileSeek $1 0 END
1 FindClose $2
1 FindFirst $2 $3 "$INSTDIR\*.*"
1 FindNext $2 $3
1 Function .onInit
1 Function .onInstFailed
1 Function AttrOf
1 Function CheckLocation
1 Function CheckNoLinks
1 Function CheckPathBudget
1 Function CheckShortcutFree
1 Function DecideExisting
1 Function RefuseElevated
1 Function VerifyFolder
1 Function WriteLog
11 FunctionEnd
1 GetErrorLevel $0
1 IntOp $0 $0 + ${LONGEST_RELATIVE}
1 IntOp $0 $0 + 1
1 IntOp $1 $0 & 0x10
2 IntOp $1 $0 & 0x410
1 IntOp $1 $0 + ${LONGEST_DIRECTORY}
1 IntOp $Attr $Attr & 0x400
2 IntOp $LinkPos $LinkPos + 1
1 IntOp $Tries $Tries + 1
1 MessageBox MB_OK|MB_ICONEXCLAMATION "…" /SD IDOK
1 MessageBox MB_OK|MB_ICONINFORMATION "…" /SD IDOK
1 MessageBox MB_OK|MB_ICONSTOP "…" /SD IDOK
9 Pop $0
3 Pop $1
2 Pop $2
1 Pop $Attr
1 Push "$INSTDIR"
2 Push "$INSTDIR\$VerDir"
1 Push "$INSTDIR\install-receipt.json"
1 Push "$LinkPrefix"
3 Push "$Partial"
1 Push "$SMPROGRAMS\Nornyx Forge.lnk"
1 Push "${TEXT}"
1 Push "refused (${CODE}): ${TEXT}"
2 Push $1
1 Push $2
1 Quit
2 Return
1 SearchPath $0 "git.exe"
1 Section "Install"
1 SectionEnd
1 SetErrorLevel ${CODE}
1 SetErrorLevel ${EXIT_FAILED}
1 SetErrorLevel 0
1 StrCpy $0 "$INSTDIR" 1 1
1 StrCpy $0 "$INSTDIR" 2
1 StrCpy $0 "0"
1 StrCpy $0 "exit $1: $2"
1 StrCpy $1 "$INSTDIR" $0
1 StrCpy $1 "$INSTDIR" 1 2
1 StrCpy $GitState "found"
1 StrCpy $GitState "not found"
1 StrCpy $HasEntries 0
1 StrCpy $HasEntries 1
1 StrCpy $INSTDIR "$LOCALAPPDATA\Programs\Nornyx Forge"
1 StrCpy $LinkChar "$LinkPath" 1 $LinkPos
2 StrCpy $LinkPath "$INSTDIR"
1 StrCpy $LinkPrefix ""
1 StrCpy $LinkPrefix "$LinkPath"
1 StrCpy $LinkPrefix "$LinkPath" $LinkPos
1 StrCpy $LogPath ""
1 StrCpy $Partial "$INSTDIR\$VerDir.partial"
1 StrCpy $RootCreated "false"
2 StrCpy $RootCreated "true"
1 StrCpy $Tries 0
1 StrCpy $VerDir "${VERSION}+${COMMIT12}"
1 StrLen $0 "$PROFILE\"
1 StrLen $0 "$Partial"
1 StrLen $LinkLen "$LinkPath"
1 StrLen $LinkPos "$PROFILE"
# Directives: defines, includes, macros and the build guards (a compile-time conditional
# decides what is compiled, so it is here and not inert; `_depth_problems` pins where
# it may stand). The text of a message is not part of a form.
1 !define EXIT_DOES_NOT_VERIFY 16
1 !define EXIT_ELEVATED 10
1 !define EXIT_ELEVATION_UNKNOWN 19
1 !define EXIT_FAILED 17
1 !define EXIT_LINK 12
1 !define EXIT_LOCATION 11
1 !define EXIT_NOT_FORGE 13
1 !define EXIT_OTHER_VERSION 18
1 !define EXIT_SHORTCUT_EXISTS 20
1 !define EXIT_TOO_LONG 15
1 !define EXIT_UNFINISHED 14
1 !include "${STAGE_DIR}/files.nsh"
1 !include "${STAGE_DIR}/receipt.nsh"
1 !include "FileFunc.nsh"
1 !include "LogicLib.nsh"
1 !macro Refuse CODE TEXT
1 !macro Say TEXT
2 !macroend
1 !insertmacro GetOptions
1 !insertmacro GetParameters
3 !insertmacro Refuse ${EXIT_DOES_NOT_VERIFY} "…"
1 !insertmacro Refuse ${EXIT_ELEVATED} "…"
2 !insertmacro Refuse ${EXIT_ELEVATION_UNKNOWN} "…"
4 !insertmacro Refuse ${EXIT_FAILED} "…"
1 !insertmacro Refuse ${EXIT_LINK} "…"
3 !insertmacro Refuse ${EXIT_LOCATION} "…"
4 !insertmacro Refuse ${EXIT_NOT_FORGE} "…"
1 !insertmacro Refuse ${EXIT_OTHER_VERSION} "…"
1 !insertmacro Refuse ${EXIT_SHORTCUT_EXISTS} "…"
2 !insertmacro Refuse ${EXIT_TOO_LONG} "…"
2 !insertmacro Refuse ${EXIT_UNFINISHED} "…"
3 !insertmacro Say "…"
1 !ifndef COMMIT12
1 !ifndef LONGEST_DIRECTORY
1 !ifndef LONGEST_RELATIVE
1 !ifndef OUT_FILE
1 !ifndef PAYLOAD_SHA256
1 !ifndef STAGE_DIR
1 !ifndef VERSION
1 !ifndef VI_VERSION
1 !error "COMMIT12 is not defined"
1 !error "LONGEST_DIRECTORY is not defined"
1 !error "LONGEST_RELATIVE is not defined"
1 !error "OUT_FILE is not defined"
1 !error "PAYLOAD_SHA256 is not defined"
1 !error "STAGE_DIR is not defined"
1 !error "VERSION is not defined: this script is compiled by build_windows_installer.py"
1 !error "VI_VERSION is not defined"
8 !endif
"""


def _parse_table(table: str) -> Counter:
    forms: Counter = Counter()
    for line in table.strip().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        count, verb, *rest = line.split(" ", 2)
        forms[(verb, rest[0] if rest else "")] += int(count)
    return forms


ALLOWED_INSTRUCTIONS = _parse_table(ALLOWED_INSTRUCTIONS_TABLE)


def _script_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith((";", "#"))]


def _instructions(text: str) -> list[tuple[str, str]]:
    """(verb, arguments) of every line that is not a comment: a run-time
    instruction, a LogicLib line (`${If}`), a compile-time directive (`!define`).
    Whitespace runs in the arguments are collapsed."""
    found = []
    for line in _script_lines(text):
        verb, _, arguments = line.partition(" ")
        found.append((verb, re.sub(r"\s+", " ", arguments.strip())))
    return found


def _normalised(verb: str, arguments: str) -> tuple[str, str]:
    """The text of a message is not part of an instruction's form (the refusals
    are listed on their own, by their words): the quoted message of a MessageBox,
    of `!insertmacro Refuse` and of `!insertmacro Say` becomes "…". Anything after
    the message (`/SD IDOK`, a jump target) stays."""
    if verb == "MessageBox" or (verb == "!insertmacro" and arguments.startswith(("Refuse ", "Say "))):
        arguments = re.sub(r'"(.*)"(?=(?:\s+/SD\s+\w+)?$)', '"…"', arguments, count=1)
    return verb, arguments


def _forms(text: str) -> Counter:
    return Counter(_normalised(verb, arguments) for verb, arguments in _instructions(text)
                   if verb not in INERT_VERBS)


# Every check of the census is a function of the script's TEXT and returns its
# problems, so the real script and each planted one below go through the same
# code: a plant is refused by the check that passes the real script, not by a
# copy of it.
def _instruction_problems(text: str) -> list[str]:
    used = _forms(text)
    if used == ALLOWED_INSTRUCTIONS:
        return []
    unlisted, missing = used - ALLOWED_INSTRUCTIONS, ALLOWED_INSTRUCTIONS - used
    verbs = sorted({verb for verb, _ in unlisted} - {verb for verb, _ in ALLOWED_INSTRUCTIONS})
    named = f" (new verbs {verbs}; known destructive {sorted(set(verbs) & KNOWN_DESTRUCTIVE)})" if verbs else ""
    return [f"instructions that are not the reviewed ones{named}: unlisted {sorted(unlisted.items())}; "
            f"missing {sorted(missing.items())}"]


def _win32_functions(text: str) -> set[str]:
    """Every `dll::function` a `System::Call` names, up to the argument list, so a
    name built at run time (`DeleteFile$R0`) is a name that is not allowed."""
    named: set[str] = set()
    for verb, arguments in _instructions(text):
        if verb == "System::Call":
            named |= {found.strip("'") for found in re.findall(r"[\w$.]+::[^\s(]*", arguments)}
    return named


def _win32_problems(text: str) -> list[str]:
    problems = []
    functions = _win32_functions(text)
    if functions - ALLOWED_WIN32:
        problems.append(f"win32 functions {sorted(functions - ALLOWED_WIN32)}")
    for verb, arguments in _instructions(text):
        if verb == "System::Call" and "::" not in arguments and not re.fullmatch(
                r"'\*(?:\(i 0\) p \.r3|\$3\(i \.r6\))'", arguments):
            problems.append(f"a System::Call with no named function: {arguments}")
    return problems


GUARD_OPENERS = ("!ifdef", "!ifndef", "!if", "!ifmacrodef", "!ifmacrondef")


def _depth_problems(text: str) -> list[str]:
    """What the multiset cannot see about conditional compilation. A compile-time
    conditional decides which instructions are compiled at all, so moving one
    `!endif` down over instructions keeps every pinned form and changes the
    installer. The only conditionals the script has are build guards, `!ifndef X`
    with an `!error` inside, and nothing else may stand inside one. Anything else
    is refused: any other instruction at a conditional depth, a conditional that is
    not an `!ifndef`, an `!else`, an unbalanced `!endif`."""
    problems = []
    found = _instructions(text)
    depth = 0
    for verb, arguments in found:
        if verb in GUARD_OPENERS:
            if verb != "!ifndef":
                problems.append(f"a conditional that is not a build guard: {verb} {arguments}")
            depth += 1
        elif verb == "!endif":
            depth -= 1
            if depth < 0:
                problems.append("an !endif that closes nothing")
                depth = 0
        elif depth and verb != "!error":
            problems.append(f"compiled only conditionally: {verb} {arguments}")
    if depth:
        problems.append("a conditional that is never closed")
    return problems


def _census_problems(text: str) -> list[str]:
    return [*_instruction_problems(text), *_depth_problems(text), *_win32_problems(text)]


def test_the_script_changes_only_what_the_census_names_and_nothing_else():
    """CLASS: any instruction the reviewed script does not have, in any spelling:
    a deletion, a move, a registry write, an uninstaller, a run of another
    program, but also a variable assigned a folder the script was never meant to
    write into (`StrCpy $Partial "$PROFILE\\.codex"`), a changed argument, one
    more or one fewer of an allowed instruction. Every instruction is either of an
    inert verb or an exact entry of the table; there is nothing in between."""
    assert _instruction_problems(contract.nsi_text()) == []


def test_the_inert_verbs_are_inert_and_the_table_holds_no_inert_verb():
    """The only verbs that may carry any arguments, checked against a list of
    those that cannot be inert: variables, the stack, branches, paths, the
    registry, processes, plug-ins and directives."""
    assert not (INERT_VERBS & PATH_ALTERING_VERBS), sorted(INERT_VERBS & PATH_ALTERING_VERBS)
    assert not [verb for verb in INERT_VERBS if "::" in verb or verb.startswith("${")]
    assert not ({verb for verb, _ in ALLOWED_INSTRUCTIONS} & INERT_VERBS)
    used = {verb for verb, _ in _instructions(contract.nsi_text())}
    assert INERT_VERBS <= used, f"inert verbs the script never uses: {sorted(INERT_VERBS - used)}"


def test_every_plug_in_call_is_one_exact_form_the_exact_number_of_times():
    """CLASS: a plug-in call that is exempt because of what it is called.
    `nsExec::ExecToStack` runs ANY command line, so the table pins the script's
    plug-in calls to ten exact forms, and the one command line it runs is the
    payload's own verifier. A second run, a changed command, another execution
    plug-in or a plug-in that downloads is a red test."""
    text = contract.nsi_text()
    runs = [arguments for verb, arguments in _instructions(text) if verb == "nsExec::ExecToStack"]
    assert runs == [VERIFIER], runs
    assert sum(count for (verb, _args), count in ALLOWED_INSTRUCTIONS.items() if "::" in verb) == 10
    reserved = sorted(re.findall(r"^ReserveFile /plugin (\S+)$", "\n".join(_script_lines(text)),
                                 re.M))
    assert reserved == ["System.dll", "nsExec.dll"], "the plug-ins loaded are the ones called"


def test_the_only_win32_functions_the_script_can_reach_read_a_token_or_an_attribute():
    """`System::Call` runs any exported function. `DeleteFileW`, `RemoveDirectoryW`,
    `MoveFileExW`, `SHFileOperationW` and `RegDeleteKeyW` delete or rewrite with
    none of the NSIS verbs, so the functions are checked by name as well as pinned
    by the table, and the only calls without a function are the two struct forms
    that hold and read the token flag."""
    text = contract.nsi_text()
    calls = [arguments for verb, arguments in _instructions(text) if verb == "System::Call"]
    assert len(calls) >= 6, "the script makes its token and attribute calls"
    assert _win32_problems(text) == []
    functions = _win32_functions(text)
    assert functions == ALLOWED_WIN32, (
        f"unlisted: {sorted(functions - ALLOWED_WIN32)}; missing: {sorted(ALLOWED_WIN32 - functions)}")


def test_the_script_has_one_install_section_no_uninstall_section_and_one_page():
    """The ways a Windows installer registers a removal path of its own: an
    `Uninstall` section, an `un.` function, an uninstaller page, a written
    uninstaller. None exists, so no Add/Remove Programs entry has anything to
    point at, and the driver's census of the `Uninstall` registry place stays
    empty for a reason."""
    text = contract.nsi_text()
    code = "\n".join(_script_lines(text))
    assert re.findall(r"^Section\b.*$", code, re.M) == ['Section "Install"']
    assert not re.search(r"^Function un\.|\bun\.\w+|UninstPage|Uninstall|WriteUninstaller", code, re.M)
    assert re.findall(r"^Page\b.*$", code, re.M) == ["Page instfiles"]
    macros = sorted(set(re.findall(r"^!insertmacro (\w+)", code, re.M)))
    assert macros == ["GetOptions", "GetParameters", "Refuse", "Say"], macros
    includes = sorted(re.findall(r'^!include "([^"]+)"', code, re.M))
    assert includes == ["${STAGE_DIR}/files.nsh", "${STAGE_DIR}/receipt.nsh", "FileFunc.nsh",
                        "LogicLib.nsh"], includes
    plugins = sorted({verb for verb, _ in _instructions(text) if "::" in verb})
    assert plugins == ["System::Call", "System::Free", "nsExec::ExecToStack"], plugins


def test_the_generated_includes_write_only_under_the_unfinished_folder_and_the_receipt():
    """`files.nsh` and `receipt.nsh` are compiled into the script. The first may
    set an output folder only under `$Partial` and extract with `File`; the
    second opens the receipt and writes lines to it."""
    manifest = {**MANIFEST, "version": "1.2.3"}
    listing = contract.files_nsh([["a/b.py", 1, "d" * 64], ["c.py", 1, "e" * 64]], "/tmp/payload",
                                 manifest_name=PAYLOAD_MANIFEST)
    for verb, arguments in _instructions(listing):
        assert verb in ("SetOutPath", "File"), (verb, arguments)
        if verb == "SetOutPath":
            assert re.fullmatch(r'"\$Partial(?:\\[^"\\]+)*"', arguments), arguments
        else:
            assert re.fullmatch(r'"/tmp/payload/[^"]+"', arguments), arguments
    receipt = _instructions(contract.receipt_nsh(manifest))
    opened = [(verb, arguments) for verb, arguments in receipt if verb == "FileOpen"]
    assert opened == [("FileOpen", '$0 "$INSTDIR\\install-receipt.json" w')], opened
    assert {verb for verb, _ in receipt} == {"FileOpen", "FileWrite", "FileClose"}
    assert all(arguments.startswith("$0 ") or verb == "FileClose" for verb, arguments in receipt
               if verb == "FileWrite")


def test_the_receipt_is_written_only_into_a_folder_that_held_nothing():
    """The one `w` open in the script is the receipt's, and the Section reaches
    it only after `DecideExisting` has returned: an existing install either
    quits (the same payload) or aborts, so the Section never truncates a
    receipt that was there."""
    text = contract.nsi_text()
    code = "\n".join(_script_lines(text))
    section = code[code.index('Section "Install"'):]
    assert section.count("receipt.nsh") == 1
    decide = code[code.index("Function DecideExisting"):code.index("Function .onInit")]
    assert decide.count("Quit") == 1 and decide.rstrip().endswith("FunctionEnd")
    refusals = len(re.findall(r"!insertmacro Refuse", decide))
    assert refusals >= 8, "every other existing-install outcome is a refusal"
    init = code[code.index("Function .onInit"):code.index("Function .onInstFailed")]
    assert init.index("Call DecideExisting") > init.index("Call RefuseElevated")
    for forbidden in ("Delete", "RMDir"):
        assert forbidden not in decide


# The census is useless if it cannot fail: each of these is a script a review
# could be shown, and each must be refused by the SAME check that passes the real
# one (`_census_problems` is that check, over a text).
PLANTED = {
    # a verb the reviewed script does not have
    "a deletion": '  Delete "$PROFILE\\ForgeProject\\capsule\\capsule.json"\n',
    "a recursive removal": '  RMDir /r "$PROFILE\\.nornyx"\n',
    "an uninstaller": '  WriteUninstaller "$INSTDIR\\uninstall.exe"\n',
    "a registry entry": '  WriteRegStr HKCU "Software\\Nornyx" "x" "y"\n',
    "a copy": '  CopyFiles "$INSTDIR\\a" "$PROFILE\\.claude"\n',
    "an attribute change": '  SetFileAttributes "$INSTDIR" NORMAL\n',
    "another program": '  ExecWait "cmd /c rd /s /q x"\n',
    "a call that is not to a function of the script": "  Call $0\n",
    # a second use of a verb the script has, or other arguments
    "a move over something": '  Rename "$PROFILE\\.codex\\config.toml" "$PROFILE\\x"\n',
    "a write that truncates": '  FileOpen $2 "$PROFILE\\.nornyx\\x" w\n',
    "an extra shortcut": '  CreateShortcut "$DESKTOP\\x.lnk" "$INSTDIR\\x"\n',
    # a destination variable pointed at state (the instructions that write into it
    # are allowed, so only the assignment shows)
    "the unfinished-install folder pointed at a provider's home":
        '  StrCpy $Partial "$PROFILE\\.codex"\n',
    "the install folder pointed at the profile": '  StrCpy $INSTDIR "$PROFILE"\n',
    "the log pointed at a provider's settings": '  StrCpy $LogPath "$PROFILE\\.claude\\settings.json"\n',
    "a value pushed for the verifier or the shortcut": '  Push "$PROFILE\\.codex"\n',
    "a destination computed": "  IntOp $Partial $Partial + 1\n",
    "a destination read from the environment": '  ReadEnvStr $INSTDIR "USERPROFILE"\n',
    "a destination read from the registry":
        '  ReadRegStr $INSTDIR HKCU "Software\\Nornyx" "Path"\n',
    "a destination expanded": '  ExpandEnvStrings $INSTDIR "%USERPROFILE%\\.codex"\n',
    "a destination resolved": '  GetFullPathName $INSTDIR "..\\.codex"\n',
    "a length taken that feeds a path": '  StrLen $0 "$PROFILE"\n',
    "a stack value swapped": "  Exch $INSTDIR\n",
    # control flow
    "a jump": "  Goto +2\n",
    "a branch": "  ${If} 1 = 1\n  ${EndIf}\n",
    "a message box that branches": '  MessageBox MB_YESNO "x" IDYES +2\n',
    # win32 and plug-ins
    "a win32 delete": '  System::Call \'kernel32::DeleteFileW(w "x") i .r0\'\n',
    "a win32 directory removal": '  System::Call \'kernel32::RemoveDirectoryW(w "x") i .r0\'\n',
    "a win32 move": '  System::Call \'kernel32::MoveFileExW(w "a", w "b", i 1) i .r0\'\n',
    "a win32 function named at run time":
        '  System::Call \'kernel32::DeleteFile$R0(w "x") i .r0\'\n',
    "a win32 call through an address": '  System::Call \'$0(w "x") i .r1\'\n',
    "a second run of the verifier": f"  nsExec::ExecToStack {VERIFIER}\n",
    "a destructive command through the verifier's plug-in":
        '  nsExec::ExecToStack \'cmd /c rd /s /q "$PROFILE\\.nornyx"\'\n',
    "another form of the same plug-in": '  nsExec::Exec "cmd /c del x"\n',
    "another execution plug-in": '  ExecDos::exec "cmd /c del x" ""\n',
    "a download plug-in": '  inetc::get "http://example.invalid/x" "$INSTDIR\\x"\n',
    "a second free of the token buffer": "  System::Free $4\n",
    # directives: the ways to write an instruction so that the verb is not seen
    "a verb hidden in a define": '  !define REMOVE Delete\n  ${REMOVE} "$INSTDIR\\x"\n',
    "a destination hidden in a define": '  !define DEST "$PROFILE\\.codex"\n',
    "a macro": '  !macro Evil\n  Delete "x"\n  !macroend\n',
    "an include": '  !include "evil.nsh"\n',
    "a new function": "  Function Evil\n  FunctionEnd\n",
}

#: Changes to an instruction the real script has, as (old text, new text). The
#: old text occurs once in the script.
REWRITTEN = {
    "the unfinished-install folder moved": (
        'StrCpy $Partial "$INSTDIR\\$VerDir.partial"', 'StrCpy $Partial "$PROFILE\\.codex"'),
    "the install folder moved": (
        'StrCpy $INSTDIR "$LOCALAPPDATA\\Programs\\Nornyx Forge"', 'StrCpy $INSTDIR "$PROFILE"'),
    "the version folder named by something else": (
        'StrCpy $VerDir "${VERSION}+${COMMIT12}"', 'StrCpy $VerDir ".codex"'),
    "the verifier replaced by a destructive command": (
        "'\"$0\\python\\python.exe\" -B -I -m nornyx_forge.windows_payload verify \"$0\" "
        "--expect ${PAYLOAD_SHA256}'", "'cmd /c rd /s /q \"$PROFILE\"'"),
    "the verifier asked for something else": (
        "nornyx_forge.windows_payload verify \"$0\" --expect ${PAYLOAD_SHA256}'",
        "nornyx_forge.windows_payload prune \"$0\"'"),
    "the verifier no longer held to the identity": (" --expect ${PAYLOAD_SHA256}'", "'"),
    "the verifier's time limit removed": ("nsExec::ExecToStack /TIMEOUT=900000 ",
                                          "nsExec::ExecToStack "),
    "the shortcut starts something else": ("-m nornyx_forge.windows_launch --bundle-root",
                                           "-m nornyx_forge.cli --bundle-root"),
    "the shortcut points the project at the profile": (
        '--project-dir "$PROFILE\\ForgeProject"\'', '--project-dir "$PROFILE"\''),
    "extraction that replaces what is there": ("SetOverwrite off", "SetOverwrite on"),
    "extraction that skips files": ("AllowSkipFiles off", "AllowSkipFiles on"),
    "the shortcut in the all-users Start menu": ("SetShellVarContext current",
                                                 "SetShellVarContext all"),
    "an installer that asks for administrator": ("RequestExecutionLevel user",
                                                 "RequestExecutionLevel admin"),
}

#: Plants that name a Win32 function or call one through an address: the separate
#: by-name check must refuse them too, so it cannot stop judging unseen behind
#: the table.
WIN32_PLANTS = frozenset({
    "a win32 delete", "a win32 directory removal", "a win32 move",
    "a win32 function named at run time", "a win32 call through an address",
})


def _plant(real: str, label: str) -> str:
    anchor = '  SetOutPath "$INSTDIR"\n  ClearErrors\n  CreateShortcut'
    assert anchor in real
    return real.replace(anchor, PLANTED[label] + anchor, 1)


def _wrap_an_existing_assignment(real: str) -> str:
    line = 'StrCpy $Partial "$INSTDIR\\$VerDir.partial"'
    assert real.count(line) == 1
    return real.replace(line, "!ifndef OUT_FILE\n  " + line + "\n!endif", 1)


def _move_a_guards_end_down(real: str) -> str:
    old = '!ifndef OUT_FILE\n  !error "OUT_FILE is not defined"\n!endif\n\nTarget x86-unicode\n'
    assert real.count(old) == 1
    return real.replace(old, '!ifndef OUT_FILE\n  !error "OUT_FILE is not defined"\n\n'
                        "Target x86-unicode\n!endif\n", 1)


#: Rewrites of the real script that change what is COMPILED: (the rewrite, whether
#: the multiset of instructions sees it). The multiset sees an added conditional
#: (its `!ifndef` and `!endif` are extra) but not a moved `!endif`, which the depth
#: check alone refuses.
TRANSFORMED = {
    "an existing assignment wrapped in a conditional": (_wrap_an_existing_assignment, True),
    "a new conditional block": (lambda real: real.replace(
        "Target x86-unicode\n", '!ifdef OUT_FILE\n  StrCpy $0 "x"\n!endif\nTarget x86-unicode\n', 1), True),
    "a conditional with an else branch": (lambda real: real.replace(
        "Target x86-unicode\n",
        '!ifndef OUT_FILE\n  !error "x"\n!else\n  StrCpy $0 "x"\n!endif\nTarget x86-unicode\n', 1), True),
    "a guard's end moved down over instructions (every form and count unchanged)": (
        _move_a_guards_end_down, False),
}


@pytest.mark.parametrize("label", sorted(TRANSFORMED))
def test_the_census_refuses_a_conditional_that_changes_what_is_compiled(label: str):
    """CLASS: the multiset of instructions is kept and the installer is not. A
    compile-time conditional is not inert: it decides which instructions exist.
    Wrapping a pinned instruction, adding a block, adding an `else` and moving a
    guard's `!endif` over instructions are each refused, the last by the depth
    check alone."""
    real = contract.nsi_text()
    assert _depth_problems(real) == [], "the real script's only conditionals are its build guards"
    transform, seen_by_the_multiset = TRANSFORMED[label]
    planted = transform(real)
    assert planted != real
    assert _census_problems(planted), f"{label} passed the census"
    assert _depth_problems(planted), f"{label} passed the depth check"
    assert bool(_instruction_problems(planted)) is seen_by_the_multiset, label


@pytest.mark.parametrize("label", sorted(PLANTED))
def test_the_census_refuses_each_planted_instruction_the_real_script_does_not_have(label: str):
    real = contract.nsi_text()
    assert _census_problems(real) == [], "the real script passes the check the plants fail"
    planted = _plant(real, label)
    assert planted != real
    assert _census_problems(planted), f"{label} passed the census"
    if label in WIN32_PLANTS:
        assert _win32_problems(planted), f"{label} passed the by-name check"


@pytest.mark.parametrize("label", sorted(REWRITTEN))
def test_the_census_refuses_each_change_to_an_instruction_the_real_script_has(label: str):
    real = contract.nsi_text()
    assert _census_problems(real) == [], "the real script passes the check the changes fail"
    old, new = REWRITTEN[label]
    assert real.count(old) == 1, f"{old!r} is not one place in the script"
    assert _census_problems(real.replace(old, new, 1)), f"{label} passed the census"


def test_an_inert_verb_is_the_only_thing_the_census_lets_through_with_any_arguments():
    """The converse of the plants: an instruction of an inert verb is not a
    difference, whatever it says, and nothing else is. `Name` is metadata; the
    same line with the verb of an assignment is refused."""
    real = contract.nsi_text()
    assert _census_problems(real.replace('Name "Nornyx Forge"', 'Name "anything at all"', 1)) == []
    assert _census_problems(real.replace('Name "Nornyx Forge"', 'StrCpy $0 "Nornyx Forge"', 1))


# ---------------------------------------------------------------------------
# Every way the script refuses or exits, listed, and whether the driver runs it
# against the person's state
# ---------------------------------------------------------------------------

REPLAYED = "replayed with the specimen planted"
ELEVATED = "run as the administrator, where no specimen is planted"
NOT_RUN = "not run by the driver"

#: Every `Refuse` in the script: (the function or section that holds it, its exit
#: code, words of its message that no other message has and that hold no
#: variable, what the driver does with it, and why not when it does not).
#: The list is compared with the script both ways: a refusal added, removed or reworded is
#: a red test until it is listed here and, if the driver does not replay it, says
#: why. `state_survival` replays the REPLAYED ones with the person's state
#: planted; whether it does is read from a run over a stand-in installer, not
#: from this list.
REFUSALS = (
    ("RefuseElevated", "EXIT_ELEVATION_UNKNOWN", "could not read this process's token", NOT_RUN,
     "a process whose token cannot be read cannot be produced on the runner (the driver "
     "declares this in UNEXERCISED)"),
    ("RefuseElevated", "EXIT_ELEVATION_UNKNOWN", "could not read this process's elevation", NOT_RUN,
     "a process whose elevation cannot be read cannot be produced on the runner (the driver "
     "declares this in UNEXERCISED)"),
    ("RefuseElevated", "EXIT_ELEVATED", "installs for the signed-in user only", ELEVATED, ""),
    ("CheckNoLinks", "EXIT_LINK", "is a link (a junction or symbolic link)", REPLAYED, ""),
    ("CheckLocation", "EXIT_LOCATION", "is a network or extended-length path", NOT_RUN,
     "moving the account's Local AppData folder to a network path makes the shell resolve it to "
     "nothing, so the location becomes a bare `\\Programs\\Nornyx Forge` and the drive-path check "
     "refuses first (measured on Windows); no folder the driver can set gives the network or "
     "extended-length spelling"),
    ("CheckLocation", "EXIT_LOCATION", "is not a plain drive path", REPLAYED, ""),
    ("CheckLocation", "EXIT_LOCATION", "is outside your profile folder", REPLAYED, ""),
    ("CheckPathBudget", "EXIT_TOO_LONG", "would create file paths of up to", REPLAYED, ""),
    ("CheckPathBudget", "EXIT_TOO_LONG", "would create folder paths of up to", NOT_RUN,
     "the one over-long payload the build makes is refused by the file-path check, which runs first"),
    ("CheckShortcutFree", "EXIT_SHORTCUT_EXISTS", "already exists and Setup does not replace it",
     REPLAYED, ""),
    ("DecideExisting", "EXIT_NOT_FORGE", "exists and is not a folder", REPLAYED, ""),
    ("DecideExisting", "EXIT_UNFINISHED", "An earlier install did not finish", REPLAYED, ""),
    ("DecideExisting", "EXIT_NOT_FORGE", "exists but cannot be listed", NOT_RUN,
     "it needs an install folder the account may see but not list, and the driver sets no such "
     "permission on it"),
    ("DecideExisting", "EXIT_NOT_FORGE", "so it is not a Forge install this setup made", REPLAYED,
     ""),
    ("DecideExisting", "EXIT_NOT_FORGE", "is not a plain file", REPLAYED, ""),
    ("DecideExisting", "EXIT_OTHER_VERSION", "Another version of Forge is installed", REPLAYED, ""),
    ("DecideExisting", "EXIT_DOES_NOT_VERIFY", "is not a plain folder", REPLAYED, ""),
    ("DecideExisting", "EXIT_DOES_NOT_VERIFY", "is not the payload this Setup carries", REPLAYED,
     ""),
    ("Install", "EXIT_FAILED", "Setup could not create", NOT_RUN,
     "it needs the folder above the install folder to refuse a new folder after every check has "
     "passed, and the driver denies no write there"),
    ("Install", "EXIT_UNFINISHED", "already exists. Setup does not delete anything", NOT_RUN,
     "it is reached only if the unfinished-install folder appears between the start-up check and "
     "the section, a race the driver cannot time"),
    ("Install", "EXIT_DOES_NOT_VERIFY", "do not verify against the payload it carries", NOT_RUN,
     "it is reached only if the extraction produces files that do not verify, and the build "
     "verifies the payload it embeds"),
    ("Install", "EXIT_FAILED", "could not move the verified folder", NOT_RUN,
     "it needs the rename of the verified folder to fail five times in a row, which the driver "
     "cannot cause"),
    ("Install", "EXIT_FAILED", "could not create the Start-menu shortcut", REPLAYED, ""),
    ("Install", "EXIT_FAILED", "could not write install-receipt.json", NOT_RUN,
     "it needs the receipt to fail to write after the shortcut was written, which the driver "
     "cannot cause"),
)


def _refusal_sites(text: str) -> list[tuple[str, str, str]]:
    """(function or section, exit code name, message) of each `Refuse` the script
    invokes, read from the text."""
    sites, where = [], ""
    for line in _script_lines(text):
        if line.startswith(("Function ", "Section ")):
            where = line.split(" ", 1)[1].strip('"')
        elif line in ("FunctionEnd", "SectionEnd"):
            where = ""
        match = re.fullmatch(r'!insertmacro Refuse \$\{(EXIT_\w+)\} "(.*)"', line)
        if match:
            sites.append((where, match.group(1), match.group(2)))
    return sites


def _refusal(fragment: str) -> tuple[int, str]:
    """(exit code, the installer's log line) of the one refusal whose message
    holds `fragment`: the words of the script itself."""
    text = contract.nsi_text()
    hits = [(code, message) for _where, code, message in _refusal_sites(text)
            if fragment in message]
    assert len(hits) == 1, (fragment, hits)
    number = contract.exit_codes(text)[hits[0][0]]
    return number, f"refused ({number}): {hits[0][1]}"


def test_every_refusal_the_script_has_is_listed_once_and_says_whether_it_is_replayed():
    """CLASS: a refusal added, reworded or removed without anyone deciding what
    the state scenario does with it. Every `Refuse` in the script is listed once;
    every listed one is in the script; each says whether the driver replays it
    with the specimen planted, and one that it does not says why."""
    text = contract.nsi_text()
    sites = _refusal_sites(text)
    claimed = []
    for where, code, fragment, status, why in REFUSALS:
        assert status in (REPLAYED, ELEVATED, NOT_RUN), fragment
        assert "$" not in fragment and len(fragment) >= 12, fragment
        assert len([site for site in sites if fragment in site[2]]) == 1, (
            f"{fragment!r} does not name one refusal")
        hits = [site for site in sites if site[:2] == (where, code) and fragment in site[2]]
        assert len(hits) == 1, f"{fragment!r} is not a refusal of {where} with {code}"
        claimed += hits
        assert (len(why) > 60) is (status == NOT_RUN), f"{fragment!r}: a reason, and only for NOT_RUN"
    assert sorted(claimed) == sorted(sites), (
        f"unlisted: {sorted(set(sites) - set(claimed))}; listed twice: "
        f"{sorted(site for site in set(claimed) if claimed.count(site) > 1)}")
    assert len(sites) == len(REFUSALS)
    source = DRIVER.read_text(encoding="utf-8")
    elevated = source[source.index("def mode_elevated"):source.index("USER_SHELL_FOLDERS = ")]
    for _where, _code, fragment, status, _why in REFUSALS:
        if status == ELEVATED:
            assert f'"{fragment}"' in elevated, "the elevated run names its refusal"
        if status == NOT_RUN:
            assert fragment not in source, f"{fragment!r} is run, so it is not 'not run'"


def test_every_other_way_the_script_leaves_is_the_two_it_is_known_to_have():
    """Beyond the refusals: the script stops through `Abort` in one macro, quits
    once (the same payload already installed, exit 0), and sets an exit code in
    three places, the third being the callback that gives a failed extraction
    (a file that could not be written) the generic one. A refusal written without
    the macro would be one of these, so the counts are pinned."""
    text = contract.nsi_text()
    instructions = _instructions(text)
    assert [args for verb, args in instructions if verb == "Abort"] == [""]
    assert [args for verb, args in instructions if verb == "Quit"] == [""]
    assert sorted(args for verb, args in instructions if verb == "SetErrorLevel") == sorted(
        ["${CODE}", "0", "${EXIT_FAILED}"])
    code = "\n".join(_script_lines(text))
    macro = code[code.index("!macro Refuse"):code.index("!macroend")]
    assert "Abort" in macro and "SetErrorLevel ${CODE}" in macro
    callback = code[code.index("Function .onInstFailed"):]
    assert "SetErrorLevel ${EXIT_FAILED}" in callback.split("FunctionEnd")[0]
    assert code.count("!insertmacro Refuse") == len(REFUSALS)


# ---------------------------------------------------------------------------
# The state specimen, against the locations the product names
# ---------------------------------------------------------------------------

def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _product_locations() -> dict[str, str]:
    """Where the product keeps governed state, as profile-relative POSIX paths,
    read from the product's own constants and not restated."""
    from nornyx_forge import capsule_store, reviewer_trust, windows_runtime  # noqa: PLC0415
    from nornyx_forge.approval_trust import DEFAULT_TRUST_STORE  # noqa: PLC0415
    from nornyx_forge.nornyx_runtime import DEFAULT_APPROVAL_LEDGER  # noqa: PLC0415

    home = Path.home()
    project = re.search(r'%USERPROFILE%\\(\w+)"', bundle.PROJECT_ARGUMENT).group(1)
    return {
        "the seals": capsule_store.DEFAULT_SEAL_DIR.relative_to(home).as_posix(),
        "the runtime record, lock and log":
            windows_runtime.DEFAULT_RUNTIME_DIR.relative_to(home).as_posix(),
        "the reviewer trust store": reviewer_trust.DEFAULT_REVIEWER_STORE.relative_to(home).as_posix(),
        "the approver trust store": DEFAULT_TRUST_STORE.relative_to(home).as_posix(),
        "the approval ledger": f"{project}/{DEFAULT_APPROVAL_LEDGER}",
        "the capsule's authority files": f"{project}/capsule",
    }


#: State the product can leave that the specimen deliberately does not plant, and
#: why. A-044 names each; the test below fails if one is planted or its reason
#: stops being true.
NOT_PLANTED = {
    "action_approvals.sqlite3-journal": (
        "SQLite's rollback journal (the ledger's journal mode is `delete`) exists only inside "
        "a write transaction, never at rest where an installer could remove it"),
    "objects, refs and hooks of the capsule store's real git repository": (
        "only a representative repository is planted (its HEAD, config, one ref and one "
        "object), so removing only a part the specimen does not hold would be unseen"),
    "a runtime session file": (
        "written only when `--session-file` is passed, which the shipped launchers never do"),
}


def test_everything_the_product_itself_leaves_on_disk_is_in_the_specimen(tmp_path: Path,
                                                                         monkeypatch):
    """CLASS: a state location the product creates and nobody named. The product
    is RUN, in a scratch folder, and what it leaves is listed: every top-level
    entry of a real capsule store (its git repository, its marker, its seal marker,
    its authority files), every kind of file in its seal directory, and every file
    beside a provisioned approval ledger. Each needs a representative in the
    specimen; a location the product adds is a red test here."""
    from nornyx_forge.capsule import Actor, create_document  # noqa: PLC0415
    from nornyx_forge.capsule_store import CapsuleStore  # noqa: PLC0415
    from nornyx_forge.experience import start_experience  # noqa: PLC0415
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        APPROVAL_LEDGER_ENV,
        DEFAULT_APPROVAL_LEDGER,
        REQUIRED_JOURNAL_MODE,
        approval_ledger_path,
    )

    specimen = set(contract.state_specimen())
    locations = _product_locations()
    casey = Actor("human", "casey")
    capsule_dir, seals_dir = tmp_path / "ForgeProject" / "capsule", tmp_path / "seals"
    CapsuleStore(capsule_dir, seal_dir=seals_dir).initialize(
        create_document("proj-1", "Portal", casey, AT), experience=start_experience(casey, AT))
    capsule = locations["the capsule's authority files"]
    entries = sorted(os.listdir(capsule_dir))
    assert {".git", ".forge-capsule", ".forge-seal", "capsule.json", "experience.json"} <= set(entries)
    for entry in entries:
        assert any(_under(path, f"{capsule}/{entry}") for path in specimen), (
            f"the product leaves {entry} in the capsule store and the specimen plants nothing there")
    seals = locations["the seals"]
    for entry in os.listdir(seals_dir):
        assert any(_under(path, seals) and (Path(path).name == entry or (
            not entry.startswith(".") and Path(path).suffix == Path(entry).suffix))
            for path in specimen), f"the product leaves {entry} in the seal directory"

    monkeypatch.delenv(APPROVAL_LEDGER_ENV, raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    assert _ledger_cli(root)[0] == 0
    ledger = approval_ledger_path(root.resolve())
    planted = f"{capsule.split('/')[0]}/{DEFAULT_APPROVAL_LEDGER}"
    besides = sorted(os.listdir(ledger.parent))
    assert ledger.name in besides and len(besides) >= 2, besides
    for entry in besides:
        assert entry.startswith(ledger.name), entry
        assert planted + entry[len(ledger.name):] in specimen, (
            f"the product leaves {entry} beside the approval ledger and the specimen plants none")
    assert REQUIRED_JOURNAL_MODE == "delete", "a write-ahead journal leaves -wal and -shm files at rest"


def test_what_the_specimen_does_not_plant_is_named_with_its_reason_and_is_not_planted():
    section = _flat(_assumption("A-044"))
    for what, reason in NOT_PLANTED.items():
        assert len(reason) > 50 and _flat(what) in section, what
    assert not [path for path in contract.state_specimen()
                if path.endswith(("-journal", "-wal", "-shm", "session.json"))]


def test_every_governed_location_the_product_names_is_in_the_specimen_and_the_other_way_round():
    """Coverage both ways. Everything the product keeps is planted (a dead
    location would make the scenario blind to it), and everything planted as
    governed state lies under a location the product names or under the project
    folder the launchers pass (a phantom would make it pass over a file the
    product never writes)."""
    from nornyx_forge import capsule_store  # noqa: PLC0415

    locations = _product_locations()
    for what, location in locations.items():
        assert any(_under(path, location) for path in contract.GOVERNED_STATE), (
            f"{what} ({location}) holds no specimen file")
    capsule = locations["the capsule's authority files"]
    for name in (*capsule_store._AUTHORITY_FILES, capsule_store._MARKER_FILE):
        assert f"{capsule}/{name}" in contract.GOVERNED_STATE, name
    project = capsule.split("/")[0]
    for path in contract.GOVERNED_STATE:
        assert any(_under(path, location) for location in locations.values()) or _under(
            path, project), f"{path} is under no location the product names"
    assert any(_under(path, f"{project}/app") for path in contract.GOVERNED_STATE), (
        "the provider's output beside the capsule is planted")


EXPECTED_STATE_SOURCES = frozenset({
    "installer_contract.FORBIDDEN_RECEIPT_NAMES", "installer_contract.STATE_ROOTS",
    "standard_user_checks.STATE_NAMES",
})


def _collections_naming_provider_homes() -> set[str]:
    """`module.NAME` of every assignment, in the installer scripts, the other
    scripts and the product, that holds a collection naming two or more provider
    homes as whole strings. These are the places the code CLASSIFIES something as
    a provider's state; a list added elsewhere is found here and must become a
    source of the derivation below."""
    anchors = {".claude", ".codex", ".crewai"}
    found = set()
    for base in (ROOT / "scripts", ROOT / "src"):
        for path in sorted(base.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    target, value = node.targets[0], node.value
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    target, value = node.target, node.value
                else:
                    continue
                if not isinstance(target, ast.Name):
                    continue
                for inner in ast.walk(value):
                    if isinstance(inner, (ast.Tuple, ast.List, ast.Set)):
                        strings = {item.value for item in inner.elts
                                   if isinstance(item, ast.Constant) and isinstance(item.value, str)}
                        if len(strings & anchors) >= 2:
                            found.add(f"{path.stem}.{target.id}")
    return found


def _protected_name_sources() -> dict[str, set[str]]:
    """Every list that classifies a name as protected state, read from the code:
    the receipt's refused names, the driver's watched names, and the last
    component of each root the driver observes (a root that holds only a
    neighbour is not state)."""
    specimen = contract.state_specimen()
    neighbours = {root for root in contract.STATE_ROOTS
                  if all(path in contract.NEIGHBOURS for path in specimen if _under(path, root))}
    return {
        "installer_contract.FORBIDDEN_RECEIPT_NAMES": set(contract.FORBIDDEN_RECEIPT_NAMES),
        "standard_user_checks.STATE_NAMES": set(driver.STATE_NAMES),
        "installer_contract.STATE_ROOTS": {root.rsplit("/", 1)[-1]
                                           for root in contract.STATE_ROOTS
                                           if root not in neighbours},
    }


def _protected_names() -> dict[str, set[str]]:
    """The names the code classifies as protected state, in any list, casefolded,
    each with the lists that classify it. This is what the specimen has to plant
    and the driver has to observe: not a subset someone picked."""
    names: dict[str, set[str]] = {}
    for source, members in _protected_name_sources().items():
        for name in members:
            names.setdefault(name.casefold(), set()).add(source)
    return names


def _names_in(path: str) -> set[str]:
    """The names a specimen path can be classified by: each component, and each
    component without its extension (`trusted_approvers.json`)."""
    parts = path.split("/")
    return {part.casefold() for part in parts} | {Path(part).stem.casefold() for part in parts}


def test_every_list_that_names_provider_homes_is_a_source_of_the_derivation():
    """CLASS: a classification of state kept in a list nobody derived the
    specimen from. The scripts and the product are searched for every collection
    that names provider homes; each must be one of the sources below, so a new
    one is a red test until it is a source."""
    assert _collections_naming_provider_homes() == set(EXPECTED_STATE_SOURCES)
    assert set(_protected_name_sources()) == set(EXPECTED_STATE_SOURCES)
    assert all(_protected_name_sources().values()), "a source holds no name"


def test_the_derivation_takes_every_name_of_every_source():
    """A name that two lists share would survive a derivation that skipped one of
    them, so each name is derived WITH the lists that classify it."""
    required = _protected_names()
    for source, names in _protected_name_sources().items():
        for name in names:
            assert source in required[name.casefold()], f"{source} is skipped for {name}"
    assert {".crewai", "crewai", ".claude", ".codex", ".config", "forgeproject", ".nornyx",
            ".nornyx-forge", "capsule", "seals", "trusted_approvers",
            "forge_reviewer_trust"} <= set(required)


@pytest.mark.parametrize("name", sorted(_protected_names()))
def test_every_name_the_code_classifies_as_protected_state_is_planted_and_its_deletion_is_seen(
        tmp_path: Path, name: str):
    """CLASS: a name classified as protected state (by the receipt, by the
    driver, by its roots) that the specimen does not plant, or plants where the
    driver does not look. The names come from the code (`_protected_names`), not
    from a list written here. For each place the specimen plants the name, the
    place is removed ALONE and the driver must report exactly that removal."""
    planted = [path for path in (*contract.GOVERNED_STATE, *contract.PROVIDER_STATE)
               if name in _names_in(path)]
    assert planted, f"{name} is classified as protected state and the specimen plants nothing under it"
    for index, path in enumerate(planted):
        (tmp_path / str(index)).mkdir()
        profile = _planted(tmp_path / str(index))
        before = driver.state_snapshot(profile)
        parts = path.split("/")
        depth = next(i for i, part in enumerate(parts)
                     if name in {part.casefold(), Path(part).stem.casefold()}) + 1
        target = profile.joinpath(*parts[:depth])
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        changes = driver.state_changes(before, driver.state_snapshot(profile))
        assert changes and all(change.startswith("removed: ") for change in changes), (name, path)
        assert any(path in change.removeprefix("removed: ") or
                   change.removeprefix("removed: ").rstrip("/") == "/".join(parts[:depth])
                   for change in changes), (name, path, changes)


def test_every_name_the_specimen_plants_is_classified_as_protected_state():
    """The other way round: nothing is planted as state that nothing classifies
    (a stand-in for a file the product never keeps), and a neighbour is not
    classified by any name the code protects."""
    forbidden = {name.casefold() for name in contract.FORBIDDEN_RECEIPT_NAMES}
    watched = {name.casefold() for name in driver.STATE_NAMES}
    for path in (*contract.GOVERNED_STATE, *contract.PROVIDER_STATE):
        names = _names_in(path)
        assert names & forbidden, f"{path} lies under no name the receipt refuses"
        assert names & watched, f"{path} lies under no name the driver watches"
    for source, names in _protected_name_sources().items():
        for name in names:
            assert any(name.casefold() in _names_in(path) for path in contract.state_specimen()
                       if path not in contract.NEIGHBOURS), f"{source}: {name} is planted nowhere"
    for path in contract.NEIGHBOURS:
        assert not (_names_in(path) & set(_protected_names())), f"{path} is a neighbour and must not be state"
    for root in contract.STATE_ROOTS:
        if not any(_under(path, root) for path in (*contract.GOVERNED_STATE,
                                                   *contract.PROVIDER_STATE)):
            continue
        last = root.rsplit("/", 1)[-1].casefold()
        assert last in forbidden and last in watched, f"the root {root} is state nothing classifies"


def test_the_roots_the_driver_lists_hold_the_whole_specimen_and_each_holds_part_of_it():
    specimen = contract.state_specimen()
    assert len(specimen) == len(contract.GOVERNED_STATE) + len(contract.PROVIDER_STATE) + len(
        contract.NEIGHBOURS), "a path is listed twice"
    for path in specimen:
        assert any(_under(path, root) for root in contract.STATE_ROOTS), (
            f"{path} is under no root the driver lists, so a change to it is unseen")
    for root in contract.STATE_ROOTS:
        assert any(_under(path, root) for path in specimen), f"{root} holds no specimen file"
    assert len(set(specimen.values())) == len(specimen), "two files hold the same bytes"
    for data in specimen.values():
        assert data.startswith(contract.SPECIMEN_LABEL) and data.endswith(b"\n")
    for path in specimen:
        assert not path.startswith(("/", "\\")) and ".." not in path.split("/")
        assert not re.match(r"[A-Za-z]:", path)


def test_the_specimen_holds_no_secret_and_no_name_a_secret_scan_would_flag():
    for path, data in contract.state_specimen().items():
        text = data.decode("utf-8")
        assert re.fullmatch(r"[A-Za-z0-9 :/._\-\n]+", text), path
        assert not re.search(r"(?i)(password|secret|token|api[_-]?key|bearer)", text + path), path


# ---------------------------------------------------------------------------
# The driver's pure parts
# ---------------------------------------------------------------------------

def _planted(tmp_path: Path) -> Path:
    profile = tmp_path / "profile"
    profile.mkdir()
    assert driver.seed_state(profile) == []
    return profile


def test_the_specimen_is_planted_in_full_and_never_over_anything_that_is_there(tmp_path: Path):
    profile = _planted(tmp_path)
    for relative, data in contract.state_specimen().items():
        assert profile.joinpath(*relative.split("/")).read_bytes() == data
    before = driver.state_snapshot(profile)
    assert any(name.endswith("/") for name in before), "folders are in the snapshot"
    problems = driver.seed_state(profile)
    assert problems and all("already exists" in problem for problem in problems)
    assert driver.state_changes(before, driver.state_snapshot(profile)) == []
    other = tmp_path / "other"
    other.mkdir()
    (other / ".claude").mkdir()
    (other / ".claude" / "mine.txt").write_text("not the specimen\n", encoding="utf-8")
    assert driver.seed_state(other) == [".claude already exists"]
    assert not (other / ".nornyx").exists(), "nothing is planted beside what was there"


def test_a_refusal_must_be_the_one_asked_for_and_not_another_that_shares_its_exit_code():
    log = ("refused (13): C:\\x already holds files and no install-receipt.json, so it is not a "
           "Forge install this setup made.")
    assert driver.refusal_problems(13, log, 13, "so it is not a Forge install this setup made") == []
    assert driver.refusal_problems(13, log, 13) == [], "without words the exit code alone decides"
    other = driver.refusal_problems(13, log, 13, "exists and is not a folder")
    assert len(other) == 1 and "exists and is not a folder" in other[0]
    assert driver.refusal_problems(14, log, 13)[0].startswith("exit code 14")


def _each_change(profile: Path) -> dict[str, Callable[[], object]]:
    governed = profile / "ForgeProject" / "capsule" / "experience.json"
    provider = profile / ".codex" / "config.toml"
    neighbour = profile / "AppData" / "Local" / "Programs" / "Neighbour App" / "neighbour.txt"
    crew = profile / "AppData" / "Local" / "CrewAI" / "Nornyx Forge"

    def rewrite_same_bytes() -> None:
        data = governed.read_bytes()
        governed.write_bytes(data)
        os.utime(governed, ns=(1, 1))

    def rewrite_other_bytes_same_time() -> None:
        stamp = governed.stat().st_mtime_ns
        data = governed.read_bytes()
        governed.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        os.utime(governed, ns=(stamp, stamp))

    return {
        "removed: ForgeProject/capsule/experience.json": governed.unlink,
        "changed: ForgeProject/capsule/experience.json (other bytes, the same time)":
            rewrite_other_bytes_same_time,
        "changed: ForgeProject/capsule/experience.json":
            lambda: governed.write_bytes(governed.read_bytes() + b"x"),
        "changed: ForgeProject/capsule/experience.json (the same bytes, another time)":
            rewrite_same_bytes,
        "removed: .codex/config.toml": provider.unlink,
        "removed: AppData/Local/Programs/Neighbour App/neighbour.txt": neighbour.unlink,
        "removed: AppData/Local/CrewAI/Nornyx Forge/storage.db":
            (crew / "storage.db").unlink,
        "added: .nornyx/forge/seals/stray.json":
            lambda: (profile / ".nornyx" / "forge" / "seals" / "stray.json").write_text("x"),
        "added: ForgeProject/capsule/stray/": (profile / "ForgeProject" / "capsule" / "stray").mkdir,
    }


@pytest.mark.parametrize("expected", sorted(_each_change(Path("."))))
def test_a_removed_added_changed_or_retimed_file_or_folder_is_a_change(tmp_path: Path,
                                                                      expected: str):
    profile = _planted(tmp_path)
    before = driver.state_snapshot(profile)
    assert driver.state_changes(before, driver.state_snapshot(profile)) == []
    _each_change(profile)[expected]()
    changes = driver.state_changes(before, driver.state_snapshot(profile))
    wanted = expected.split(" (")[0]
    assert wanted in changes, (wanted, changes)


def test_a_removed_folder_with_nothing_in_it_is_a_change(tmp_path: Path):
    profile = _planted(tmp_path)
    (profile / ".claude" / "empty").mkdir()
    before = driver.state_snapshot(profile)
    (profile / ".claude" / "empty").rmdir()
    assert driver.state_changes(before, driver.state_snapshot(profile)) == [
        "removed: .claude/empty/"]


def _calls(source: str, name: str) -> list[str]:
    """The names of the functions `name` calls, in source order."""
    tree = ast.parse(source)
    function = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef) and node.name == name)
    calls = []
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            target = node.func
            label = target.id if isinstance(target, ast.Name) else (
                target.attr if isinstance(target, ast.Attribute) else None)
            if label:
                calls.append((node.lineno, node.col_offset, label))
    return [label for _line, _col, label in sorted(calls)]


def test_the_scenario_compares_the_whole_specimen_after_every_run_it_makes():
    """Structure, not effect (the effect is the `windows-install` job's): the
    scenario is reached from the standard-user run, plants before it runs
    anything, replays the refusals before it installs, and every run of an
    installer, whether it installs or refuses, is followed by a comparison before
    the next one, in the scenario and in the replay of the refusals. A run that is
    not followed by one is a path the scenario does not judge."""
    source = DRIVER.read_text(encoding="utf-8")
    standard = source[source.index("def mode_standard_user"):source.index("def check_install")]
    assert "state_survival(work," in standard
    first = standard[standard.index("refusal_runs("):]
    first = first[:first.index(")\n") + 1]
    assert "after=" not in first and "prefix=" not in first, (
        "the first pass judges what a refusal leaves of the installer's folders, in a clean profile")
    order = [name for name in _calls(source, "state_survival")
             if name in ("seed_state", "state_snapshot", "refusal_runs", "run_setup", "refused",
                         "unchanged")]
    assert order[:2] == ["seed_state", "state_snapshot"], order
    replay = order.index("refusal_runs")
    assert replay < min(index for index, name in enumerate(order) if name in ("run_setup", "refused")), (
        "the refusals are replayed before the first install")
    body = source[source.index("def state_survival"):source.index("def main")]
    assert 'prefix="state-", after=unchanged' in body, "the replay is compared after each run"
    runs = [index for index, name in enumerate(order) if name in ("run_setup", "refused")]
    assert len(runs) >= 8, "fresh, again, other, same-version, reinstall, unfinished, failed, recovered"
    for position, index in enumerate(runs):
        following = order[index + 1:runs[position + 1]] if position + 1 < len(runs) else order[index + 1:]
        assert "unchanged" in following, f"run {position} is not followed by a comparison: {order}"
    replayed = [name for name in _calls(source, "refusal_runs") if name in ("run", "after")]
    assert replayed.count("run") >= 9, "every refusal the replay makes goes through `run`"
    for position, name in enumerate(replayed):
        if name == "run":
            assert replayed[position + 1:position + 2] == ["after"], (
                f"a refusal is not followed by a comparison: {replayed}")
    assert "state_changes(baseline, state_snapshot(profile))" in body
    assert "expect(not changes" in body
    removed = body.index('unchanged("the install folder and the shortcut were removed')
    for removal in ("shutil.rmtree(root)", "shortcut_path.unlink("):
        assert removal in body[max(0, removed - 200):removed], (
            "the removal a refusal message directs is made, then compared")
    for exit_name in ("EXIT_OTHER_VERSION", "EXIT_DOES_NOT_VERIFY", "EXIT_UNFINISHED",
                      "EXIT_FAILED"):
        assert f'codes["{exit_name}"]' in body, exit_name


def test_the_scenario_removes_exactly_the_folder_the_receipt_describes():
    body = DRIVER.read_text(encoding="utf-8")
    body = body[body.index("def state_survival"):body.index("def main")]
    assert 'sorted(os.listdir(root)) == owned' in body
    assert 'item["kind"] != "shortcut"' in body and "contract.RECEIPT_NAME" in body
    launch = DRIVER.read_text(encoding="utf-8")
    launch = launch[launch.index("def mode_standard_user"):launch.index("def check_install")]
    assert "sorted(os.listdir(root)) == sorted([folder.name, contract.RECEIPT_NAME])" in launch


def test_the_scenario_runs_after_everything_that_judges_the_profile_as_a_whole():
    """The earlier checks list the profile and expect no state-class name in it;
    the specimen is planted last so it cannot be read as an install's doing."""
    source = DRIVER.read_text(encoding="utf-8")
    body = source[source.index("def mode_standard_user"):source.index("def check_install")]
    assert body.index("check_install(") < body.index("state_survival(")
    assert body.index("launch_checks(") < body.index("state_survival(")
    assert body.rstrip().endswith("start_menu=start_menu)")


#: The refusal each run of the scenario printed when the real installer ran on
#: Windows (the `windows-install` job on the head before this one), by the tag of
#: the run. The stand-in installer below must print the same refusal for the same
#: run: it is checked against this table, so a stand-in that prints what the
#: script's text suggests, and not what Windows printed, is a red test.
WINDOWS_PRINTED = {
    "state-long": "would create file paths of up to",
    "state-location-outside": "is outside your profile folder",
    "state-location-unc": "is not a plain drive path",
    "state-stranger": "so it is not a Forge install this setup made",
    "state-not-a-folder": "exists and is not a folder",
    "state-receipt-folder": "is not a plain file",
    "state-version-file": "is not a plain folder",
    "state-junction": "is a link (a junction or symbolic link)",
    "state-partial-receipt": "An earlier install did not finish",
    "state-partial-bare": "An earlier install did not finish",
    "state-shortcut-file": "already exists and Setup does not replace it",
    "state-shortcut-folder": "already exists and Setup does not replace it",
    "state-other": "Another version of Forge is installed",
    "state-same-version": "is not the payload this Setup carries",
    "state-unfinished": "An earlier install did not finish",
    "state-failed": "could not create the Start-menu shortcut",
}


class _FakeSetup:
    """The observable surface of ForgeSetup.exe that the scenario reads (an exit
    code, a log line, and the files left behind), following the script's order
    of decisions (the location, the path budget, `DecideExisting`, the
    shortcut's name) and its failure after the folder is in place. Each refusal
    says what the script's own message says: the log line is read from the
    script, by the words the driver asks for. It is a stand-in, built after
    reading that rule, and it stands for the installer only as far as the
    scenario can see: whether the real one behaves like it is the
    `windows-install` job's. `damage` names the run (`run_setup`'s tag) after
    which it also deletes one provider file, which is what an installer that
    destroyed state would look like to the scenario."""

    def __init__(self, tmp_path: Path, profile: Path, damage: str | None = None, *,
                 force: dict[str, str] | None = None, ran: list | None = None):
        self.force, self.ran = force or {}, ran
        self.root = tmp_path / "Programs" / "Nornyx Forge"
        self.start_menu = tmp_path / "StartMenu"
        self.start_menu.mkdir()
        self.shortcut = self.start_menu / contract.SHORTCUT_NAME
        self.profile, self.damage, self.denied, self.redirect = profile, damage, False, None
        self.manifests = {
            "real": {**MANIFEST, "version": "1.2.3"},
            "small": {**MANIFEST, "version": "0.0.1", "source_commit": "b" * 40},
            "other": {**MANIFEST, "version": "0.0.2"},
            "same-version": {**MANIFEST, "version": "1.2.3"},
            "long": {**MANIFEST, "version": "0.0.3", "source_commit": "d" * 40},
        }
        self.exes = {name: tmp_path / "artifact" / name / "ForgeSetup.exe" for name in self.manifests}

    def run(self, exe: Path, work: Path, tag: str, *, env=None, timeout: int = 0):
        kind = exe.parent.name
        version = contract.version_directory(self.manifests[kind])
        self._heal()
        code, log = self._decide(kind, version)
        if tag in self.force:  # a same-exit sibling refusal, to show it is not accepted
            code, log = _refusal(self.force[tag])
        if self.ran is not None:
            self.ran.append((tag, code, log))
        if tag == self.damage:
            self.damaged = self.profile / ".codex" / "config.toml"
            self.kept = (self.damaged.read_bytes(), self.damaged.stat().st_mtime_ns)
            self.damaged.unlink()
        print(f"  {kind} -> exit {code}")
        return code, log

    def _heal(self) -> None:
        """Put a damaged file back before the next run, as it was: the damage is
        then visible to the comparison made right after the run that did it, and
        to no later one, so each comparison has to be there to see its own."""
        if getattr(self, "damaged", None) is not None:
            data, stamp = self.kept
            self.damaged.write_bytes(data)
            os.utime(self.damaged, ns=(stamp, stamp))
            self.damaged = None

    def _decide(self, kind: str, version: str) -> tuple[int, str]:
        root = self.root
        if self.redirect is not None:
            # Windows resolves a Local AppData folder moved to a network path to
            # nothing (measured), so the location is a bare `\Programs\...` and the
            # drive-path check refuses it, not the network-spelling check.
            return _refusal("is not a plain drive path" if self.redirect.startswith(
                "\\\\") else "is outside your profile folder")
        if root.is_symlink():
            return _refusal("is a link (a junction or symbolic link)")
        if kind == "long":
            return _refusal("would create file paths of up to")
        if root.exists():
            if not root.is_dir():
                return _refusal("exists and is not a folder")
            if (root / (version + contract.PARTIAL_SUFFIX)).exists():
                return _refusal("An earlier install did not finish")
            if os.listdir(root):
                receipt = root / contract.RECEIPT_NAME
                if not receipt.exists():
                    return _refusal("so it is not a Forge install this setup made")
                if receipt.is_dir():
                    return _refusal("is not a plain file")
                if not (root / version).exists():
                    return _refusal("Another version of Forge is installed")
                if not (root / version).is_dir():
                    return _refusal("is not a plain folder")
                if kind == "same-version":
                    return _refusal("is not the payload this Setup carries")
                return 0, "already installed: verified"
        if self.shortcut.exists():
            return _refusal("already exists and Setup does not replace it")
        root.mkdir(parents=True, exist_ok=True)
        (root / version).mkdir()
        (root / version / "forge-payload.json").write_text("{}", encoding="utf-8")
        if self.denied:
            return _refusal("could not create the Start-menu shortcut")
        self.shortcut.write_text("shortcut", encoding="utf-8")
        (root / contract.RECEIPT_NAME).write_text(
            contract.render_receipt(self.manifests[kind], git="found", root_created=True),
            encoding="utf-8")
        return 0, f"installed {version}; git found"

    def icacls(self, argv, **_):
        if "/deny" in argv:
            self.denied = True
        elif "/remove:d" in argv:
            self.denied = False
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    @contextlib.contextmanager
    def redirected(self, target: str):
        self.redirect = target
        try:
            yield
        finally:
            self.redirect = None

    @staticmethod
    def make_junction(link: Path, target: Path) -> None:
        os.symlink(target, link, target_is_directory=True)

    @staticmethod
    def remove_junction(link: Path) -> None:
        link.unlink()


def _run_scenario(tmp_path: Path, monkeypatch, damage: str | None,
                  seen: list[tuple[int, str]] | None = None, *,
                  force: dict[str, str] | None = None, ran: list | None = None) -> list[str]:
    """`state_survival` over a profile in `tmp_path` and the stand-in installer;
    the observations it reports as failed. `seen` collects the (exit code,
    words) of every refusal the scenario asked a run to be."""
    from types import SimpleNamespace  # noqa: PLC0415

    profile = tmp_path / "profile"
    profile.mkdir()
    fake = _FakeSetup(tmp_path, profile, damage, force=force, ran=ran)
    monkeypatch.setattr(driver, "run_setup", fake.run)
    monkeypatch.setattr(driver, "subprocess", SimpleNamespace(run=fake.icacls))
    monkeypatch.setattr(driver, "redirected_local_appdata", fake.redirected)
    monkeypatch.setattr(driver, "make_junction", fake.make_junction)
    monkeypatch.setattr(driver, "remove_junction", fake.remove_junction)
    monkeypatch.setattr(driver, "FAILURES", [])
    if seen is not None:
        real = driver.refusal_problems

        def spy(got, log, wanted, fragment=""):
            seen.append((wanted, fragment))
            return real(got, log, wanted, fragment)

        monkeypatch.setattr(driver, "refusal_problems", spy)
    codes = contract.exit_codes(contract.nsi_text())
    driver.state_survival(
        tmp_path / "work", profile=profile, user="forgeci", real_exe=fake.exes["real"],
        variants={name: fake.exes[name].parent
                  for name in ("small", "other", "same-version", "long")},
        manifest=fake.manifests["real"], small_manifest=fake.manifests["small"], codes=codes,
        root=fake.root, shortcut_path=fake.shortcut, start_menu=fake.start_menu)
    return list(driver.FAILURES)


def test_the_scenario_passes_an_installer_that_leaves_the_specimen_alone(tmp_path: Path,
                                                                        monkeypatch, capsys):
    failures = _run_scenario(tmp_path, monkeypatch, damage=None)
    assert failures == []
    output = capsys.readouterr().out
    assert output.count("PASS [state]") >= 40, output


def test_the_stand_in_prints_the_refusal_windows_printed_for_every_run(tmp_path: Path, monkeypatch):
    """CLASS: a stand-in that agrees with the driver because both were written
    from the script's text. Each refusal the stand-in prints for a run is found by
    the script's own words and must be the one the real installer printed."""
    ran: list = []
    assert _run_scenario(tmp_path, monkeypatch, damage=None, ran=ran) == []
    printed = {}
    for tag, _code, log in ran:
        if "refused (" in log:
            hits = [entry[2] for entry in REFUSALS if entry[2] in log]
            assert len(hits) == 1, (tag, hits)
            printed[tag] = hits[0]
    assert printed == WINDOWS_PRINTED, {tag: (printed.get(tag), WINDOWS_PRINTED.get(tag))
                                        for tag in set(printed) | set(WINDOWS_PRINTED)
                                        if printed.get(tag) != WINDOWS_PRINTED.get(tag)}


def _same_exit_siblings() -> list[tuple[str, str]]:
    """(run tag, another refusal of the same exit code as the one it expects)."""
    sites = _refusal_sites(contract.nsi_text())
    code_of = {fragment: code for _where, code, fragment, *_ in REFUSALS}
    return [(tag, sibling) for tag, printed in sorted(WINDOWS_PRINTED.items())
            for sibling in code_of if sibling != printed and code_of[sibling] == code_of[printed]
            and any(sibling in message for _w, _c, message in sites)]


@pytest.mark.parametrize("tag, sibling", _same_exit_siblings())
def test_a_refusal_that_shares_the_exit_code_of_the_expected_one_is_not_accepted(
        tmp_path: Path, monkeypatch, tag: str, sibling: str):
    """CLASS: a case that provokes one refusal but could be satisfied by another
    of the same exit code (an exit code alone cannot tell them apart). Whatever
    run is forced to print a sibling, the scenario must report that run's
    observation as failed, so the words a case expects are exactly its refusal."""
    failures = _run_scenario(tmp_path, monkeypatch, damage=None, force={tag: sibling})
    assert any("the refusal is not the one that says" in failure for failure in failures), (
        tag, sibling, failures)


def test_the_scenario_replays_exactly_the_refusals_the_list_says_it_does(tmp_path: Path,
                                                                        monkeypatch):
    """CLASS: a refusal the scenario claims to judge against the specimen and
    does not run, or runs without saying which one it is. The refusals the
    scenario asked a run to be (an exit code AND the words of one message) are
    the REPLAYED ones of `REFUSALS`, no more and no fewer."""
    seen: list[tuple[int, str]] = []
    assert _run_scenario(tmp_path, monkeypatch, damage=None, seen=seen) == []
    codes = contract.exit_codes(contract.nsi_text())
    claimed = {(codes[code], fragment) for _where, code, fragment, status, _why in REFUSALS
               if status == REPLAYED}
    assert set(seen) == claimed, (f"asked but not listed: {sorted(set(seen) - claimed)}; "
                                  f"listed but not asked: {sorted(claimed - set(seen))}")


#: Each run the scenario makes, and the words of the comparison made right after it.
STEPS = {
    "state-long": "after paths of 297 characters were refused,",
    "state-location-outside": "after a location outside the profile was refused,",
    "state-location-unc": "after a UNC location was refused,",
    "state-stranger": "after a folder that is not Forge's was refused,",
    "state-not-a-folder": "after a file where the install folder goes was refused,",
    "state-receipt-folder": "after a folder where the receipt goes was refused,",
    "state-version-file": "after a file where the version folder goes was refused,",
    "state-junction": "after a junction at the install folder was refused,",
    "state-partial-receipt": "after an unfinished earlier install with a receipt was refused,",
    "state-partial-bare": "after an unfinished earlier install with no receipt (a failed first "
                          "install) was refused,",
    "state-shortcut-file": "after a file already named like the shortcut was refused,",
    "state-shortcut-folder": "after a folder already named like the shortcut was refused,",
    "state-install": "after a fresh install,",
    "state-again": "after the same payload run again,",
    "state-other": "after another version was refused,",
    "state-same-version": "after other bytes under the same version were refused,",
    "state-reinstall": "after Setup was run again after that removal,",
    "state-unfinished": "after an unfinished earlier install was refused,",
    "state-failed": "after an install that failed after the folder was in place,",
    "state-recovered": "after the advised removal and a new install,",
}


@pytest.mark.parametrize("step", sorted(STEPS))
def test_the_scenario_fails_when_an_installer_destroys_a_provider_file_in_any_one_run(
        tmp_path: Path, monkeypatch, step: str):
    """CLASS: a comparison that is skipped, misplaced or made against the wrong
    baseline. An installer that deletes `~/.codex/config.toml` in ONE run, and
    whose damage is put back before the next, is seen by the comparison made
    right after that run or by none: the scenario must report exactly that
    comparison as failed. Every run, the refusals replayed before the install
    included."""
    failures = _run_scenario(tmp_path, monkeypatch, damage=step)
    state = [failure for failure in failures if "exactly as planted" in failure]
    # No run lies between the last refusal before the removal and the comparison
    # made after the removal, so that damage is seen by both.
    wanted = 2 if step == "state-same-version" else 1
    assert len(state) == wanted, (step, failures)
    assert STEPS[step] in state[0] and "removed: .codex/config.toml" in state[0], state


def test_every_run_of_the_scenario_is_in_the_table_of_steps(tmp_path: Path, monkeypatch):
    """The table above is the scenario's runs, not a sample: a run the scenario
    makes that the table does not name is a run no test proves a comparison
    follows."""
    ran: list[str] = []
    real = _FakeSetup.run

    def record(self, exe, work, tag, **kwargs):
        ran.append(tag)
        return real(self, exe, work, tag, **kwargs)

    monkeypatch.setattr(_FakeSetup, "run", record)
    assert _run_scenario(tmp_path, monkeypatch, damage=None) == []
    assert sorted(ran) == sorted(STEPS), (sorted(set(ran) ^ set(STEPS)), ran)


def test_the_scenario_refuses_to_start_in_a_profile_that_already_holds_part_of_the_specimen(
        tmp_path: Path, monkeypatch):
    profile = tmp_path / "profile"
    (profile / ".claude").mkdir(parents=True)
    (profile / ".claude" / "mine.txt").write_text("the person's own\n", encoding="utf-8")
    fake = _FakeSetup(tmp_path, profile)
    monkeypatch.setattr(driver, "run_setup", fake.run)
    monkeypatch.setattr(driver, "FAILURES", [])
    driver.state_survival(
        tmp_path / "work", profile=profile, user="forgeci", real_exe=fake.exes["real"],
        variants={name: fake.exes[name].parent for name in ("small", "other", "same-version")},
        manifest=fake.manifests["real"], small_manifest=fake.manifests["small"],
        codes=contract.exit_codes(contract.nsi_text()), root=fake.root,
        shortcut_path=fake.shortcut, start_menu=fake.start_menu)
    assert driver.FAILURES and ".claude already exists" in driver.FAILURES[0]
    assert (profile / ".claude" / "mine.txt").read_text(encoding="utf-8") == "the person's own\n"
    assert not fake.root.exists(), "no installer ran against a profile it could not judge"


# ---------------------------------------------------------------------------
# The product's own reset paths
# ---------------------------------------------------------------------------

def _tree(root: Path, skip: tuple[str, ...] = ()) -> dict[str, str]:
    """The bytes of every file under `root`, by relative path, except what lies
    at or under a relative path in `skip`. Nothing is excluded by its name."""
    found = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_file() and not any(relative == part or relative.startswith(part + "/")
                                      for part in skip):
            found[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


def _repository_state(git_dir: Path) -> dict[str, object]:
    """A repository's own metadata: the bytes of every file in it (HEAD, config,
    the index, refs, objects, logs) and the folders it holds, empty ones too."""
    return {"files": _tree(git_dir),
            "folders": sorted(path.relative_to(git_dir).as_posix()
                              for path in git_dir.rglob("*") if path.is_dir())}


def _parent_repository(project: Path) -> None:
    """The project as a provider's workspace often is: a git repository with a
    tracked file, so that it has an index, a ref and an object of its own."""
    project.mkdir(exist_ok=True)
    subprocess.run(["git", "init", "--quiet"], cwd=project, check=True, capture_output=True)
    (project / "app").mkdir(exist_ok=True)
    (project / "app" / "main.py").write_text("print('the person built this')\n", encoding="utf-8")
    subprocess.run(["git", "add", "app/main.py"], cwd=project, check=True, capture_output=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit",
                    "--quiet", "-m", "the person's own work"],
                   cwd=project, check=True, capture_output=True)


def _world(root: Path, skip: tuple[str, ...] = (), loose: tuple[str, ...] = ()) -> dict[str, object]:
    """Everything under `root` except what lies at or under a path in `skip`: each
    file by its bytes, size, modification time and mode, each folder (empty ones
    too). Under a path in `loose` a file is compared by its bytes alone, because
    the restoration legitimately rewrites those files with the bytes they had."""
    def inside(relative: str, prefixes: tuple[str, ...]) -> bool:
        return any(relative == prefix or relative.startswith(prefix + "/") for prefix in prefixes)

    files: dict[str, object] = {}
    folders = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if inside(relative, skip):
            continue
        if path.is_dir():
            folders.append(relative)
        elif path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if inside(relative, loose):
                files[relative] = digest
            else:
                status = path.stat()
                files[relative] = (digest, status.st_size, status.st_mtime_ns, status.st_mode)
    return {"files": files, "folders": folders}


def _own_seal_problems(before: dict, after: dict, *, store: str, revision: str) -> list[str]:
    """Whether a store's own seal was rewritten the permitted way: the same
    schema, the same fields, the same store, the same authority files (the
    sealed bytes), and the revision the store stands at now."""
    problems = []
    if set(after) != set(before):
        problems.append(f"fields differ: {sorted(set(after) ^ set(before))}")
    for field in ("schema", "files"):
        if after.get(field) != before.get(field):
            problems.append(f"{field} differs")
    if after.get("store") != store:
        problems.append(f"names another store: {after.get('store')!r}")
    if after.get("revision") != revision:
        problems.append("does not name the revision the store stands at")
    return problems


_PARENT_CHANGES = {
    "the index rewritten": lambda git: git.joinpath("index").write_bytes(
        git.joinpath("index").read_bytes() + b"\0"),
    "a ref moved": lambda git: next(git.joinpath("refs", "heads").iterdir()).write_text(
        "0" * 40 + "\n", encoding="utf-8"),
    "HEAD pointed elsewhere": lambda git: git.joinpath("HEAD").write_text(
        "ref: refs/heads/elsewhere\n", encoding="utf-8"),
    "an object added": lambda git: (git / "objects" / "zz").mkdir() or (
        git / "objects" / "zz" / "added").write_text("x", encoding="utf-8"),
    "an empty folder added": lambda git: (git / "objects" / "yy").mkdir(),
    "the config rewritten": lambda git: git.joinpath("config").write_text(
        "[core]\n", encoding="utf-8"),
}


@pytest.mark.parametrize("change", sorted(_PARENT_CHANGES))
def test_the_restoration_check_sees_a_change_to_the_enclosing_repository(tmp_path: Path,
                                                                        change: str):
    """The check that the restoration stays inside the capsule must be able to
    fail on the repository AROUND the project (a provider's workspace): its
    index, a ref, HEAD, an object, a folder or its config."""
    project = tmp_path / "ForgeProject"
    _parent_repository(project)
    git = project / ".git"
    before = _repository_state(git)
    assert {"HEAD", "index", "config"} <= set(before["files"])
    assert any(name.startswith("refs/heads/") for name in before["files"])
    assert any(name.startswith("objects/") for name in before["files"])
    assert _repository_state(git) == before, "the snapshot is stable when nothing changes"
    _PARENT_CHANGES[change](git)
    assert _repository_state(git) != before, change


@pytest.mark.parametrize("route", ["reset-to-the-sealed-revision", "rebuild"])
def test_restoring_the_capsule_rewrites_its_own_seal_and_nothing_else_beside_it(tmp_path: Path,
                                                                                route: str):
    """The restoration is the one place the product rewrites a person's
    directory on its own account. What it writes outside the capsule store is ONE
    file: this store's own seal (`self.seal()` ends it, `os.replace` of a
    temporary file onto `<ident>.json` in the seal directory). Nothing else under
    the scratch root changes, in bytes, size, time, mode or folders: the
    provider's output beside the capsule, the git workspace around the project,
    a second project's seal and every other file. The own seal is checked
    explicitly: same place, same fields, same store, the sealed authority bytes,
    the revision the store stands at. Both routes: the honest one (reset to the
    sealed revision, clean what the seal does not know) and the rebuild when the
    repository is gone. The project is itself a git repository, because a
    provider's workspace often is, and a clean run from the wrong directory would
    take the neighbours with it. (A store given a witness also records the new
    seal in memory, which is no file.)"""
    from nornyx_forge.capsule import Actor, create_document  # noqa: PLC0415
    from nornyx_forge.capsule_store import CapsuleStore, _remove_tree  # noqa: PLC0415
    from nornyx_forge.experience import start_experience  # noqa: PLC0415

    project, seals = tmp_path / "ForgeProject", tmp_path / "seals"
    _parent_repository(project)
    store = CapsuleStore(project / "capsule", seal_dir=seals)
    casey = Actor("human", "casey")
    store.initialize(create_document("proj-1", "Portal", casey, AT),
                     experience=start_experience(casey, AT))
    (project / "notes.txt").write_text("untracked, beside the capsule\n", encoding="utf-8")
    (seals / "other-project.json").write_text('{"another": "project"}\n', encoding="utf-8")
    capsule = project / "capsule"
    own = store.seal_path()
    assert own is not None and own.parent == seals and own.is_file()
    own_relative = own.relative_to(tmp_path).as_posix()
    # What the restoration may change: the capsule store (its own repository
    # included; its other files are compared by bytes) and its own seal.
    skip = ("ForgeProject/capsule/.git", own_relative)
    world_before = _world(tmp_path, skip=skip, loose=("ForgeProject/capsule",))
    parent_before = _repository_state(project / ".git")
    own_before = json.loads(own.read_text(encoding="utf-8"))
    assert {"HEAD", "index"} <= set(parent_before["files"]), "the parent repository is a real one"
    assert set(world_before["files"]) >= {"seals/other-project.json", "ForgeProject/notes.txt"}
    sealed = store.sealed()

    (capsule / "experience.json").write_text("{}\n", encoding="utf-8")
    (capsule / "stray.txt").write_text("left in the capsule\n", encoding="utf-8")
    if route == "rebuild":
        _remove_tree(capsule / ".git")
    revision, notes = store.restore(sealed)

    assert bool(notes) is (route == "rebuild"), (route, notes)
    assert not (capsule / "stray.txt").exists(), "the restoration did clean the capsule"
    assert store.seal_problems(store.sealed()) == []
    assert revision == store.revision()
    assert own.is_file(), "the store's own seal is where it was"
    assert _own_seal_problems(own_before, json.loads(own.read_text(encoding="utf-8")),
                              store=str(capsule.resolve()), revision=revision) == []
    assert _world(tmp_path, skip=skip, loose=("ForgeProject/capsule",)) == world_before, (
        "the restoration changed something beside the capsule other than its own seal")
    assert _repository_state(project / ".git") == parent_before, (
        "the restoration touched the repository around the project")
    assert sorted(path.name for path in seals.iterdir()) == sorted(
        [own.name, "other-project.json"]), "the seal directory holds the two seals and no more"


def _scratch_world(root: Path) -> tuple[Path, Path]:
    """A tree shaped like the one the restoration test builds, without a store."""
    (root / "ForgeProject" / "capsule" / ".git").mkdir(parents=True)
    (root / "ForgeProject" / "capsule" / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")
    (root / "ForgeProject" / "capsule" / "capsule.json").write_text("{}\n", encoding="utf-8")
    (root / "ForgeProject" / "notes.txt").write_text("notes\n", encoding="utf-8")
    (root / "seals").mkdir()
    own, other = root / "seals" / "own.json", root / "seals" / "other-project.json"
    own.write_text("{}\n", encoding="utf-8")
    other.write_text('{"another": "project"}\n', encoding="utf-8")
    return own, other


_SCRATCH_SKIP = ("ForgeProject/capsule/.git", "seals/own.json")
_SCRATCH_LOOSE = ("ForgeProject/capsule",)
_BESIDE_CHANGES = {
    "another project's seal rewritten": lambda own, other: other.write_text("{}\n", encoding="utf-8"),
    "another project's seal touched": lambda own, other: os.utime(other, ns=(1, 1)),
    "another project's seal removed": lambda own, other: other.unlink(),
    "a second file written beside the seal": lambda own, other: own.with_name("own.json.tmp").write_text("x"),
    "the seal moved to another location": lambda own, other: own.rename(own.with_name("moved.json")),
    "a file written beside the seal directory": lambda own, other: own.parent.parent.joinpath(
        "stray.txt").write_text("x"),
    "a folder added beside the seal": lambda own, other: own.parent.joinpath("extra").mkdir(),
    "a file in the project beside the capsule changed": lambda own, other: own.parent.parent.joinpath(
        "ForgeProject", "notes.txt").write_text("changed\n", encoding="utf-8"),
    "a file in the capsule changed to other bytes": lambda own, other: own.parent.parent.joinpath(
        "ForgeProject", "capsule", "capsule.json").write_text("{\"x\": 1}\n", encoding="utf-8"),
}


@pytest.mark.parametrize("change", sorted(_BESIDE_CHANGES))
def test_the_restoration_check_sees_a_change_beside_the_capsule_and_beside_the_seal(
        tmp_path: Path, change: str):
    own, other = _scratch_world(tmp_path)
    before = _world(tmp_path, skip=_SCRATCH_SKIP, loose=_SCRATCH_LOOSE)
    assert _world(tmp_path, skip=_SCRATCH_SKIP, loose=_SCRATCH_LOOSE) == before
    # The permitted change: the store's own seal rewritten, the capsule's files
    # rewritten with the bytes they had (and a new time).
    own.write_text('{"rewritten": true}\n', encoding="utf-8")
    capsule_json = tmp_path / "ForgeProject" / "capsule" / "capsule.json"
    capsule_json.write_text(capsule_json.read_text(encoding="utf-8"), encoding="utf-8")
    assert _world(tmp_path, skip=_SCRATCH_SKIP, loose=_SCRATCH_LOOSE) == before, (
        "the permitted change is not a difference")
    _BESIDE_CHANGES[change](own, other)
    assert _world(tmp_path, skip=_SCRATCH_SKIP, loose=_SCRATCH_LOOSE) != before, change


_OWN_SEAL_BEFORE = {"schema": "s", "store": "/a/capsule", "revision": "r1",
                    "files": {"capsule.json": "hash-a", "experience.json": "hash-b"}}


@pytest.mark.parametrize("label, after", [
    ("another store's identity", {**_OWN_SEAL_BEFORE, "store": "/b/capsule", "revision": "r2"}),
    ("another schema", {**_OWN_SEAL_BEFORE, "schema": "t", "revision": "r2"}),
    ("a changed authority file", {**_OWN_SEAL_BEFORE, "files": {"capsule.json": "x",
                                                                "experience.json": "hash-b"},
                                  "revision": "r2"}),
    ("an added field", {**_OWN_SEAL_BEFORE, "extra": 1, "revision": "r2"}),
    ("a revision the store is not at", {**_OWN_SEAL_BEFORE, "revision": "r3"}),
])
def test_the_own_seal_check_refuses_a_seal_that_is_not_the_permitted_rewrite(label: str, after: dict):
    assert _own_seal_problems(_OWN_SEAL_BEFORE, {**_OWN_SEAL_BEFORE, "revision": "r2"},
                              store="/a/capsule", revision="r2") == []
    assert _own_seal_problems(_OWN_SEAL_BEFORE, after, store="/a/capsule", revision="r2"), label


def _ledger_cli(root: Path, *flags: str) -> tuple[int, dict | None, str]:
    from typer.testing import CliRunner  # noqa: PLC0415

    from nornyx_forge.cli import app  # noqa: PLC0415

    result = CliRunner().invoke(app, ["provision-ledger", "--root", str(root), *flags])
    try:
        parsed = json.loads(result.output)
    except ValueError:
        parsed = None
    return result.exit_code, parsed, result.output


def test_the_ledger_is_reset_only_when_asked_and_the_command_says_it_did(tmp_path: Path,
                                                                         monkeypatch):
    """The operator's repair that DISCARDS approvals is behind its own flag, is
    not what a plain run does to an existing ledger, and reports `reset` when it
    ran, so neither a re-run of provisioning nor the reset is a silent loss."""
    from nornyx_forge.nornyx_runtime import (  # noqa: PLC0415
        APPROVAL_LEDGER_ENV,
        LEDGER_WATERMARK_SUFFIX,
        approval_ledger_path,
    )

    monkeypatch.delenv(APPROVAL_LEDGER_ENV, raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    location = approval_ledger_path(root.resolve())
    code, created, _output = _ledger_cli(root)
    assert code == 0 and created and created["action"] == "created"
    watermark = location.with_name(location.name + LEDGER_WATERMARK_SUFFIX)
    kept = {path: path.read_bytes() for path in (location, watermark)}
    before = _tree(root)

    for _ in range(2):
        code, again, output = _ledger_cli(root)
        assert code == 0 and again and again["action"] == "left_unchanged", output
        assert {path: path.read_bytes() for path in kept} == kept, (
            "a plain run changed an existing ledger or its mark")
        assert _tree(root) == before, "a plain run changed or added a file anywhere under the root"

    code, reset, output = _ledger_cli(root, "--reset-replay-history")
    assert code == 0 and reset and reset["action"] == "reset", output
    assert location.is_file() and watermark.is_file(), "the reset leaves a provisioned ledger"
    after = _tree(root)
    assert set(after) == set(before), "the reset added or removed a file"
    changed = {name for name in after if after[name] != before[name]}
    assert changed <= {location.relative_to(root).as_posix(),
                       watermark.relative_to(root).as_posix()}, (
        f"the reset rewrote more than the ledger and its mark: {sorted(changed)}")
    import typer.main  # noqa: PLC0415

    from nornyx_forge.cli import app  # noqa: PLC0415

    command = typer.main.get_command(app).commands["provision-ledger"]
    option = next(param for param in command.params if param.name == "reset_replay_history")
    flat = " ".join(option.help.split())
    assert option.opts == ["--reset-replay-history"] and option.default is False
    assert "Discard the replay history" in flat and "a NEW human approval is required" in flat


# ---------------------------------------------------------------------------
# The text
# ---------------------------------------------------------------------------

def _assumption(number: str) -> str:
    text = ASSUMPTIONS.read_text(encoding="utf-8")
    start = text.index(f"\n## {number} ") + 1
    end = text.find("\n## A-", start + 1)
    return text[start:end if end != -1 else len(text)]


def _flat(text: str) -> str:
    return " ".join(text.split()).casefold()


def test_the_assumption_states_the_guarantee_its_definitions_and_its_limits():
    section = _flat(_assumption("A-044"))
    for stated in (
            "measured on windows once", "there is no uninstaller and no repair",
            "governed user state", "provider state", "state specimen",
            "holds exactly what the receipt lists", "restoring the sealed authority",
            "provision-ledger", "--reset-replay-history", "no. it runs only with its own flag",
            "not established", "windows-install", "the registry",
            "`--project-dir` and `--runtime-dir` take any absolute path",
            "a roaming or redirected profile", "unsigned",
            "this claim does not make an uninstaller safe",
            "any future uninstaller, repair or upgrade is a new path"):
        assert stated in section, stated
    provider = {name for name in _protected_names()
                if any(name in _names_in(path) for path in contract.PROVIDER_STATE)}
    assert {".claude", ".codex", ".config", ".crewai", "crewai"} <= provider
    for name in provider:
        assert name in section, f"A-044's definition of provider state does not name {name}"
    # The guarantee is about paths that exist. It must not read as a promise
    # about ones that do not.
    for claim in (r"\bsafe to uninstall\b", r"\buninstall(?:er)? preserves\b",
                  r"\bsupports uninstall\b", r"\bupgrade preserves\b"):
        for match in re.finditer(claim, section):
            window = section[max(0, match.start() - 40):match.start()]
            assert re.search(r"\b(no|not|never|without|nor)\b", window), match.group(0)


def test_the_assumption_lists_every_refusal_no_run_provokes_and_says_what_the_scenario_replays():
    """A-044 may not claim more than the scenario runs. Every refusal the driver
    does not run with the specimen planted is named in it, by the script's own
    words, and what the scenario does replay is stated as a class and as exactly
    the refusals made before anything is extracted, plus the four it makes with an
    install in place."""
    section = _flat(_assumption("A-044"))
    for _where, _code, fragment, status, _why in REFUSALS:
        if status in (NOT_RUN, ELEVATED):
            assert _flat(fragment) in section, f"{fragment!r} is run without the specimen, or not"
    for stated in ("refusals that the scenario does not run against the specimen",
                   "replays ten of the refusals setup makes before it extracts anything",
                   "replayed with the specimen planted",
                   "elevated", "does not plant the specimen",
                   "is not a claim about those paths",
                   "compared with the script both ways", "every refusal in the script",
                   "default-deny", "tripwire", "not a proof", "data flow",
                   "complexity alarm fired", "the removal of its own artifacts", "outside this claim"):
        assert stated in section, stated
    assert section.count("outside this claim") >= 3, "the claim, the table row and the limits say it"
    # What the census is made of is stated as it is, not as it was.
    assert f"{len(INERT_VERBS)} inert ones" in section
    assert (f"{sum(ALLOWED_INSTRUCTIONS.values())} instructions in {len(ALLOWED_INSTRUCTIONS)} forms"
            in section)
    assert f"{len(PLANTED)} planted instructions and {len(REWRITTEN)} changes" in section
    for claim in (r"\bevery refusal path is covered\b", r"\bevery refusal is covered\b",
                  r"\ball refusals are covered\b"):
        assert not re.search(claim, section), claim
    # The restoration's blast radius is stated as it is: its own seal, and nothing else.
    restored = "rewrites its own seal and nothing else beside the capsule"
    assert restored in section
    for path in (ROOT / "CHANGELOG.md", ROOT / "docs" / "VALIDATION.md"):
        assert restored in _flat(path.read_text(encoding="utf-8")), path.name
        assert "removal of its own artifacts" in _flat(path.read_text(encoding="utf-8")), path.name
    assert section.count(restored) >= 2, "the table row and the paragraph both say it"
    assert not re.search(r"touch(?:es)? nothing beside the capsule", section)
    # The count is stated, the same way, wherever the claim is made.
    replayed = sum(1 for entry in REFUSALS if entry[3] == REPLAYED)
    sentence = (f"{replayed} of the script's {len(REFUSALS)} refusals are replayed with the "
                "specimen planted").casefold()
    assert sentence in section
    for path in (ROOT / "CHANGELOG.md", ROOT / "docs" / "VALIDATION.md"):
        flat = _flat(path.read_text(encoding="utf-8"))
        assert sentence in flat, f"{path.name} does not state how many refusals are replayed"
        covered = r"\b(each|every|all) refusals? (is|are) (replayed|covered|exercised|run)\b"
        assert not re.search(covered, flat), (path.name, covered)


def test_every_test_the_assumption_cites_exists():
    """A named test is a record row; a name that matches nothing is prose."""
    section = _assumption("A-044")
    names = set(re.findall(r"`(?:[\w/]+\.py::)?(test_\w+)`", section))
    assert len(names) >= 8, names
    corpus = "\n".join(path.read_text(encoding="utf-8", errors="replace")
                       for path in (ROOT / "tests").glob("test_*.py"))
    for name in sorted(names):
        assert re.search(rf"^def {re.escape(name)}\(", corpus, re.M), f"{name} is not a test"


def test_the_texts_that_speak_of_removal_say_the_same_thing():
    """README, the changelog and the validation table each speak of an
    uninstaller; none may promise one, and each must point at the assumption."""
    for path in (ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "docs" / "VALIDATION.md"):
        flat = _flat(path.read_text(encoding="utf-8"))
        assert "a-044" in flat, f"{path.name} does not point at A-044"
        for match in re.finditer(r"\buninstaller\b", flat):
            window = flat[max(0, match.start() - 60):match.start()]
            assert re.search(r"\b(no|not|nor|never|without|registers no|has no)\b", window), (
                f"{path.name} mentions an uninstaller without denying it: "
                f"{flat[match.start() - 60:match.end() + 40]!r}")


def test_the_one_failure_path_that_leaves_the_shortcut_behind_is_named():
    """In one failure path Setup has already created the shortcut when it fails,
    and the message names only the install folder: a person who follows it is left
    with a stale shortcut (a leftover; nothing is destroyed). This is a known limit
    and a candidate improvement, not changed here (the installer is unchanged).
    The facts are read from the script; the texts must name the limit."""
    text = contract.nsi_text()
    code = "\n".join(_script_lines(text))
    section = code[code.index('Section "Install"'):]
    assert section.index("CreateShortcut") < section.index("receipt.nsh"), (
        "the shortcut exists when the receipt is written")
    message = next(site[2] for site in _refusal_sites(text) if "could not write install-receipt.json" in site[2])
    advice = message.split("Remove", 1)[1]
    assert "$INSTDIR" in advice and "shortcut" not in advice.lower() and "$SMPROGRAMS" not in advice
    shortcut_message = next(site[2] for site in _refusal_sites(text)
                            if "already exists and Setup does not replace it" in site[2])
    assert "Remove or rename it" in shortcut_message, "the next Setup run refuses on the stale shortcut"
    for path in (ASSUMPTIONS, ROOT / "CHANGELOG.md", ROOT / "docs" / "VALIDATION.md"):
        body = _assumption("A-044") if path == ASSUMPTIONS else path.read_text(encoding="utf-8")
        assert "stale shortcut" in _flat(body), path.name
    assert _flat(_assumption("A-044")).count("stale shortcut") >= 3, (
        "the paths table, the refusals not run and the limits all name it")


SETUP_MADE = "an object Setup made"
PRE_EXISTING = "a path that was there before Setup and that Setup refused to touch"

#: Every message of the script that tells a person to remove, move or rename
#: something, by who owns the thing: (words of the message, owner, what it names).
#: The claim covers what Setup does and the removal of its own artifacts; a path
#: Setup refused because it is not its own is named, with advice to move or rename
#: it, and what the person then does is their own choice and outside the claim.
ADVISED_REMOVALS = (
    ("Remove or rename it and run Setup again", PRE_EXISTING, "$SMPROGRAMS\\Nornyx Forge.lnk"),
    ("Move or remove that folder", PRE_EXISTING, "$INSTDIR"),
    ("is still there. Setup does not delete anything. Remove that folder", SETUP_MADE, "$Partial"),
    ("already exists. Setup does not delete anything. Remove that folder", SETUP_MADE, "$Partial"),
    ("and wrote no receipt. Remove $INSTDIR", SETUP_MADE, "$INSTDIR"),
    ("could not write install-receipt.json. Remove $INSTDIR", SETUP_MADE, "$INSTDIR"),
)


def test_every_message_that_tells_a_person_to_remove_something_says_whose_it_is():
    """CLASS: advice to remove something that is not Setup's, passed off as the
    removal of Setup's own artifacts. Each advice message of the script is found
    and must be listed once, as the removal of something Setup made (named, and
    spoken after Setup wrote it or named it as an earlier install's unfinished
    folder) or as the move or rename of something that was there before Setup
    (spoken by a refusal that says Setup does not own or replace it); a listed
    message the script does not have is as much a failure as an unlisted one."""
    sites = _refusal_sites(contract.nsi_text())
    advice = [site for site in sites if re.search(r"\b(?:Remove|Move or remove)\b", site[2])]
    assert len(advice) == len(ADVISED_REMOVALS) >= 6, [site[2][:60] for site in advice]
    others = [site[2] for site in sites if re.search(r"(?i)remove", site[2]) and site not in advice]
    assert len(others) == 1 and "does not replace or remove another version" in others[0], others
    for fragment, owner, named in ADVISED_REMOVALS:
        hits = [site for site in advice if fragment in site[2]]
        assert len(hits) == 1, f"{fragment!r} is not one advice message of the script"
        where, code, message = hits[0]
        assert named in message, (fragment, named)
        assert "$PROFILE" not in message and "ForgeProject" not in message, message
        if owner == PRE_EXISTING:
            assert code in ("EXIT_NOT_FORGE", "EXIT_SHORTCUT_EXISTS"), code
            assert ("so it is not a Forge install this setup made" in message
                    or "already exists and Setup does not replace it" in message), message
            assert re.search(r"Move or remove|Remove or rename", message), "advice to move or rename"
        else:
            assert owner == SETUP_MADE
            if named == "$INSTDIR":
                assert where == "Install" and message.startswith("Setup installed"), (
                    "spoken after Setup wrote into the folder")
            else:
                assert where in ("DecideExisting", "Install") and (
                    "An earlier install did not finish" in message
                    or "already exists. Setup does not delete anything" in message), message


def test_the_scenarios_advised_removal_removes_only_what_setup_made():
    """The step the scenario calls the advised removal: after a real install it
    checks the folder holds exactly what the receipt lists and then removes that
    folder and the shortcut Setup wrote; after the failed install it removes that
    install's folder. The foreign folders and shortcuts the driver plants to provoke
    a refusal are its own fixtures, cleaned up between cases."""
    source = DRIVER.read_text(encoding="utf-8")
    body = source[source.index("def state_survival"):source.index("def main")]
    checked = body.index("sorted(os.listdir(root)) == owned")
    removed = body.index("shutil.rmtree(root)", checked)
    assert checked < removed < body.index("unchanged(\"the install folder and the shortcut were removed")
    assert "shortcut_path.unlink(missing_ok=True)" in body[removed:removed + 120]
    assert "an install that failed after the folder was in place" in body
    fixtures = source[source.index("def refusal_runs"):source.index("def mode_standard_user")]
    assert "the driver's own fixtures" in fixtures
