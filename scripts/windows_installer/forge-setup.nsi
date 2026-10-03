; ForgeSetup.exe -- the per-user Windows installer for Nornyx Forge.
;
; Compiled ONLY by scripts/build_windows_installer.py, which verifies the
; payload folder against its manifest first, generates the two includes below
; (`files.nsh`: one `File` per manifest entry, in manifest order; `receipt.nsh`:
; the receipt) and passes every -D define this script reads. Compiled by NSIS
; 3.09 on Linux; never by hand, and never from Windows.
;
; WHAT THIS INSTALLER DOES, in order:
;   1. refuses to run elevated (exit 10; exit 19 when it cannot tell);
;   2. fixes the location: %LOCALAPPDATA%\Programs\Nornyx Forge, whatever /D= says;
;      refuses a UNC or \\?\ spelling, a location outside the profile
;      directory, a reparse point below the profile directory, and a location
;      whose longest payload file path would reach 260 characters or whose
;      longest payload folder path would reach 248 (what CreateDirectory takes);
;   3. applies the existing-install rule: an unfinished earlier install
;      (<version>+<commit12>.partial) is refused first (14); an empty or absent
;      folder is a fresh install; a non-empty folder without
;      install-receipt.json is not this installer's (13); the same payload
;      already installed is verified and left alone (exit 0); any other payload
;      in the same version directory fails verification (16); another version
;      is refused (18); an existing Start-menu shortcut of the same name is
;      refused (20). This installer deletes nothing and replaces no existing
;      folder, file or shortcut; the one file it appends to is the log a caller
;      names with /LOG=;
;   4. extracts into <version>+<commit12>.partial, verifies it with the
;      payload's own standard-library verifier against the identity baked into
;      THIS executable, then renames it to <version>+<commit12>;
;   5. writes one per-user Start-menu shortcut, then install-receipt.json last.
;
; WHAT IT NEVER DOES: write outside the install folder, the shortcut and the
; /LOG= file; write the registry; change PATH; register an uninstaller; run
; another installer; download anything; create or touch the person's project,
; ~\.nornyx*, the CrewAI storage locations or any provider's configuration.
; (NSIS itself, and the plug-ins this script loads, extract into $PLUGINSDIR
; under %TEMP% before any of this runs: see A-042.)
;
; EXIT CODES. One table, here. The CI driver and the tests read it from this
; file; the build does not. A code a refusal sets stays the exit code: the
; install-failed callback sets 17 only when no code was set.
!define EXIT_ELEVATED        10
!define EXIT_LOCATION        11
!define EXIT_LINK            12
!define EXIT_NOT_FORGE       13
!define EXIT_UNFINISHED      14
!define EXIT_TOO_LONG        15
!define EXIT_DOES_NOT_VERIFY 16
!define EXIT_FAILED          17
!define EXIT_OTHER_VERSION   18
!define EXIT_ELEVATION_UNKNOWN 19
!define EXIT_SHORTCUT_EXISTS 20

!ifndef VERSION
  !error "VERSION is not defined: this script is compiled by build_windows_installer.py"
!endif
!ifndef COMMIT12
  !error "COMMIT12 is not defined"
!endif
!ifndef PAYLOAD_SHA256
  !error "PAYLOAD_SHA256 is not defined"
!endif
!ifndef LONGEST_RELATIVE
  !error "LONGEST_RELATIVE is not defined"
!endif
!ifndef LONGEST_DIRECTORY
  !error "LONGEST_DIRECTORY is not defined"
!endif
!ifndef VI_VERSION
  !error "VI_VERSION is not defined"
!endif
!ifndef STAGE_DIR
  !error "STAGE_DIR is not defined"
!endif
!ifndef OUT_FILE
  !error "OUT_FILE is not defined"
!endif

Unicode true
SetCompressor /SOLID lzma
SetDatablockOptimize off
RequestExecutionLevel user
CRCCheck on
AllowSkipFiles off
SetOverwrite off
OutFile "${OUT_FILE}"
Name "Nornyx Forge"
Caption "Nornyx Forge ${VERSION} setup"
BrandingText "Nornyx Forge ${VERSION}+${COMMIT12}"
InstallDir "$LOCALAPPDATA\Programs\Nornyx Forge"
XPStyle on

VIProductVersion "${VI_VERSION}"
VIAddVersionKey "ProductName" "Nornyx Forge"
VIAddVersionKey "FileDescription" "Nornyx Forge installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}+${COMMIT12}"
VIAddVersionKey "Comments" "payload sha256 ${PAYLOAD_SHA256}"

!include "LogicLib.nsh"
!include "FileFunc.nsh"
!insertmacro GetParameters
!insertmacro GetOptions

; The two plug-ins this script uses go into the data block FIRST. The data
; block is one solid stream; a plug-in placed after the payload would make
; .onInit decompress all of it before the elevation check could run.
ReserveFile /plugin System.dll
ReserveFile /plugin nsExec.dll

Page instfiles

Var LogPath
Var VerDir
Var Partial
Var GitState
Var RootCreated
Var LinkPath
Var LinkLen
Var LinkPos
Var LinkChar
Var LinkPrefix
Var Attr
Var Tries
Var HasEntries

; Say a refusal (the log named by /LOG=, if any, and a message box that a
; silent run suppresses), set the exit code, and stop.
!macro Refuse CODE TEXT
  Push "refused (${CODE}): ${TEXT}"
  Call WriteLog
  SetErrorLevel ${CODE}
  MessageBox MB_OK|MB_ICONSTOP "${TEXT}" /SD IDOK
  Abort
!macroend

!macro Say TEXT
  Push "${TEXT}"
  Call WriteLog
!macroend

; The opt-in log: /LOG=<absolute path> on the command line. Appends one line.
; FileOpen "a" opens for writing at the start in NSIS, so the append is a seek
; to the end.
Function WriteLog
  Exch $0
  Push $1
  ${If} $LogPath != ""
    ClearErrors
    FileOpen $1 "$LogPath" a
    ${IfNot} ${Errors}
      FileSeek $1 0 END
      FileWrite $1 "$0$\r$\n"
      FileClose $1
    ${EndIf}
  ${EndIf}
  Pop $1
  Pop $0
FunctionEnd

; Input on the stack: a path. Output on the stack: its file attributes, or -1
; when nothing is there (INVALID_FILE_ATTRIBUTES). 0x10 is a directory and
; 0x400 a reparse point (a junction or a symbolic link).
Function AttrOf
  Exch $0
  System::Call 'kernel32::GetFileAttributesW(w r0) i .r0'
  Exch $0
FunctionEnd

; Refuse a process whose token is elevated, and fail closed when the token
; cannot be read. TokenElevation is information class 20, a 4-byte flag.
; IsUserAnAdmin is asked as well: an administrator with UAC off holds a full
; token that is administrator all the time, which this installer treats as
; elevated too.
Function RefuseElevated
  System::Call 'kernel32::GetCurrentProcess() p .r0'
  System::Call 'advapi32::OpenProcessToken(p r0, i 8, *p .r1) i .r2'
  ${If} $2 = 0
    !insertmacro Refuse ${EXIT_ELEVATION_UNKNOWN} "Forge Setup could not read this process's token, so it cannot tell whether it is running elevated. Nothing was installed."
  ${EndIf}
  System::Call '*(i 0) p .r3'
  System::Call 'advapi32::GetTokenInformation(p r1, i 20, p r3, i 4, *i .r4) i .r5'
  System::Call '*$3(i .r6)'
  System::Free $3
  System::Call 'kernel32::CloseHandle(p r1)'
  ${If} $5 = 0
    !insertmacro Refuse ${EXIT_ELEVATION_UNKNOWN} "Forge Setup could not read this process's elevation, so it cannot tell whether it is running elevated. Nothing was installed."
  ${EndIf}
  System::Call 'shell32::IsUserAnAdmin() i .r7'
  ${If} $6 <> 0
  ${OrIf} $7 <> 0
    !insertmacro Refuse ${EXIT_ELEVATED} "Forge installs for the signed-in user only. Run ForgeSetup.exe without 'Run as administrator', from a standard account if you have one. Nothing was installed."
  ${EndIf}
FunctionEnd

; $LinkPath is an absolute path under $PROFILE. Refuse when it, or any folder
; between the profile directory (exclusive) and it, is a reparse point.
Function CheckNoLinks
  StrLen $LinkLen "$LinkPath"
  StrLen $LinkPos "$PROFILE"
  IntOp $LinkPos $LinkPos + 1
  ${DoWhile} $LinkPos <= $LinkLen
    StrCpy $LinkPrefix ""
    ${If} $LinkPos = $LinkLen
      StrCpy $LinkPrefix "$LinkPath"
    ${Else}
      StrCpy $LinkChar "$LinkPath" 1 $LinkPos
      ${If} $LinkChar == "\"
        StrCpy $LinkPrefix "$LinkPath" $LinkPos
      ${EndIf}
    ${EndIf}
    ${If} $LinkPrefix != ""
      Push "$LinkPrefix"
      Call AttrOf
      Pop $Attr
      ${If} $Attr <> -1
        IntOp $Attr $Attr & 0x400
        ${If} $Attr <> 0
          !insertmacro Refuse ${EXIT_LINK} "$LinkPrefix is a link (a junction or symbolic link), and Forge does not install through links. No payload file was installed."
        ${EndIf}
      ${EndIf}
    ${EndIf}
    IntOp $LinkPos $LinkPos + 1
  ${Loop}
FunctionEnd

Function CheckLocation
  StrCpy $0 "$INSTDIR" 2
  ${If} $0 == "\\"
    !insertmacro Refuse ${EXIT_LOCATION} "The install location $INSTDIR is a network or extended-length path. Forge installs on a local drive, under your profile. Nothing was installed."
  ${EndIf}
  StrCpy $0 "$INSTDIR" 1 1
  StrCpy $1 "$INSTDIR" 1 2
  ${If} $0 != ":"
  ${OrIf} $1 != "\"
    !insertmacro Refuse ${EXIT_LOCATION} "The install location $INSTDIR is not a plain drive path. Nothing was installed."
  ${EndIf}
  StrLen $0 "$PROFILE\"
  StrCpy $1 "$INSTDIR" $0
  ${If} $1 != "$PROFILE\"
    !insertmacro Refuse ${EXIT_LOCATION} "The install location $INSTDIR is outside your profile folder $PROFILE. Nothing was installed."
  ${EndIf}
  StrCpy $LinkPath "$INSTDIR"
  Call CheckNoLinks
FunctionEnd

; The longest paths this install creates are the longest payload file path and
; the longest payload folder path inside the .partial folder. Windows refuses
; a file path of 260 characters or more, and CreateDirectory a folder path of
; 248 or more, unless long paths are enabled machine-wide, which this
; installer does not ask for.
Function CheckPathBudget
  StrLen $0 "$Partial"
  IntOp $0 $0 + 1
  IntOp $1 $0 + ${LONGEST_DIRECTORY}
  IntOp $0 $0 + ${LONGEST_RELATIVE}
  ${If} $0 > 259
    !insertmacro Refuse ${EXIT_TOO_LONG} "Installing under $INSTDIR would create file paths of up to $0 characters, and Windows allows 259. Nothing was installed."
  ${EndIf}
  ${If} $1 > 247
    !insertmacro Refuse ${EXIT_TOO_LONG} "Installing under $INSTDIR would create folder paths of up to $1 characters, and Windows allows 247. Nothing was installed."
  ${EndIf}
FunctionEnd

; A Start-menu shortcut of this name that Setup did not write is not Setup's to
; replace: CreateShortcut would replace it without a word.
Function CheckShortcutFree
  Push "$SMPROGRAMS\Nornyx Forge.lnk"
  Call AttrOf
  Pop $0
  ${If} $0 <> -1
    !insertmacro Refuse ${EXIT_SHORTCUT_EXISTS} "$SMPROGRAMS\Nornyx Forge.lnk already exists and Setup does not replace it. Remove or rename it and run Setup again. Nothing was installed."
  ${EndIf}
FunctionEnd

; Verify the folder on the stack with ITS OWN interpreter and the verifier in
; its payload, against the identity baked into this executable. Output on the
; stack: "0" when it verifies, otherwise the reason.
Function VerifyFolder
  Exch $0
  Push $1
  Push $2
  SetOutPath "$INSTDIR"
  nsExec::ExecToStack /TIMEOUT=900000 '"$0\python\python.exe" -B -I -m nornyx_forge.windows_payload verify "$0" --expect ${PAYLOAD_SHA256}'
  Pop $1
  Pop $2
  ${If} $1 == "0"
    StrCpy $0 "0"
  ${Else}
    StrCpy $0 "exit $1: $2"
  ${EndIf}
  Pop $2
  Pop $1
  Exch $0
FunctionEnd

Function DecideExisting
  Push "$INSTDIR"
  Call AttrOf
  Pop $0
  ${If} $0 = -1
    StrCpy $RootCreated "true"
    Return
  ${EndIf}
  IntOp $1 $0 & 0x10
  ${If} $1 = 0
    !insertmacro Refuse ${EXIT_NOT_FORGE} "$INSTDIR exists and is not a folder, so it is not Forge's. Nothing was installed or changed."
  ${EndIf}
  StrCpy $RootCreated "false"
  ; An unfinished earlier install is named as such first, with or without a
  ; receipt: a failed first install leaves a .partial folder and no receipt.
  Push "$Partial"
  Call AttrOf
  Pop $0
  ${If} $0 <> -1
    !insertmacro Refuse ${EXIT_UNFINISHED} "An earlier install did not finish: $Partial is still there. Setup does not delete anything. Remove that folder and run Setup again."
  ${EndIf}
  ; FindFirst on an existing folder finds at least "." and "..". It finds
  ; nothing only when the folder cannot be listed, which is a refusal and not
  ; an empty folder. FindNext sets the error flag at the end of every listing,
  ; so the flag is cleared when the listing is done.
  StrCpy $HasEntries 0
  ClearErrors
  FindFirst $2 $3 "$INSTDIR\*.*"
  ${If} $3 == ""
    !insertmacro Refuse ${EXIT_NOT_FORGE} "$INSTDIR exists but cannot be listed, so Setup cannot tell whether it is empty. Nothing was installed or changed."
  ${EndIf}
  ${DoWhile} $3 != ""
    ${If} $3 != "."
    ${AndIf} $3 != ".."
      StrCpy $HasEntries 1
      ${Break}
    ${EndIf}
    FindNext $2 $3
  ${Loop}
  FindClose $2
  ClearErrors
  ${If} $HasEntries = 0
    Return
  ${EndIf}
  Push "$INSTDIR\install-receipt.json"
  Call AttrOf
  Pop $0
  ${If} $0 = -1
    !insertmacro Refuse ${EXIT_NOT_FORGE} "$INSTDIR already holds files and no install-receipt.json, so it is not a Forge install this setup made. Nothing was installed or changed. Move or remove that folder, or ask for help, and run Setup again."
  ${EndIf}
  IntOp $1 $0 & 0x410
  ${If} $1 <> 0
    !insertmacro Refuse ${EXIT_NOT_FORGE} "$INSTDIR\install-receipt.json is not a plain file. Nothing was installed or changed."
  ${EndIf}
  Push "$INSTDIR\$VerDir"
  Call AttrOf
  Pop $0
  ${If} $0 = -1
    !insertmacro Refuse ${EXIT_OTHER_VERSION} "Another version of Forge is installed under $INSTDIR. This Setup installs ${VERSION}+${COMMIT12} and does not replace or remove another version. Nothing was changed."
  ${EndIf}
  IntOp $1 $0 & 0x410
  ${If} $1 <> 0x10
    !insertmacro Refuse ${EXIT_DOES_NOT_VERIFY} "$INSTDIR\$VerDir is not a plain folder. Nothing was changed."
  ${EndIf}
  Push "$INSTDIR\$VerDir"
  Call VerifyFolder
  Pop $0
  ${If} $0 != "0"
    !insertmacro Refuse ${EXIT_DOES_NOT_VERIFY} "$INSTDIR\$VerDir is not the payload this Setup carries, or is damaged ($0). Nothing was changed."
  ${EndIf}
  !insertmacro Say "already installed: $INSTDIR\$VerDir verified"
  SetErrorLevel 0
  MessageBox MB_OK|MB_ICONINFORMATION "Nornyx Forge ${VERSION}+${COMMIT12} is already installed here and verified. Nothing was changed." /SD IDOK
  Quit
FunctionEnd

Function .onInit
  SetShellVarContext current
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/LOG=" $LogPath
  ${If} ${Errors}
    StrCpy $LogPath ""
  ${EndIf}
  StrCpy $VerDir "${VERSION}+${COMMIT12}"
  StrCpy $INSTDIR "$LOCALAPPDATA\Programs\Nornyx Forge"
  StrCpy $Partial "$INSTDIR\$VerDir.partial"
  StrCpy $GitState "found"
  StrCpy $RootCreated "true"
  Call RefuseElevated
  Call CheckLocation
  Call CheckPathBudget
  Call DecideExisting
  Call CheckShortcutFree
FunctionEnd

; A refusal in the Section has already set its own exit code; this callback
; only gives a failure that set none (an extraction that could not write a
; file) the generic one.
Function .onInstFailed
  GetErrorLevel $0
  ${If} $0 = -1
    SetErrorLevel ${EXIT_FAILED}
  ${EndIf}
FunctionEnd

Section "Install"
  ClearErrors
  CreateDirectory "$INSTDIR"
  ${If} ${Errors}
    !insertmacro Refuse ${EXIT_FAILED} "Setup could not create $INSTDIR. Nothing was installed."
  ${EndIf}
  StrCpy $LinkPath "$INSTDIR"
  Call CheckNoLinks
  Push "$Partial"
  Call AttrOf
  Pop $0
  ${If} $0 <> -1
    !insertmacro Refuse ${EXIT_UNFINISHED} "$Partial already exists. Setup does not delete anything. Remove that folder and run Setup again."
  ${EndIf}

  ; Advisory only: Forge needs Git for Windows and refuses to start without it.
  ClearErrors
  SearchPath $0 "git.exe"
  ${If} ${Errors}
    StrCpy $GitState "not found"
  ${EndIf}

  !insertmacro Say "extracting ${VERSION}+${COMMIT12} into $Partial"
  SetDetailsPrint none
  !include "${STAGE_DIR}/files.nsh"
  SetDetailsPrint both
  SetOutPath "$INSTDIR"

  Push "$Partial"
  Call VerifyFolder
  Pop $0
  ${If} $0 != "0"
    !insertmacro Refuse ${EXIT_DOES_NOT_VERIFY} "The files Setup extracted into $Partial do not verify against the payload it carries ($0). Setup leaves that folder for you to inspect; it deletes nothing."
  ${EndIf}

  StrCpy $Tries 0
  ${Do}
    ClearErrors
    Rename "$Partial" "$INSTDIR\$VerDir"
    ${IfNot} ${Errors}
      ${Break}
    ${EndIf}
    IntOp $Tries $Tries + 1
    ${If} $Tries >= 5
      !insertmacro Refuse ${EXIT_FAILED} "Setup could not move the verified folder $Partial to $INSTDIR\$VerDir. It is left where it is; Setup deletes nothing."
    ${EndIf}
    Sleep 1000
  ${Loop}

  SetOutPath "$INSTDIR"
  ClearErrors
  CreateShortcut "$SMPROGRAMS\Nornyx Forge.lnk" "$INSTDIR\$VerDir\python\pythonw.exe" '-B -m nornyx_forge.windows_launch --bundle-root "$INSTDIR\$VerDir" --project-dir "$PROFILE\ForgeProject"' "" 0 SW_SHOWNORMAL "" "Start Nornyx Forge"
  ${If} ${Errors}
    !insertmacro Refuse ${EXIT_FAILED} "Setup installed $INSTDIR\$VerDir but could not create the Start-menu shortcut, and wrote no receipt. Remove $INSTDIR and run Setup again."
  ${EndIf}

  ClearErrors
  !include "${STAGE_DIR}/receipt.nsh"
  ${If} ${Errors}
    !insertmacro Refuse ${EXIT_FAILED} "Setup installed $INSTDIR\$VerDir and the shortcut but could not write install-receipt.json. Remove $INSTDIR and run Setup again."
  ${EndIf}

  !insertmacro Say "installed ${VERSION}+${COMMIT12}; git $GitState"
  ${If} $GitState == "not found"
    MessageBox MB_OK|MB_ICONEXCLAMATION "Nornyx Forge is installed, but Git for Windows was not found on your PATH. Forge needs Git and will refuse to start until it is installed (https://git-scm.com/download/win)." /SD IDOK
  ${EndIf}
SectionEnd
