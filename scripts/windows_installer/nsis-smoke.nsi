; Smoke test for the pinned NSIS toolchain.
;
; Compiled by `build_nsis_toolchain.py compile-smoke` with the compiler that was
; just built, and run on a Windows host by `run-smoke`. It exercises what an
; installer built with this compiler will rely on: the System plug-in reading
; the process token, nsExec returning a child's exit code and output, the
; FileFunc and LogicLib includes, a script-selected target, and a user-level
; execution manifest. It installs nothing and writes only the result file named
; by /RESULT=.
;
; It then takes the refusal path an installer takes when it is elevated: exit
; code 10. A non-elevated run exits 0. Either way the result file says which.

!ifndef OUT_FILE
  !error "OUT_FILE is not defined: this script is compiled by build_nsis_toolchain.py"
!endif

Target x86-unicode
Unicode true
SetCompressor /SOLID lzma
RequestExecutionLevel user
XPStyle on
CRCCheck on
OutFile "${OUT_FILE}"
Name "NSIS toolchain smoke"

!include "LogicLib.nsh"
!include "FileFunc.nsh"
!insertmacro GetParameters
!insertmacro GetOptions

ReserveFile /plugin System.dll
ReserveFile /plugin nsExec.dll

Page instfiles

Var ResultPath
Var SystemCall
Var Elevated
Var ExecCode
Var ExecOutput

Function .onInit
  ${GetParameters} $0
  ${GetOptions} $0 "/RESULT=" $ResultPath
  ${If} $ResultPath == ""
    SetErrorLevel 2
    Abort
  ${EndIf}

  StrCpy $SystemCall "fail"
  StrCpy $Elevated "unknown"
  System::Call 'kernel32::GetCurrentProcess() p .r0'
  System::Call 'advapi32::OpenProcessToken(p r0, i 8, *p .r1) i .r2'
  ${If} $2 <> 0
    System::Call '*(i 0) p .r3'
    System::Call 'advapi32::GetTokenInformation(p r1, i 20, p r3, i 4, *i .r4) i .r5'
    System::Call '*$3(i .r6)'
    System::Free $3
    System::Call 'kernel32::CloseHandle(p r1)'
    ${If} $5 <> 0
      StrCpy $SystemCall "ok"
      StrCpy $Elevated "$6"
    ${EndIf}
  ${EndIf}
  ; An administrator whose token is not marked elevated (a host without UAC) is
  ; still one the installer refuses.
  System::Call 'shell32::IsUserAnAdmin() i .r7'
  ${If} $7 <> 0
    StrCpy $Elevated "1"
  ${EndIf}

  nsExec::ExecToStack /TIMEOUT=60000 '"$SYSDIR\cmd.exe" /c echo smoke& exit /b 7'
  Pop $ExecCode
  Pop $ExecOutput

  ClearErrors
  FileOpen $0 "$ResultPath" w
  ${If} ${Errors}
    SetErrorLevel 3
    Abort
  ${EndIf}
  FileWrite $0 "nsis=${NSIS_VERSION}$\r$\n"
  FileWrite $0 "system_call=$SystemCall$\r$\n"
  FileWrite $0 "elevated=$Elevated$\r$\n"
  FileWrite $0 "nsexec_exit=$ExecCode$\r$\n"
  FileWrite $0 "nsexec_output=$ExecOutput$\r$\n"
  FileClose $0

  ${If} $Elevated == "1"
    SetErrorLevel 10
  ${Else}
    SetErrorLevel 0
  ${EndIf}
  Abort
FunctionEnd

Section "Smoke"
SectionEnd
