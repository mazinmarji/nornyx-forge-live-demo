"""An opt-in way to start a provider through a hash-pinned run-act gate.

WHAT THIS IS. The two worker adapters, `claude_worker` and `codex_worker`,
start their provider CLI directly. Each now takes an optional `launch`. With
`launch=None`, the default, nothing in this module runs and the worker starts
its provider exactly as before: the same argument vector, the same
`_provider_env()` environment, the same working directory, timeout and
capture. With a `GateLaunch`, the worker builds the same argument vector it
always builds and hands it here, and this module starts Windows PowerShell 5.1
on a gate script instead, with exactly this vector:

    <system directory>\\WindowsPowerShell\\v1.0\\powershell.exe
        -NoProfile -ExecutionPolicy <policy> -File <gate script>
        -Action Run -AuthorizedSha256 <PINNED_RUN_ACT_SHA256>
        -Role <role> -ProviderExe <provider executable>
        -ProviderArgs <subprocess.list2cmdline(the worker's arguments)>

`-ProviderArgs` is ONE argument: the worker's arguments after the executable,
joined by the same rule `subprocess` uses to build a Windows command line,
because the gate hands that string on as the provider's command line.

WHAT IS REFUSED, AND WHEN. Every refusal below is decided before any process
exists, and each is reported as a `WorkerResult` in the Provider Contract's
`error` class (`REFUSED_BEFORE_START_RETURNCODE`), never as an exception:

  * a `launch` that is not a `GateLaunch`;
  * a host with no Windows system directory (the gate is Windows-only);
  * an execution policy outside PowerShell's own names, a role that is not a
    short identifier, a gate script that is not absolute by this host's rules
    (it is opened here) or a provider executable that is not an absolute
    Windows path (it is only named to the gate), or either holding a NUL or a
    double quote;
  * a worker whose executable is not the gate's provider executable, so the
    recorded command and the process the gate starts name one file;
  * an argument vector holding a NUL, or a command line longer than Windows
    accepts (32767 characters, terminator included);
  * a `-ProviderArgs` value PowerShell would read as a PARAMETER NAME. Measured
    through a real `powershell.exe -File`: list2cmdline leaves a value with no
    space or tab unquoted, and an unquoted value that begins with `-` (or with
    U+2013, U+2014 or U+2015, which PowerShell also reads as a dash) is bound
    as a parameter, not as the value -- `-NoCredential` among them. No worker
    builds such a vector today, since every one carries a prompt with spaces;
    the class is refused rather than assumed absent;
  * no console. The gate reads its credential prompt from the console, so a
    process with no console input -- a pipe, a file, the NUL device, a service
    -- is refused rather than started to fail at the prompt;
  * a gate script whose bytes do not have the SHA-256 `PINNED_RUN_ACT_SHA256`,
    or that cannot be read as one regular file.

THE HASH AND THE START ARE ONE HOLD. On Windows the script is opened once,
with a share mode that admits other readers and refuses writers, renames and
deletion; its bytes are read and hashed through that handle, and the handle is
held until the gate process has exited. So the file PowerShell opens by path
is the file hashed, unless a directory on its path is replaced -- that is not
closed here. The gate also checks its own SHA-256 against `-AuthorizedSha256`,
which is the pin. Off Windows the read is one `O_NOFOLLOW` descriptor checked
as a regular file; nothing is started there, because there is no system
directory.

WHAT THE GATE PROCESS GETS. Only `-Action Run`: nothing here can spell
another action, a `-NoCredential`, a step or a confirmation. No credential:
Forge holds none for this path, the gate prompts for it, and the environment
is CONSTRUCTED, not filtered -- `SystemRoot`, `windir`, `ComSpec` and `PATH`
derived from the system directory, plus the fixed names in
`GATE_ENVIRONMENT_INHERITED` copied when present. No `FORGE_*` variable, no
provider key and no provider home variable can pass, because none is named.
The streams are the console's: nothing is captured, so the person at the
console sees the gate's lines and answers its prompt. There is NO timeout:
the worker's `timeout_seconds` does not apply on this path, because killing
the gate mid-cycle would leave its cycle open. PowerShell is started by its
absolute path under the system directory the operating system reports
(`GetSystemDirectoryW`), never through PATH and never from `SystemRoot`.

WHAT IS NOT CLAIMED. Nothing here establishes how the gate logs the provider
on, that the provider is separated from Forge, or that any provider is
eligible: eligibility is decided by the Provider Contract's own table, which
this module neither reads nor changes. Passing this module's checks means only
that the gate script's bytes are the pinned bytes and the vector is the
documented one.

WHAT THIS PATH CANNOT DO YET. The gate gives the provider its own fresh run
directory, not Forge's workspace, and releases what the provider produced only
after later actions this module never takes. So no provider output reaches the
worker's workspace, and a gate run is NEVER reported as a successful worker
run: `success` is False for every exit code, and the exit code is reported as
the gate's (`GATE_EXIT_MEANINGS`). Handing the workspace in and the output
back is a separate decision.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePath, PureWindowsPath
from typing import Any

from .models import WorkerResult


class LaunchVia(str, Enum):
    """How a worker starts its provider. `direct` is today's path and the
    default; `d2_gate` is the opt-in path through the run-act gate."""

    DIRECT = "direct"
    D2_GATE = "d2_gate"


#: The SHA-256 of the only gate script this path will start, lower-case hex.
#: Not configurable: a caller names WHERE the script is, never which bytes are
#: acceptable. The same value is passed to the gate as `-AuthorizedSha256`.
PINNED_RUN_ACT_SHA256 = "8830b243ff911a5c1aaaa026cb30a259d8bfc070ae6e6753a2096f8b1c7441e1"

#: The gate's exit codes and what each means. Every one of them is reported
#: with `success=False`: see the module docstring.
GATE_EXIT_MEANINGS: Mapping[int, str] = {
    0: ("the gate completed its Run action and holds the cycle, waiting for "
        "the run's credential to be invalidated; nothing was released"),
    10: "the gate refused before opening a cycle; nothing was changed",
    20: ("the gate failed with its cycle open; the cycle stays open and the "
         "next run is refused until it is completed or closed"),
}

#: Forge's refusal before any process exists. Equal to both workers'
#: MALFORMED_INVOCATION_RETURNCODE (a test holds the three equal) and distinct
#: from every gate exit code, so a refusal by Forge cannot read as the gate's.
REFUSED_BEFORE_START_RETURNCODE = 2

#: The provider executable could not be started at all; the workers' value.
NOT_STARTED_RETURNCODE = 127

#: PowerShell's own execution-policy names. The value is one argument either
#: way; the list keeps it from being anything but a policy.
EXECUTION_POLICIES = frozenset({
    "AllSigned", "Bypass", "Default", "RemoteSigned", "Restricted", "Undefined",
    "Unrestricted",
})

#: The variables copied from Forge's environment, when present, by name
#: (compared without regard to case, as Windows compares them). Nothing else
#: is copied: no FORGE_* variable, no provider key, no provider home.
GATE_ENVIRONMENT_INHERITED = (
    "SystemDrive", "TEMP", "TMP", "USERPROFILE", "USERNAME", "USERDOMAIN",
    "COMPUTERNAME", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS",
    "PATHEXT", "ALLUSERSPROFILE", "ProgramData", "ProgramFiles",
    "CommonProgramFiles", "APPDATA", "LOCALAPPDATA",
)

#: The longest command line Windows accepts, terminator included; the
#: workers' WINDOWS_COMMAND_LINE_LIMIT (a test holds them equal).
WINDOWS_COMMAND_LINE_LIMIT = 32767

#: The characters PowerShell reads as the dash that opens a parameter name.
POWERSHELL_DASHES = ("-", "–", "—", "―")

_ROLE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")


@dataclass(frozen=True)
class GateLaunch:
    """Where the gate is, and what it is asked to start. Validated when used,
    not when built, so a bad value is a refusal the worker reports."""

    gate_script: str
    provider_exe: str
    role: str
    execution_policy: str

    @property
    def via(self) -> LaunchVia:
        return LaunchVia.D2_GATE


def build_gate_argv(launch: GateLaunch, worker_args: Sequence[str], *,
                    system_dir: str) -> tuple[str, ...]:
    """The exact vector this module starts. Builds; refuses nothing."""
    return (
        str(PureWindowsPath(system_dir, "WindowsPowerShell", "v1.0", "powershell.exe")),
        "-NoProfile",
        "-ExecutionPolicy", launch.execution_policy,
        "-File", launch.gate_script,
        "-Action", "Run",
        "-AuthorizedSha256", PINNED_RUN_ACT_SHA256,
        "-Role", launch.role,
        "-ProviderExe", launch.provider_exe,
        "-ProviderArgs", subprocess.list2cmdline(list(worker_args)),
    )


def build_gate_environment(environ: Mapping[str, str], *, system_dir: str) -> dict[str, str]:
    """The gate process's whole environment: constructed, never filtered."""
    system = PureWindowsPath(system_dir)
    folded = {key.casefold(): value for key, value in environ.items()}
    env = {name: folded[name.casefold()] for name in GATE_ENVIRONMENT_INHERITED
           if name.casefold() in folded}
    env["SystemRoot"] = str(system.parent)
    env["windir"] = str(system.parent)
    env["ComSpec"] = str(system / "cmd.exe")
    env["PATH"] = ";".join((str(system), str(system.parent), str(system / "Wbem"),
                            str(system / "WindowsPowerShell" / "v1.0")))
    return env


def launch_through_gate(launch: Any, command: Sequence[str], *, role: str, goal: str,
                        worker: str) -> WorkerResult:
    """Start `command`'s provider through the gate, or refuse before starting.

    `command` is the worker's whole vector, executable first. The defaults
    are resolved here, at call time, so nothing a caller passes can replace
    the console check, the system directory, the script read or the runner."""
    return _launch(launch, command, role=role, goal=goal, worker=worker,
                   system_directory=_system_directory, has_console=_has_console,
                   read_script=_read_script, runner=_run_on_console,
                   environ=os.environ)


def _launch(launch: Any, command: Sequence[str], *, role: str, goal: str, worker: str,
            system_directory: Callable[[], str | None], has_console: Callable[[], bool],
            read_script: Callable[[str], tuple[bytes, Callable[[], None]]],
            runner: Callable[[tuple[str, ...], dict[str, str], str], int],
            environ: Mapping[str, str]) -> WorkerResult:
    def refuse(reason: str, argv: tuple[str, ...] = ()) -> WorkerResult:
        return WorkerResult(
            role=role, goal=goal, success=False,
            output=f"{worker} gate launch refused before any process started: {reason}",
            command=argv, returncode=REFUSED_BEFORE_START_RETURNCODE)

    if not isinstance(launch, GateLaunch):
        return refuse(f"launch is {type(launch).__name__}, not a GateLaunch")
    system_dir = system_directory()
    if not system_dir:
        return refuse("this host reports no Windows system directory; the gate runs only on Windows")
    problem = _field_problem(launch, command)
    if problem:
        return refuse(problem)
    argv = build_gate_argv(launch, command[1:], system_dir=system_dir)
    problem = _argv_problem(argv)
    if problem:
        return refuse(problem, argv)
    if not has_console():
        return refuse("this process has no console input, and the gate reads its "
                      "credential prompt from the console", argv)
    try:
        data, release = read_script(launch.gate_script)
    except OSError as exc:
        return refuse(f"the gate script could not be read as one regular file: {exc}", argv)
    try:
        digest = hashlib.sha256(data).hexdigest()
        if digest != PINNED_RUN_ACT_SHA256:
            return refuse(f"the gate script's SHA-256 is {digest}, not the pinned "
                          f"{PINNED_RUN_ACT_SHA256}", argv)
        env = build_gate_environment(environ, system_dir=system_dir)
        try:
            returncode = runner(argv, env, system_dir)
        except ValueError as exc:
            return refuse(f"the vector could not be formed: {exc}", argv)
        except OSError as exc:
            return WorkerResult(
                role=role, goal=goal, success=False,
                output=f"{worker} gate launch could not start Windows PowerShell: {exc}",
                command=argv, returncode=NOT_STARTED_RETURNCODE)
    finally:
        release()
    meaning = GATE_EXIT_MEANINGS.get(
        returncode, "that is not one of the gate's exit codes (0, 10, 20)")
    return WorkerResult(
        role=role, goal=goal, success=False,
        output=(f"{worker} started through the run-act gate (-Action Run). The gate "
                f"exited {returncode}: {meaning}. No provider output reaches the "
                "workspace on this path, so this is not a successful worker run."),
        command=argv, returncode=returncode)


def _field_problem(launch: GateLaunch, command: Sequence[str]) -> str | None:
    fields = (("gate_script", launch.gate_script), ("provider_exe", launch.provider_exe),
              ("role", launch.role), ("execution_policy", launch.execution_policy))
    for name, value in fields:
        if not isinstance(value, str):
            return f"{name} is not a string"
    if launch.execution_policy not in EXECUTION_POLICIES:
        return f"execution policy {launch.execution_policy!r} is not one of PowerShell's"
    if not _ROLE.fullmatch(launch.role):
        return f"role {launch.role!r} is not a letter followed by up to 63 letters, digits or underscores"
    # The script is opened HERE, so it is absolute by this host's rules; the
    # executable is only named to the gate, which runs on Windows.
    paths = (("gate_script", launch.gate_script, PurePath(launch.gate_script)),
             ("provider_exe", launch.provider_exe, PureWindowsPath(launch.provider_exe)))
    for name, value, path in paths:
        if "\0" in value or '"' in value or not path.is_absolute():
            return f"{name} {value!r} is not an absolute path without a NUL or a quote"
    if isinstance(command, str) or not all(isinstance(item, str) for item in command):
        return "the worker's vector is not a sequence of strings"
    if not command or command[0] != launch.provider_exe:
        first = command[0] if command else None
        return (f"the worker's executable {first!r} is not the gate's provider "
                f"executable {launch.provider_exe!r}")
    return None


def _argv_problem(argv: tuple[str, ...]) -> str | None:
    if any(not isinstance(item, str) or "\0" in item for item in argv):
        return "an argument holds a NUL"
    provider_args = argv[-1]
    quoted = provider_args == "" or " " in provider_args or "\t" in provider_args
    if not quoted and provider_args.startswith(POWERSHELL_DASHES):
        return (f"-ProviderArgs {provider_args!r} would reach PowerShell unquoted and "
                "be read as a parameter name, not as the provider's arguments")
    length = len(subprocess.list2cmdline(argv)) + 1
    if length > WINDOWS_COMMAND_LINE_LIMIT:
        return (f"the command line is {length} characters with its terminator, over "
                f"Windows' {WINDOWS_COMMAND_LINE_LIMIT}")
    return None


def _system_directory() -> str | None:
    """The system directory the operating system reports, or None off Windows.
    Read with `GetSystemDirectoryW`, so no environment variable moves it."""
    if os.name != "nt":
        return None
    import ctypes  # noqa: PLC0415 - Windows only

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW(buffer, 32768)
    if length <= 0 or length >= 32768:
        return None
    return buffer.value


def _has_console() -> bool:
    """Whether this process's standard input is a console the gate can read.
    `GetConsoleMode` answers only for a console input handle: a pipe, a file
    and the NUL device -- which `isatty()` reports as a terminal on Windows --
    all fail it. False off Windows."""
    if os.name != "nt":
        return False
    import ctypes  # noqa: PLC0415 - Windows only
    from ctypes import wintypes  # noqa: PLC0415

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetStdHandle.restype = wintypes.HANDLE
    kernel32.GetStdHandle.argtypes = (wintypes.DWORD,)
    kernel32.GetConsoleMode.restype = wintypes.BOOL
    kernel32.GetConsoleMode.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    handle = kernel32.GetStdHandle(wintypes.DWORD(-10 & 0xFFFFFFFF))  # STD_INPUT_HANDLE
    if not handle or handle == wintypes.HANDLE(-1).value:
        return False
    mode = wintypes.DWORD()
    return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode)))


#: The most a gate script may be; larger is not the pinned file.
_SCRIPT_READ_LIMIT = 16 * 1024 * 1024


def _read_script(path: str) -> tuple[bytes, Callable[[], None]]:
    """The script's bytes through ONE handle, and the call that releases it.

    On Windows the handle refuses other writers, renames and deletion while it
    is held, and it is held until the gate has exited. Elsewhere the read is
    one `O_NOFOLLOW` descriptor checked as a regular file. Raises OSError."""
    if os.name == "nt":
        return _read_script_windows(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"{path!r} is not a regular file")
        data = _read_bounded(descriptor)
    finally:
        os.close(descriptor)
    return data, lambda: None


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, 1 << 20)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > _SCRIPT_READ_LIMIT:
            raise OSError("the gate script is larger than any script this path starts")
        chunks.append(chunk)


def _read_script_windows(path: str) -> tuple[bytes, Callable[[], None]]:
    import ctypes  # noqa: PLC0415 - Windows only
    import msvcrt  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE)
    generic_read, file_share_read, open_existing = 0x80000000, 0x00000001, 3
    file_attribute_normal, open_reparse_point = 0x80, 0x00200000
    handle = kernel32.CreateFileW(path, generic_read, file_share_read, None, open_existing,
                                  file_attribute_normal | open_reparse_point, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY)
    except BaseException:
        kernel32.CloseHandle(wintypes.HANDLE(handle))
        raise
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_reparse_tag", 0):
            raise OSError(f"{path!r} is not a regular file")
        data = _read_bounded(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return data, lambda: os.close(descriptor)


def _run_on_console(argv: tuple[str, ...], env: dict[str, str], cwd: str) -> int:
    """Start the gate on this process's console and wait for it, with no
    capture and no timeout, and return its exit code."""
    return subprocess.run(argv, env=env, cwd=cwd, check=False).returncode  # noqa: S603
