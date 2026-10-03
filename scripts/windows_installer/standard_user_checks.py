"""Install, launch, stop and reopen ForgeSetup.exe on Windows, as a standard user.

Run by the `windows-install` CI job, in two modes:

    elevated       as the runner's administrator: the installer must REFUSE
                   (exit 10) and leave nothing;
    standard-user  as a local account the job creates in the Users group only,
                   with no administrator token: every other behaviour.

It reads the artifact the Linux job built (the real installer, and four
installers built from tiny sealed payloads that exercise refusals which all
happen before anything is extracted) and prints one PASS or FAIL line per
observation. It exits non-zero if any observation failed.

WHAT A PASS HERE IS, AND IS NOT. It is a run on a GitHub-hosted Windows image,
non-interactive, by a freshly created local account. It is NOT a run on a clean
accepted machine by a person: nothing here observes a UAC prompt on a default
configuration, SmartScreen or Smart App Control on a downloaded copy, the
Start-menu shortcut being double-clicked, the browser opening, or the absence of
network traffic during install. Those stay with the real-machine acceptance.

The pure parts (parsing, comparing) import and run anywhere; the Windows parts
are reached only by `main`.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _path in (ROOT / "src", ROOT / "scripts", ROOT / "scripts" / "windows_installer"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import installer_contract as contract  # noqa: E402

#: Names the installer must never create, before or after it runs: the state
#: classes it does not own (the person's project, Forge's runtime and seals,
#: the trust stores, CrewAI's storage and the provider homes).
STATE_NAMES = frozenset(name.casefold() for name in (
    ".nornyx", ".nornyx-forge", ".config", ".crewai", ".claude", ".codex", "ForgeProject",
    "CrewAI"))
#: Where an installer could leave state, as profile-relative folders, and the
#: only names each may gain from an install. Listing them is non-recursive.
WATCHED = {
    "": set(),
    "AppData/Local": {"Programs", "Microsoft", "Temp", "Packages"},
    "AppData/Local/Programs": {"Nornyx Forge"},
    "AppData/Roaming": {"Microsoft"},
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs": {contract.SHORTCUT_NAME},
}
#: Registry places an installer registers itself in; each must be unchanged.
#: "values" are read as named values (Environment, Run and RunOnce hold values,
#: and a `Run` entry is a value); "subkeys" as key names (Uninstall and App
#: Paths register one subkey per program).
REGISTRY_WATCH = {
    r"Environment": "values",
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall": "subkeys",
    r"Software\Microsoft\Windows\CurrentVersion\App Paths": "subkeys",
    r"Software\Microsoft\Windows\CurrentVersion\Run": "values",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce": "values",
}

#: Exit codes this driver does not provoke, and why. Each stays a property of
#: the script's text until a real machine shows it.
UNEXERCISED = {
    "EXIT_ELEVATION_UNKNOWN": "a process whose token cannot be read cannot be produced here",
}

FAILURES: list[str] = []


def expect(ok: bool, what: str) -> bool:
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    if not ok:
        FAILURES.append(what)
    return ok


# ---------------------------------------------------------------------------
# Pure parts
# ---------------------------------------------------------------------------

def parse_icacls(output: str, path: str) -> list[tuple[str, str]]:
    """(principal, permission flags) for each ACE `icacls <path>` printed. The
    first line leads with the path; the line "Successfully processed" and blank
    lines are not ACEs."""
    aces = []
    for raw in output.splitlines():
        line = raw.replace(path, "", 1).strip()
        match = re.fullmatch(r"(.+?):(\(.+\))", line)
        if match:
            aces.append((match.group(1).strip(), match.group(2)))
    return aces


def acl_problems(aces: list[tuple[str, str]], *, computer: str, user: str) -> list[str]:
    """Why an ACL names someone the installer should not have granted
    anything: a principal beyond SYSTEM, Administrators and the user, or no
    ACE at all (a path that does not exist prints none).

    WHAT THIS DOES NOT JUDGE: whether an ACE is inherited. On the CI runner the
    objects the installer makes show their ACEs as explicit ((OI)(CI)(F) with no
    (I)); whether that is the installer's doing or the way this profile's
    parent hands its ACEs on is decided by `acl_differences` against a control
    made the plain way in the same parent, never by the presence of "(I)"."""
    allowed = {"nt authority\\system", "builtin\\administrators",
               f"{computer}\\{user}".casefold()}
    problems = []
    if not aces:
        problems.append("icacls printed no ACE")
    for principal, flags in aces:
        if principal.casefold() not in allowed:
            problems.append(f"{principal} holds {flags}")
    return problems


def acl_signature(aces: list[tuple[str, str]]) -> frozenset[tuple[str, str]]:
    """The access an ACL grants: principal and rights with their inheritance
    flags, without the (I) mark that says only where the ACE came from."""
    return frozenset((principal.casefold(), flags.replace("(I)", "")) for principal, flags in aces)


def acl_differences(subject: list[tuple[str, str]], control: list[tuple[str, str]]) -> list[str]:
    """What the installer's object grants that a control made by a plain
    mkdir or copy, by the same user in the same parent, does not, and what the
    control grants that the installer's object does not."""
    made, plain = acl_signature(subject), acl_signature(control)
    return ([f"only on the installer's object: {who} {flags}" for who, flags in sorted(made - plain)]
            + [f"only on the control: {who} {flags}" for who, flags in sorted(plain - made)])


def listing_problems(before: dict[str, set[str]], after: dict[str, set[str]]) -> list[str]:
    """What an install added to the watched folders beyond what each may gain,
    what it removed, and any state-class name present afterwards."""
    problems = []
    for folder, allowed in WATCHED.items():
        added = {name for name in after[folder] - before[folder]
                 if not name.casefold().startswith("ntuser")} - allowed
        if added:
            problems.append(f"{folder or '<profile>'} gained {sorted(added)}")
        if before[folder] - after[folder]:
            problems.append(f"{folder or '<profile>'} lost {sorted(before[folder] - after[folder])}")
        stateful = {name for name in after[folder] if name.casefold() in STATE_NAMES}
        if stateful:
            problems.append(f"{folder or '<profile>'} holds state-class names {sorted(stateful)}")
    return problems


def tree_state(root: Path) -> dict[str, tuple[int, int]]:
    """Every file under `root` as relative path -> (size, mtime in ns), and
    every folder as "relative path/" -> (0, 0): a folder's own time moves with
    its children and is not compared, but a folder that appears or goes does
    change the state (an empty `.partial` folder is a difference)."""
    state = {}
    for directory, subdirectories, files in os.walk(root):
        for name in subdirectories:
            state[(Path(directory) / name).relative_to(root).as_posix() + "/"] = (0, 0)
        for name in files:
            path = Path(directory) / name
            status = path.lstat()
            state[path.relative_to(root).as_posix()] = (status.st_size, status.st_mtime_ns)
    return state


def refusal_problems(got: int, log: str, wanted: int) -> list[str]:
    """Why a run is not the installer's refusal with exit code `wanted`: another
    exit code, or a log that does not carry the installer's own line for it. A
    process that never ran the script (or a code from somewhere else) cannot
    produce that line."""
    problems = []
    if got != wanted:
        problems.append(f"exit code {got}, not {wanted}")
    if f"refused ({wanted}):" not in log:
        problems.append(f"the log has no 'refused ({wanted}):' line: {log.strip()[:200]!r}")
    return problems


def registry_problems(state: dict[str, object]) -> list[str]:
    """Why a registry census cannot be trusted to see a change: the places
    that always hold something (the user's Environment, the machine PATH) read
    as empty, which is what an unreadable key looks like."""
    problems = []
    if not state.get("HKCU Environment"):
        problems.append("HKCU Environment read as empty")
    if not state.get("HKLM PATH"):
        problems.append("HKLM PATH read as empty")
    return problems


def path_without(names: tuple[str, ...], path_value: str) -> str:
    """`path_value` without any folder that holds one of `names`."""
    kept = [entry for entry in path_value.split(os.pathsep)
            if entry and not any((Path(entry) / name).exists() for name in names)]
    return os.pathsep.join(kept)


# ---------------------------------------------------------------------------
# Windows parts
# ---------------------------------------------------------------------------

def _powershell(script: str, **variables: str) -> str:
    environment = {**os.environ, **variables}
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, timeout=180, env=environment)
    # Bytes, decoded here: the output is ASCII (JSON, process ids) and a
    # replacement character is a visible difference, never a crash.
    if completed.returncode != 0:
        raise RuntimeError(f"powershell exited {completed.returncode}: "
                           f"{completed.stderr.decode('utf-8', 'replace')[:400]}")
    return completed.stdout.decode("utf-8", "replace").strip()


def read_shortcut(path: Path) -> dict[str, str]:
    script = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:FORGE_LNK); "
              "@{TargetPath=$s.TargetPath; Arguments=$s.Arguments; "
              "WorkingDirectory=$s.WorkingDirectory} | ConvertTo-Json -Compress")
    return json.loads(_powershell(script, FORGE_LNK=str(path)))


def processes_under(folder: Path, name: str | None = None) -> list[int]:
    script = ("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and "
              "$_.ExecutablePath.StartsWith($env:FORGE_DIR, [StringComparison]::OrdinalIgnoreCase) "
              "-and ((-not $env:FORGE_NAME) -or $_.Name -ieq $env:FORGE_NAME) } | "
              "ForEach-Object { $_.ProcessId }")
    out = _powershell(script, FORGE_DIR=str(folder) + "\\", FORGE_NAME=name or "")
    return [int(line) for line in out.split() if line.strip()]


def is_admin() -> bool:
    import ctypes  # noqa: PLC0415 - Windows only

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def registry_state() -> dict[str, object]:
    import winreg  # noqa: PLC0415 - Windows only

    def read(hive, key: str, want_values: bool):
        try:
            with winreg.OpenKey(hive, key) as handle:
                if want_values:
                    values, index = {}, 0
                    while True:
                        try:
                            name, value, _kind = winreg.EnumValue(handle, index)
                        except OSError:
                            return values
                        values[name] = value
                        index += 1
                subkeys, index = [], 0
                while True:
                    try:
                        subkeys.append(winreg.EnumKey(handle, index))
                    except OSError:
                        return sorted(subkeys)
                    index += 1
        except OSError:
            return None

    state: dict[str, object] = {
        "HKLM PATH": (read(winreg.HKEY_LOCAL_MACHINE,
                           r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                           True) or {}).get("Path")}
    for key, kind in REGISTRY_WATCH.items():
        state["HKCU " + key] = read(winreg.HKEY_CURRENT_USER, key, kind == "values")
    return state


def watched_listing(profile: Path) -> dict[str, set[str]]:
    listing = {}
    for folder in WATCHED:
        path = profile.joinpath(*folder.split("/")) if folder else profile
        listing[folder] = set(os.listdir(path)) if path.is_dir() else set()
    return listing


def run_setup(exe: Path, work: Path, tag: str, *, env: dict[str, str] | None = None,
              timeout: int = 1800) -> tuple[int, str]:
    """Run an installer silently with an opt-in log; (exit code, log text)."""
    log = work / f"{tag}.log"
    log.unlink(missing_ok=True)
    started = time.monotonic()
    completed = subprocess.run([str(exe), "/S", f"/LOG={log}"], env=env, timeout=timeout,
                               cwd=str(work))
    text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    print(f"  {exe.parent.name}\\{exe.name} /S -> exit {completed.returncode} in "
          f"{time.monotonic() - started:.1f}s; log {text.strip()[:500]!r}", flush=True)
    return completed.returncode, text


def build_record(folder: Path) -> dict:
    return json.loads((folder / "ForgeSetup.build.json").read_text(encoding="utf-8"))


def manifest_of(record: dict) -> dict:
    """The fields of a payload manifest the receipt and the shortcut name,
    from a build record."""
    payload = record["payload"]
    return {"version": payload["version"], "source_commit": payload["source_commit"],
            "payload_sha256": payload["sha256"]}


def verify_installed(folder: Path, sha: str) -> int:
    python = folder / "python" / "python.exe"
    return subprocess.run([str(python), "-B", "-I", "-m", "nornyx_forge.windows_payload",
                           "verify", str(folder), "--expect", sha],
                          capture_output=True, timeout=900).returncode


def install_root() -> Path:
    return Path(os.environ["LOCALAPPDATA"]).joinpath(*contract.INSTALL_ROOT_PARTS)


# ---------------------------------------------------------------------------
# The two modes
# ---------------------------------------------------------------------------

def mode_elevated(artifact: Path, work: Path) -> None:
    codes = contract.exit_codes(contract.nsi_text())
    expect(is_admin(), "the runner's process is elevated (the refusal needs an elevated process "
                       "to be observed at all)")
    root = install_root()
    expect(not root.exists(), "no install folder exists before the elevated run")
    code, log = run_setup(artifact / "forge-setup" / "ForgeSetup.exe", work, "elevated")
    problems = refusal_problems(code, log, codes["EXIT_ELEVATED"])
    expect(not problems, f"an elevated run is refused by the installer's own line {problems}")
    expect("without 'Run as administrator'" in log, "the refusal explains itself in the log")
    expect(not root.exists(), "the elevated run created no install folder")


USER_SHELL_FOLDERS = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
START_MENU_PROGRAMS = ("Microsoft", "Windows", "Start Menu", "Programs")


@contextlib.contextmanager
def redirected_local_appdata(target: str):
    """Point this account's own `Local AppData` shell folder at `target` for the
    length of the `with`, then put the old value back. A standard user may write
    its own HKCU; the installer reads the folder through the shell, not through
    the environment variable."""
    import winreg  # noqa: PLC0415 - Windows only

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, USER_SHELL_FOLDERS, 0,
                        winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        old, kind = winreg.QueryValueEx(key, "Local AppData")
        winreg.SetValueEx(key, "Local AppData", 0, winreg.REG_EXPAND_SZ, target)
        try:
            yield
        finally:
            winreg.SetValueEx(key, "Local AppData", 0, kind, old)


def aces_of(path: Path) -> tuple[list[tuple[str, str]], str]:
    """(ACEs, raw `icacls` text) of one path."""
    completed = subprocess.run(["icacls", str(path)], capture_output=True, timeout=60)
    listing = completed.stdout.decode("utf-8", "replace")
    return parse_icacls(listing, str(path)), listing


def acl_check(path: Path, *, computer: str, user: str, label: str) -> list[str]:
    """The installer's object judged against a control: SYSTEM, Administrators
    and the user only, and the same access as a plain mkdir (for a folder) or
    copy (for a file) made by this user in the same parent, which is removed
    again. The raw ACLs of the parent, the control and the object are printed,
    so a failure shows its own cause. An empty listing is a problem, so a path
    that does not exist cannot pass."""
    parent = path.parent
    control = parent / (".acl-control-dir" if path.is_dir() else ".acl-control-file")
    if path.is_dir():
        control.mkdir()
    else:
        shutil.copyfile(path, control)
    try:
        made, made_raw = aces_of(path)
        plain, plain_raw = aces_of(control)
        _parent_aces, parent_raw = aces_of(parent)
    finally:
        if control.is_dir():
            control.rmdir()
        else:
            control.unlink(missing_ok=True)
    print(f"  [acl {label}] parent {parent}:\n{parent_raw.rstrip()}\n"
          f"  [acl {label}] control, made the plain way beside it:\n{plain_raw.rstrip()}\n"
          f"  [acl {label}] the installer's object {path}:\n{made_raw.rstrip()}", flush=True)
    return acl_problems(made, computer=computer, user=user) + acl_differences(made, plain)


def planted_acl_problems(work: Path, *, computer: str, user: str) -> list[str]:
    """The ACL check on an object that really does carry an extra ACE (the
    Users group granted read on a folder made the plain way): it must find
    something. Proof that `acl_check` can fail on this host's own `icacls`."""
    base = work / "acl-plant"
    shutil.rmtree(base, ignore_errors=True)
    plain, planted = base / "plain", base / "planted"
    plain.mkdir(parents=True)
    planted.mkdir()
    try:
        subprocess.run(["icacls", str(planted), "/grant", "BUILTIN\\Users:(OI)(CI)(R)"],
                       check=True, capture_output=True, timeout=60)
        made, _raw = aces_of(planted)
        control, _raw = aces_of(plain)
        return acl_problems(made, computer=computer, user=user) + acl_differences(made, control)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def refused(exe: Path, work: Path, tag: str, code: int) -> tuple[list[str], str]:
    """Run an installer that must refuse with `code`: (problems, log)."""
    got, log = run_setup(exe, work, tag)
    return refusal_problems(got, log, code), log


def mode_standard_user(artifact: Path, work: Path) -> None:
    codes = contract.exit_codes(contract.nsi_text())
    import build_windows_bundle as bundle  # noqa: PLC0415

    profile = Path(os.environ["USERPROFILE"])
    user, computer = os.environ["USERNAME"], os.environ["COMPUTERNAME"]
    real_dir = artifact / "forge-setup"
    real_exe = real_dir / "ForgeSetup.exe"
    manifest = manifest_of(build_record(real_dir))
    variants = {name: artifact / "variants" / name for name in
                ("small", "other", "same-version", "long")}
    small = variants["small"]
    small_manifest = manifest_of(build_record(small))
    root = install_root()
    programs = root.parent
    folder = root / contract.version_directory(manifest)
    start_menu = Path(os.environ["APPDATA"]).joinpath(*START_MENU_PROGRAMS)
    shortcut_path = start_menu / contract.SHORTCUT_NAME

    expect(not is_admin(), f"this process is not elevated (user {user})")
    expect(not root.exists(), "no install folder exists before the run")
    expect(not shortcut_path.exists(), "no Start-menu shortcut of the installer's name exists "
                                       "before the run")
    before_listing, before_registry = watched_listing(profile), registry_state()
    expect(registry_problems(before_registry) == [],
           f"the registry census read what it is meant to read {registry_problems(before_registry)}")
    planted = planted_acl_problems(work, computer=computer, user=user)
    expect(bool(planted), f"the ACL check finds an extra ACE planted on a folder it is shown {planted}")

    # --- refusals, each from a tiny sealed payload, each leaving nothing
    problems, _log = refused(variants["long"] / "ForgeSetup.exe", work, "long",
                             codes["EXIT_TOO_LONG"])
    expect(not problems and not root.exists(),
           f"paths of 297 characters (the boundary at 259 is not run) are refused {problems}")

    outside = work / "redirected-appdata"
    for label, target in (("a location outside the profile", str(outside)),
                          ("a UNC location", r"\\forge-ci-unreachable\share\AppData\Local")):
        try:
            with redirected_local_appdata(target):
                problems, _log = refused(small / "ForgeSetup.exe", work, "location",
                                         codes["EXIT_LOCATION"])
        finally:
            for leftover in (root, outside):
                if leftover.exists():
                    shutil.rmtree(leftover)
            shortcut_path.unlink(missing_ok=True)
        expect(not problems, f"{label} (the account's Local AppData shell folder moved) is "
                             f"refused {problems}")
    expect(not outside.exists() and not root.exists(), "the location refusals created nothing")

    programs.mkdir(parents=True, exist_ok=True)
    root.mkdir()
    (root / "stranger.txt").write_text("not forge's\n", encoding="utf-8", newline="")
    problems, _log = refused(small / "ForgeSetup.exe", work, "stranger", codes["EXIT_NOT_FORGE"])
    expect(not problems and sorted(os.listdir(root)) == ["stranger.txt"],
           f"a non-empty folder without a receipt is not Forge's and is left alone {problems}")
    shutil.rmtree(root)

    target = work / "junction-target"
    target.mkdir()
    subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(root), str(target)], check=True,
                   capture_output=True, timeout=60)
    problems, _log = refused(small / "ForgeSetup.exe", work, "junction", codes["EXIT_LINK"])
    expect(not problems and os.listdir(target) == [],
           f"a junction at the install folder is refused and its target is untouched {problems}")
    os.rmdir(root)
    shutil.rmtree(target)

    partial = contract.version_directory(small_manifest) + contract.PARTIAL_SUFFIX
    for label, receipt in (("with a receipt", True), ("with no receipt (a failed first install)",
                                                      False)):
        root.mkdir()
        if receipt:
            (root / contract.RECEIPT_NAME).write_text("{}\n", encoding="utf-8", newline="")
        (root / partial).mkdir()
        problems, _log = refused(small / "ForgeSetup.exe", work, "unfinished",
                                 codes["EXIT_UNFINISHED"])
        expect(not problems and (root / partial).is_dir(),
               f"an unfinished earlier install {label} is refused and left in place {problems}")
        shutil.rmtree(root)

    for label in ("a file", "a folder"):
        if label == "a file":
            shortcut_path.write_text("not the installer's\n", encoding="utf-8", newline="")
        else:
            shortcut_path.unlink()
            shortcut_path.mkdir()
        problems, _log = refused(small / "ForgeSetup.exe", work, "shortcut-exists",
                                 codes["EXIT_SHORTCUT_EXISTS"])
        expect(not problems and not root.exists(),
               f"{label} already named like the shortcut is refused and nothing is installed "
               f"{problems}")
        if label == "a file":
            expect(shortcut_path.read_text(encoding="utf-8") == "not the installer's\n",
                   "the file named like the shortcut is unchanged")
    shortcut_path.rmdir()

    # --- a failure after the folder is in place: the shortcut cannot be written
    subprocess.run(["icacls", str(start_menu), "/deny", f"{user}:(WD,AD)"], check=True,
                   capture_output=True, timeout=60)
    try:
        problems, _log = refused(small / "ForgeSetup.exe", work, "shortcut-fails",
                                 codes["EXIT_FAILED"])
    finally:
        subprocess.run(["icacls", str(start_menu), "/remove:d", user], check=True,
                       capture_output=True, timeout=60)
    small_folder = root / contract.version_directory(small_manifest)
    expect(not problems and small_folder.is_dir() and not (root / contract.RECEIPT_NAME).exists()
           and not shortcut_path.exists(),
           f"a shortcut that cannot be written fails the install (17), keeps that code, writes "
           f"no receipt and leaves the verified folder in place {problems}")
    shutil.rmtree(root)

    # --- the real installer, into an existing EMPTY folder and into an ABSENT one
    root.mkdir()
    check_install("install-empty-root", real_exe, work, manifest, folder=folder, root=root,
                  shortcut_path=shortcut_path, profile=profile, user=user, computer=computer,
                  root_created=False, before_listing=before_listing,
                  before_registry=before_registry)
    if not folder.is_dir():
        return

    # --- the existing-install rule
    receipt_path = root / contract.RECEIPT_NAME
    state, kept_receipt = tree_state(root), receipt_path.read_bytes()
    code, log = run_setup(real_exe, work, "again")
    expect(code == 0 and "already installed" in log, "the same payload again verifies and "
                                                      "exits 0, by its own log")
    expect(tree_state(root) == state and receipt_path.read_bytes() == kept_receipt,
           "the second run changed no file, size, time or folder")
    problems, _log = refused(variants["other"] / "ForgeSetup.exe", work, "other",
                             codes["EXIT_OTHER_VERSION"])
    expect(not problems and tree_state(root) == state,
           f"another version is refused and nothing changes {problems}")
    problems, _log = refused(variants["same-version"] / "ForgeSetup.exe", work, "same-version",
                             codes["EXIT_DOES_NOT_VERIFY"])
    expect(not problems and tree_state(root) == state,
           f"other bytes under the same version are refused and nothing changes {problems}")

    # --- launch, stop, reopen, from the shortcut's own command line
    launch_checks(bundle, work, folder, read_shortcut(shortcut_path), manifest)
    expect(verify_installed(folder, manifest["payload_sha256"]) == 0,
           "the installed copy still verifies after being run (the shortcut starts the "
           "interpreter with bytecode writing off)")

    # --- the real installer again, now into an ABSENT folder
    shutil.rmtree(root)
    shortcut_path.unlink()
    check_install("install-absent-root", real_exe, work, manifest, folder=folder, root=root,
                  shortcut_path=shortcut_path, profile=profile, user=user, computer=computer,
                  root_created=True, before_listing=before_listing,
                  before_registry=before_registry)

    # --- git absent: a fresh install from a tiny payload, with no git and no Python on PATH
    shutil.rmtree(root)
    shortcut_path.unlink(missing_ok=True)
    lean = {**os.environ, "PATH": path_without(("git.exe", "python.exe"), os.environ["PATH"])}
    code, log = run_setup(small / "ForgeSetup.exe", work, "no-git", env=lean)
    expect(code == 0 and f"installed {contract.version_directory(small_manifest)}" in log,
           "an install with no git and no Python on PATH succeeds, by its own log (git is "
           "advisory; only the embedded interpreter runs)")
    absent = (root / contract.RECEIPT_NAME).read_text(encoding="utf-8") if code == 0 else "{}"
    expect(not contract.check_receipt(absent, small_manifest)
           and json.loads(absent)["prerequisites"]["git"] == "not found"
           and json.loads(absent)["root_created"] is True,
           "the receipt records git as not found and the root as created")


def check_install(tag: str, exe: Path, work: Path, manifest: dict, *, folder: Path, root: Path,
                  shortcut_path: Path, profile: Path, user: str, computer: str,
                  root_created: bool, before_listing: dict, before_registry: dict) -> None:
    """One install of the real installer and everything it must have done. The
    ACL of the install ROOT is judged only where the installer made it
    (`root_created`); otherwise the driver made it and it says nothing."""
    expect(not folder.exists() and not shortcut_path.exists(),
           f"[{tag}] neither the version folder nor the shortcut exists before the run")
    code, log = run_setup(exe, work, tag)
    if not expect(code == 0 and f"installed {folder.name}" in log,
                  f"[{tag}] the real installer exits 0 and its own log says it installed "
                  f"(got {code})"):
        return
    expect(folder.is_dir() and (folder / "forge-payload.json").is_file(),
           f"[{tag}] the verified payload folder is in place")
    expect(not (root / (folder.name + contract.PARTIAL_SUFFIX)).exists(),
           f"[{tag}] no .partial folder remains")
    receipt_path = root / contract.RECEIPT_NAME
    receipt = receipt_path.read_text(encoding="utf-8")
    problems = contract.check_receipt(receipt, manifest)
    expect(not problems, f"[{tag}] the receipt is the installer's and names exactly this "
                         f"payload {problems}")
    parsed = json.loads(receipt)
    expect(parsed["root_created"] is root_created,
           f"[{tag}] the receipt says the root folder was {'' if root_created else 'not '}"
           "created by the installer")
    expect(parsed["prerequisites"]["git"] == "found", f"[{tag}] git on PATH is reported found")
    expect(verify_installed(folder, manifest["payload_sha256"]) == 0,
           f"[{tag}] the installed copy verifies, from outside, against the expected identity")
    expect(shortcut_path.is_file(), f"[{tag}] the per-user Start-menu shortcut exists")
    if shortcut_path.is_file():
        found = read_shortcut(shortcut_path)
        wanted = contract.shortcut_expectation(manifest, install_root=str(root),
                                               profile=str(profile))
        expect({k: found[k].casefold() for k in wanted} == {k: v.casefold()
                                                            for k, v in wanted.items()},
               f"[{tag}] the shortcut starts the embedded interpreter in the install root {found}")
    judged = [folder, folder / "forge-payload.json"] + ([root] if root_created else [])
    for path in judged:
        acl = acl_check(path, computer=computer, user=user, label=f"{tag} {path.name}")
        expect(not acl, f"[{tag}] {path.name} grants no one anything that a plain mkdir or "
                        f"copy beside it does not {acl}")
    after_listing, after_registry = watched_listing(profile), registry_state()
    listed = listing_problems(before_listing, after_listing)
    expect(not listed, f"[{tag}] only the install folder and the shortcut were added {listed}")
    expect(after_registry == before_registry,
           f"[{tag}] no registry value changed (PATH, Uninstall, App Paths, Run, RunOnce)")


def launch_checks(bundle, work: Path, folder: Path, shortcut: dict, manifest: dict) -> None:
    """Start the runtime with the shortcut's exact command line (plus the
    scratch arguments the smoke also passes), join it, stop it, and start it
    again."""
    scratch = work / "launch"
    shutil.rmtree(scratch, ignore_errors=True)
    (scratch / "profile").mkdir(parents=True)
    runtime, project, session = scratch / "runtime", scratch / "project", work / "session.json"
    session.unlink(missing_ok=True)
    environment = {**os.environ, "USERPROFILE": str(scratch / "profile"),
                   "HOME": str(scratch / "profile"),
                   "PATH": path_without(("python.exe",), os.environ["PATH"])}
    extra = subprocess.list2cmdline(["--project-dir", str(project), "--runtime-dir", str(runtime),
                                     "--port", "0", "--no-browser", "--session-file",
                                     str(session)])
    command = f'"{shortcut["TargetPath"]}" {shortcut["Arguments"]} {extra}'

    def wait_record(status: str, timeout: float = 180.0) -> dict | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for path in sorted(runtime.glob("*.json")) if runtime.exists() else []:
                record = bundle._read_record(path)
                if isinstance(record, dict) and record.get("status") == status:
                    return record
            time.sleep(0.5)
        return None

    first = subprocess.Popen(command, env=environment, cwd=str(folder.parent),
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    ready = wait_record("ready")
    if not expect(ready is not None, "the shortcut's command line starts the runtime and it "
                                      "reaches ready"):
        first.kill()
        return
    port, instance = ready["port"], ready["instance"]
    status, body, _kind = bundle._get(port, "/api/runtime")
    expect(status == 200 and json.loads(body).get("instance") == instance,
           "the running runtime answers as the recorded instance")
    expect(len(processes_under(folder, "pythonw.exe")) == 1,
           "one pythonw.exe from the install folder is running")

    joined = subprocess.run(command, env=environment, cwd=str(folder.parent), timeout=300,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    again = wait_record("ready", 30)
    expect(joined.returncode == 0 and again is not None and again["instance"] == instance
           and len(processes_under(folder, "pythonw.exe")) == 1,
           "a second launch joins the running instance and starts no second server")

    deadline, token = time.monotonic() + 30, None
    while token is None and time.monotonic() < deadline:
        token = bundle._read_session_token(session)
        time.sleep(0.2)
    stop_status, _body = bundle._post_json(port, "/api/runtime/stop",
                                           {"actor": bundle.SMOKE_ACTOR}, token=token)
    stopped = wait_record("stopped", 60)
    expect(stop_status == 200 and stopped is not None and stopped["instance"] == instance,
           "stop is accepted and the record reaches stopped")
    try:
        first.wait(timeout=60)
    except subprocess.TimeoutExpired:
        first.kill()
    gone = time.monotonic() + 30
    while processes_under(folder, "pythonw.exe") and time.monotonic() < gone:
        time.sleep(0.5)
    expect(not processes_under(folder, "pythonw.exe"),
           "no pythonw.exe from the install folder remains after stop")

    restarted = subprocess.Popen(command, env=environment, cwd=str(folder.parent),
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
    time.sleep(2)  # the previous record says stopped; the new owner writes its own
    second = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline and second is None:
        for path in sorted(runtime.glob("*.json")):
            record = bundle._read_record(path)
            if isinstance(record, dict) and record.get("status") == "ready" and record.get(
                    "instance") != instance:
                second = record
        time.sleep(0.5)
    expect(second is not None, "a launch after stop starts a new instance")
    if second is not None:
        token = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            token = bundle._read_session_token(session)
            if token:
                break
            time.sleep(0.2)
        bundle._post_json(second["port"], "/api/runtime/stop", {"actor": bundle.SMOKE_ACTOR},
                          token=token)
    try:
        restarted.wait(timeout=60)
    except subprocess.TimeoutExpired:
        restarted.kill()
    gone = time.monotonic() + 30
    while processes_under(folder, "pythonw.exe") and time.monotonic() < gone:
        time.sleep(0.5)
    expect(not processes_under(folder, "pythonw.exe"),
           "the second instance stopped too and no pythonw.exe remains")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("mode", choices=["elevated", "standard-user"])
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    arguments = parser.parse_args(argv)
    arguments.work.mkdir(parents=True, exist_ok=True)
    try:
        {"elevated": mode_elevated, "standard-user": mode_standard_user}[arguments.mode](
            arguments.artifact, arguments.work)
    except Exception as error:  # noqa: BLE001 - a crash is a failed observation, never a pass
        expect(False, f"the run crashed: {type(error).__name__}: {error}")
    print(f"{len(FAILURES)} failed observations" if FAILURES else "all observations passed",
          flush=True)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
