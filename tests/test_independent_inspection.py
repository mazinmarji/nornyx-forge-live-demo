"""An independent inspection is a claim about a subject, and both must hold.

Two things have to be true at once, and the old version of this file only
checked one of them.

The subject half was right: an inspection is bound to
``H(governed_input_digest + contract_set_digest + pre_inspection_evidence)``,
so anything moving that digest makes the inspection stale, and recomputing the
current digest must never rebind old PASS evidence to it. Those tests survive
here unchanged in intent.

The identity half was missing entirely. The attestation was unauthenticated, so
independence was read off the artifact — a builder asserting their own
non-self-approval. Authentication is now a precondition, which changes what this
file has to do: every attestation is signed by an ephemeral reviewer key through
the real issuer, and read back through the production verifier. Nothing here
hand-writes an attestation, because a hand-written one no longer means anything.

The authentication controls themselves live in `test_reviewer_authentication.py`.
This file assumes them and tests what the assurance derivation does with the
result.
"""

from __future__ import annotations

import getpass
import json
import ntpath
import os
import platform
import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import refresh_governance_evidence as rge  # noqa: E402
from issue_inspection_attestation import (  # noqa: E402
    build_attestation,
    sign_attestation,
)

CONTRACTS = Path(".nornyx/contracts")
REFRESH = "scripts/refresh_governance_evidence.py"
ATTESTATIONS = CONTRACTS / "evidence" / "attestations"

#: Where the generator writes the independent-review verdict.
RECORD_RELATIVE = ".nornyx/contracts/evidence/architecture_independent_review.json"
INDEX_RELATIVE = ".nornyx/contracts/evidence/INDEX.json"
REQUIRED = ("test-inspector", "architecture-inspector", "security-inspector")
BUILDER = "builder.nornyx_forge"


def _git(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(work), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )


class Reviewers:
    """Three distinct reviewers, one per required role.

    Ephemeral: generated per test, never written to the repository, and the
    private halves exist only in memory. The trust store holds public keys and
    sits outside the governed tree, so no edit to the workspace can add a
    trusted reviewer — which is the property the store exists to have.
    """

    def __init__(self, tmp_path: Path):
        self.private: dict[str, bytes] = {}
        entries = []
        for index, role in enumerate(REQUIRED):
            key = Ed25519PrivateKey.generate()
            name = f"reviewer.{role.split('-')[0]}"
            self.private[role] = key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            entries.append(
                {
                    "key_id": f"rev-{index}",
                    "reviewer": name,
                    "roles": [role],
                    "public_key": key.public_key()
                    .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                    .decode("utf-8"),
                    "status": "active",
                }
            )
        self.names = {role: entry["reviewer"] for role, entry in zip(REQUIRED, entries)}
        self.key_ids = {role: entry["key_id"] for role, entry in zip(REQUIRED, entries)}
        self.store = tmp_path / "reviewer_trust.json"
        self.store.write_text(
            json.dumps(
                {"schema": "nornyx.forge.reviewer_trust_store.v1", "reviewers": entries},
                indent=2,
            ),
            encoding="utf-8",
        )


def _workspace(tmp_path: Path) -> Path:
    work = tmp_path / "repo"
    work.mkdir()
    for item in ("scripts", "src", "docs", ".nornyx", "tests", ".github"):
        shutil.copytree(
            ROOT / item,
            work / item,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
        )
    # Derived from the scope, not listed here. Seven fixtures each kept
    # their own copy of this list and all seven broke the moment the scope
    # gained a required file -- SUBJECT_SCOPE_INCOMPLETE, which is the scope
    # correctly refusing to call a smaller subject verified.
    sys.path.insert(0, str(ROOT / 'tests'))
    from governed_workspace import copy_governed_workspace  # noqa: PLC0415

    copy_governed_workspace(work)
    _git(work, "init", "-q")
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "fixture")
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "fixture")
    return work


def _run(work: Path, reviewers: Reviewers | None, *args: str):
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    if reviewers is not None:
        env["FORGE_REVIEWER_TRUST_STORE"] = str(reviewers.store)
    else:
        # Explicitly nowhere, so an operator's real store cannot leak in and
        # make a negative case pass for the wrong reason.
        env["FORGE_REVIEWER_TRUST_STORE"] = str(work / "no-such-store.json")
    env["FORGE_BUILDER_IDENTITY"] = BUILDER
    return subprocess.run(
        [sys.executable, *args],
        cwd=work,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )


def _settle(work: Path) -> None:
    """Generate machine evidence and let the contracts settle."""
    assert _run(work, None, REFRESH, "--as-of", "2026-08-02T00:00:00Z").returncode == 0
    assert _run(work, None, REFRESH, "--sync-contracts").returncode == 0


def _current_subject(work: Path) -> str:
    """Ask the tool itself what an inspection here would be reviewing."""
    completed = _run(
        work,
        None,
        "-c",
        "import sys; sys.path.insert(0,'scripts');"
        "import refresh_governance_evidence as r;"
        "print(r.current_inspection_subject())",
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _attest(
    work: Path,
    reviewers: Reviewers,
    *,
    subject: str | None = None,
    roles: tuple[str, ...] = REQUIRED,
    verdicts: dict[str, str] | None = None,
    reviewer_override: dict[str, str] | None = None,
    role_override: dict[str, str] | None = None,
) -> None:
    """Sign real attestations, honest by default.

    Signed through `scripts/issue_inspection_attestation.py` — the reviewer-side
    tool an actual reviewer runs. A fixture that produced signatures its own way
    would prove the fixture works.
    """
    subject = subject if subject is not None else _current_subject(work)
    target = work / ATTESTATIONS
    target.mkdir(parents=True, exist_ok=True)

    for role in roles:
        signing_role = (role_override or {}).get(role, role)
        attestation = build_attestation(
            inspection_subject_digest=subject,
            reviewer=(reviewer_override or {}).get(role, reviewers.names[role]),
            reviewer_key_id=reviewers.key_ids[role],
            inspector_role=signing_role,
            verdict=(verdicts or {}).get(role, "pass"),
            findings=[],
            tool="claude-opus",
            tool_version="5",
        )
        signed = sign_attestation(attestation, reviewers.private[role])
        (target / f"{role}.json").write_bytes(
            json.dumps(signed, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )

    # The attestations join the final evidence set, so the review binding is
    # regenerated over them. That is the chain order: contracts settle, the
    # subject freezes, inspectors report, and only then does the package saying
    # what was reviewed get written.
    assert _run(work, reviewers, REFRESH, "--review-binding").returncode == 0


def _assurance(work: Path, reviewers: Reviewers | None) -> dict:
    """Recompute the assurance position, as --verify does."""
    completed = _run(
        work,
        reviewers,
        "-c",
        "import json,sys; sys.path.insert(0,'scripts');"
        "import refresh_governance_evidence as r;"
        "print(json.dumps(r.derive_assurance_state()))",
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _inspected(work: Path, reviewers: Reviewers | None) -> bool:
    return _assurance(work, reviewers)["assurance_state"] == "independently_inspected"


@pytest.fixture
def settled(tmp_path: Path) -> tuple[Path, Reviewers]:
    work = _workspace(tmp_path)
    _settle(work)
    return work, Reviewers(tmp_path)


# --------------------------------------------------------------------------
# What a complete inspection requires
# --------------------------------------------------------------------------


def test_a_complete_authenticated_inspection_over_the_current_subject_passes(settled):
    work, reviewers = settled
    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "independently_inspected", state["problems"]
    assert state["problems"] == []
    assert state["assurance_problems"] == []
    assert state["required_inspectors_complete"] is True
    assert state["independent"] is True
    assert state["authenticated_reviewers"] == sorted(reviewers.names.values())


def test_an_inspection_nobody_can_authenticate_establishes_nothing(settled):
    """Same files, no trust store. The artifacts alone must decide nothing."""
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True

    state = _assurance(work, None)
    assert state["assurance_state"] == "not_independently_inspected"
    assert any("no reviewer trust store" in p for p in state["assurance_problems"])
    assert state["independent"] is False


def test_the_absent_default_store_is_reported_without_the_readers_identity(settled):
    """The generator's own evidence must not embed WHO ran it or WHERE.

    `reviewer_store_path()` falls back to `Path.home()/".nornyx"/...` when
    `FORGE_REVIEWER_TRUST_STORE` is unset. Measured before this test existed:
    on a clean regeneration that absent default's FULL path -- which on a real
    developer's machine names their actual Windows account and computer name
    -- reached `.nornyx/contracts/evidence/architecture_independent_review.json`'s
    `verdict_basis` verbatim, a file this repository commits. A fake HOME
    stands in for a real one here so the test does not depend on, or leak,
    whoever actually runs it; the fake directory's own name is exactly the
    kind of machine-specific string that must not survive into governed
    evidence.
    """
    work, _reviewers = settled
    fake_home = work.parent / "definitely-not-a-real-home.SOMEMACHINE-01"
    fake_home.mkdir()
    env = {**os.environ, "PYTHONPATH": str(work / "src")}
    env.pop("FORGE_REVIEWER_TRUST_STORE", None)
    env["FORGE_BUILDER_IDENTITY"] = BUILDER
    env["HOME"] = str(fake_home)
    env["USERPROFILE"] = str(fake_home)
    completed = subprocess.run(
        [sys.executable, REFRESH, "--as-of", "2026-08-02T00:00:00Z"],
        cwd=work, capture_output=True, text=True, encoding="utf-8", env=env,
    )
    assert completed.returncode == 0, completed.stderr

    record = json.loads((work / RECORD_RELATIVE).read_text(encoding="utf-8"))
    basis = record["verdict_basis"]
    assert fake_home.name not in basis, (
        f"the fake home directory's own name leaked into governed evidence: {basis!r}"
    )
    assert str(fake_home) not in basis, (
        f"the fake home directory's full path leaked into governed evidence: {basis!r}"
    )
    # THE EXACT RENDERING, not merely "~" in basis. A bare substring check is
    # satisfiable by an UNRELATED "~" -- an 8.3 Windows short name literally
    # contains one (e.g. "DEVUSE~1.SOM"), so a regression that stopped
    # home-relativizing but happened to print a short name elsewhere in the
    # sentence would still pass a check that only asked whether "~" appears
    # anywhere at all. Forward slashes always, per `_store_display`.
    assert "~/.nornyx/forge_reviewer_trust.json (absent)" in basis, (
        f"the absent default store is not rendered as the exact expected "
        f"home-relative form: {basis!r}"
    )


# --------------------------------------------------------------------------
# `_store_display` directly: the rendering rule for the store PATH, in every
# spelling two review rounds found unmet. SYNTHETIC NAMES THROUGHOUT. An
# earlier form of these specimens spelled the developer's real account and
# machine name as string literals -- putting into the committed test tree
# exactly the identity the rule exists to keep out of the committed evidence
# tree. `Devuser`, `SOMEBOX-07` and `DEVUSE~1.SOM` belong to nobody.
# --------------------------------------------------------------------------

HOME_LONG = r"C:\Users\Devuser.SOMEBOX-07"
HOME_SHORT = r"C:\Users\DEVUSE~1.SOM"
HOME_POSIX = "/home/devuser"
STORE_TAIL = ".nornyx/forge_reviewer_trust.json"
OUTSIDE = "<FORGE_REVIEWER_TRUST_STORE>"


def _with_home_forms(monkeypatch: pytest.MonkeyPatch, *forms: str) -> None:
    monkeypatch.setattr(rge, "_home_directory_forms", lambda: forms)


def _under_the_windows_case_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows semantics on ANY host: case folded, `/` and `\\` equal."""
    monkeypatch.setattr(rge, "_path_normcase", ntpath.normcase)


def _under_the_posix_case_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    """POSIX semantics on ANY host: the identity, because paths there are
    case-sensitive and two spellings that differ in case are two directories."""
    monkeypatch.setattr(rge, "_path_normcase", posixpath.normcase)


def test_the_case_rule_is_the_platforms_own():
    """`_path_normcase` is a NAME for `os.path.normcase`, not a
    reimplementation of it: the seam exists so the tests below can exercise
    both platforms' behaviour on one host, and this pins that in production
    the seam is exactly the platform's rule. Without this pin the branch
    tests could pass against a seam that had quietly become a hand-written
    lowercase on every platform."""
    assert rge._path_normcase is os.path.normcase


def test_store_display_folds_case_under_the_windows_rule(
    monkeypatch: pytest.MonkeyPatch,
):
    """A lowercase drive letter and account name spell the SAME directory as
    the mixed-case form `Path.home()` returns on Windows, and must render as
    home. The round-2 test finding: the earlier form of this test relied on
    the HOST's `os.path.normcase` and so asserted Windows behaviour while
    running on ubuntu-latest, where `normcase` is the identity -- red on
    every CI interpreter. The case rule is substituted here, so this branch
    is exercised on every host."""
    _under_the_windows_case_rule(monkeypatch)
    _with_home_forms(monkeypatch, HOME_LONG)
    lowercase = r"c:\users\devuser.somebox-07\.nornyx\forge_reviewer_trust.json"
    assert rge._store_display(lowercase) == "~/" + STORE_TAIL
    # And separators: a forward-slash spelling of a Windows home is still home.
    assert rge._store_display("C:/Users/Devuser.SOMEBOX-07/.nornyx/x.json") == "~/.nornyx/x.json"


def test_store_display_does_not_fold_case_under_the_posix_rule(
    monkeypatch: pytest.MonkeyPatch,
):
    """The other branch of the same rule. `/HOME/DEVUSER` is a DIFFERENT
    directory from `/home/devuser` on a case-sensitive filesystem, so under
    the POSIX rule the uppercase spelling is not the reader's home and is
    rendered by its configuration name -- treating it as home would render
    some other account's store as the reader's own. The exact-case spelling
    renders as home. Both assertions run on every host."""
    _under_the_posix_case_rule(monkeypatch)
    _with_home_forms(monkeypatch, HOME_POSIX)
    assert rge._store_display("/HOME/DEVUSER/" + STORE_TAIL) == OUTSIDE
    assert rge._store_display("/home/devuser/" + STORE_TAIL) == "~/" + STORE_TAIL


def test_store_display_matches_an_8_3_short_name(monkeypatch: pytest.MonkeyPatch):
    """The 8.3 short form of the SAME directory the long form names. Real
    Windows accounts and computer names routinely exceed 8 characters, and
    `GetShortPathNameW` then produces a `NAME~1`-shaped alias for the
    identical directory -- a path built from that alias must still be
    recognised as home, matched against the SECOND form
    `_home_directory_forms` returns, not merely the first."""
    _under_the_windows_case_rule(monkeypatch)
    _with_home_forms(monkeypatch, HOME_LONG, HOME_SHORT)
    assert rge._store_display(HOME_SHORT + r"\.nornyx\forge_reviewer_trust.json") == "~/" + STORE_TAIL


def test_store_display_redacts_a_different_users_directory(
    monkeypatch: pytest.MonkeyPatch,
):
    """A path under the SAME drive but a DIFFERENT account is not home --
    `FORGE_REVIEWER_TRUST_STORE` pointed there is rendered by its
    configuration name, never verbatim, because a different account's
    directory layout is exactly the kind of machine-specific string this
    generator exists to keep out of committed evidence."""
    _under_the_windows_case_rule(monkeypatch)
    _with_home_forms(monkeypatch, HOME_LONG)
    assert rge._store_display(r"C:\Users\otheruser\.nornyx\forge_reviewer_trust.json") == OUTSIDE


def test_store_display_redacts_a_different_drive(monkeypatch: pytest.MonkeyPatch):
    """A path on a DIFFERENT drive entirely -- the other shape an override
    outside home can take."""
    _under_the_windows_case_rule(monkeypatch)
    _with_home_forms(monkeypatch, HOME_LONG)
    assert rge._store_display(r"D:\ops\forge_reviewer_trust.json") == OUTSIDE


def test_store_display_matches_the_posix_shape(monkeypatch: pytest.MonkeyPatch):
    """The rule is host-independent BY RENDERING, not merely by the platform
    this test happens to run on: forward slashes always, so a Linux
    regeneration produces the SAME `~/...` bytes a Windows one does over the
    same relative path."""
    _under_the_posix_case_rule(monkeypatch)
    _with_home_forms(monkeypatch, HOME_POSIX)
    assert rge._store_display("/home/devuser/" + STORE_TAIL) == "~/" + STORE_TAIL


def test_store_display_holds_the_boundary_after_home(monkeypatch: pytest.MonkeyPatch):
    """`C:\\Users\\DevuserX` is not `C:\\Users\\Devuser`: a longer name that
    merely STARTS like home is another account's directory. The boundary
    rule is that the character after the matched home form must be a
    separator or the end of the path. Home itself, with or without a
    trailing separator, renders as a bare `~`."""
    _under_the_windows_case_rule(monkeypatch)
    _with_home_forms(monkeypatch, r"C:\Users\Devuser")
    assert rge._store_display(r"C:\Users\DevuserX\.nornyx\forge_reviewer_trust.json") == OUTSIDE
    assert rge._store_display(r"C:\Users\Devuser") == "~"
    assert rge._store_display("C:\\Users\\Devuser\\") == "~"
    assert rge._store_display(r"C:\Users\Devuser\x") == "~/x"


@pytest.mark.parametrize(
    "location",
    [
        r"C:\Users\John Doe\.nornyx\forge_reviewer_trust.json",
        r"D:\Program Files (x86)\Nornyx\store.json",
        r"\\fileserver01\team$\devuser\store.json",
        "//fileserver01/team$/devuser/store.json",
        "/home/john doe/.nornyx/forge_reviewer_trust.json",
    ],
    ids=["a-space", "parentheses", "unc", "forward-slash-unc", "posix-space"],
)
def test_redaction_replaces_the_whole_store_path_whatever_it_contains(
    monkeypatch: pytest.MonkeyPatch, location: str
):
    """The round-2 security finding, closed by construction. The earlier
    helper searched composed prose with a regular expression that stopped at
    the first space -- so `C:\\Users\\John Doe\\...` rendered as the placeholder
    followed by ` Doe\\...` -- cut a path at `(x86)`, and matched a UNC path
    not at all. There is no regular expression now: the store path is a value
    the generator holds, and `_redact_store_path` replaces that exact value.
    Each of these shapes therefore vanishes WHOLE, and every occurrence of it
    does, with the surrounding prose untouched."""
    _with_home_forms(monkeypatch, HOME_LONG)  # none of these sits under home
    message = (
        f"{location} is unreadable: Expecting value: line 1 column 1 (char 0); "
        f"retried {location}"
    )
    redacted = rge._redact_store_path(message, location)
    assert location not in redacted
    assert redacted == (
        f"{OUTSIDE} is unreadable: Expecting value: line 1 column 1 (char 0); "
        f"retried {OUTSIDE}"
    )


def test_redaction_renders_a_store_under_home_relative_even_with_a_space(
    monkeypatch: pytest.MonkeyPatch,
):
    """The same whole-token rule when the path IS under home: an account
    name with a space in it renders home-relative, and the ` (absent)` the
    store appends to its `source` survives beside it."""
    _under_the_windows_case_rule(monkeypatch)
    _with_home_forms(monkeypatch, r"C:\Users\John Doe")
    location = r"C:\Users\John Doe\.nornyx\forge_reviewer_trust.json"
    assert rge._redact_store_path(f"{location} (absent)", location) == f"~/{STORE_TAIL} (absent)"
    assert rge._redact_store_path("no path mentioned here", location) == "no path mentioned here"


# --------------------------------------------------------------------------
# The home forms themselves, and the Windows short name
# --------------------------------------------------------------------------


def test_home_directory_forms_returns_home_its_resolved_form_and_the_short_form(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Three spellings, in order: what `Path.home()` returns, its resolved
    form when that differs, and the 8.3 short name when the platform
    produces one -- each de-duplicated, so a host where two of them coincide
    yields fewer forms rather than a repeated one. `Path.home` and
    `_short_path_name` are both substituted, so the test asserts the
    ASSEMBLY of the forms and not whatever this host's home happens to be."""
    home = tmp_path / "HomeDirectoryForForms"
    home.mkdir()
    monkeypatch.setattr(rge.Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(rge, "_short_path_name", lambda path: r"C:\HOMEDI~1")

    forms = rge._home_directory_forms()
    assert forms[0] == str(home)
    assert str(home.resolve()) in forms
    assert r"C:\HOMEDI~1" in forms
    assert len(set(forms)) == len(forms), f"a form is repeated: {forms}"

    monkeypatch.setattr(rge, "_short_path_name", lambda path: None)
    assert r"C:\HOMEDI~1" not in rge._home_directory_forms()


def test_short_path_name_is_none_for_a_path_that_does_not_exist(tmp_path: Path):
    """On Windows `GetShortPathNameW` returns 0 for a path that does not
    exist; off Windows the function answers None before asking. Both are the
    documented None, so this runs on every host without a skip."""
    assert rge._short_path_name(tmp_path / "does-not-exist") is None


def test_short_path_name_is_none_where_the_api_does_not_exist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """The first thing the function checks is the platform name, and off
    Windows it returns None for an EXISTING path too. Exercised on every host
    by substituting that name, so a Windows workstation also proves the
    off-Windows branch rather than leaving it to CI."""
    monkeypatch.setattr(rge.os, "name", "posix")
    assert rge._short_path_name(tmp_path) is None


def _short_form_from_the_windows_api(path: Path) -> str | None:
    """The 8.3 form as `GetShortPathNameW` itself reports it, called here
    directly -- INDEPENDENTLY of `_short_path_name`, the function under test
    -- or None when the API is absent or answers 0. This is what makes the
    test below able to fail: its precondition no longer comes from the code
    it is checking."""
    try:
        import ctypes  # noqa: PLC0415

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    except (ImportError, AttributeError):
        return None
    buffer = ctypes.create_unicode_buffer(260)
    length = kernel32.GetShortPathNameW(str(path), buffer, 260)
    return buffer.value if length else None


def test_short_path_name_is_the_real_8_3_form_on_windows(tmp_path: Path):
    """On a Windows volume that generates short names, a directory whose
    name exceeds eight characters gets a `NAME~1` alias that names the SAME
    directory -- proven with `os.path.samefile`, not by string shape alone.

    THE PRECONDITION IS OBTAINED FROM THE API, NOT FROM THE FUNCTION UNDER
    TEST. The earlier form asked `_short_path_name` whether a short form
    existed and skipped when it said no -- so a `_short_path_name` that
    always returned None turned this test into a skip on a volume that does
    generate short names (round-3 test NEW-1). Now `GetShortPathNameW` is
    asked directly; wherever it yields a short form, `_short_path_name` must
    return exactly that or this test FAILS. It skips, with the reason
    declared in the census, only off Windows (no such API) and where the API
    itself yields no short form (8.3 generation disabled on the volume, when
    it returns the long form unchanged)."""
    if os.name != "nt":
        pytest.skip(
            "GetShortPathNameW is a Windows API; off Windows _short_path_name "
            "returns None by design (pinned by the two tests above)"
        )
    long_dir = tmp_path / "LongDirectoryNameForShortForm"
    long_dir.mkdir()
    api_short = _short_form_from_the_windows_api(long_dir)
    if api_short is None or os.path.normcase(api_short) == os.path.normcase(str(long_dir)):
        pytest.skip(
            "GetShortPathNameW, asked directly, yielded no short form for a "
            "long-named directory on this volume (8.3 generation is off), so "
            "there is no short form to compare against the long one"
        )
    assert "~" in api_short and os.path.samefile(api_short, long_dir), (
        f"the API's own answer is not a short alias of the directory: {api_short!r}"
    )
    assert rge._short_path_name(long_dir) == api_short, (
        "the API yields a short form for this directory and _short_path_name "
        f"did not return it: {rge._short_path_name(long_dir)!r} != {api_short!r}"
    )


# --------------------------------------------------------------------------
# The committed evidence tree carries nobody's identity
# --------------------------------------------------------------------------

#: Every host-path shape, raw or JSON-escaped: inside a JSON string a
#: backslash is doubled, so `[\\/]{1,2}` matches `\`, `\\` and `/` alike.
#: The drive pattern refuses a letter preceded by an alphanumeric so that
#: `http://` (whose `p:/` is a letter, a colon and a separator) is not one.
_HOST_PATH_PATTERNS = (
    ("a Windows user-profile path", re.compile(rb"(?<![A-Za-z0-9])[A-Za-z]:[\\/]{1,2}Users[\\/]{1,2}", re.I)),
    ("a drive-letter path", re.compile(rb"(?<![A-Za-z0-9])[A-Za-z]:[\\/]{1,2}")),
    ("a POSIX home path", re.compile(rb"/home/")),
    ("a macOS home path", re.compile(rb"/Users/")),
)


def _identity_leaks(raw: bytes, *, login: str, node: str) -> list[str]:
    """Where `raw` carries a host path, or the reader's login or machine name
    AS A PATH SEGMENT. One description per pattern that fires.

    Segments, never bare substrings: the round-2 P1 finding was that the
    earlier grep searched for `getpass.getuser()` as a substring, and on
    ubuntu-latest that is `runner`, which `architecture_conformance_report.
    json` legitimately contains inside `module.gate_runner` -- red on every
    CI interpreter over a file that leaked nothing. A name counts here only
    when a path separator (raw or JSON-escaped) immediately precedes it AND
    a separator, a dot, a quote, whitespace or the end follows -- so
    `Users\\devuser` and `/home/devuser` both count, through the separator
    that ends `Users` or `home`, without naming either word -- or when it is
    the machine half of a Windows `account.MACHINE` profile-folder segment.
    Case-insensitive, because Windows paths are and over-detection here is
    the safe direction.
    """
    patterns = list(_HOST_PATH_PATTERNS)
    for label, name in (("login name", login), ("machine name", node)):
        if not name:
            continue
        escaped = re.escape(name.encode("utf-8"))
        patterns.append((
            f"the reader's {label} as a path segment",
            re.compile(
                rb"[\\/]{1,2}" + escaped + rb"(?=[\\/]{1,2}|[.\"'\s]|$)",
                re.I,
            ),
        ))
        patterns.append((
            f"the reader's {label} as the machine half of an account.MACHINE folder",
            re.compile(
                rb"[\\/]{1,2}[A-Za-z0-9_-]+\." + escaped + rb"(?=[\\/]{1,2}|[\"'\s]|$)",
                re.I,
            ),
        ))
    hits: list[str] = []
    for label, pattern in patterns:
        match = pattern.search(raw)
        if match:
            hits.append(f"{label}: {match.group(0)!r} at byte {match.start()}")
    return hits


def _reader_identity() -> tuple[str, str]:
    try:
        login = getpass.getuser()
    except (KeyError, OSError):  # a container with no passwd entry
        login = ""
    return login, platform.node()


def _committed_evidence_files() -> list[Path]:
    files = sorted((ROOT / ".nornyx" / "contracts" / "evidence").rglob("*.json"))
    assert files, "the committed evidence tree is empty; nothing to check"
    return files


def test_the_leak_detector_fires_on_the_json_escaped_windows_shape():
    """KNOWN POSITIVE. The shape a Windows path takes INSIDE a JSON file --
    every backslash doubled -- which the round-2 finding showed the earlier
    single-backslash pattern missing entirely. The detector must fire on the
    profile path, the drive, the login segment and the machine name, with
    and without knowing whose identity it is looking for."""
    document = json.dumps({
        "verdict_basis": "no reviewer trust store, so no inspection can be "
                         r"authenticated (C:\Users\Devuser.SOMEBOX-07\.nornyx"
                         r"\forge_reviewer_trust.json (absent))",
    }).encode("utf-8")
    assert rb"C:\\Users\\Devuser.SOMEBOX-07\\" in document, "the specimen is not JSON-escaped"
    hits = _identity_leaks(document, login="devuser", node="SOMEBOX-07")
    labels = "\n".join(hits)
    assert "a Windows user-profile path" in labels, labels
    assert "a drive-letter path" in labels, labels
    assert "login name as a path segment" in labels, labels
    assert "machine name as the machine half" in labels, labels
    assert _identity_leaks(document, login="", node=""), "the generic patterns alone must fire"


def test_the_leak_detector_fires_on_the_raw_windows_and_posix_shapes():
    """KNOWN POSITIVES for the two other shapes: a raw (single-backslash)
    Windows path, as it would appear outside a JSON string, and the POSIX
    home shape a Linux regeneration would leak."""
    raw_windows = rb"store at C:\Users\Devuser.SOMEBOX-07\.nornyx\x.json"
    hits = _identity_leaks(raw_windows, login="devuser", node="SOMEBOX-07")
    assert any("Windows user-profile path" in h for h in hits), hits
    assert any("login name as a path segment" in h for h in hits), hits
    assert any("machine half" in h for h in hits), hits

    posix = json.dumps({"verdict_basis": "(/home/devuser/.nornyx/forge_reviewer_trust.json (absent))"}).encode()
    hits = _identity_leaks(posix, login="devuser", node="somebox-07")
    assert any("POSIX home path" in h for h in hits), hits
    assert any("login name as a path segment" in h for h in hits), hits


def test_the_leak_detector_stays_silent_on_a_login_that_is_inside_a_word():
    """KNOWN NEGATIVE, the CI case. `runner` inside `module.gate_runner`,
    `ann` inside `cannot`, `test` inside `tests/test_x.py`, and `p:/` inside
    a URL are none of them a path segment naming the reader, and a detector
    that fired on them would be red on ubuntu-latest over a file that leaked
    nothing -- exactly what happened."""
    document = json.dumps({
        "module": "module.gate_runner",
        "note": "cannot; the runner ran tests/test_runner_x.py; see https://example.invalid/x",
        "path": "src/nornyx_forge/gates.py",
    }).encode("utf-8")
    assert _identity_leaks(document, login="runner", node="fv-az123-456") == []
    assert _identity_leaks(document, login="ann", node="") == []
    assert _identity_leaks(document, login="test", node="") == []
    assert _identity_leaks(document, login="", node="") == []


def test_committed_evidence_carries_no_readers_identity():
    """Static regression over the COMMITTED evidence tree, not a fixture.

    The specimens above prove the rendering rule in isolation; this proves
    the rule is actually APPLIED to what this repository ships.
    `.nornyx/contracts/evidence/*.json` is read as BYTES, not decoded text,
    and the detector knows the JSON-escaped spelling of a Windows path, so a
    leaked account name inside a doubled-backslash path is found rather than
    missed. The detector's own power and silence are pinned by the three
    control tests above.
    """
    login, node = _reader_identity()
    offenders = [
        f"{path.relative_to(ROOT)}: {hit}"
        for path in _committed_evidence_files()
        for hit in _identity_leaks(path.read_bytes(), login=login, node=node)
    ]
    assert not offenders, "\n".join(offenders)


def test_committed_evidence_is_clean_for_the_ci_runners_identity_too():
    """The same sweep with the identity the Linux CI matrix runs under,
    checked on EVERY host -- so the developer's workstation observes the
    exact condition that made the round-2 finding a CI-red, rather than
    learning it from the CI log."""
    offenders = [
        f"{path.relative_to(ROOT)}: {hit}"
        for path in _committed_evidence_files()
        for hit in _identity_leaks(path.read_bytes(), login="runner", node="fv-az000-000")
    ]
    assert not offenders, "\n".join(offenders)


def test_an_incomplete_inspection_is_not_an_independent_one(settled):
    """Two of three roles. A missing lens is a missing lens."""
    work, reviewers = settled
    _attest(work, reviewers, roles=REQUIRED[:2])

    state = _assurance(work, reviewers)
    assert state["required_inspectors_complete"] is False
    assert state["assurance_state"] == "not_independently_inspected"


def test_a_failing_inspector_is_not_a_passing_inspection(settled):
    work, reviewers = settled
    _attest(work, reviewers, verdicts={"security-inspector": "fail"})

    state = _assurance(work, reviewers)
    assert state["required_inspectors_complete"] is False
    assert state["assurance_state"] == "not_independently_inspected"


def test_one_reviewer_cannot_cover_every_role(tmp_path: Path):
    """Three lenses from one identity is one lens applied three times.

    The value of separate inspectors is that they disagree. A single reviewer
    authorized for all three roles satisfies the count while removing the
    property the count was standing in for.
    """
    work = _workspace(tmp_path)
    _settle(work)
    reviewers = Reviewers(tmp_path)

    # Re-issue the store with a single reviewer holding all three roles.
    key = Ed25519PrivateKey.generate()
    reviewers.store.write_text(
        json.dumps(
            {
                "schema": "nornyx.forge.reviewer_trust_store.v1",
                "reviewers": [
                    {
                        "key_id": "rev-solo",
                        "reviewer": "reviewer.solo",
                        "roles": list(REQUIRED),
                        "public_key": key.public_key()
                        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                        .decode("utf-8"),
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    private = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    for role in REQUIRED:
        reviewers.private[role] = private
        reviewers.names[role] = "reviewer.solo"
        reviewers.key_ids[role] = "rev-solo"
    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["required_inspectors_complete"] is True, state["problems"]
    assert state["independent"] is False, (
        "one identity signing all three roles was counted as three independent "
        "inspections"
    )
    assert state["assurance_state"] == "not_independently_inspected"

    # AND THE EMITTED RECORD MUST SAY THE SAME THING.
    #
    # This test used to stop at the line above, and the defect it could not
    # see lived one file away: the record generator applied the COVERAGE
    # clause and not the DISTINCTNESS clause, so the same three attestations
    # produced `status: pass` in
    # `evidence/architecture_independent_review.json` -- and, through
    # `--sync-contracts`, in the contract -- while the control above refused
    # them. A review measured `verdict_basis: attested by reviewer.solo,
    # reviewer.solo, reviewer.solo` beside a statement calling it an
    # independent machine review.
    #
    # Enforcement was never wrong. What was wrong is that a governed artifact
    # asserted a passing independent review over an inspection the deciding
    # control rejects, which is the disagreement the generator's own comment
    # says it exists to prevent.
    assert _run(work, reviewers, REFRESH).returncode == 0
    # THE INDEX ENTRY CARRIES THE VERDICT, not the record body. The first
    # draft of this block read `status` off the record file, where the key
    # does not exist at all -- so `!= "pass"` was true whatever the
    # generator decided, and reverting the fix left it green. Measured
    # before this correction: revert applied, test still passed.
    index = json.loads(
        (work / INDEX_RELATIVE).read_text(encoding="utf-8")
    )
    entry = index["entries"]["architecture_independent_review"]
    record = json.loads(
        (work / RECORD_RELATIVE).read_text(encoding="utf-8")
    )
    assert entry.get("status") != "pass", (
        "the evidence index claims a passing independent review over an "
        "inspection derive_assurance_state refuses: "
        + json.dumps({"status": entry.get("status"),
                      "verdict_basis": record.get("verdict_basis")})
    )
    assert "not independent" in str(record.get("verdict_basis", "")), (
        "the record withheld the verdict without saying why: "
        + str(record.get("verdict_basis"))
    )


def test_a_duplicate_role_cannot_be_resolved_by_ordering(settled):
    """Two attestations for one role: which applies must not depend on filename."""
    work, reviewers = settled
    _attest(work, reviewers)
    duplicate = work / ATTESTATIONS / "aaa-first.json"
    duplicate.write_bytes((work / ATTESTATIONS / "security-inspector.json").read_bytes())

    state = _assurance(work, reviewers)
    assert any("already attested" in p for p in state["assurance_problems"])


def test_the_builder_cannot_satisfy_an_inspector_role(tmp_path: Path):
    """Even holding a trusted key issued in their own name.

    This asserted a disjunction -- identity mismatch OR builder -- and the
    fixture overrode only the *claimed* reviewer name, so the record was signed
    by `reviewer.security`'s key while claiming to be the builder. Identity
    mismatch fired, the builder branch was never reached, and an independent
    review deleted the builder check entirely with this test still green.

    So the store now genuinely vouches for the builder: the key belongs to them,
    the signature is theirs, the claimed name matches. Every other check passes,
    which leaves exactly one control able to produce the refusal.
    """
    work = _workspace(tmp_path)
    _settle(work)
    reviewers = Reviewers(tmp_path)

    # Re-issue the security-inspector slot in the builder's own name.
    store = json.loads(reviewers.store.read_text(encoding="utf-8"))
    for entry in store["reviewers"]:
        if "security-inspector" in entry["roles"]:
            entry["reviewer"] = BUILDER
    reviewers.store.write_text(json.dumps(store, indent=2), encoding="utf-8")
    reviewers.names["security-inspector"] = BUILDER

    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "not_independently_inspected"
    assert any("REVIEWER_IS_THE_BUILDER" in p for p in state["assurance_problems"]), (
        "the refusal did not come from the independence derivation: "
        + repr(state["assurance_problems"])
    )
    assert not any(
        "REVIEWER_IDENTITY_MISMATCH" in p for p in state["assurance_problems"]
    ), "identity mismatch fired, so this proves the identity binding, not independence"


# --------------------------------------------------------------------------
# Staleness: the inspection is bound to the subject it actually saw
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "relative", "content"),
    [
        ("authored source", "src/nornyx_forge/late_addition.py", b"X = 1\n"),
        ("a governed contract", ".nornyx/contracts/runtime_network.nyx", None),
    ],
)
def test_moving_the_subject_makes_the_inspection_stale(
    settled, label: str, relative: str, content: bytes | None
):
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True, label

    target = work / relative
    if content is None:
        # A DECLARED value, not a comment. The subject is computed from what the
        # contracts say rather than their exact bytes, because adopting an
        # approval rewrites the declared revision and every recorded evidence
        # digest -- and binding an inspection to those bytes made the two
        # prerequisites unsatisfiable together: attest before adoption and the
        # attestation is stale, attest after and the attestations are untracked
        # against the revision the approval pins.
        #
        # Byte-level contract drift is not unguarded; it is caught elsewhere, by
        # `test_a_comment_only_contract_edit_is_still_caught`.
        target.write_bytes(
            target.read_bytes().replace(
                b"name: GovernedCustomerOperationsRuntime",
                b"name: GovernedCustomerOperationsRuntimeX",
                1,
            )
        )
    else:
        target.write_bytes(content)

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "not_independently_inspected", label
    assert any(
        "not the subject this tree now presents" in problem
        for problem in state["assurance_problems"]
    ), label


def test_a_comment_only_contract_edit_is_still_caught(settled):
    """Byte-level contract drift stays covered, just not by the subject.

    The inspection subject digests what the contracts SAY, and a comment says
    nothing -- so it does not invalidate an inspection of the meaning. It is
    still drift, and the review binding records the exact contract bytes, which
    `--verify` recomputes. Asserted here so the coverage is seen to have moved
    rather than shrunk.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True

    target = work / ".nornyx/contracts/runtime_network.nyx"
    target.write_bytes(target.read_bytes() + b"\n# moved after inspection\n")

    completed = _run(work, reviewers, REFRESH, "--verify")
    report = json.loads(completed.stdout[completed.stdout.find("{"):])["verification"]
    assert report["integrity_state"] == "compromised", (
        "a comment-only contract edit went unreported by integrity verification"
    )


def test_sync_contracts_after_inspection_makes_it_stale(settled):
    """Settling contracts changes the control pack, so it changes the subject."""
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True

    assert _run(work, reviewers, REFRESH, "--as-of", "2026-08-03T00:00:00Z").returncode == 0
    assert _run(work, reviewers, REFRESH, "--sync-contracts").returncode == 0

    assert _inspected(work, reviewers) is False


def test_regenerating_the_digest_alone_leaves_the_inspection_stale(settled):
    """P2-D, restated against signed evidence.

    The tool may recompute what the current subject is. It must never rebind a
    previously produced PASS to that new value — which, now that attestations
    are signed, it could not do even if it tried: the subject is inside the
    signature.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    (work / "src/nornyx_forge/drifted.py").write_bytes(b"X = 1\n")
    assert _inspected(work, reviewers) is False

    assert _run(work, reviewers, REFRESH, "--review-binding").returncode == 0
    assert _inspected(work, reviewers) is False, (
        "regenerating the binding rebound stale PASS evidence to the new subject"
    )


def test_signing_an_inspection_does_not_move_the_subject_it_inspects(settled):
    """Otherwise no inspection could ever match, and the reason is not obvious.

    The subject includes pre-inspection evidence. If attestations counted as
    that evidence, writing one would change the subject it names — a fixed point
    nothing converges to. It works today because the evidence manifest globs one
    directory level and the attestations live one below it, which is a load-
    bearing property that currently looks like an implementation detail.
    """
    work, reviewers = settled
    before = _current_subject(work)
    _attest(work, reviewers)
    assert _current_subject(work) == before, (
        "writing a signed attestation moved the subject it attests to"
    )


def test_a_fresh_inspection_alone_does_not_restore_assurance(settled):
    """Re-inspecting fixes the inspection, not the evidence it sits on.

    After drift the machine evidence still describes the old content. A new
    signed inspection makes `independent` true again — and assurance stays
    withheld, because assurance requires integrity and the evidence set is
    stale. These are separate facts and must not substitute for each other.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    (work / "src/nornyx_forge/drifted.py").write_bytes(b"X = 1\n")
    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["independent"] is True
    assert state["required_inspectors_complete"] is True
    assert state["integrity_state"] == "compromised"
    assert state["assurance_state"] == "not_independently_inspected"


def test_the_full_causal_chain_restores_assurance(settled):
    """Staleness is recoverable by redoing the work, not by asserting again.

    Order is the point: evidence is regenerated, contracts settle, only then is
    the subject stable enough to inspect, and the binding is written last. Run
    out of order it does not converge, which is the honest outcome.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    (work / "src/nornyx_forge/drifted.py").write_bytes(b"X = 1\n")
    assert _inspected(work, reviewers) is False

    _settle(work)
    _attest(work, reviewers)

    state = _assurance(work, reviewers)
    assert state["assurance_state"] == "independently_inspected", state["problems"]
    assert state["integrity_state"] == "intact"


def test_a_stale_attestation_does_not_perturb_the_next_subject(settled):
    """H13. Evidence ABOUT a subject must never become part of it.

    THE CONJUNCTION NEITHER EXISTING TEST COVERED. The fixed-point tests
    regenerate twice with attestations that are never stale, so the
    stale-diagnostic branch never executes. `test_moving_the_subject_makes_the_
    inspection_stale` has a genuinely stale attestation but regenerates once, so
    a subject that moves BETWEEN passes cannot be observed. Only both together
    reach the defect, which is why the historical mutation survived three
    correct-looking attempts.

    The stale diagnostic lands in `verdict_basis`, inside the evidence set the
    subject is computed from. If it names the CURRENT subject, the subject
    becomes a function of itself: every regeneration moves it, and no
    attestation can ever name the one the next run will present.

    Asserted as STATE STABILITY, not as wording. Checking the sentence for a
    digest would be a string-format test wearing a security proof's name, and
    would pass for a system whose subject drifted anyway.

    Reuses the provisioned reviewer trust and real signing from `settled` and
    `_attest`. An earlier version of this proof attached an UNSIGNED
    attestation, which is discarded at authentication -- H14's clause -- before
    control reaches the mismatch branch at all. Branch-body probing reported
    INVALID_TEST_AIM for it, correctly.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    assert _inspected(work, reviewers) is True, "the baseline inspection is not complete"

    subject_before = _current_subject(work)

    # Move the subject, so the signed attestation above becomes stale. A
    # DECLARED value, matching what test_moving_the_subject_makes_the_inspection
    # _stale changes, so this exercises the same staleness the suite already
    # recognises rather than inventing a new one.
    contract = work / ".nornyx/contracts/runtime_network.nyx"
    contract.write_bytes(
        contract.read_bytes().replace(
            b"name: GovernedCustomerOperationsRuntime",
            b"name: GovernedCustomerOperationsRuntimeX",
            1,
        )
    )

    _settle(work)
    subject_after = _current_subject(work)
    assert subject_after != subject_before, (
        "the governed subject did not move, so the attestation never became "
        "stale and this test cannot reach the property"
    )

    # The attestation is now stale AND authenticated, so the mismatch branch
    # runs on every pass from here.
    state = _assurance(work, reviewers)
    assert any(
        "not the subject this tree now presents" in problem
        for problem in state["assurance_problems"]
    ), state["assurance_problems"]

    # THE FIXED POINT, with the stale diagnostic being written each time.
    # Nothing governed changes between these two regenerations.
    _settle(work)
    first = _current_subject(work)
    _settle(work)
    second = _current_subject(work)

    assert first == second, (
        "two consecutive regenerations over an unchanged governed tree produced "
        f"different subjects ({first} then {second}) while a stale attestation "
        "was present, so evidence ABOUT the subject has become part of it and "
        "no attestation can name the subject the next run will present"
    )


def test_the_stale_attestation_keeps_naming_the_subject_it_reviewed(settled):
    """Identity preservation, paired with the stability proof above.

    Stability alone could be satisfied by a system that stopped reporting
    staleness at all. This requires the mismatch to stay OBSERVABLE and to be
    described against the subject that was actually reviewed.
    """
    work, reviewers = settled
    _attest(work, reviewers)
    reviewed = _current_subject(work)

    contract = work / ".nornyx/contracts/runtime_network.nyx"
    contract.write_bytes(
        contract.read_bytes().replace(
            b"name: GovernedCustomerOperationsRuntime",
            b"name: GovernedCustomerOperationsRuntimeX",
            1,
        )
    )
    _settle(work)
    current = _current_subject(work)
    assert reviewed != current

    state = _assurance(work, reviewers)
    stale = [p for p in state["assurance_problems"]
             if "not the subject this tree now presents" in p]
    assert stale, state["assurance_problems"]
    assert any(reviewed in problem for problem in stale), (
        "the stale diagnostic no longer names the subject that was reviewed, so "
        "the mismatch has been rewritten as though the attestation belonged to "
        f"the current subject. reviewed={reviewed} current={current}"
    )
    assert not any(current in problem for problem in stale), (
        "the stale diagnostic names the CURRENT subject, which puts the subject "
        "inside the evidence it is derived from"
    )
    assert _inspected(work, reviewers) is False
