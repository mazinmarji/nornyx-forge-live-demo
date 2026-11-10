"""Doctor names the one condition under which greenfield acceptance cannot pass.

Every case passes its platform and user id explicitly, or replaces what the
verifier reads them from, so the module runs, and skips nothing, on every
platform the census covers.
"""

from __future__ import annotations

import os
import sys
import types

from typer.testing import CliRunner

from nornyx_forge import cli, greenfield_verifier
from nornyx_forge.cli import app


def test_root_on_posix_is_reported_unable_to_pass_greenfield_limits():
    enforceable, detail = cli.greenfield_limits_enforceable("posix", 0)
    assert enforceable is False
    assert "uid 0" in detail and "RLIMIT_NPROC" in detail


def test_a_non_root_posix_user_is_not_refused():
    enforceable, detail = cli.greenfield_limits_enforceable("posix", 1000)
    assert enforceable is True
    assert "not refused" in detail


def test_the_windows_row_claims_only_what_doctor_checks():
    """Doctor never builds the verifier's job object, so it cannot say it was applied."""
    enforceable, detail = cli.greenfield_limits_enforceable("nt", None)
    assert enforceable is True
    assert "not refused by this check" in detail
    assert "the verifier applies and verifies them itself" in detail
    assert "applied by" not in detail


def test_doctor_prints_the_root_refusal(monkeypatch):
    real = cli.greenfield_limits_enforceable
    monkeypatch.setattr(cli, "greenfield_limits_enforceable", lambda: real("posix", 0))
    result = CliRunner().invoke(app, ["doctor"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    assert "verifier limits" in result.output
    assert "running as root" in result.output


class _PosixAs:
    """The real ``os`` module, except that it reports POSIX and the given euid.

    Installed as the verifier module's own ``os`` only, so nothing else in the
    process sees a different platform or user.
    """

    name = "posix"

    def __init__(self, euid: int) -> None:
        self._euid = euid

    def geteuid(self) -> int:
        return self._euid

    def __getattr__(self, attribute: str):
        return getattr(os, attribute)


def _drive_the_verifier_as(euid: int, monkeypatch) -> tuple[dict, list]:
    """Run the verifier's own limit step as ``euid``, applying nothing to this process.

    The ``resource`` module the step imports is a recorder, so a regression
    that let it past the uid-0 refusal would show up as recorded limits rather
    than as real limits on the test runner. The ambient task count is fixed for
    the same reason: it is an input to the budget, not the subject here.
    """
    applied: list = []
    recorder = types.ModuleType("resource")
    recorder.RLIMIT_AS, recorder.RLIMIT_CPU, recorder.RLIMIT_NPROC = "AS", "CPU", "NPROC"
    recorder.RLIM_INFINITY = -1
    recorder.getrlimit = lambda _which: (-1, -1)
    recorder.setrlimit = lambda which, limits: applied.append((which, limits))
    monkeypatch.setitem(sys.modules, "resource", recorder)
    monkeypatch.setattr(greenfield_verifier, "os", _PosixAs(euid))
    monkeypatch.setattr(greenfield_verifier, "_real_uid_task_count", lambda: 1)
    return greenfield_verifier._apply_resource_limits(), applied


def test_the_verifier_itself_refuses_uid_0_and_doctor_agrees(monkeypatch):
    """The doctor's root rule is the verifier's rule, shown by running the verifier."""
    limits, applied = _drive_the_verifier_as(0, monkeypatch)
    assert limits == {
        "enforced": False,
        "platform": "posix-rlimit",
        "error": "RLIMIT_NPROC is not enforceable for uid 0",
    }
    assert applied == [], "the verifier went on to apply limits as uid 0"
    enforceable, detail = cli.greenfield_limits_enforceable("posix", 0)
    assert enforceable is limits["enforced"]
    assert "uid 0" in detail and "RLIMIT_NPROC" in detail


def test_the_same_harness_lets_a_non_root_user_through_the_verifier(monkeypatch):
    """The control: the euid alone decides it, not the harness around the call."""
    limits, applied = _drive_the_verifier_as(1000, monkeypatch)
    assert limits["enforced"] is True
    assert limits["platform"] == "posix-rlimit"
    assert {which for which, _limits in applied} == {"AS", "CPU", "NPROC"}
    enforceable, _detail = cli.greenfield_limits_enforceable("posix", 1000)
    assert enforceable is limits["enforced"]
