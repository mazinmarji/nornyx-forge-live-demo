"""One command starts the onboarding surface — with no ambient authority.

WHAT WOULD FALSIFY THIS SLICE: a launch path where the environment or the
working directory selects the project directory, a server that binds
beyond loopback, or a launcher that quietly resolves a relative path
instead of refusing it. The FORGE_ROOT closure recorded the doctrine;
these tests hold the new launch path to it at every layer, because a
refusal enforced in only one layer is bypassed by calling the next one
down.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from nornyx_forge import app_launcher, cli, onboarding_serve
from nornyx_forge.onboarding_serve import ONBOARDING_HOST, assemble, main

# ---------------------------------------------------------------------------
# Assembly: explicit absolute directory in, structural contracts, no cwd
# ---------------------------------------------------------------------------

def test_assemble_builds_the_app_over_the_chosen_directory(tmp_path: Path):
    application = assemble(tmp_path)
    assert application.state.project_dir == str(tmp_path)
    routes = {route.path for route in application.routes}
    assert {"/", "/api/state", "/api/governance"} <= routes


def test_assemble_refuses_a_relative_project_directory():
    with pytest.raises(ValueError, match="must be absolute"):
        assemble(Path("forge-project"))


def test_the_contracts_come_from_the_package_not_the_launch_directory(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Structural derivation: chdir anywhere, the governed contracts are the
    packaged ones — the launch directory selects nothing."""
    monkeypatch.chdir(tmp_path)
    from fastapi.testclient import TestClient
    response = TestClient(assemble(tmp_path)).get("/api/governance")
    assert response.status_code == 200
    assert [c["file"] for c in response.json()["contracts"]] == [
        "architecture_governance.nyx", "forge_control.nyx", "runtime_network.nyx",
    ]


# ---------------------------------------------------------------------------
# Serving: loopback only, explicit argv only
# ---------------------------------------------------------------------------

def test_main_serves_on_loopback_with_the_explicit_directory(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    observed = {}

    def fake_run(application, *, host, port):
        observed.update(app=application, host=host, port=port)

    monkeypatch.setattr(onboarding_serve.uvicorn, "run", fake_run)
    main(["--port", "8710", "--project-dir", str(tmp_path)])
    assert observed["host"] == ONBOARDING_HOST == "127.0.0.1"
    assert observed["port"] == 8710
    assert observed["app"].state.project_dir == str(tmp_path)


def test_main_refuses_a_relative_directory_before_serving(
        monkeypatch: pytest.MonkeyPatch):
    def must_not_serve(*args, **kwargs):  # pragma: no cover - the specimen
        raise AssertionError("uvicorn.run was reached with ambient authority")

    monkeypatch.setattr(onboarding_serve.uvicorn, "run", must_not_serve)
    with pytest.raises(ValueError, match="must be absolute"):
        main(["--port", "8710", "--project-dir", "forge-project"])


# ---------------------------------------------------------------------------
# The launcher: one exec site, explicit argv, refusal at this layer too
# ---------------------------------------------------------------------------

def test_launch_onboarding_execs_the_declared_target_with_explicit_argv(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    observed = {}

    def fake_execvp(executable, argv):
        observed.update(executable=executable, argv=argv)

    monkeypatch.setattr(app_launcher.os, "execvp", fake_execvp)
    app_launcher.launch_onboarding(port=8710, project_dir=str(tmp_path))
    argv = observed["argv"]
    assert argv[1:3] == ["-m", "nornyx_forge.onboarding_serve"]
    assert argv[argv.index("--port") + 1] == "8710"
    assert argv[argv.index("--project-dir") + 1] == str(tmp_path)
    assert "0.0.0.0" not in argv, "the onboarding surface must never leave loopback"


def test_launch_onboarding_refuses_a_relative_directory(
        monkeypatch: pytest.MonkeyPatch):
    def must_not_exec(*args):  # pragma: no cover - the specimen
        raise AssertionError("execvp was reached with a relative project dir")

    monkeypatch.setattr(app_launcher.os, "execvp", must_not_exec)
    with pytest.raises(ValueError, match="must be absolute"):
        app_launcher.launch_onboarding(port=8710, project_dir="forge-project")


# ---------------------------------------------------------------------------
# The console command: where a relative path legitimately becomes a decision
# ---------------------------------------------------------------------------

def test_the_onboard_command_resolves_at_the_console_and_launches(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    observed = {}

    def fake_launch(*, port, project_dir):
        observed.update(port=port, project_dir=project_dir)

    monkeypatch.setattr(cli, "launch_onboarding", fake_launch)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli.app, ["onboard"])
    assert result.exit_code == 0, result.output
    assert observed["port"] == 8710
    assert observed["project_dir"] == str((tmp_path / "forge-project").resolve())
    assert Path(observed["project_dir"]).is_absolute()


def test_the_onboard_command_honours_an_explicit_directory_and_port(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    observed = {}
    monkeypatch.setattr(
        cli, "launch_onboarding",
        lambda *, port, project_dir: observed.update(
            port=port, project_dir=project_dir),
    )
    chosen = tmp_path / "my-project"
    result = CliRunner().invoke(
        cli.app, ["onboard", "--port", "9001", "--project-dir", str(chosen)],
    )
    assert result.exit_code == 0, result.output
    assert observed == {"port": 9001, "project_dir": str(chosen.resolve())}
