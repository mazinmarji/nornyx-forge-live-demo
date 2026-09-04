"""One command starts the onboarding surface — with no ambient authority.

WHAT WOULD FALSIFY THIS SLICE: a launch path where the environment or the
working directory selects the project directory, a server that binds
beyond loopback, or a launcher that quietly resolves a relative path
instead of refusing it. The FORGE_ROOT closure recorded the doctrine;
these tests hold the new launch path to it at every layer, because a
refusal enforced in only one layer is bypassed by calling the next one
down.

THE HOST RULE (N3 of the independent PR-18 review): the served composition
answers only to a loopback Host header. It was first installed on the
Windows runtime's composition alone, which left the console `onboard` path
-- the same authority-bearing surface -- weaker. The rule now belongs to
`assemble`, the one composition every production launch path serves, and
the tests here hold both paths to it and census the source tree for any
composition that omits it. Requests in this module carry a loopback base
URL on purpose: the test client's default `testserver` Host is refused by
the production rule, and the rule is not widened to admit it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from nornyx_forge import app_launcher, cli, onboarding_serve
from nornyx_forge.onboarding_serve import ONBOARDING_HOST, ONBOARDING_HOSTS, assemble, main

ROOT = Path(__file__).resolve().parents[1]
LOOPBACK = "http://127.0.0.1"

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
    response = TestClient(assemble(tmp_path), base_url=LOOPBACK).get("/api/governance")
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


# ---------------------------------------------------------------------------
# The Host rule: loopback identities only, installed on the common composition
# ---------------------------------------------------------------------------

def _served(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """`assemble` over a scratch project, its seals kept out of the home."""
    monkeypatch.setattr(onboarding_serve, "SEAL_DIR", tmp_path / "seals")
    return assemble(tmp_path)


def test_h1_h2_assemble_answers_both_loopback_host_identities(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    application = _served(tmp_path, monkeypatch)
    for host in ("127.0.0.1", "localhost", "127.0.0.1:8710", "localhost:8710"):
        response = TestClient(application, base_url=f"http://{host}").get("/api/state")
        assert response.status_code == 200, host
        assert response.json()["initialized"] is False
        assert TestClient(application, base_url=f"http://{host}").get("/").status_code == 200


def test_h3_a_foreign_host_is_refused_before_any_route_runs(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A page that rebinds a name it controls to 127.0.0.1 arrives with that
    name as the Host: refused on every route, reads and writes alike, and
    before the surface touches the store."""
    application = _served(tmp_path, monkeypatch)
    foreign = ("evil.example", "evil.example:8710", "testserver", "192.168.1.20",
               "127.0.0.1.evil.example", "localhost.evil.example")
    for host in foreign:
        client = TestClient(application, base_url=f"http://{host}")
        for path in ("/", "/api/state", "/api/governance"):
            response = client.get(path)
            assert response.status_code == 400, (host, path, response.status_code)
    # An absent Host is no loopback identity either.
    assert TestClient(application, base_url=LOOPBACK).get(
        "/api/state", headers={"Host": ""}).status_code == 400
    response = TestClient(application, base_url="http://evil.example").post(
        "/api/project", json={"project_id": "proj-h3", "project_name": "Rebound",
                              "actor": {"kind": "human", "ident": "casey"}})
    assert response.status_code == 400
    assert not (tmp_path / "capsule").exists(), "a refused request reached the store"


def test_h4_the_console_onboard_composition_inherits_the_host_rule(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The console path is `onboard` -> `launch_onboarding` -> `-m
    nornyx_forge.onboarding_serve` -> `main` -> `assemble` (each link pinned
    above). The application `main` hands to the server is the one that
    refuses a foreign Host; `main` adds nothing of its own and needs to add
    nothing."""
    monkeypatch.setattr(onboarding_serve, "SEAL_DIR", tmp_path / "seals")
    observed = {}

    def fake_run(application, *, host, port):
        observed.update(app=application, host=host, port=port)

    monkeypatch.setattr(onboarding_serve.uvicorn, "run", fake_run)
    main(["--port", "8710", "--project-dir", str(tmp_path)])
    served = observed["app"]
    assert TestClient(served, base_url="http://evil.example").get("/api/state").status_code == 400
    assert TestClient(served, base_url=LOOPBACK).get("/api/state").status_code == 200
    assert TestClient(served, base_url="http://localhost").get("/").status_code == 200
    assert observed["host"] == ONBOARDING_HOST


def test_h6_no_production_composition_of_the_surface_omits_the_host_rule(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Repository-wide, over the source tree rather than over one caller:
    the onboarding application is constructed in exactly one place and
    composed for serving in exactly one (`create_app`, called only inside
    `assemble`); `assemble` installs the Host rule once, with exactly the
    declared identities and no wildcard; no other module under `src/`
    installs, restates or widens it; and every server construction under
    `src/` is fed by `assemble` -- the console `main` directly, the Windows
    runtime through a seam whose default is `assemble` (pinned by
    `test_the_served_composition_passes_no_seam`). `src/demo_app` builds the
    governed demonstration application, a different surface on its own
    port; it neither imports nor composes the onboarding surface, which the
    census states rather than assumes."""
    import ast

    constructions: dict[str, list[str]] = {"FastAPI": [], "create_app": []}
    serve_sites: set[tuple[str, str]] = set()
    host_rule_modules: list[str] = []
    for module in sorted((ROOT / "src").rglob("*.py")):
        text = module.read_text(encoding="utf-8")
        relative = module.relative_to(ROOT / "src").as_posix()
        if "TrustedHostMiddleware" in text or "allowed_hosts" in text:
            host_rule_modules.append(relative)
        for node in ast.walk(ast.parse(text)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute) else None)
            if name in constructions:
                constructions[name].append(relative)
            if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                    and func.value.id == "uvicorn"):
                serve_sites.add((relative, func.attr))
    assert constructions["FastAPI"] == ["demo_app/main.py", "nornyx_forge/onboarding_app.py"]
    assert constructions["create_app"] == ["nornyx_forge/onboarding_serve.py"]
    assert host_rule_modules == ["nornyx_forge/onboarding_serve.py"], (
        "the Host rule must be installed once, by the common composition, and "
        f"restated nowhere else: {host_rule_modules}")
    assert serve_sites == {("nornyx_forge/onboarding_serve.py", "run"),
                           ("nornyx_forge/windows_runtime.py", "Server"),
                           ("nornyx_forge/windows_runtime.py", "Config")}
    demo = (ROOT / "src" / "demo_app" / "main.py").read_text(encoding="utf-8")
    assert "onboarding" not in demo, "the demonstration app must not compose the onboarding surface"

    served = ast.parse(
        (ROOT / "src" / "nornyx_forge" / "onboarding_serve.py").read_text(encoding="utf-8"))
    assemble_def = next(n for n in ast.walk(served)
                        if isinstance(n, ast.FunctionDef) and n.name == "assemble")
    calls_inside = [n.func.id for n in ast.walk(assemble_def)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    assert calls_inside.count("create_app") == 1, "create_app is composed inside assemble, once"

    application = _served(tmp_path, monkeypatch)
    installed = [m for m in application.user_middleware if m.cls is TrustedHostMiddleware]
    assert len(installed) == 1, "the rule is installed exactly once"
    assert installed[0].kwargs == {"allowed_hosts": ["127.0.0.1", "localhost"]}
    assert ONBOARDING_HOSTS == ("127.0.0.1", "localhost")
    assert "*" not in "".join(ONBOARDING_HOSTS) and "testserver" not in ONBOARDING_HOSTS
