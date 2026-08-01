from pathlib import Path

from nornyx_forge.repo_qualifier import qualify_local

ROOT = Path(__file__).resolve().parents[1]


def test_local_repository_qualifies():
    report = qualify_local(ROOT)
    assert report.verdict in {"GO", "CONDITIONAL_GO"}
    assert report.overall_score >= 70


def test_public_contracts_exist():
    assert (ROOT / ".nornyx/contracts/forge_control.nyx").exists()
    assert (ROOT / ".nornyx/contracts/runtime_network.nyx").exists()
