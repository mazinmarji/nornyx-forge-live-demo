from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import QualificationReport, RequirementProfile, ScoreDimension

_IGNORED_PARTS = {
    ".git",
    ".venv",
    ".nornyx",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
    "evidence",
    "node_modules",
}


def _github_request(url: str) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "nornyx-forge-live-demo",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response)


def parse_repo(value: str) -> tuple[str, str]:
    match = re.search(r"github\.com/([^/]+)/([^/#?]+)", value)
    if match:
        return match.group(1), match.group(2).removesuffix(".git")
    if "/" in value and not Path(value).exists():
        owner, repo = value.split("/", 1)
        if owner and repo:
            return owner, repo.removesuffix(".git")
    raise ValueError(f"not a GitHub repository: {value}")


def _activity_score(pushed_at: str | None) -> tuple[float, tuple[str, ...]]:
    if not pushed_at:
        return 35, ("No pushed_at metadata",)
    try:
        pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - pushed).days
    except ValueError:
        return 45, (f"Unparseable activity date: {pushed_at}",)
    if age_days <= 90:
        score = 90
    elif age_days <= 365:
        score = 75
    elif age_days <= 730:
        score = 55
    else:
        score = 30
    return score, (f"Last push {age_days} days ago",)


def _path_flags(paths: set[str]) -> dict[str, bool]:
    lowered = {path.lower() for path in paths}
    return {
        "readme": any(path.startswith("readme") for path in lowered),
        "tests": any(
            path.startswith(("tests/", "test/"))
            or "/tests/" in path
            or path.endswith(("_test.py", ".spec.ts", ".test.ts", ".test.tsx"))
            for path in lowered
        ),
        "ci": any(path.startswith(".github/workflows/") for path in lowered),
        "docker": any(
            path == "dockerfile" or path.endswith("/dockerfile") or "docker-compose" in path
            for path in lowered
        ),
        "python_manifest": "pyproject.toml" in lowered or "requirements.txt" in lowered,
        "frontend_manifest": "package.json" in lowered,
        "security": "security.md" in lowered,
        "architecture": any(
            "architecture" in path and path.endswith((".md", ".yaml", ".yml", ".json"))
            for path in lowered
        ),
        "license": any(
            path in {"license", "license.md", "license.txt", "copying"} for path in lowered
        ),
        "migrations": any("migration" in path or "alembic" in path for path in lowered),
    }


def _dimensions(
    *,
    profile: RequirementProfile,
    topics: set[str],
    language: str | None,
    flags: dict[str, bool],
    license_id: str | None,
    archived: bool,
    pushed_at: str | None,
) -> tuple[ScoreDimension, ...]:
    topic_hits = sorted(topics.intersection(profile.topics))
    business_score = min(95, 55 + 10 * len(topic_hits))
    architecture_score = 45 + 15 * flags["architecture"] + 15 * flags["docker"] + 10 * flags["migrations"]
    delivery_score = 45 + 20 * flags["tests"] + 15 * flags["ci"] + 10 * flags["docker"]
    language_fit = 95 if language in profile.languages else (70 if language is None else 50)
    nornyx_score = min(95, language_fit + (5 if flags["architecture"] else 0))
    agentic_score = 88 if language == "Python" else 58
    security_score = 45 + 20 * flags["security"] + 10 * flags["tests"] + 10 * flags["ci"]
    activity, activity_evidence = _activity_score(pushed_at)
    legal_score = 95 if license_id and license_id != "NOASSERTION" and not archived else 15
    legal_score = min(legal_score, activity)
    return (
        ScoreDimension(
            "business_fit",
            business_score,
            0.25,
            tuple(topic_hits),
            () if topic_hits else ("No BRD-derived topic match in repository topics.",),
        ),
        ScoreDimension(
            "architecture_fit",
            architecture_score,
            0.20,
            tuple(name for name in ("architecture", "docker", "migrations") if flags[name]),
        ),
        ScoreDimension(
            "delivery_readiness",
            delivery_score,
            0.15,
            tuple(name for name in ("tests", "ci", "docker") if flags[name]),
        ),
        ScoreDimension(
            "nornyx_compatibility",
            nornyx_score,
            0.15,
            (f"primary language: {language or 'unknown'}",),
        ),
        ScoreDimension(
            "agentic_runtime_fit",
            agentic_score,
            0.10,
            ("Python supports the current Nornyx CrewAI adapter." if language == "Python" else "Adapter integration requires a Python boundary.",),
        ),
        ScoreDimension(
            "security",
            security_score,
            0.10,
            tuple(name for name in ("security", "tests", "ci") if flags[name]),
        ),
        ScoreDimension(
            "legal_maintainability",
            legal_score,
            0.05,
            tuple(filter(None, (license_id, *activity_evidence))),
        ),
    )


def qualify_remote(
    repository: str,
    profile: RequirementProfile | None = None,
) -> QualificationReport:
    profile = profile or RequirementProfile()
    try:
        owner, repo = parse_repo(repository)
        meta = _github_request(f"https://api.github.com/repos/{owner}/{repo}")
        branch = meta["default_branch"]
        commit = _github_request(f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}")
        tree = _github_request(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/{commit['sha']}?recursive=1"
        )
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, ValueError) as exc:
        return QualificationReport(
            repository,
            None,
            "INSUFFICIENT_EVIDENCE",
            0,
            (),
            (f"GitHub inspection failed: {type(exc).__name__}: {exc}",),
            metadata={"evidence_depth": "none"},
        )

    paths = {item.get("path", "") for item in tree.get("tree", []) if item.get("type") == "blob"}
    flags = _path_flags(paths)
    topics = set(meta.get("topics") or [])
    language = meta.get("language")
    license_id = (meta.get("license") or {}).get("spdx_id")
    archived = bool(meta.get("archived"))
    dimensions = _dimensions(
        profile=profile,
        topics=topics,
        language=language,
        flags=flags,
        license_id=license_id,
        archived=archived,
        pushed_at=meta.get("pushed_at"),
    )
    hard_stops: list[str] = []
    if profile.require_license and (not license_id or license_id == "NOASSERTION"):
        hard_stops.append("No usable repository license was detected.")
    if profile.require_active and archived:
        hard_stops.append("Repository is archived.")
    if not flags["readme"]:
        hard_stops.append("No repository README was found.")
    overall = round(sum(item.score * item.weight for item in dimensions), 1)
    if hard_stops:
        verdict = "NO_GO"
    elif overall >= 82:
        verdict = "GO"
    elif overall >= 68:
        verdict = "CONDITIONAL_GO"
    else:
        verdict = "REBASE_RECOMMENDED"
    remediation: list[str] = []
    if not flags["tests"]:
        remediation.append("Add an executable acceptance-test baseline.")
    if not flags["ci"]:
        remediation.append("Add CI validation.")
    if not flags["docker"]:
        remediation.append("Add a reproducible container build.")
    if not flags["architecture"]:
        remediation.append("Declare current and target architecture boundaries.")
    if language != "Python":
        remediation.append("Introduce a Python service boundary for the CrewAI/Nornyx runtime.")
    return QualificationReport(
        repository=f"{owner}/{repo}",
        revision=f"git:{commit['sha']}",
        verdict=verdict,  # type: ignore[arg-type]
        overall_score=overall,
        dimensions=dimensions,
        hard_stops=tuple(hard_stops),
        remediations=tuple(remediation),
        metadata={
            "default_branch": branch,
            "language": language,
            "license": license_id,
            "archived": archived,
            "stars": meta.get("stargazers_count"),
            "fork": meta.get("fork"),
            "size_kb": meta.get("size"),
            "pushed_at": meta.get("pushed_at"),
            "tree_truncated": tree.get("truncated", False),
            "evidence_depth": "github_metadata_and_tree",
            "flags": flags,
        },
    )


def _local_paths(path: Path) -> set[str]:
    output: set[str] = set()
    for item in path.rglob("*"):
        if not item.is_file() or any(part in _IGNORED_PARTS for part in item.parts):
            continue
        output.add(str(item.relative_to(path)).replace("\\", "/"))
    return output


def qualify_local(path: Path, profile: RequirementProfile | None = None) -> QualificationReport:
    profile = profile or RequirementProfile()
    paths = _local_paths(path)
    flags = _path_flags(paths)
    license_present = flags["license"]
    language = "Python" if flags["python_manifest"] else None
    dimensions = _dimensions(
        profile=profile,
        topics=set(profile.topics) if "BRD.md" in paths else set(),
        language=language,
        flags=flags,
        license_id="detected-local" if license_present else None,
        archived=False,
        pushed_at=datetime.now(timezone.utc).isoformat(),
    )
    hard_stops = () if license_present else ("No license file detected.",)
    overall = round(sum(item.score * item.weight for item in dimensions), 1)
    verdict = "NO_GO" if hard_stops else ("GO" if overall >= 82 else "CONDITIONAL_GO")
    remediation: list[str] = []
    if not flags["tests"]:
        remediation.append("Add tests.")
    if not flags["ci"]:
        remediation.append("Add CI.")
    return QualificationReport(
        repository=str(path),
        revision=_local_git_revision(path),
        verdict=verdict,  # type: ignore[arg-type]
        overall_score=overall,
        dimensions=dimensions,
        hard_stops=hard_stops,
        remediations=tuple(remediation),
        metadata={"evidence_depth": "local_static", "flags": flags},
    )


def _local_git_revision(path: Path) -> str | None:
    result = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=path,
        text=True,
        capture_output=True,
        check=False,
    )
    sha = result.stdout.strip()
    return f"git:{sha}" if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", sha) else None


def qualify_deep_remote(
    repository: str,
    profile: RequirementProfile | None = None,
) -> QualificationReport:
    """Clone a public repository at depth one and add local structural evidence.

    It does not execute repository-provided install or build scripts. This avoids
    turning qualification into arbitrary code execution.
    """

    remote = qualify_remote(repository, profile)
    if remote.verdict in {"NO_GO", "INSUFFICIENT_EVIDENCE"}:
        return remote
    owner, repo = parse_repo(repository)
    with tempfile.TemporaryDirectory(prefix="nornyx-forge-qualify-") as temp:
        target = Path(temp) / repo
        clone = subprocess.run(
            ("git", "clone", "--depth", "1", f"https://github.com/{owner}/{repo}.git", str(target)),
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
        if clone.returncode:
            return QualificationReport(
                repository=remote.repository,
                revision=remote.revision,
                verdict="INSUFFICIENT_EVIDENCE",
                overall_score=remote.overall_score,
                dimensions=remote.dimensions,
                hard_stops=(f"Deep clone failed: {clone.stderr.strip()}",),
                remediations=remote.remediations,
                metadata={**remote.metadata, "evidence_depth": "github_metadata_only"},
            )
        local = qualify_local(target, profile)
    combined = round((remote.overall_score * 0.65) + (local.overall_score * 0.35), 1)
    verdict = "GO" if combined >= 82 else "CONDITIONAL_GO" if combined >= 68 else "REBASE_RECOMMENDED"
    return QualificationReport(
        repository=remote.repository,
        revision=remote.revision,
        verdict=verdict,  # type: ignore[arg-type]
        overall_score=combined,
        dimensions=remote.dimensions,
        hard_stops=remote.hard_stops,
        remediations=tuple(dict.fromkeys((*remote.remediations, *local.remediations))),
        metadata={**remote.metadata, "evidence_depth": "github_tree_plus_safe_clone"},
    )
