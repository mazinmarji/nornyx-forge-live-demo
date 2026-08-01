from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from .models import RequirementProfile
from .repo_qualifier import qualify_remote


def search_repositories(query: str, *, limit: int = 10) -> list[dict[str, Any]]:
    encoded = urllib.parse.quote(query)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "nornyx-forge-live-demo",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"https://api.github.com/search/repositories?q={encoded}&sort=stars&order=desc&per_page={limit}",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response).get("items", [])


def scout(
    profile: RequirementProfile | None = None,
    *,
    limit: int = 5,
    candidate_pool: int = 15,
) -> list[dict[str, Any]]:
    profile = profile or RequirementProfile()
    topic_query = " ".join(f"topic:{item}" for item in profile.topics[:3])
    language = profile.languages[0] if profile.languages else "Python"
    query = f"{topic_query} language:{language} archived:false fork:false"
    reports: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in search_repositories(query, limit=max(limit, candidate_pool)):
        url = item.get("html_url")
        if not isinstance(url, str) or url in seen:
            continue
        seen.add(url)
        report = qualify_remote(url, profile)
        if report.verdict != "NO_GO":
            reports.append(report.to_dict())
        if len(reports) >= candidate_pool:
            break
    reports.sort(
        key=lambda item: (
            item["verdict"] == "GO",
            item["overall_score"],
            item.get("metadata", {}).get("stars") or 0,
        ),
        reverse=True,
    )
    return reports[:limit]
