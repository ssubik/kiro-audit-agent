"""
Ingest findings from Code4rena contest repositories hosted on GitHub.

This module fetches issues from specified GitHub repositories and returns
normalized dictionaries with basic metadata.  It does not infer SWC IDs or
exploit details; that logic lives in the synthesis layer.
"""

import os
import requests


GITHUB_API = "https://api.github.com"
TOKEN = os.getenv("GITHUB_TOKEN")

# Prepare HTTP headers.  If a GitHub token is available it will be used to
# increase rate limits; otherwise anonymous requests will be made.
HEADERS = {"Accept": "application/vnd.github+json"}
if TOKEN:
    HEADERS["Authorization"] = f"Bearer {TOKEN}"


def fetch(repo: str):
    """
    Fetch all issues from a given GitHub repository.

    Args:
        repo: The repository in "owner/name" format.

    Returns:
        A list of issue dictionaries as returned by the GitHub API.
    """
    issues = []
    page = 1
    while True:
        url = f"{GITHUB_API}/repos/{repo}/issues?state=all&per_page=100&page={page}"
        res = requests.get(url, headers=HEADERS)
        if res.status_code != 200:
            raise RuntimeError(
                f"Failed to fetch issues for {repo}: {res.status_code} {res.text}"
            )
        data = res.json()
        if not data:
            break
        issues.extend(data)
        page += 1
    return issues


def normalize(issue):
    """
    Convert a GitHub issue into our minimal finding schema.

    Args:
        issue: A dictionary returned by the GitHub API.

    Returns:
        A dictionary with keys: source, title, severity, swc_id, description,
        reference.  The swc_id is left as 'unknown' because mapping is
        performed later in the synthesis stage.
    """
    labels = [l["name"].lower() for l in issue.get("labels", [])]
    severity = "medium"
    if any(l.startswith("h") for l in labels):
        severity = "high"
    elif any(l.startswith("m") for l in labels):
        severity = "medium"
    elif any(l.startswith("l") for l in labels):
        severity = "low"
    return {
        "source": "code4rena",
        "title": issue.get("title", ""),
        "severity": severity,
        "swc_id": "unknown",
        "description": (issue.get("body") or "")[:500],
        "reference": issue.get("html_url"),
    }


def run():
    """
    Entry point for ingestion.  Specify contest repositories here.

    Returns:
        A list of normalized finding dictionaries.
    """
    repos = [
        "code-423n4/2024-11-nibiru-findings",
    ]
    results = []
    for repo in repos:
        for issue in fetch(repo):
            if "pull_request" in issue:
                continue
            results.append(normalize(issue))
    return results