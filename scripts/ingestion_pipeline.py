"""
Ingestion pipeline for building the Solidity auditor rulebook.

This script provides a template for downloading and normalising contest reports from
Code4rena and Sherlock into a unified JSON rulebook.  It uses the GitHub API to
fetch issues (findings) from contest repositories, parses each issue, maps the
finding to a SWC category and severity, and emits entries conforming to the
schema described in `security_rules.json`.

Note: this script is a starting point; you need to fill in authentication,
repository enumeration and SWC mapping logic.  See the deep research report
for details【26†L83-L91】【30†L21-L29】.
"""

import json
import os
import re
from typing import List, Dict, Any

import requests

GITHUB_API = "https://api.github.com"

# Replace with your personal access token or environment variable
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "YOUR_GITHUB_TOKEN_HERE")

HEADERS = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {GITHUB_TOKEN}",
}


def fetch_issues(repo: str, state: str = "all") -> List[Dict[str, Any]]:
    """Fetch all issues from a GitHub repository (contest findings)."""
    issues = []
    page = 1
    while True:
        url = f"{GITHUB_API}/repos/{repo}/issues?state={state}&per_page=100&page={page}"
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch issues from {repo}: {resp.status_code} {resp.text}")
        data = resp.json()
        if not data:
            break
        issues.extend(data)
        page += 1
    return issues


def parse_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a GitHub issue into a preliminary rule entry.

    This function extracts the title, body, labels and maps them into our schema.  You need
    to implement the mapping from labels/severity to SWC IDs and severity levels.
    """
    title = issue.get("title", "Untitled finding")
    body = issue.get("body", "")
    labels = [lbl["name"] for lbl in issue.get("labels", [])]

    # Determine severity (example: Code4rena labels issues with 'H', 'M', 'L', etc.)
    severity = "medium"
    for lbl in labels:
        if lbl.lower().startswith("h"):  # high severity label
            severity = "high"
            break
        if lbl.lower().startswith("m"):
            severity = "medium"
        if lbl.lower().startswith("l"):
            severity = "low"

    # Map keywords in the body to SWC IDs – simplistic example
    swc_id = ""
    if re.search(r"reentrancy", body, re.IGNORECASE):
        swc_id = "SWC-107"
    elif re.search(r"overflow|underflow", body, re.IGNORECASE):
        swc_id = "SWC-101"
    elif re.search(r"access control|authorization", body, re.IGNORECASE):
        swc_id = "SWC-115"

    return {
        "id": issue.get("number"),
        "title": title,
        "swc_id": swc_id or "SWC-000",  # default if unknown
        "severity": severity,
        "description": body[:200],
        "detection_pattern": "",  # to be filled manually or via heuristics
        "example_code": "",
        "exploit_scenario": "",
        "remediation": "",
        "test_template": "",
        "references": [f"{issue.get('html_url')}"]
    }


def normalise_reports(repos: List[str]) -> List[Dict[str, Any]]:
    """Fetch and parse all issues from multiple contest repositories."""
    entries: List[Dict[str, Any]] = []
    for repo in repos:
        issues = fetch_issues(repo)
        for issue in issues:
            # Skip pull requests; we only want issues
            if "pull_request" in issue:
                continue
            entry = parse_issue(issue)
            entries.append(entry)
    return entries


def write_rulebook(entries: List[Dict[str, Any]], out_path: str) -> None:
    """Write the list of rule entries to a JSON file."""
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def main():
    # Example contest repositories; replace with real ones
    contest_repos = [
        "code-423n4/2024-11-nibiru-findings",
        "sherlock-audit/2024-06-allora-judging",
    ]
    entries = normalise_reports(contest_repos)
    write_rulebook(entries, "security_rules_generated.json")
    print(f"Generated {len(entries)} rules to security_rules_generated.json")


if __name__ == "__main__":
    main()
