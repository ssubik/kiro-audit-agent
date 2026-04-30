"""
Ingest findings from Sherlock audit contests hosted on GitHub.

This module reuses the Code4rena ingestion logic because Sherlock uses a
similar GitHub issue format.  Only the repository list differs.  The
normalize() function is imported from the Code4rena module.
"""

from .code4rena import fetch, normalize


def run():
    """
    Entry point for Sherlock ingestion.

    Returns:
        A list of normalized finding dictionaries for Sherlock contests.
    """
    repos = [
        # Example Sherlock contest repository; replace or extend as needed.
        "sherlock-audit/2024-06-allora-judging",
    ]
    results = []
    for repo in repos:
        for issue in fetch(repo):
            if "pull_request" in issue:
                continue
            results.append(normalize(issue))
    return results