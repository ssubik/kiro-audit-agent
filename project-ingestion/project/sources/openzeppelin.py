"""
Ingest findings from OpenZeppelin security audit listings.

OpenZeppelin publish a list of their completed audits on their website.  This
module scrapes the audit index page and extracts links to individual
reports.  Because OpenZeppelin's audits are primarily documented in PDF
reports, this ingestion only captures the existence of a report; the
detailed findings must be extracted manually or via additional scripts.
"""

import requests
from bs4 import BeautifulSoup

URL = "https://www.openzeppelin.com/security-audits"


def run():
    """
    Fetch OpenZeppelin's audit index and extract report links.

    Returns:
        A list of normalized finding dictionaries.  Each entry corresponds
        to a single audit report and provides a reference to the report URL.
    """
    results = []
    try:
        res = requests.get(URL)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")
        # Extract anchor tags that appear to be audit report links.
        for a in soup.find_all("a"):
            href = a.get("href")
            text = a.get_text().strip()
            if not href:
                continue
            # Heuristic: include links containing the word 'audit'.  This may
            # capture some false positives; further filtering could be added.
            if "audit" in href.lower():
                results.append(
                    {
                        "source": "openzeppelin",
                        "title": text or href,
                        "severity": "unknown",
                        "swc_id": "unknown",
                        "description": "OpenZeppelin audit report",
                        "reference": href,
                    }
                )
    except Exception:
        # Silent failure; return empty list if scraping fails.
        pass
    return results