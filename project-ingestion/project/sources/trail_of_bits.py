"""
Ingest findings from Trail of Bits public datasets.

Trail of Bits publish a CSV file containing smart contract audit findings in
their `publications` repository.  This module downloads that CSV and
converts each row into a normalized finding dictionary.  If the CSV
changes format in the future you may need to update the parsing logic.
"""

import requests

# URL of the Trail of Bits dataset.  Only the first file is used here, but
# additional datasets could be added as needed.
URL = (
    "https://raw.githubusercontent.com/trailofbits/publications/master/"
    "datasets/smart_contract_audit_findings.csv"
)


def run():
    """
    Fetch and parse the Trail of Bits smart contract audit findings dataset.

    Returns:
        A list of normalized finding dictionaries.
    """
    results = []
    try:
        res = requests.get(URL)
        res.raise_for_status()
        lines = res.text.split("\n")
        # Skip header row; the CSV is expected to have at least four columns:
        # title, description, severity, reference.
        for row in lines[1:]:
            if not row.strip():
                continue
            parts = row.split(",")
            # Ensure we have enough columns to parse; skip malformed rows.
            if len(parts) < 4:
                continue
            title, description, severity, reference = parts[0], parts[1], parts[2], parts[3]
            results.append(
                {
                    "source": "trail_of_bits",
                    "title": title,
                    "severity": severity.lower(),
                    "swc_id": "unknown",
                    "description": description,
                    "reference": reference,
                }
            )
    except Exception:
        # If the dataset cannot be fetched (e.g. network issues), return an empty list.
        # In production you might log this error instead.
        pass
    return results