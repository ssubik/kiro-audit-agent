"""
Provide a minimal list of SWC categories for reference.

This module defines a static list of Smart Contract Weakness Classification
entries.  The ingestion and synthesis scripts can reference this list to
validate SWC IDs or to provide human-readable titles for rules.  The list
included here is intentionally small; you may extend it as your needs
grow.
"""

SWC = [
    {"id": "SWC-107", "title": "Reentrancy"},
    {"id": "SWC-101", "title": "Integer Overflow and Underflow"},
    {"id": "SWC-115", "title": "Authorization Issues"},
    {"id": "SWC-120", "title": "Oracle Manipulation"},
    {"id": "SWC-112", "title": "Delegatecall to Untrusted Callee"},
    {"id": "SWC-113", "title": "DoS with Block Gas Limit"},
    {"id": "SWC-114", "title": "Arithmetic Underflow and Overflow"},
    {"id": "SWC-000", "title": "Unknown or Unclassified"},
]


def run():
    """
    Return the list of SWC entries.

    Returns:
        A list of dictionaries with keys 'id' and 'title'.
    """
    return SWC