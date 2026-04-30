#!/usr/bin/env python3

import json
from collections import defaultdict, Counter
from typing import List, Dict
from difflib import SequenceMatcher


# -----------------------------
# LOAD
# -----------------------------

def load_raw(path="raw_findings.json"):
    with open(path) as f:
        return json.load(f)


# -----------------------------
# BETTER SWC INFERENCE
# -----------------------------

SWC_MAP = {
    "reentrancy": "SWC-107",
    "re-enter": "SWC-107",
    "callback": "SWC-107",

    "overflow": "SWC-101",
    "underflow": "SWC-101",
    "rounding": "SWC-101",

    "access control": "SWC-115",
    "authorization": "SWC-115",
    "owner": "SWC-115",
    "admin": "SWC-115",

    "delegatecall": "SWC-112",
    "proxy": "SWC-112",

    "oracle": "SWC-120",
    "price": "SWC-120",
    "twap": "SWC-120",

    "flash loan": "SWC-114",
    "front run": "SWC-114",
}


def extract_vulnerability(text: str):
    t = text.lower()

    # REENTRANCY
    if any(x in t for x in [
        "reentrancy", "re-enter", "recursive call", "callback",
        "external call before state"
    ]):
        return {
            "swc": "SWC-107",
            "type": "reentrancy",
            "confidence": 0.9
        }

    # ACCESS CONTROL
    if any(x in t for x in [
        "onlyowner", "missing access control", "no access control",
        "unauthorized", "owner", "admin"
    ]):
        return {
            "swc": "SWC-115",
            "type": "access_control",
            "confidence": 0.9
        }

    # ORACLE
    if any(x in t for x in [
        "oracle", "price", "twap", "manipulation"
    ]):
        return {
            "swc": "SWC-120",
            "type": "oracle",
            "confidence": 0.8
        }

    # ARITHMETIC
    if any(x in t for x in [
        "overflow", "underflow", "rounding", "precision"
    ]):
        return {
            "swc": "SWC-101",
            "type": "math",
            "confidence": 0.8
        }

    return {
        "swc": "SWC-000",
        "type": "unknown",
        "confidence": 0.0
    }


# -----------------------------
# NORMALIZATION
# -----------------------------

def normalize(entry):
    text = (entry.get("title", "") + " " + entry.get("description", ""))

    vuln = extract_vulnerability(text)

    return {
        "text": text,
        "swc_id": vuln["swc"],
        "type": vuln["type"],
        "severity": normalize_severity(entry.get("severity")),
        "reference": entry.get("reference")
    }


def normalize_severity(s):
    if not s:
        return "medium"
    s = s.lower()
    if "critical" in s:
        return "critical"
    if "high" in s or s.startswith("h"):
        return "high"
    if "medium" in s or s.startswith("m"):
        return "medium"
    if "low" in s or s.startswith("l"):
        return "low"
    return "medium"


# -----------------------------
# GROUP BY SWC FIRST (IMPORTANT)
# -----------------------------

def group_by_swc(entries):
    grouped = defaultdict(list)
    for e in entries:
        grouped[e["swc_id"]].append(e)
    return grouped


# -----------------------------
# CLUSTER WITH LOWER THRESHOLD
# -----------------------------

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()


def cluster(entries):
    clusters = []

    for e in entries:
        placed = False

        for c in clusters:
            if similar(e["text"], c[0]["text"]) > 0.45:
                c.append(e)
                placed = True
                break

        if not placed:
            clusters.append([e])

    return clusters


# -----------------------------
# RULE GENERATION
# -----------------------------

def most_common(lst):
    return Counter(lst).most_common(1)[0][0]


def synthesize(cluster, idx):
    base = cluster[0]
    swc = base["swc_id"]

    return {
        "id": f"R{idx:03}",
        "title": title(swc),
        "swc_id": swc,
        "severity": most_common([e["severity"] for e in cluster]),

        "description": f"Derived from {len(cluster)} findings",

        "detection_pattern": detection(swc),
        "example_code": example(swc),
        "exploit_scenario": exploit(swc),
        "remediation": fix(swc),
        "test_template": test(swc),

        "references": [e["reference"] for e in cluster[:5]]
    }


# -----------------------------
# KNOWLEDGE BASE
# -----------------------------

def title(swc):
    return {
        "SWC-107": "Reentrancy",
        "SWC-101": "Arithmetic / Rounding Bug",
        "SWC-115": "Access Control Issue",
        "SWC-120": "Oracle Manipulation",
    }.get(swc, "Generic Vulnerability")


def detection(swc):
    return {
        "SWC-107": "external call before state update",
        "SWC-101": "unsafe arithmetic / rounding",
        "SWC-115": "missing access control modifier",
        "SWC-120": "spot price or weak oracle usage",
    }.get(swc, "manual review")


def example(swc):
    return {
        "SWC-107": "msg.sender.call(...); balance[msg.sender] = 0;",
        "SWC-115": "function setOwner(address o) public { owner = o; }",
    }.get(swc, "")


def exploit(swc):
    return {
        "SWC-107": ["deposit", "withdraw", "reenter", "drain"],
        "SWC-120": ["flash loan", "manipulate price", "exploit"],
    }.get(swc, ["manual"])


def fix(swc):
    return {
        "SWC-107": "checks-effects-interactions",
        "SWC-115": "add onlyOwner",
        "SWC-120": "use TWAP",
    }.get(swc, "manual fix")


def test(swc):
    return {
        "SWC-107": "function testReentrancy() public {}",
        "SWC-115": "function testUnauthorized() public {}",
    }.get(swc, "manual test")


# -----------------------------
# MAIN
# -----------------------------

def main():
    raw = load_raw()

    normalized = [normalize(e) for e in raw]

    grouped = group_by_swc(normalized)

    rules = []
    idx = 1

    for swc, entries in grouped.items():
        clusters = cluster(entries)

        for c in clusters:
            rules.append(synthesize(c, idx))
            idx += 1

    with open("security_rules.json", "w") as f:
        json.dump(rules, f, indent=2)

    print(f"✅ Generated {len(rules)} rules")


if __name__ == "__main__":
    main()