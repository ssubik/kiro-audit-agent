#!/usr/bin/env python3
"""
Synthesize useful Solidity / EVM audit rules from raw_findings.json.

Outputs:
  security_rules.json             -> classified rules only
  unclassified_rules.json         -> unknown findings converted into rule-like triage candidates
  unclassified_findings.json      -> raw unknown findings for debugging
  synthesis_stats.json            -> stats

This fixes the issue where unclassified findings were only raw GitHub links.
"""

import argparse
import json
import re
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional


Finding = Dict[str, Any]
Rule = Dict[str, Any]

DEFAULT_INPUT = "raw_findings.json"
DEFAULT_RULE_OUTPUT = "security_rules.json"
DEFAULT_UNCLASSIFIED_RULE_OUTPUT = "unclassified_rules.json"
DEFAULT_UNCLASSIFIED_FINDINGS_OUTPUT = "unclassified_findings.json"
DEFAULT_STATS_OUTPUT = "synthesis_stats.json"
SIMILARITY_THRESHOLD = 0.45


VULN_PATTERNS: Dict[str, Dict[str, Any]] = {
    "reentrancy": {
        "swc_id": "SWC-107",
        "severity": "critical",
        "patterns": [
            r"\breentranc\w*\b", r"\bre-enter\b", r"\brecursive call\b",
            r"\bcallback\b", r"\bexternal call before\b", r"\bcall\{value:",
            r"\bonerc721received\b", r"\bonerc1155received\b", r"\btokensreceived\b",
            r"\berc777\b",
        ],
        "title": "Reentrancy / Callback Before State Update",
        "description": "A function performs an external interaction before finalizing internal accounting or state changes, allowing an attacker-controlled callback to re-enter and consume the same state more than once.",
        "detection_pattern": "Look for ETH/token transfers, low-level calls, safeTransfer callbacks, ERC777 hooks, or arbitrary external calls before balance, debt, share, or status variables are updated.",
        "example_code": "function withdraw(uint256 amount) external {\n    (bool ok,) = msg.sender.call{value: amount}(\"\");\n    require(ok);\n    balances[msg.sender] -= amount;\n}",
        "exploit_scenario": [
            "Attacker obtains a valid withdrawable balance.",
            "Attacker calls the vulnerable function.",
            "The contract transfers ETH/tokens or triggers a callback before updating state.",
            "Attacker re-enters through fallback/hook while the old balance is still valid.",
            "The same balance is withdrawn or consumed multiple times."
        ],
        "remediation": "Apply checks-effects-interactions, update all accounting before external calls, add ReentrancyGuard for cross-function reentrancy, and review token hooks such as ERC777/ERC721/ERC1155 callbacks.",
        "test_template": "function testReentrancyBlocked() public {\n    // Deploy attacker receiver with fallback/hook that re-enters.\n    // Fund victim state.\n    // Expect revert or assert protocol balance cannot be drained twice.\n}",
    },
    "access_control": {
        "swc_id": "SWC-105",
        "severity": "critical",
        "patterns": [
            r"\baccess control\b", r"\bmissing access\b", r"\bunauthori[sz]ed\b",
            r"\bonlyowner\b", r"\bowner\b", r"\badmin\b", r"\bprivileged\b",
            r"\brole\b", r"\bpermission\b", r"\bgovernance\b", r"\bupgrade\b",
        ],
        "title": "Missing or Weak Access Control",
        "description": "A privileged function can be called by an unauthorized actor or a sensitive role can be changed without proper authorization.",
        "detection_pattern": "Look for external/public functions that modify owner, admin, roles, implementation addresses, fee parameters, oracle addresses, treasury, minting rights, pausing, or protocol configuration without explicit access checks.",
        "example_code": "function setOwner(address newOwner) external {\n    owner = newOwner;\n}",
        "exploit_scenario": [
            "Attacker identifies a privileged state-changing function.",
            "The function lacks onlyOwner, AccessControl, governance, or equivalent checks.",
            "Attacker changes ownership/configuration or triggers privileged movement of funds.",
            "Protocol control or assets are compromised."
        ],
        "remediation": "Use explicit role-based access control, restrict initializers and upgrade paths, emit events for privileged changes, and test every admin function as an attacker.",
        "test_template": "function testUnauthorizedAdminCallReverts() public {\n    vm.prank(attacker);\n    vm.expectRevert();\n    target.adminFunction();\n}",
    },
    "arithmetic_precision": {
        "swc_id": "SWC-101",
        "severity": "high",
        "patterns": [
            r"\boverflow\b", r"\bunderflow\b", r"\brounding\b", r"\bprecision\b",
            r"\btruncat\w*\b", r"\bdivision before multiplication\b", r"\bdecimal\b",
            r"\bshare\b", r"\bexchange rate\b", r"\baccounting\b", r"\binvariant\b",
            r"\bdebt\b", r"\bcollateral\b", r"\bliabilit", r"\brefund\b",
            r"\bfee\b", r"\bbalance\b",
        ],
        "title": "Arithmetic, Precision, or Accounting Error",
        "description": "Math, rounding, scaling, refund, fee, or accounting logic can create incorrect balances, shares, collateral values, debt values, or protocol totals.",
        "detection_pattern": "Look for division before multiplication, unchecked blocks, mixed token decimals, rounding in favor of users, share/asset conversions, refund logic, fee logic, and total supply or reserve invariants.",
        "example_code": "uint256 shares = assets * totalSupply / totalAssets;\n// Missing rounding direction, zero-share guard, and manipulated totalAssets protection.",
        "exploit_scenario": [
            "Attacker chooses amounts around precision, refund, fee, or rounding boundaries.",
            "Protocol mints, burns, refunds, borrows, repays, or settles using lossy arithmetic.",
            "Attacker repeats the operation or combines it with state manipulation.",
            "Value is created, debt is understated, refunds are wrong, or balances become inconsistent."
        ],
        "remediation": "Use full-precision mulDiv, explicitly define rounding direction, normalize decimals, add zero-share/minimum amount guards, and enforce accounting invariants with fuzz tests.",
        "test_template": "function testFuzzNoAccountingValueCreation(uint256 amount) public {\n    amount = bound(amount, 1, 1e36);\n    // execute accounting path\n    // assert total assets, liabilities, shares, refunds, and balances remain consistent\n}",
    },
    "oracle_manipulation": {
        "swc_id": "SWC-120",
        "severity": "high",
        "patterns": [
            r"\boracle\b", r"\bprice\b", r"\btwap\b", r"\bstale\b", r"\bchainlink\b",
            r"\bfeed\b", r"\bspot\b", r"\bmanipulat\w*\b", r"\bflash loan\b.*\bprice\b",
        ],
        "title": "Oracle or Price Manipulation",
        "description": "Protocol logic depends on manipulable, stale, incorrectly scaled, or insufficiently validated price data.",
        "detection_pattern": "Look for AMM spot prices, missing stale-price checks, no heartbeat validation, missing min/max bounds, wrong decimals, single-source oracle reliance, or price reads after same-block liquidity manipulation.",
        "example_code": "uint256 price = pair.getSpotPrice();\nuint256 collateralValue = collateralAmount * price / 1e18;",
        "exploit_scenario": [
            "Attacker sources temporary liquidity or manipulates a low-liquidity pool.",
            "Protocol reads the manipulated or stale price.",
            "Collateral, debt, minting, or liquidation logic uses the bad price.",
            "Attacker borrows, withdraws, mints, or liquidates for profit."
        ],
        "remediation": "Use TWAP or trusted oracle feeds, validate heartbeat/staleness, normalize decimals, apply deviation bounds, require sufficient liquidity, and avoid same-block spot prices.",
        "test_template": "function testOracleManipulationDoesNotCreateProfit() public {\n    // manipulate mock AMM price\n    // call borrow/mint/liquidate path\n    // assert protocol rejects or uses bounded oracle value\n}",
    },
    "compatibility_validation": {
        "swc_id": "SCSVS-COMPAT",
        "severity": "medium",
        "patterns": [
            r"\bcompatib", r"\berc20\b", r"\bsymbol\(\)", r"\bbytes32\b", r"\bstring\b",
            r"\bprecompile\b", r"\bevm\b", r"\bopcode\b", r"\brandao\b", r"\binterface\b",
            r"\bnon-standard\b", r"\breturn value\b", r"\bparseargs", r"\berror validation\b",
            r"\bdoesn't check\b", r"\bdoes not check\b",
        ],
        "title": "Compatibility or Input Validation Gap",
        "description": "The system assumes a specific interface, encoding, return type, precompile behavior, or argument format and may break or skip validation for valid edge cases.",
        "detection_pattern": "Look for strict assumptions about ERC20 metadata return types, EVM opcode/precompile behavior, parsed arguments, unchecked parser errors, non-standard token behavior, or unsupported but valid interface variants.",
        "example_code": "string memory symbol = IERC20(token).symbol();\n// Fails for tokens that return bytes32 symbol or non-standard metadata.",
        "exploit_scenario": [
            "A valid but non-standard token, precompile input, or EVM compatibility edge case is used.",
            "The system assumes only one encoding, return type, or execution behavior.",
            "Validation is skipped or the call fails unexpectedly.",
            "Users are blocked, accounting diverges, or EVM compatibility is broken."
        ],
        "remediation": "Check parser errors explicitly, support known non-standard return formats where required, use defensive decoding, add compatibility tests for edge cases, and fail closed when parsing fails.",
        "test_template": "function testCompatibilityEdgeCaseDoesNotBypassValidation() public {\n    // mock non-standard token/precompile/parser response\n    // assert validation catches errors or supports expected alternate encoding\n}",
    },
}

UNKNOWN_RULE_META = {
    "swc_id": "UNCLASSIFIED",
    "severity": "medium",
    "title": "Unclassified Audit Finding Requiring Manual Triage",
    "description": "This finding could not be confidently mapped to an existing vulnerability class. It should be manually triaged and either mapped to an existing rule, converted into a new rule category, or dismissed if it is not a reusable security pattern.",
    "detection_pattern": "Review the finding title, affected code links, proof of concept, and impact. Identify the failed assumption, missing validation, broken invariant, compatibility gap, or incorrect state transition. Promote this candidate to a typed rule once the reusable pattern is clear.",
    "example_code": "// Candidate-specific. Inspect evidence.sample_titles and references.\n// Add minimal vulnerable pseudocode after manual triage.",
    "exploit_scenario": [
        "Read the referenced finding and identify the attacker or failing actor.",
        "Determine the violated assumption or invariant.",
        "Reconstruct the minimal failing input, state, or transaction sequence.",
        "Decide whether the issue is reusable enough to become a new rule category."
    ],
    "remediation": "Manual triage required. Add explicit validation, compatibility handling, invariant enforcement, or error handling based on the referenced finding.",
    "test_template": "function testUnclassifiedCandidateRegression() public {\n    // Reproduce the referenced finding.\n    // Convert this into a typed invariant/unit test after triage.\n}",
}


def load_raw(path: str) -> List[Finding]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON array")
    return data


def write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def clean_text(value: Optional[str]) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def normalize_severity(value: Optional[str]) -> str:
    text = clean_text(value).lower()
    if "critical" in text or text in {"c", "crit"}:
        return "critical"
    if "high" in text or text.startswith("h"):
        return "high"
    if "medium" in text or text.startswith("m"):
        return "medium"
    if "low" in text or text.startswith("l"):
        return "low"
    if "informational" in text or "info" in text:
        return "low"
    return "medium"


def classify(text: str) -> Dict[str, Any]:
    matches = []
    for vuln_type, meta in VULN_PATTERNS.items():
        score = 0
        matched_patterns = []
        for pattern in meta["patterns"]:
            if re.search(pattern, text, flags=re.IGNORECASE):
                score += 1
                matched_patterns.append(pattern)
        if score:
            matches.append({
                "type": vuln_type,
                "swc_id": meta["swc_id"],
                "score": score,
                "matched_patterns": matched_patterns,
            })

    if not matches:
        return {"type": "unknown", "swc_id": "UNCLASSIFIED", "score": 0, "matched_patterns": []}

    matches.sort(key=lambda item: item["score"], reverse=True)
    return matches[0]


def normalize_finding(entry: Finding) -> Finding:
    title = clean_text(entry.get("title"))
    description = clean_text(entry.get("description"))
    source = clean_text(entry.get("source")) or "unknown"
    reference = clean_text(entry.get("reference"))
    text = f"{title} {description}".strip()
    classification = classify(text)

    return {
        "source": source,
        "title": title,
        "description": description,
        "text": text.lower(),
        "type": classification["type"],
        "swc_id": classification["swc_id"],
        "classification_score": classification["score"],
        "matched_patterns": classification["matched_patterns"],
        "severity": normalize_severity(entry.get("severity")),
        "reference": reference,
    }


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def cluster_findings(findings: List[Finding], threshold: float) -> List[List[Finding]]:
    clusters: List[List[Finding]] = []
    for finding in findings:
        placed = False
        for cluster in clusters:
            representative = cluster[0]
            if (
                finding["type"] == representative["type"]
                and finding["swc_id"] == representative["swc_id"]
                and similarity(finding["text"], representative["text"]) >= threshold
            ):
                cluster.append(finding)
                placed = True
                break
        if not placed:
            clusters.append([finding])
    return clusters


def most_common(values: List[str], default: str = "medium") -> str:
    values = [v for v in values if v]
    if not values:
        return default
    return Counter(values).most_common(1)[0][0]


def compact_references(cluster: List[Finding], limit: int = 8) -> List[str]:
    refs, seen = [], set()
    for item in cluster:
        ref = item.get("reference")
        if not ref or ref in seen:
            continue
        refs.append(ref)
        seen.add(ref)
        if len(refs) >= limit:
            break
    return refs


def summarize_sources(cluster: List[Finding]) -> Dict[str, int]:
    return dict(Counter(item.get("source", "unknown") for item in cluster))


def evidence_for(cluster: List[Finding]) -> Dict[str, Any]:
    return {
        "finding_count": len(cluster),
        "sources": summarize_sources(cluster),
        "sample_titles": [item["title"] for item in cluster[:5] if item.get("title")],
        "matched_patterns": sorted({
            pattern
            for item in cluster
            for pattern in item.get("matched_patterns", [])
        })[:12],
    }


def synthesize_rule(cluster: List[Finding], idx: int, status: str) -> Rule:
    meta = VULN_PATTERNS[cluster[0]["type"]]
    severity = most_common([item["severity"] for item in cluster], meta["severity"])
    return {
        "id": f"R{idx:03}",
        "status": status,
        "title": meta["title"],
        "type": cluster[0]["type"],
        "swc_id": meta["swc_id"],
        "severity": severity,
        "description": meta["description"],
        "detection_pattern": meta["detection_pattern"],
        "example_code": meta["example_code"],
        "exploit_scenario": meta["exploit_scenario"],
        "remediation": meta["remediation"],
        "test_template": meta["test_template"],
        "evidence": evidence_for(cluster),
        "references": compact_references(cluster),
    }


def synthesize_unclassified_rule(cluster: List[Finding], idx: int) -> Rule:
    severity = most_common([item["severity"] for item in cluster], UNKNOWN_RULE_META["severity"])
    sample_title = cluster[0].get("title") or UNKNOWN_RULE_META["title"]
    return {
        "id": f"U{idx:03}",
        "status": "needs_triage",
        "title": f"Manual Triage: {sample_title[:100]}",
        "type": "unclassified",
        "swc_id": "UNCLASSIFIED",
        "severity": severity,
        "description": UNKNOWN_RULE_META["description"],
        "detection_pattern": UNKNOWN_RULE_META["detection_pattern"],
        "example_code": UNKNOWN_RULE_META["example_code"],
        "exploit_scenario": UNKNOWN_RULE_META["exploit_scenario"],
        "remediation": UNKNOWN_RULE_META["remediation"],
        "test_template": UNKNOWN_RULE_META["test_template"],
        "evidence": evidence_for(cluster),
        "references": compact_references(cluster),
    }


def build_rules(raw_findings: List[Finding], threshold: float, include_candidates: bool) -> Dict[str, Any]:
    normalized = [normalize_finding(item) for item in raw_findings]
    known = [item for item in normalized if item["type"] != "unknown"]
    unknown = [item for item in normalized if item["type"] == "unknown"]

    grouped: Dict[str, List[Finding]] = defaultdict(list)
    for item in known:
        grouped[item["type"]].append(item)

    rules: List[Rule] = []
    idx = 1
    for vuln_type in sorted(grouped.keys()):
        for cluster in cluster_findings(grouped[vuln_type], threshold):
            status = "confirmed" if len(cluster) >= 2 else "candidate"
            if status == "candidate" and not include_candidates:
                continue
            rules.append(synthesize_rule(cluster, idx, status))
            idx += 1

    unknown_clusters = cluster_findings(unknown, threshold) if unknown else []
    unclassified_rules = [
        synthesize_unclassified_rule(cluster, idx)
        for idx, cluster in enumerate(unknown_clusters, 1)
    ]

    return {
        "rules": rules,
        "unclassified_rules": unclassified_rules,
        "unknown_findings": unknown,
        "stats": {
            "raw_findings": len(raw_findings),
            "classified_findings": len(known),
            "unclassified_findings": len(unknown),
            "generated_rules": len(rules),
            "unclassified_rules": len(unclassified_rules),
            "confirmed_rules": sum(1 for rule in rules if rule["status"] == "confirmed"),
            "candidate_rules": sum(1 for rule in rules if rule["status"] == "candidate"),
            "classification_by_type": dict(Counter(item["type"] for item in known)),
            "classification_by_swc": dict(Counter(item["swc_id"] for item in known)),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synthesize Solidity audit rules from raw findings.")
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_RULE_OUTPUT)
    parser.add_argument("--unclassified-rules-output", default=DEFAULT_UNCLASSIFIED_RULE_OUTPUT)
    parser.add_argument("--unclassified-findings-output", default=DEFAULT_UNCLASSIFIED_FINDINGS_OUTPUT)
    parser.add_argument("--stats-output", default=DEFAULT_STATS_OUTPUT)
    parser.add_argument("--threshold", type=float, default=SIMILARITY_THRESHOLD)
    parser.add_argument("--confirmed-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    raw = load_raw(args.input)
    result = build_rules(
        raw_findings=raw,
        threshold=args.threshold,
        include_candidates=not args.confirmed_only,
    )

    write_json(args.output, result["rules"])
    write_json(args.unclassified_rules_output, result["unclassified_rules"])
    write_json(args.unclassified_findings_output, result["unknown_findings"])
    write_json(args.stats_output, result["stats"])

    print(
        f"✅ Generated {result['stats']['generated_rules']} classified rules "
        f"({result['stats']['confirmed_rules']} confirmed, {result['stats']['candidate_rules']} candidate)"
    )
    print(f"🧾 Generated {result['stats']['unclassified_rules']} unclassified triage rules")
    print(f"📄 Wrote: {args.output}, {args.unclassified_rules_output}, {args.unclassified_findings_output}, {args.stats_output}")


if __name__ == "__main__":
    main()
