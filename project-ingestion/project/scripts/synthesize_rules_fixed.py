#!/usr/bin/env python3
"""
Synthesize useful Solidity audit rules from raw_findings.json.

This version fixes the main problem in the previous script:
- It does NOT emit useless SWC-000 "Generic Vulnerability" rules.
- It groups findings by vulnerability type, not just raw SWC.
- It preserves unknown findings in a separate review file instead of polluting security_rules.json.
- It produces more meaningful titles, descriptions, examples, exploit scenarios, remediations, and test templates.
- It writes:
    1. security_rules.json
    2. unclassified_findings.json
    3. synthesis_stats.json

Run from the repo root:

    python3 -m project.scripts.synthesize_rules

Expected inputs:
    raw_findings.json

Expected outputs:
    security_rules.json
    unclassified_findings.json
    synthesis_stats.json
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
DEFAULT_UNCLASSIFIED_OUTPUT = "unclassified_findings.json"
DEFAULT_STATS_OUTPUT = "synthesis_stats.json"
SIMILARITY_THRESHOLD = 0.45

VULN_PATTERNS: Dict[str, Dict[str, Any]] = {
    "reentrancy": {
        "swc_id": "SWC-107",
        "severity": "critical",
        "patterns": [
            r"\breentranc\w*\b",
            r"\bre-enter\b",
            r"\brecursive call\b",
            r"\bcallback\b",
            r"\bexternal call before\b",
            r"\bcall\{value:",
            r"\bonerc721received\b",
            r"\bonerc1155received\b",
            r"\btokensreceived\b",
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
            r"\baccess control\b",
            r"\bmissing access\b",
            r"\bunauthori[sz]ed\b",
            r"\bonlyowner\b",
            r"\bowner\b",
            r"\badmin\b",
            r"\bprivileged\b",
            r"\brole\b",
            r"\bpermission\b",
            r"\bgovernance\b",
            r"\bset[A-Z]\w*\b",
            r"\bupgrade\b",
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
            r"\boverflow\b",
            r"\bunderflow\b",
            r"\brounding\b",
            r"\bprecision\b",
            r"\btruncat\w*\b",
            r"\bdivision before multiplication\b",
            r"\bdecimal\b",
            r"\bshare\b",
            r"\bexchange rate\b",
            r"\baccounting\b",
            r"\binvariant\b",
            r"\bdebt\b",
            r"\bcollateral\b",
            r"\bliabilit",
        ],
        "title": "Arithmetic, Precision, or Accounting Error",
        "description": "Math, rounding, scaling, or accounting logic can create incorrect balances, shares, collateral values, debt values, or protocol totals.",
        "detection_pattern": "Look for division before multiplication, unchecked blocks, mixed token decimals, rounding in favor of users, share/asset conversions, collateral/debt accounting, and total supply or reserve invariants.",
        "example_code": "uint256 shares = assets * totalSupply / totalAssets;\n// Missing rounding direction, zero-share guard, and manipulated totalAssets protection.",
        "exploit_scenario": [
            "Attacker chooses amounts around precision or rounding boundaries.",
            "Protocol mints, burns, borrows, repays, or settles using lossy arithmetic.",
            "Attacker repeats the operation or combines it with state manipulation.",
            "Value is created, debt is understated, or collateral/share accounting becomes inconsistent."
        ],
        "remediation": "Use full-precision mulDiv, explicitly define rounding direction, normalize decimals, add zero-share/minimum amount guards, and enforce accounting invariants with fuzz tests.",
        "test_template": "function testFuzzNoAccountingValueCreation(uint256 amount) public {\n    amount = bound(amount, 1, 1e36);\n    // deposit/borrow/withdraw/repay sequence\n    // assert total assets, liabilities, shares, and balances remain consistent\n}",
    },
    "oracle_manipulation": {
        "swc_id": "SWC-120",
        "severity": "high",
        "patterns": [
            r"\boracle\b",
            r"\bprice\b",
            r"\btwap\b",
            r"\bstale\b",
            r"\bchainlink\b",
            r"\bfeed\b",
            r"\bspot\b",
            r"\bmanipulat\w*\b",
            r"\bflash loan\b.*\bprice\b",
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
    "delegatecall_upgradeability": {
        "swc_id": "SWC-112",
        "severity": "critical",
        "patterns": [
            r"\bdelegatecall\b",
            r"\bproxy\b",
            r"\bupgrade\b",
            r"\bimplementation\b",
            r"\binitiali[sz]er\b",
            r"\bstorage collision\b",
            r"\bstorage slot\b",
            r"\bfacet\b",
            r"\bdiamond\b",
        ],
        "title": "Unsafe Delegatecall or Upgradeability",
        "description": "Delegatecall or upgrade logic can execute untrusted code, reinitialize a proxy, or corrupt storage layout.",
        "detection_pattern": "Look for delegatecall to user-controlled targets, unrestricted upgrade functions, missing initializer protection, storage layout changes, diamond/facet selector mistakes, or unguarded migration functions.",
        "example_code": "function execute(address target, bytes calldata data) external {\n    target.delegatecall(data);\n}",
        "exploit_scenario": [
            "Attacker controls or influences a delegatecall target or implementation address.",
            "Malicious logic executes in the proxy/caller storage context.",
            "Critical storage such as owner, implementation, balances, or roles is overwritten.",
            "Attacker takes control, drains funds, or bricks the system."
        ],
        "remediation": "Restrict upgrades to authorized governance, avoid arbitrary delegatecall, protect initializers, version migrations, and validate storage layout compatibility before deployment.",
        "test_template": "function testUnauthorizedUpgradeOrDelegatecallReverts() public {\n    vm.prank(attacker);\n    vm.expectRevert();\n    proxy.upgradeTo(address(maliciousImplementation));\n}",
    },
    "signature_replay": {
        "swc_id": "SWC-121",
        "severity": "high",
        "patterns": [
            r"\bsignature\b",
            r"\becrecover\b",
            r"\bpermit\b",
            r"\bnonce\b",
            r"\breplay\b",
            r"\bdomain separator\b",
            r"\beip-712\b",
            r"\bsigner\b",
        ],
        "title": "Signature Verification or Replay Issue",
        "description": "A signature can be forged, replayed, used in the wrong domain, or accepted from an unintended signer.",
        "detection_pattern": "Look for signatures without nonce, deadline, chainId, verifying contract, domain separator, zero-address signer checks, low-s validation, or consumed-signature tracking.",
        "example_code": "bytes32 digest = keccak256(abi.encode(user, amount));\naddress signer = ecrecover(digest, v, r, s);",
        "exploit_scenario": [
            "User signs a valid authorization once.",
            "Attacker reuses it across chains, contracts, functions, or time.",
            "Contract accepts the replay because domain, nonce, or deadline is missing.",
            "Attacker repeats an approval, withdrawal, mint, or privileged action."
        ],
        "remediation": "Use EIP-712 typed data, include chainId/verifyingContract/domain, enforce nonces and deadlines, validate recovered signer, and reject malleable signatures.",
        "test_template": "function testSignatureCannotReplay() public {\n    // use signature once successfully\n    // second use must revert\n}",
    },
    "dos_gas_griefing": {
        "swc_id": "SWC-113",
        "severity": "medium",
        "patterns": [
            r"\bdos\b",
            r"\bdenial of service\b",
            r"\bunbounded loop\b",
            r"\bout of gas\b",
            r"\bgas grief",
            r"\bfailed call\b",
            r"\bblock gas\b",
            r"\barray length\b",
        ],
        "title": "Denial of Service or Gas Griefing",
        "description": "A function can become uncallable or block progress because it depends on unbounded loops, external call success, or attacker-controlled gas behavior.",
        "detection_pattern": "Look for loops over unbounded arrays, push-based payouts, external calls inside loops, state progress blocked by a revert, or gas assumptions on recipient contracts.",
        "example_code": "for (uint256 i = 0; i < users.length; i++) {\n    payable(users[i]).transfer(rewards[i]);\n}",
        "exploit_scenario": [
            "Attacker increases the number of loop iterations or adds a reverting recipient.",
            "Critical function exceeds gas limits or always reverts.",
            "Withdrawals, settlement, liquidation, or admin actions become blocked."
        ],
        "remediation": "Use pull payments, pagination, bounded loops, checkpointing, and avoid making global progress depend on external call success.",
        "test_template": "function testCannotDoSWithRevertingReceiver() public {\n    // add malicious receiver\n    // assert other users can still withdraw or progress via pull model\n}",
    },
    "front_running_mev": {
        "swc_id": "SWC-114",
        "severity": "medium",
        "patterns": [
            r"\bfront.?run",
            r"\bmev\b",
            r"\bsandwich\b",
            r"\btransaction order\b",
            r"\bslippage\b",
            r"\bdeadline\b",
            r"\bcommit reveal\b",
        ],
        "title": "Transaction Ordering / MEV Risk",
        "description": "A user action can be exploited through ordering, sandwiching, missing slippage controls, or missing commit-reveal protection.",
        "detection_pattern": "Look for swaps/mints/liquidations/auctions without slippage, deadlines, commit-reveal, or sequencing protections where ordering changes value.",
        "example_code": "function swap(uint256 amountIn) external {\n    pool.swap(amountIn, 0); // no minOut or deadline\n}",
        "exploit_scenario": [
            "Attacker observes a profitable pending transaction.",
            "Attacker places transactions before and/or after it.",
            "Victim receives worse price or attacker captures auction/liquidation value.",
            "Attacker profits from ordering control."
        ],
        "remediation": "Add minOut/slippage/deadline checks, consider commit-reveal for auctions, and design liquidation/settlement paths to be robust against MEV.",
        "test_template": "function testSlippageProtectsAgainstSandwich() public {\n    // move price before victim action\n    // victim action with minOut should revert\n}",
    },
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
        return {"type": "unknown", "swc_id": "SWC-000", "score": 0, "matched_patterns": []}

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
            same_type = finding["type"] == representative["type"]
            same_swc = finding["swc_id"] == representative["swc_id"]
            similar_text = similarity(finding["text"], representative["text"]) >= threshold
            if same_type and same_swc and similar_text:
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
    refs = []
    seen = set()
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


def synthesize_rule(cluster: List[Finding], idx: int, status: str) -> Rule:
    first = cluster[0]
    vuln_type = first["type"]
    meta = VULN_PATTERNS[vuln_type]
    severity = most_common([item["severity"] for item in cluster], meta["severity"])
    return {
        "id": f"R{idx:03}",
        "status": status,
        "title": meta["title"],
        "type": vuln_type,
        "swc_id": meta["swc_id"],
        "severity": severity,
        "description": meta["description"],
        "detection_pattern": meta["detection_pattern"],
        "example_code": meta["example_code"],
        "exploit_scenario": meta["exploit_scenario"],
        "remediation": meta["remediation"],
        "test_template": meta["test_template"],
        "evidence": {
            "finding_count": len(cluster),
            "sources": summarize_sources(cluster),
            "sample_titles": [item["title"] for item in cluster[:5] if item.get("title")],
            "matched_patterns": sorted({pattern for item in cluster for pattern in item.get("matched_patterns", [])})[:12],
        },
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
        clusters = cluster_findings(grouped[vuln_type], threshold)
        for cluster in clusters:
            status = "confirmed" if len(cluster) >= 2 else "candidate"
            if status == "candidate" and not include_candidates:
                continue
            rules.append(synthesize_rule(cluster, idx, status))
            idx += 1

    stats = {
        "raw_findings": len(raw_findings),
        "classified_findings": len(known),
        "unclassified_findings": len(unknown),
        "generated_rules": len(rules),
        "confirmed_rules": sum(1 for rule in rules if rule["status"] == "confirmed"),
        "candidate_rules": sum(1 for rule in rules if rule["status"] == "candidate"),
        "classification_by_type": dict(Counter(item["type"] for item in known)),
        "classification_by_swc": dict(Counter(item["swc_id"] for item in known)),
    }
    return {"rules": rules, "unknown": unknown, "stats": stats}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synthesize Solidity audit rules from raw findings.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to raw_findings.json")
    parser.add_argument("--output", default=DEFAULT_RULE_OUTPUT, help="Path to write security_rules.json")
    parser.add_argument("--unclassified-output", default=DEFAULT_UNCLASSIFIED_OUTPUT, help="Path to write unclassified findings")
    parser.add_argument("--stats-output", default=DEFAULT_STATS_OUTPUT, help="Path to write synthesis stats")
    parser.add_argument("--threshold", type=float, default=SIMILARITY_THRESHOLD, help="Similarity threshold for splitting clusters")
    parser.add_argument("--confirmed-only", action="store_true", help="Only output rules supported by 2+ findings")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    raw = load_raw(args.input)
    result = build_rules(raw_findings=raw, threshold=args.threshold, include_candidates=not args.confirmed_only)
    write_json(args.output, result["rules"])
    write_json(args.unclassified_output, result["unknown"])
    write_json(args.stats_output, result["stats"])
    print(
        "✅ Generated "
        f"{result['stats']['generated_rules']} rules "
        f"({result['stats']['confirmed_rules']} confirmed, "
        f"{result['stats']['candidate_rules']} candidate)"
    )
    print(f"🧾 Unclassified findings: {result['stats']['unclassified_findings']}")
    print(f"📄 Wrote: {args.output}, {args.unclassified_output}, {args.stats_output}")


if __name__ == "__main__":
    main()
