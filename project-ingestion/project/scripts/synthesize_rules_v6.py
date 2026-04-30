#!/usr/bin/env python3
"""
Synthesize Solidity / EVM audit rules from raw_findings.json.

v6 behavior:
- Fetches full GitHub issue bodies from each finding reference when possible.
- Extracts a clean, finding-specific summary from GitHub issue sections.
- Uses that summary in rule descriptions instead of erasing the content.
- Keeps GitHub URLs only in `references`, not inside descriptions.
- Converts unclassified findings into full candidate rule objects.

Run:
  python3 -m project.scripts.synthesize_rules

Optional:
  export GITHUB_TOKEN=ghp_xxx
"""

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


Finding = Dict[str, Any]
Rule = Dict[str, Any]

DEFAULT_INPUT = "raw_findings.json"
DEFAULT_RULE_OUTPUT = "security_rules.json"
DEFAULT_UNCLASSIFIED_OUTPUT = "unclassified_findings.json"
DEFAULT_STATS_OUTPUT = "synthesis_stats.json"
SIMILARITY_THRESHOLD = 0.45

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_HEADERS = {"Accept": "application/vnd.github+json"}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"


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
}


TRIAGE_PATTERNS: Dict[str, Dict[str, Any]] = {
    "input_error_validation": {
        "swc_id": "SCSVS-INPUT-VALIDATION",
        "severity": "medium",
        "patterns": [
            r"\berror validation\b", r"\berror returned\b", r"\bdoesn't check\b",
            r"\bdoes not check\b", r"\bunchecked error\b", r"\bparseargs\b",
            r"\bparse\b", r"\bvalidation\b", r"\binvalid\b", r"\bargument\b",
            r"\binput\b",
        ],
        "title": "Missing Input or Error Validation",
        "description": "A function accepts parsed arguments, external return data, or intermediate results without validating errors or malformed inputs before continuing execution.",
        "detection_pattern": "Look for parser/helper functions returning `(value, error)` or equivalent status values where the caller uses the parsed value before checking whether parsing failed.",
        "example_code": "value, err := parseArgs(input)\n// BUG: value is used before checking err\nuse(value)\nif err != nil { return err }",
        "exploit_scenario": [
            "Attacker or failing integration provides malformed input.",
            "Parser returns an error or invalid parsed value.",
            "Caller ignores the error and continues execution.",
            "Incorrect state, incorrect response, or compatibility failure occurs."
        ],
        "remediation": "Check parser errors immediately, fail closed on invalid input, and add regression tests for malformed argument decoding.",
        "test_template": "func TestRejectsMalformedParsedArguments(t *testing.T) {\n    // pass malformed input\n    // assert function returns error before using parsed value\n}",
    },
    "compatibility_gap": {
        "swc_id": "SCSVS-COMPATIBILITY",
        "severity": "medium",
        "patterns": [
            r"\bcompatib", r"\berc20\b", r"\bsymbol\(\)", r"\bbytes32\b",
            r"\bstring\b", r"\bprecompile\b", r"\bevm\b", r"\bopcode\b",
            r"\brandao\b", r"\binterface\b", r"\bnon-standard\b",
            r"\breturn type\b", r"\bmetadata\b",
        ],
        "title": "Protocol Compatibility Gap",
        "description": "The system assumes a narrow interface, return type, EVM behavior, or metadata format and fails for valid but non-standard or expected compatibility cases.",
        "detection_pattern": "Look for hardcoded assumptions about ERC20 metadata, bytes/string return types, precompile behavior, EVM opcode support, chain compatibility, or unsupported edge cases.",
        "example_code": "string memory symbol = IERC20(token).symbol();\n// BUG: some widely used tokens return bytes32 instead of string.",
        "exploit_scenario": [
            "A valid integration uses a non-standard but common interface or EVM behavior.",
            "The system assumes only one return type or opcode behavior.",
            "The integration fails, returns incorrect data, or blocks a valid asset/user flow.",
            "Users or integrations experience denial of service or incorrect compatibility behavior."
        ],
        "remediation": "Support known compatibility variants, use defensive decoding, document unsupported cases, and add tests for non-standard tokens/precompiles/opcodes.",
        "test_template": "function testNonStandardCompatibilityCase() public {\n    // mock token/precompile/opcode behavior\n    // assert system handles it or fails safely with clear error\n}",
    },
    "nonce_or_sequence_logic": {
        "swc_id": "SCSVS-STATE-SEQUENCE",
        "severity": "medium",
        "patterns": [
            r"\bnonce\b", r"\bpending tx\b", r"\bpendingtx\b",
            r"\bpremature loop termination\b", r"\bincorrect nonce\b",
            r"\bsequence\b", r"\bordering\b", r"\bloop termination\b",
            r"\breturned to users\b",
        ],
        "title": "Incorrect Nonce, Sequence, or Pending State Calculation",
        "description": "A loop, state query, or pending-transaction calculation can terminate early or ignore valid entries, causing incorrect nonces, sequence numbers, or pending state to be returned.",
        "detection_pattern": "Look for loops over pending transactions/messages where `break`, `return`, filtering, or unsupported message types can skip later valid entries.",
        "example_code": "for _, tx := range pendingTxs {\n    for _, msg := range tx.GetMsgs() {\n        if !isSupported(msg) { break } // BUG: may skip later valid messages\n        nonce++\n    }\n}",
        "exploit_scenario": [
            "A user or attacker creates pending transactions with mixed message types.",
            "Nonce/sequence calculation terminates early or skips valid messages.",
            "RPC or protocol returns an incorrect nonce/sequence.",
            "Users submit invalid transactions, transactions fail, or ordering assumptions break."
        ],
        "remediation": "Continue scanning after unsupported messages when appropriate, avoid premature `break`, and test mixed pending transaction/message sequences.",
        "test_template": "func TestPendingNonceSkipsUnsupportedButCountsLaterValidTxs(t *testing.T) {\n    // build pending txs with unsupported msg followed by valid msg\n    // assert returned nonce includes valid later messages\n}",
    },
    "refund_or_fee_logic": {
        "swc_id": "SCSVS-ACCOUNTING",
        "severity": "medium",
        "patterns": [
            r"\brefund\b", r"\bfee\b", r"\bgas refund\b", r"\bmaxfee\b",
            r"\bmaxpriorityfee\b", r"\beffective gas\b", r"\bincorrectly calculated\b",
            r"\bdifferent formula\b", r"\bcharged\b", r"\boverpay\b",
        ],
        "title": "Incorrect Refund, Fee, or Gas Accounting",
        "description": "Refund, fee, or gas accounting uses an inconsistent formula or state source, causing incorrect balances, refunds, or EVM compatibility behavior.",
        "detection_pattern": "Look for refund/fee calculations duplicated across code paths, formulas that differ from the canonical execution result, or user-specified fee values applied incorrectly.",
        "example_code": "refund := gasLimit - gasUsedFromDifferentPath\n// BUG: refund should use execution result refund, not recomputed formula.",
        "exploit_scenario": [
            "A transaction executes through a path with refund or fee accounting.",
            "The system recomputes refund using a different formula or stale values.",
            "User or protocol balance is credited/debited incorrectly.",
            "EVM compatibility or accounting invariants break."
        ],
        "remediation": "Use a single canonical execution result for refunds/fees, remove duplicated formulas, and add tests comparing expected EVM behavior against implementation behavior.",
        "test_template": "func TestRefundUsesCanonicalExecutionResult(t *testing.T) {\n    // execute tx with refund case\n    // assert refunded amount equals ApplyEvmMsg/execution result\n}",
    },
    "loop_logic_bug": {
        "swc_id": "SCSVS-LOGIC",
        "severity": "medium",
        "patterns": [
            r"\bloop\b", r"\biteration\b", r"\bbreak\b", r"\bcontinue\b",
            r"\bpremature\b", r"\btermination\b", r"\bskip\b", r"\bskips\b",
        ],
        "title": "Incorrect Loop Control Flow",
        "description": "Loop control flow exits, skips, or short-circuits incorrectly, causing valid items to be ignored or invalid state to be returned.",
        "detection_pattern": "Look for `break`, `continue`, early `return`, or nested-loop logic where one invalid item can prevent later valid items from being processed.",
        "example_code": "for item in items {\n    if !valid(item) { break } // BUG: should often continue, not break\n    process(item)\n}",
        "exploit_scenario": [
            "An attacker or edge case places an invalid/unsupported item before valid items.",
            "Loop exits early instead of continuing.",
            "Later valid items are ignored.",
            "Returned state, accounting, or user-facing result is incorrect."
        ],
        "remediation": "Review loop termination semantics, replace `break` with `continue` where appropriate, and add tests with invalid items before valid items.",
        "test_template": "function testLoopDoesNotTerminateBeforeLaterValidItems() public {\n    // arrange invalid item before valid item\n    // assert valid later item is still processed\n}",
    },
    "generic_manual_triage": {
        "swc_id": "UNCLASSIFIED",
        "severity": "medium",
        "patterns": [],
        "title": "Unclassified Audit Finding Requiring Manual Rule Design",
        "description": "This finding could not be confidently mapped to an existing reusable vulnerability class. It should be manually triaged and converted into a new rule if it represents a repeated security pattern.",
        "detection_pattern": "Review the title, affected code, proof of concept, and impact. Identify the failed assumption, missing validation, broken invariant, incorrect state transition, compatibility gap, or accounting mismatch.",
        "example_code": "// Candidate-specific. Add minimal vulnerable pseudocode after manual triage.",
        "exploit_scenario": [
            "Read the referenced finding.",
            "Identify the failing actor, input, state transition, or integration edge case.",
            "Determine the violated assumption or invariant.",
            "Convert it into a typed reusable rule if it generalizes beyond this specific report."
        ],
        "remediation": "Manual triage required. Add validation, compatibility handling, invariant enforcement, state-machine checks, or accounting fixes based on the finding.",
        "test_template": "function testUnclassifiedCandidateRegression() public {\n    // Reproduce the referenced issue.\n    // Convert into a typed unit/invariant test after triage.\n}",
    },
}


def github_issue_api_url(reference: str) -> Optional[str]:
    if not reference:
        return None

    parsed = urlparse(reference)
    if parsed.netloc.lower() != "github.com":
        return None

    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) >= 4 and parts[2] == "issues":
        owner, repo, _, issue_number = parts[:4]
        return f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}"

    return None


def fetch_github_issue(reference: str) -> Optional[Dict[str, str]]:
    api_url = github_issue_api_url(reference)
    if not api_url:
        return None

    try:
        resp = requests.get(api_url, headers=GITHUB_HEADERS, timeout=20)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return {
            "title": data.get("title") or "",
            "body": data.get("body") or "",
            "html_url": data.get("html_url") or reference,
        }
    except Exception:
        return None


def clean_text(value: Optional[str]) -> str:
    if not value:
        return ""

    text = str(value)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"https?://\S+", "", text)
    text = re.sub(
        r"# Lines of code.*?(?=# Vulnerability details|## Finding description|## Proof of Concept|## Impact|$)",
        "",
        text,
        flags=re.I | re.S,
    )
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def extract_section(markdown: str, section_names: List[str]) -> str:
    if not markdown:
        return ""

    escaped = "|".join(re.escape(name) for name in section_names)
    pattern = rf"(?:^|\n)#+\s*(?:{escaped})\s*(.*?)(?=\n#+\s|\Z)"
    match = re.search(pattern, markdown, flags=re.I | re.S)
    if not match:
        return ""

    return clean_text(match.group(1))


def summarize_issue_body(title: str, body: str, max_chars: int = 900) -> str:
    title = clean_text(title)
    body = body or ""

    finding = extract_section(body, [
        "Finding description and impact",
        "Finding description",
        "Vulnerability details",
        "Impact",
    ])

    poc = extract_section(body, [
        "Proof of Concept",
        "Proof of concept",
        "PoC",
    ])

    recommendation = extract_section(body, [
        "Recommended Mitigation Steps",
        "Recommendation",
        "Mitigation",
    ])

    parts = []
    if finding:
        parts.append(f"Finding summary: {finding}")
    if poc:
        parts.append(f"Proof idea: {poc}")
    if recommendation:
        parts.append(f"Suggested mitigation from report: {recommendation}")

    if not parts:
        cleaned_body = clean_text(body)
        if cleaned_body:
            parts.append(f"Finding summary: {cleaned_body}")

    if not parts and title:
        parts.append(f"Finding summary: {title}")

    summary = " ".join(parts)
    summary = re.sub(r"\s+", " ", summary).strip()

    if len(summary) > max_chars:
        summary = summary[: max_chars - 3].rstrip() + "..."

    return summary


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


def classify_with_patterns(text: str, patterns: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    matches = []

    for item_type, meta in patterns.items():
        if item_type == "generic_manual_triage":
            continue

        score = 0
        matched_patterns = []
        for pattern in meta["patterns"]:
            if re.search(pattern, text, flags=re.I):
                score += 1
                matched_patterns.append(pattern)

        if score:
            matches.append({
                "type": item_type,
                "swc_id": meta["swc_id"],
                "score": score,
                "matched_patterns": matched_patterns,
            })

    if not matches:
        return {"type": "unknown", "swc_id": "UNCLASSIFIED", "score": 0, "matched_patterns": []}

    matches.sort(key=lambda item: item["score"], reverse=True)
    return matches[0]


def classify_known(text: str) -> Dict[str, Any]:
    return classify_with_patterns(text, VULN_PATTERNS)


def classify_triage(text: str) -> Dict[str, Any]:
    result = classify_with_patterns(text, TRIAGE_PATTERNS)
    if result["type"] == "unknown":
        return {
            "type": "generic_manual_triage",
            "swc_id": TRIAGE_PATTERNS["generic_manual_triage"]["swc_id"],
            "score": 0,
            "matched_patterns": [],
        }
    return result


def hydrate_finding(entry: Finding, fetch_issues: bool) -> Finding:
    reference = str(entry.get("reference") or "").strip()

    if fetch_issues and reference:
        issue = fetch_github_issue(reference)
        if issue:
            hydrated = dict(entry)
            hydrated["title"] = issue["title"] or entry.get("title", "")
            hydrated["description"] = issue["body"] or entry.get("description", "")
            hydrated["reference"] = issue["html_url"] or reference
            hydrated["_hydrated_from_github"] = True
            return hydrated

    hydrated = dict(entry)
    hydrated["_hydrated_from_github"] = False
    return hydrated


def normalize_finding(entry: Finding, fetch_issues: bool) -> Finding:
    hydrated = hydrate_finding(entry, fetch_issues)

    raw_title = hydrated.get("title")
    raw_description = hydrated.get("description")

    title = clean_text(raw_title)
    issue_summary = summarize_issue_body(title, raw_description)

    source = clean_text(hydrated.get("source")) or "unknown"
    reference = str(hydrated.get("reference") or "").strip()

    classification_text = f"{title} {issue_summary}"
    classification = classify_known(classification_text)

    return {
        "source": source,
        "title": title,
        "description": issue_summary,
        "text": classification_text.lower(),
        "type": classification["type"],
        "swc_id": classification["swc_id"],
        "classification_score": classification["score"],
        "matched_patterns": classification["matched_patterns"],
        "severity": normalize_severity(hydrated.get("severity")),
        "reference": reference,
        "hydrated_from_github": bool(hydrated.get("_hydrated_from_github")),
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


def summarize_sources(cluster: List[Finding]) -> Dict[str, int]:
    return dict(Counter(item.get("source", "unknown") for item in cluster))


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


def evidence_for(cluster: List[Finding]) -> Dict[str, Any]:
    return {
        "finding_count": len(cluster),
        "sources": summarize_sources(cluster),
        "sample_titles": [item["title"] for item in cluster[:5] if item.get("title")],
        "sample_summaries": [item["description"] for item in cluster[:3] if item.get("description")],
        "matched_patterns": sorted({
            pattern
            for item in cluster
            for pattern in item.get("matched_patterns", [])
        })[:12],
        "hydrated_from_github_count": sum(1 for item in cluster if item.get("hydrated_from_github")),
    }


def build_specific_description(meta: Dict[str, Any], cluster: List[Finding]) -> str:
    summaries = [item.get("description", "") for item in cluster if item.get("description")]
    if not summaries:
        return meta["description"]
    return f"{summaries[0]} Generalized rule: {meta['description']}"


def synthesize_rule_from_meta(
    cluster: List[Finding],
    idx: int,
    status: str,
    meta: Dict[str, Any],
    prefix: str,
    rule_type: str,
) -> Rule:
    severity = most_common([item["severity"] for item in cluster], meta["severity"])

    return {
        "id": f"{prefix}{idx:03}",
        "status": status,
        "title": meta["title"],
        "type": rule_type,
        "swc_id": meta["swc_id"],
        "severity": severity,
        "description": build_specific_description(meta, cluster),
        "detection_pattern": meta["detection_pattern"],
        "example_code": meta["example_code"],
        "exploit_scenario": meta["exploit_scenario"],
        "remediation": meta["remediation"],
        "test_template": meta["test_template"],
        "evidence": evidence_for(cluster),
        "references": compact_references(cluster),
    }


def synthesize_classified_rule(cluster: List[Finding], idx: int, status: str) -> Rule:
    rule_type = cluster[0]["type"]
    return synthesize_rule_from_meta(cluster, idx, status, VULN_PATTERNS[rule_type], "R", rule_type)


def build_rules(
    raw_findings: List[Finding],
    threshold: float,
    include_candidates: bool,
    fetch_issues: bool,
) -> Dict[str, Any]:
    normalized = [normalize_finding(item, fetch_issues=fetch_issues) for item in raw_findings]

    known = [item for item in normalized if item["type"] != "unknown"]
    unknown = [item for item in normalized if item["type"] == "unknown"]

    classified_groups: Dict[str, List[Finding]] = defaultdict(list)
    for item in known:
        classified_groups[item["type"]].append(item)

    rules: List[Rule] = []
    idx = 1

    for vuln_type in sorted(classified_groups.keys()):
        for cluster in cluster_findings(classified_groups[vuln_type], threshold):
            status = "confirmed" if len(cluster) >= 2 else "candidate"
            if status == "candidate" and not include_candidates:
                continue
            rules.append(synthesize_classified_rule(cluster, idx, status))
            idx += 1

    unclassified_rules: List[Rule] = []
    unclassified_groups: Dict[str, List[Finding]] = defaultdict(list)

    for item in unknown:
        triage = classify_triage(f"{item['title']} {item['description']}")
        item = dict(item)
        item["type"] = triage["type"]
        item["swc_id"] = triage["swc_id"]
        item["matched_patterns"] = triage["matched_patterns"]
        unclassified_groups[item["type"]].append(item)

    uidx = 1
    for triage_type in sorted(unclassified_groups.keys()):
        for cluster in cluster_findings(unclassified_groups[triage_type], threshold):
            meta = TRIAGE_PATTERNS[triage_type]
            unclassified_rules.append(
                synthesize_rule_from_meta(cluster, uidx, "candidate", meta, "U", triage_type)
            )
            uidx += 1

    stats = {
        "raw_findings": len(raw_findings),
        "classified_findings": len(known),
        "unclassified_findings": len(unknown),
        "classified_rules": len(rules),
        "unclassified_candidate_rules": len(unclassified_rules),
        "confirmed_rules": sum(1 for rule in rules if rule["status"] == "confirmed"),
        "candidate_rules": sum(1 for rule in rules if rule["status"] == "candidate"),
        "classification_by_type": dict(Counter(item["type"] for item in known)),
        "classification_by_swc": dict(Counter(item["swc_id"] for item in known)),
        "unclassified_candidate_by_type": dict(Counter(rule["type"] for rule in unclassified_rules)),
        "hydrated_from_github_count": sum(1 for item in normalized if item.get("hydrated_from_github")),
    }

    return {
        "rules": rules,
        "unclassified_rules": unclassified_rules,
        "stats": stats,
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synthesize Solidity/EVM audit rules from raw findings.")
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=DEFAULT_RULE_OUTPUT)
    parser.add_argument("--unclassified-output", default=DEFAULT_UNCLASSIFIED_OUTPUT)
    parser.add_argument("--stats-output", default=DEFAULT_STATS_OUTPUT)
    parser.add_argument("--threshold", type=float, default=SIMILARITY_THRESHOLD)
    parser.add_argument("--confirmed-only", action="store_true")
    parser.add_argument(
        "--no-fetch-github",
        action="store_true",
        help="Do not fetch full GitHub issue bodies. Use only raw_findings.json content.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    raw = load_raw(args.input)

    result = build_rules(
        raw_findings=raw,
        threshold=args.threshold,
        include_candidates=not args.confirmed_only,
        fetch_issues=not args.no_fetch_github,
    )

    write_json(args.output, result["rules"])
    write_json(args.unclassified_output, result["unclassified_rules"])
    write_json(args.stats_output, result["stats"])

    print(
        f"✅ Generated {result['stats']['classified_rules']} classified rules "
        f"({result['stats']['confirmed_rules']} confirmed, {result['stats']['candidate_rules']} candidate)"
    )
    print(f"🧾 Generated {result['stats']['unclassified_candidate_rules']} unclassified candidate rules")
    print(f"🌐 Hydrated from GitHub: {result['stats']['hydrated_from_github_count']}")
    print(f"📄 Wrote: {args.output}, {args.unclassified_output}, {args.stats_output}")


if __name__ == "__main__":
    main()
