# Rulebook Index

This index summarises the contents of the rulebooks included in this repository.  Use it to orient yourself before diving into the JSON files.

## Files

| File name | Purpose |
|-----------|---------|
| **`security_rules.json`** | Primary rulebook containing reusable vulnerability rules.  Each rule has an ID, a title, an SWC identifier (where applicable), a severity level, a description, a detection pattern, an example, an exploit scenario, a recommended remediation, a test template and references. |
| **`unclassified_findings.json`** | Candidate rules generated from audit reports that do not map cleanly to existing categories.  Entries are marked with status (`candidate` or `needs_triage`) and include evidence such as finding count, sources and sample titles.  Use these when no rule from the primary rulebook applies. |

## Categories

The rulebook is organised conceptually by vulnerability category.  Below are the high‑level categories covered and their typical manifestations:

- **Access Control** – Missing, incorrect or weak authorisation checks allowing unauthorised callers to execute privileged functions or change critical state.
- **Reentrancy** – External calls before state updates leading to recursive entry into a function and unexpected state changes or fund drains.
- **Arithmetic & Precision** – Overflows, underflows, rounding errors, division before multiplication and incorrect share/asset conversions.
- **Oracle Manipulation** – Reliance on spot prices or manipulable oracles without bounds checks or TWAPs, enabling price attacks and insolvency.
- **Upgradeability & Delegatecall** – Storage collisions, uninitialised proxies, delegatecalls to user‑controlled addresses or missing access checks on upgrade functions.
- **Nonce & Sequence Logic** – Incorrect nonce or sequence number calculation due to premature loop termination, ignoring pending transactions or broken ordering logic.
- **Refund & Fee Logic** – Incorrect refund calculations, double refunds, missing fee validation or gas refund issues.
- **Loop & State Machine Bugs** – Unbounded loops, premature termination, off‑by‑one errors and state machine transitions that can be skipped or repeated.
- **Input Error Validation** – Lack of return value checks, missing `require` statements, failure to propagate errors from external calls or precompile interfaces.
- **Compatibility Gaps** – ERC20/ERC721 tokens with non‑standard behaviour (e.g. `bytes32` symbols), missing precompile support, breaking EVM semantics or Nibiru/Moon compatibility.
- **Oracle & Price Manipulation** – Use of stale or manipulated price feeds, missing sanity bounds or ignoring multi‑source aggregation.
- **Gas Griefing & DoS** – Attackers consuming excessive gas to prevent function completion, denial of service via expensive fallback code, or griefing via loop execution.

Each rule entry includes a `type` field indicating its category.  Use this index to quickly look up the meaning of that category.

## How to use

1. **Locate relevant rules** – When auditing a contract, identify which category or categories the function might touch.  For example, functions that transfer ether should be checked for `reentrancy` and `refund & fee logic` issues, while administrative functions relate to `access control` and `upgradeability`.
2. **Search `security_rules.json`** – Use the `detection_pattern` field or your own keywords to filter the rulebook for matching entries.  Each rule’s `id` can be referenced in your audit report.
3. **Consult `unclassified_findings.json`** – If you cannot find a matching rule, look up candidate entries by category or keyword.  These may represent new or edge‑case issues.  Include the candidate ID in your report and flag it for manual review.
4. **Iterate and refine** – When you encounter a novel vulnerability that recurs across projects, triage it (see `prompts/triage.md`) and, if warranted, add a new rule to `security_rules.json`.

For detailed usage instructions, see the top‑level `INSTRUCTIONS.md` file.