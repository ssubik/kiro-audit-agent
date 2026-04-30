# Auditor Prompt

Use this prompt when instructing Kiro to perform a smart‑contract security audit.

## Purpose

To audit a Solidity project, Kiro must read and utilise two primary knowledge sources:

* **`security_rules.json`** – the curated rulebook of known vulnerabilities.
* **`unclassified_findings.json`** – candidate rules derived from real audits that may not fit existing categories.

Always instruct Kiro to load these files before beginning the audit.  Ask it to report the number of rules and candidate entries to confirm they are loaded correctly.

## Instructions to Kiro

1. **Load the rulebooks**: read `security_rules.json` and `unclassified_findings.json`.  Confirm the total number of rules and candidate rules.
2. **Parse the code**: review each public or external function in the target contract one by one.
3. **Match rules**: for each function, search `security_rules.json` for entries whose `detection_pattern` matches the code or whose description is relevant.  When a match is found, include the rule ID and the following fields in your report:
   - Severity
   - Description
   - Exploit scenario
   - Remediation
   - Test template
4. **Use candidates**: if no rule matches, search `unclassified_findings.json` for similar patterns.  Include the candidate ID and evidence fields to indicate that the issue may require manual triage.
5. **Produce a structured report**: for each issue, follow the format defined in the steering file (`.kiro/steering/solidity‑auditor.md`).  Include the file, function, vulnerability description, exploit scenario, broken invariant, impact, recommended fix and Foundry test suggestion.
6. **Prioritise by severity**: order your findings from most to least severe (critical → high → medium → low → informational).

## Example prompt to Kiro

```
Use prompts/auditor.md to audit the following contract.  Load security_rules.json and unclassified_findings.json.  Tell me how many rules and candidate rules you see.  Then audit each function in the contract.  For every issue include:
  • rule ID (if matched) or candidate ID (if applicable)
  • severity
  • exploit scenario
  • vulnerable code location
  • recommended fix
  • Foundry test suggestion
Rank findings from most to least critical.
```