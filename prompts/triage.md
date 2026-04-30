# Triage Prompt

Use this prompt when triaging candidate entries in `unclassified_findings.json`.  The goal of triage is to decide whether a candidate finding can be generalised into a new security rule or if it requires manual review.

## Instructions

1. **Review the candidate entry**: read the title, description, detection pattern, exploit scenario, remediation and test template.  Examine the evidence including finding count, sources, sample titles and matched patterns.
2. **Summarise the vulnerability**: in your own words, describe the vulnerability or issue.  Identify whether it corresponds to a known SWC category (reentrancy, arithmetic, access control, oracle manipulation, etc.) or a new category.
3. **Generalise if possible**: if the finding describes a class of bugs that could appear in multiple projects, propose a new rule definition with fields:
   - **Title** – concise description of the vulnerability class.
   - **Type** – the category (e.g. `access_control`, `oracle_manipulation`, `nonce_logic`).
   - **SWC ID** – the closest SWC mapping or a new identifier if none exists.
   - **Severity** – critical, high, medium, low or informational.
   - **Description** – generalised description of the bug class.
   - **Detection pattern** – heuristics for identifying instances in code.
   - **Example code** – illustrative snippet.
   - **Exploit scenario** – steps a malicious user would take.
   - **Remediation** – high‑level guidance for developers.
   - **Test template** – a skeleton Foundry test.
4. **If not generalisable**: If the finding is too specific or requires deep manual validation, mark it as `manual_review` and explain why.  Suggest what additional analysis or human input is needed.
5. **Cite evidence**: Provide the source repository and issue URL.  Summarise any sample titles and matched patterns that support your classification.

## Example triage prompt to Kiro

```
You are triaging the following candidate finding from unclassified_findings.json:

  {
    "id": "U005",
    "title": "Premature loop termination in pending tx nonce could cause incorrect nonce values",
    ...
  }

Summarise the vulnerability and decide whether it can be generalised into a new rule.  If so, propose a rule.  Otherwise mark it for manual review.  Include the evidence.
```