# Auditor Prompt

Use this template to run a Solidity security audit with rulebook grounding.

## Required Setup

Read these first:

- `findings/security_rules.json`
- `findings/unclassified_findings.json`
- `.kiro/steering/solidity-auditor.md`

Before auditing, print:

1. exact rule count
2. exact candidate count
3. first 10 rule IDs
4. first 10 candidate IDs

## Audit Requirements

1. Analyze public/external functions one by one.
2. Match against `Rxxx` rules first; use `Uxxx` only when no `Rxxx` applies.
3. For every finding include:
   - severity
   - confidence (`confirmed` or `speculative`)
   - rule ID / candidate ID
   - exploit path
   - broken invariant
   - code location
   - concrete remediation
   - Foundry test suggestion
4. Do not report unsupported vulnerabilities.
5. Separate confirmed findings from speculative findings.

## Invocation Example

```text
Use prompts/auditor.md.
Read findings/security_rules.json and findings/unclassified_findings.json.
Run preflight counts and ID checks first.
Then audit src/Vault.sol function-by-function.
Return findings sorted by severity.
```
