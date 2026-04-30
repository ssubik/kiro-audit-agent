# Rulebook Index

## Rulebook Files

| File | Purpose |
|---|---|
| `findings/security_rules.json` | Primary reusable rules used during auditing. |
| `findings/unclassified_findings.json` | Candidate rules requiring triage or promotion. |
| `findings/synthesis_stats.json` | Snapshot of synthesis coverage and counts. |

## Current Snapshot

- `security_rules.json`: synthesized primary rules
- `unclassified_findings.json`: candidate entries from ingestion
- Use candidates only when no primary rule fits; label such findings as lower confidence.

## How To Use During Audit

1. Load steering: `.kiro/steering/solidity-auditor.md`.
2. Confirm Kiro can read both rulebooks and report counts.
3. Match primary rules first (`Rxxx` IDs).
4. Use candidate rules (`Uxxx`) only when no primary match exists.
5. Mark each finding `confirmed` or `speculative`.

See [INSTRUCTIONS.md](/home/ssubik/Documents/KIRO/ai_setup_final/ai_setup/INSTRUCTIONS.md) for full workflow.
