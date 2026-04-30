# Triage Prompt

Use this template to triage entries in `findings/unclassified_findings.json`.

## Goal

Decide whether a candidate should be:

- `promote_to_primary_rule`
- `keep_as_candidate`
- `manual_review`

## Decision Criteria

- Cross-project generality (not one-off project behavior)
- Clear exploitability or security impact
- Reproducible detection pattern
- Useful remediation and testability

## Output Requirements

For each triaged candidate include:

- candidate ID
- decision
- rationale
- proposed normalized rule fields (if promoting):
  - id (placeholder)
  - title
  - type
  - swc_id
  - severity
  - description
  - detection_pattern
  - example_code
  - exploit_scenario
  - remediation
  - test_template

Always cite evidence and references from the candidate object.
