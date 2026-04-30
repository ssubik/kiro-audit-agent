#!/usr/bin/env python3
"""
Canonical synthesis entrypoint.

This module delegates to `synthesize_rules_v6.py`, which supports:
- classification into primary rules
- candidate rule generation for unclassified findings
- synthesis statistics output
- optional GitHub hydration for richer summaries

Recommended invocation (from `project-ingestion/`):

python3 -m project.scripts.synthesize_rules \
  --input ../findings/raw_findings.json \
  --output ../findings/security_rules.json \
  --unclassified-output ../findings/unclassified_findings.json \
  --stats-output ../findings/synthesis_stats.json
"""

from .synthesize_rules_v6 import main


if __name__ == "__main__":
    main()
