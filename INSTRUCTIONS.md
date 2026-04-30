# Using the Kiro Solidity Auditor Toolkit

## 1) What Kiro Must See

Kiro should be able to read these files in the same workspace:

- `findings/security_rules.json`
- `findings/unclassified_findings.json`
- `.kiro/steering/solidity-auditor.md`
- `prompts/auditor.md`, `prompts/triage.md`, `prompts/invariant.md`

## 2) Workspace Strategies

### Option A: Parent Workspace (recommended)

Place both `ai_setup/` and the target Solidity repo under one parent folder and open the parent in Kiro.

### Option B: Hidden folder inside target repo

Copy auditor artifacts into `.kiro-auditor/` inside target repo, and add `.kiro-auditor/` to `.gitignore`.

## 3) Rulebook Visibility Check (mandatory)

Before auditing contracts, run a visibility prompt in Kiro:

```text
Use .kiro/steering/solidity-auditor.md as mandatory context.
Read findings/security_rules.json and findings/unclassified_findings.json.
Return:
1) exact rule count
2) exact candidate count
3) first 10 rule IDs
4) first 10 candidate IDs
Do not audit code yet.
```

If counts/IDs are missing, stop and fix workspace paths first.

## 4) Canonical Ingestion + Synthesis

Run from `project-ingestion/`.

1. Install deps:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests beautifulsoup4
```

2. Set GitHub token (recommended):
```bash
export GITHUB_TOKEN=ghp_xxxxx
```

3. Ingest raw findings:
```bash
python3 -m project.ingest --output ../findings/raw_findings.json
```

4. Synthesize rules and candidates:
```bash
python3 -m project.scripts.synthesize_rules \
  --input ../findings/raw_findings.json \
  --output ../findings/security_rules.json \
  --unclassified-output ../findings/unclassified_findings.json \
  --stats-output ../findings/synthesis_stats.json
```

Expected outputs:

- `findings/raw_findings.json`
- `findings/security_rules.json`
- `findings/unclassified_findings.json`
- `findings/synthesis_stats.json`

## 5) Audit Prompting Rules

- Always require rule/candidate IDs in findings.
- Always require exploit path and broken invariant.
- Always label findings as `confirmed` or `speculative`.
- Do not report unsupported/hallucinated vulnerabilities.

Use `prompts/auditor.md` as the default audit template.
