# Using the Kiro Solidity Auditor Toolkit

This document explains how to use the artifacts in this repository (rulebooks, steering files and prompts) with Kiro, the AI‑powered audit assistant, and how to integrate them into your smart‑contract projects without polluting the codebase.

## 1 Generate and update the rulebooks

This repository includes two JSON files that form your audit knowledge base:

- **`security_rules.json`** – the curated rulebook of reusable vulnerabilities.
- **`unclassified_findings.json`** – candidate rules derived from real audit findings that may require triage.

If you wish to regenerate or extend these files, use the Python scripts in `project-ingestion/`:

1. **Install dependencies** (Python 3.8+, `requests`, `beautifulsoup4`):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install requests beautifulsoup4
   ```
2. **Set your GitHub token** (to avoid API rate limiting):
   ```bash
   export GITHUB_TOKEN=ghp_xxxxx
   ```
3. **Ingest raw findings** from Code4rena, Sherlock and other sources:
   ```bash
   python3 -m project.ingest
   # produces raw_findings.json
   ```
4. **Synthesise rules** from the raw findings:
   ```bash
   python3 -m project.scripts.synthesize_rules
   # writes security_rules.json and unclassified_findings.json
   ```
These steps are optional if you are satisfied with the existing rulebooks.

## 2 Place the rulebooks where Kiro can see them

Kiro can only read files that are present in the workspace you open.  There are two recommended ways to make the rulebooks available:

### Option A – Parent workspace (recommended)

Create a parent directory that contains both your Solidity project and the `ai_setup` directory.  For example:

```text
KIRO_WORKSPACE/
├── ai_setup/
│   ├── security_rules.json
│   ├── unclassified_findings.json
│   ├── RULEBOOK_INDEX.md
│   ├── .kiro/steering/solidity-auditor.md
│   └── prompts/
└── my-solidity-project/
    ├── src/
    ├── test/
    └── foundry.toml
```

Open `KIRO_WORKSPACE` in Kiro.  When prompting the model, specify that it should use the steering file and rulebooks from `ai_setup` while auditing the code in `my-solidity-project`.  This approach leaves your project untouched.

### Option B – Hidden audit folder inside your project

If you prefer to keep the rulebooks within the project repository, create a hidden folder such as `.kiro-auditor/` and copy the necessary files:

```bash
mkdir -p your-project/.kiro-auditor
cp ai_setup/security_rules.json your-project/.kiro-auditor/
cp ai_setup/unclassified_findings.json your-project/.kiro-auditor/
cp -r ai_setup/.kiro your-project/.kiro-auditor/
cp -r ai_setup/prompts your-project/.kiro-auditor/
cp ai_setup/RULEBOOK_INDEX.md your-project/.kiro-auditor/
```

Add `.kiro-auditor/` to your `.gitignore` so it doesn’t pollute your version control history.  When working in Kiro, open your project and instruct the model to use files inside `.kiro-auditor/`.

### Option C – Copy rulebooks into every repo (least preferred)

You can copy `security_rules.json`, `unclassified_findings.json`, `.kiro/steering/` and `prompts/` directly into the root of each repository you audit.  This works but makes it harder to keep rulebooks in sync.  Use a script (see below) to automate copying when necessary.

## 3 Install the Kiro steering and prompts

Ensure the following files and directories are available in the workspace for Kiro to read:

- **Steering file:** `.kiro/steering/solidity-auditor.md` – defines Kiro’s behaviour and audit mindset.
- **Prompts:** `prompts/auditor.md`, `prompts/triage.md`, `prompts/invariant.md` – template prompts for common tasks.
- **Rulebooks:** `security_rules.json` and `unclassified_findings.json` – the knowledge base.
- **Index:** `RULEBOOK_INDEX.md` – summary of categories.

You can generate or edit these files yourself; sample versions are included in this repository.  Kiro does not require any special installation to read them; it simply needs them to be present in the workspace.

## 4 Prompting Kiro

When using Kiro to audit a smart‑contract project:

1. **Load the steering file:** Provide the path to `.kiro/steering/solidity-auditor.md` and instruct Kiro to use it as mandatory context.
2. **Load the rulebooks:** In the same prompt, ask Kiro to read `security_rules.json` and `unclassified_findings.json` and to report how many rules and candidate rules it sees.  This confirms the files are loaded.
3. **Specify the task:** Use one of the prompts in `prompts/` (e.g. `auditor.md`) as a template.  Describe which contract or functions to audit and what details to include in the report.
4. **Review the output:** Ensure that Kiro references rule IDs or candidate IDs, assigns severities, explains exploit scenarios and suggests fixes and tests.  If the model fails to do so, remind it to consult the rulebooks.

Example prompt:

```
Use .kiro/steering/solidity-auditor.md, security_rules.json and unclassified_findings.json.  Confirm the rule count and candidate count.  Then audit the contract in src/Vault.sol, function by function.  Use prompts/auditor.md for the format.  For each issue include rule ID or candidate ID, severity, exploit scenario, broken invariant, impact, recommended fix and test suggestion.
```

## 5 Automating the copy (optional)

If you frequently need to copy the rulebooks into different projects, create a small shell script to do so.  Example:

```bash
#!/usr/bin/env bash
# install-kiro-auditor.sh
set -e
AI_SETUP_DIR="$HOME/your-central-ai-setup"
TARGET_DIR=$(pwd)

echo "Copying Kiro auditor files into $TARGET_DIR"
mkdir -p "$TARGET_DIR/.kiro-auditor"
cp "$AI_SETUP_DIR/security_rules.json" "$TARGET_DIR/.kiro-auditor/"
cp "$AI_SETUP_DIR/unclassified_findings.json" "$TARGET_DIR/.kiro-auditor/"
cp -R "$AI_SETUP_DIR/.kiro" "$TARGET_DIR/.kiro-auditor/"
cp -R "$AI_SETUP_DIR/prompts" "$TARGET_DIR/.kiro-auditor/"
cp "$AI_SETUP_DIR/RULEBOOK_INDEX.md" "$TARGET_DIR/.kiro-auditor/"
echo ".kiro-auditor/" >> "$TARGET_DIR/.gitignore" || true
echo "Done.  Remember to instruct Kiro to use the files in .kiro-auditor/."
```

Place this script somewhere in your `$PATH` and run it inside any project to install the auditor files.

## Summary

* **You do not need to embed the rulebooks into every code repository** – the preferred approach is to keep them in a central `ai_setup` folder or hidden audit folder and to load them in Kiro via the steering file.
* Use the **steering file** to define Kiro’s behaviour, the **prompts** to instruct tasks, and the **rulebooks** to provide vulnerability definitions.
* Generate the rulebooks using the provided Python scripts when you want to update them.

By following this workflow, you can reuse the same knowledge base across multiple audits, keep your repositories clean and ensure that Kiro performs consistent, structured security reviews.