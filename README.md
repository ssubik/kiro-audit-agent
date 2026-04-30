![Kiro Solidity Auditor Banner](assets/kiro-banner.png)

<h1 align="center">Kiro Solidity Auditor Agent</h1>

<p align="center"><em>AI‑assisted smart contract security auditing framework</em></p>

<p align="center">
  <a href="https://img.shields.io/badge/license-MIT-blue.svg">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License" />
  </a>
  <a href="https://img.shields.io/badge/Solidity-0.8.x-green.svg">
    <img src="https://img.shields.io/badge/Solidity-0.8.x-green.svg" alt="Solidity 0.8.x" />
  </a>
  <a href="https://img.shields.io/badge/rules-200%2B-orange.svg">
    <img src="https://img.shields.io/badge/rules-200%2B-orange.svg" alt="200+ Rules" />
  </a>
  <a href="https://img.shields.io/badge/CI-Enabled-green.svg">
    <img src="https://img.shields.io/badge/CI-Enabled-green.svg" alt="CI Enabled" />
  </a>
</p>

## Overview

**Kiro Solidity Auditor Agent** is a production‑ready toolkit for AI‑assisted security reviews of Ethereum smart contracts.  
It combines a comprehensive rulebook of more than **200** vulnerability patterns with structured steering instructions, 
prompt templates, invariant test examples and CI integration to produce thorough audits.  
Rather than focusing solely on style, it emphasises an **adversarial**, **invariant‑driven** mindset to catch issues like 
reentrancy, access‑control failures, accounting mistakes, oracle manipulation and more.  The rules draw from the 
Smart Contract Weakness Classification registry and best practice

## 📦 What's inside

```
.
├── AGENTS.md                         # Optional cross‑agent instruction file
├── security_rules.json               # 200+ Solidity audit rules
├── .kiro/
│   └── steering/
│       └── solidity‑audit.md         # Main Kiro steering file
├── prompts/
│   └── auditor.txt                   # Reusable audit prompt
├── scripts/
│   ├── generate_rules.py             # Generates the 200+ rulebook
│   └── ingestion_pipeline.py         # Template for Code4rena/Sherlock ingestion
├── test/
│   └── InvariantExample.t.sol        # Foundry invariant example
└── .github/
    └── workflows/
        └── audit.yml                 # CI for linting + tests
```

### Key features

* **200+ security rules** – a JSON rulebook built from official SWC categories, best‑practice guides and real contest findings【76496444074783†L81-L94】.
* **Kiro steering** – instructs the AI to audit every public/external function, classify issues by severity, suggest fixes and invariants.
* **Prompt templates** – reusable prompts for quick audits and deep adversarial reviews.
* **Invariant test examples** – Foundry templates for writing property‑based tests to enforce invariants like `totalSupply == sum(balances)`.
* **CI integration** – GitHub Actions workflow running `solhint`, `prettier` and Foundry tests on every push.
* **Extensible scripts** – Python scripts to generate the rulebook and ingest new vulnerabilities from Code4rena/Sherlock reports.

## 🚀 Quick start

1. **Install dependencies** (if not already):

   ```bash
   npm install --save-dev solhint prettier prettier-plugin-solidity
   ```

2. **Copy the framework** into the root of your Solidity/Foundry/Hardhat project:

   ```bash
   cp security_rules.json your-project/
   cp -r .kiro your-project/
   cp -r prompts your-project/
   cp -r scripts your-project/
   cp -r test your-project/
   cp -r .github your-project/
   ```

3. **Teach Kiro the rules** – load `.kiro/steering/solidity‑audit.md` and `security_rules.json` in your Kiro session.  
   Use `prompts/auditor.txt` when prompting the model to audit a contract.  
   Specify that it should reference rule IDs, severity, exploit scenarios and remediation when generating its report.

4. **Run invariants** – write additional invariant tests using `test/InvariantExample.t.sol` as a starting point, and run them with Foundry:

   ```bash
   forge test
   ```

5. **Enable CI** – the provided workflow `.github/workflows/audit.yml` runs linters and tests on every pull request.

## 🔍 Using with Kiro

Kiro can act as an autonomous audit agent.  When reviewing code, ask it to:

* **Audit function by function** – for each public/external function, identify potential risks.
* **Retrieve rules** – search `security_rules.json` for patterns matching the function’s behaviour.
* **Classify issues** – assign `critical`, `high`, `medium` or `low` severity based on impact.
* **Explain the exploit** – describe a plausible attack scenario and why the rule applies.
* **Recommend fixes** – provide code changes and point to relevant references.
* **Suggest tests** – output a template for a Foundry invariant or fuzz test enforcing the fix.

To trigger a deep audit, you might use a prompt like:

```text
Use prompts/auditor.txt and security_rules.json.
Audit this Solidity contract function‑by‑function.
For each issue include:
  • rule ID
  • severity
  • exploit scenario
  • vulnerable code
  • recommended fix
  • Foundry test suggestion
Rank findings from most to least critical.
```

## 🧪 Rulebook overview

`security_rules.json` contains entries like this:

```json
{
  "id": "R001",
  "title": "Reentrancy Variation 1",
  "swc_id": "SWC-107",
  "severity": "critical",
  "description": "External call before state update allowing reentrancy",
  "detection_pattern": "external call before state update",
  "exploit_scenario": "Attacker reenters withdraw() to drain funds",
  "remediation": "Use checks-effects-interactions or a reentrancy guard",
  "test_template": "assert no state change after external call",
  "references": [
    "https://swcregistry.io/docs/SWC-107"
  ]
}
```

The rules cover reentrancy, access control, accounting correctness, oracle manipulation, gas griefing, time dependency, random number misuse and more.
Each entry includes a detection pattern so Kiro can match against ASTs or textual code, a severity rating, and references to external resources.

## 🧰 Invariant testing

Foundry invariants are powerful for catching issues that static analysis might miss.  The example in `test/InvariantExample.t.sol` shows how to ensure that `totalSupply` equals the sum of all account balances—this is a basic accounting invariant.  For each critical rule you should derive an invariant:  
* Collateral ≥ liabilities  
* No free minting or burning  
* Role assignments remain unchanged after upgrades  
* Protocol reserves cannot go negative  
* Price oracles cannot be manipulated by a single transaction  

Run your invariants regularly to detect regressions as you modify the contract.