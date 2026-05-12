# KIRO Smart Contract Audit Setup

450 vulnerability rules (2 confirmed, 448 candidate) across 10 vulnerability types.

---

## Section 1: Quick Start (Workspace File Method) — 5 minutes

### 1.1 Place the rules file

Copy `consolidated-findings.json` into your Kiro project's rules directory:

```
your-project/
└── .kiro/
    └── rules/
        └── consolidated-findings.json
```

```bash
mkdir -p .kiro/rules
cp /path/to/consolidated-findings.json .kiro/rules/
```

Kiro automatically loads all files under `.kiro/rules/` as workspace context for every chat session.

---

### 1.2 Run a full audit against a contract

Paste this prompt into Kiro chat (replace `src/MyContract.sol` with your target):

```
Using the vulnerability rules in .kiro/rules/consolidated-findings.json, audit the
contract at src/MyContract.sol.

For each rule, check whether the contract exhibits the detection_pattern.
Report findings in this format:

RULE ID | SEVERITY | TITLE | FINDING
--------|----------|-------|--------
R007    | medium   | ...   | Line 42: setOwner() has no access check. ...

Only report rules where you found a real match. Skip rules with no match.
At the end, list any confirmed-status rules (status=="confirmed") that were checked,
whether matched or not.
```

---

### 1.3 Generate a tasks.md from findings

After the audit output is in your chat, paste:

```
From the audit findings above, generate a tasks.md file.

Each task should have:
- [ ] task title (RULE_ID | SEVERITY)
- One-line description of the fix needed
- The remediation field from the matching rule as a code comment

Sort tasks: high severity first, then medium, then low.
Write the file to tasks.md.
```

---

### 1.4 Confirmed vs candidate rules

- `"status": "confirmed"` — backed by multiple real findings; treat matches as definite bugs.
  There are **2 confirmed rules**: `R007` (access control, SWC-105) and `R036` (arithmetic precision, SWC-101).
- `"status": "candidate"` — pattern is plausible but may need manual triage; treat matches as leads to verify.

When time is short, filter your audit prompt to confirmed rules only:

```
Only check rules where status == "confirmed".
```

---

## Section 2: Kiro Steering File (Optional) — 3 minutes

### When to use a steering file

Use a steering file when you want Kiro to apply a small set of short rules **automatically on every file open**, without any manual prompt. Steering files are plain Markdown loaded at startup.

**Limitation:** Kiro truncates steering content at ~2 KB. The full JSON rules file is 810 KB — it cannot fit in a steering file. Use steering only for a 2–3 rule cheat-sheet; use Section 1 for the full ruleset.

### Minimal steering file example

Create `.kiro/steering/audit-reminders.md`:

```markdown
## Smart Contract Audit Reminders

When reviewing Solidity, always check these patterns:

### R007 — Access Control (SWC-105, confirmed)
Look for external/public functions that modify owner, admin, roles, or protocol config
without onlyOwner / AccessControl guards.
Remediation: Add explicit role checks; emit events for all privileged changes.

### R036 — Arithmetic Precision (SWC-101, confirmed)
Look for division before multiplication, unchecked arithmetic on balances/shares,
and fixed-point truncation in fee/reward calculations.
Remediation: Multiply before dividing; use SafeMath or Solidity 0.8+; add invariant tests.

### R001 — Reentrancy (SWC-107)
Look for ETH/token transfers or external calls that happen before state updates.
Remediation: Checks-effects-interactions; ReentrancyGuard on cross-function paths.
```

**Warning:** This steering file gives Kiro a 3-rule summary. For all 450 rules with full
`detection_pattern`, `exploit_scenario`, `test_template`, and `remediation` fields, use
the workspace file method in Section 1 instead.

---

## Section 3: Local MCP Server (Optional) — 10 minutes

### What MCP adds

The workspace file approach loads all 450 rules into every prompt. An MCP server lets
Kiro **query rules dynamically** — fetch only high-severity rules, filter by type, or
look up a specific rule by ID. This keeps prompts focused and reduces noise.

---

### 3.1 MCP server script

Create `mcp/vuln-server.js`:

```js
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FINDINGS_PATH = join(__dirname, "../.kiro/rules/consolidated-findings.json");

let findings = [];
try {
  findings = JSON.parse(readFileSync(FINDINGS_PATH, "utf8"));
} catch (e) {
  console.error("Failed to load findings:", e.message);
}

const server = new Server(
  { name: "vuln-rules", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_rules",
      description: "Query vulnerability rules by severity, type, status, or id",
      inputSchema: {
        type: "object",
        properties: {
          severity: {
            type: "string",
            enum: ["high", "medium", "low"],
            description: "Filter by severity",
          },
          type: {
            type: "string",
            description:
              "Filter by vulnerability type (e.g. access_control, reentrancy, arithmetic_precision)",
          },
          status: {
            type: "string",
            enum: ["confirmed", "candidate", "needs_triage"],
            description: "Filter by status",
          },
          id: {
            type: "string",
            description: "Fetch a single rule by exact ID (e.g. R007)",
          },
          limit: {
            type: "number",
            description: "Max rules to return (default 20)",
          },
        },
      },
    },
    {
      name: "list_types",
      description: "List all available vulnerability types and their counts",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "get_confirmed_rules",
      description: "Return only confirmed-status rules (highest confidence)",
      inputSchema: { type: "object", properties: {} },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "get_rules") {
    let results = findings;
    if (args.id) {
      results = results.filter((r) => r.id === args.id);
    } else {
      if (args.severity) results = results.filter((r) => r.severity === args.severity);
      if (args.type) results = results.filter((r) => r.type === args.type);
      if (args.status) results = results.filter((r) => r.status === args.status);
    }
    const limit = args.limit ?? 20;
    results = results.slice(0, limit);
    return {
      content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
    };
  }

  if (name === "list_types") {
    const counts = {};
    for (const r of findings) {
      counts[r.type] = (counts[r.type] ?? 0) + 1;
    }
    return {
      content: [{ type: "text", text: JSON.stringify(counts, null, 2) }],
    };
  }

  if (name === "get_confirmed_rules") {
    const confirmed = findings.filter((r) => r.status === "confirmed");
    return {
      content: [{ type: "text", text: JSON.stringify(confirmed, null, 2) }],
    };
  }

  throw new Error(`Unknown tool: ${name}`);
});

const transport = new StdioServerTransport();
await server.connect(transport);
```

Install the SDK:

```bash
mkdir -p mcp
cd mcp
npm init -y
npm install @modelcontextprotocol/sdk
cd ..
```

---

### 3.2 Register the MCP server in Kiro

Create `.kiro/mcp.json`:

```json
{
  "mcpServers": {
    "vuln-rules": {
      "command": "node",
      "args": ["mcp/vuln-server.js"],
      "env": {}
    }
  }
}
```

Restart Kiro. The `vuln-rules` MCP server will appear in the tools panel.

---

### 3.3 Example Kiro chat queries using the MCP tool

```
Use the vuln-rules MCP tool to fetch all high-severity rules, then check each
detection_pattern against src/Vault.sol. Report any matches.
```

```
Call get_confirmed_rules from vuln-rules, then audit src/Token.sol against
each confirmed rule. Show rule ID, matched line, and the remediation step.
```

```
Call list_types from vuln-rules to see all vulnerability categories.
Then call get_rules with type="reentrancy" and audit src/Pool.sol.
```

```
Use vuln-rules get_rules with id="R007" to fetch the access control rule,
then check every public/external function in src/Governance.sol against it.
```

---

## Section 4: Recommended Workflow

### Day-to-day audit flow

```
1. NEW CONTRACT
   └─ Quick scan → paste Section 1.2 prompt into Kiro
                   uses .kiro/rules/consolidated-findings.json

2. TRIAGE RESULTS
   └─ Review matched rules
   └─ Confirmed rules (R007, R036) → treat as definite bugs
   └─ Candidate rules → manually verify before reporting

3. GENERATE TASKS
   └─ Paste Section 1.3 prompt → get tasks.md with prioritised fixes

4. DEEP DIVE (specific category)
   └─ Use MCP: get_rules with type="access_control" + severity="high"
   └─ Feed only those rules into a focused audit prompt

5. ITERATE
   └─ After fixing, re-run the audit against the patched file
   └─ Promote candidate rules to confirmed if they match repeatedly
```

---

### Which method to use when

| Situation | Method |
|---|---|
| First pass on a new contract | **Workspace file** (Section 1) |
| You want audit reminders without prompting | **Steering file** (Section 2, 2–3 rules only) |
| Targeted query: "all high-severity reentrancy rules" | **MCP server** (Section 3) |
| CI pipeline audit script | **MCP server** (Section 3) |
| Exploring rule coverage by type | **MCP** `list_types` tool |
| Confirming a specific rule (e.g. R036) | **MCP** `get_rules` with `id` |

**Rule of thumb:** Use the workspace file for speed on any audit. Add the MCP server
when you want to query rules programmatically or keep prompts focused.

---

## Appendix: Consolidated Findings Summary

| Metric | Count |
|---|---|
| Total rules | 450 |
| Confirmed | 2 (R007, R036) |
| Candidate | 448 |
| High severity | 92 |
| Medium severity | 339 |
| Unknown severity (raw findings) | 19 |

**Vulnerability types:**

| Type | Count |
|---|---|
| unclassified | 242 |
| arithmetic_precision | 36 |
| compatibility_gap | 36 |
| generic_manual_triage | 83 |
| access_control | 13 |
| input_error_validation | 23 |
| loop_logic_bug | 9 |
| nonce_or_sequence_logic | 5 |
| oracle_manipulation | 2 |
| reentrancy | 1 |
