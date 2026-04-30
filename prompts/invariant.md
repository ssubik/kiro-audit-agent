# Invariant Prompt

Use this template to generate Foundry invariants tied to concrete findings.

## Requirements

1. Reference the triggering `Rxxx` or `Uxxx` ID.
2. Define the invariant in plain language and code-level state terms.
3. Provide a Foundry-oriented skeleton with:
   - setup/handler design
   - `invariant_*` function names
   - assertions tied to protocol accounting/authorization constraints
4. Include at least one adversarial sequence that should fail if bug exists.
5. Explain expected pass/fail behavior.

## Example Invocation

```text
Using prompts/invariant.md, build an invariant test for R001 (access control)
showing that unauthorized callers cannot mutate admin configuration.
```
