# Invariant Prompt

Use this prompt when you want Kiro to generate or refine invariant tests for a Solidity system.  Invariant tests are property‑based tests that must hold true for all sequences of valid interactions with the contract.  They are useful for catching subtle state corruption or accounting errors.

## Instructions

1. **Identify the invariant**: Based on a security rule or candidate finding, specify what relationship must always be true.  For example:
   - `totalSupply == sum(userBalances)`
   - `collateral >= liabilities`
   - `contractBalance >= totalDeposits`
   - `only authorised roles can modify critical state`
   - `nonce must increase monotonically`
2. **Design the test**: Suggest how to implement the invariant using Foundry’s invariant testing framework.  This typically involves:
   - Creating a handler contract that calls various functions in random order.
   - Setting up a property function annotated with `@invariant` to assert the invariant.
   - Initialising the contract under test and seeding it with realistic state.
3. **Include fuzzing**: Consider using fuzz inputs for deposit amounts, addresses or other variables to explore edge cases.
4. **Link to the rule or finding**: Reference the rule ID or candidate ID that motivated the invariant.  Explain why the invariant is necessary.

## Example prompt to Kiro

```
Using prompts/invariant.md, generate an invariant test for rule R027 (Missing or Weak Access Control).  The invariant should assert that only the owner or authorised role can modify the contract’s admin configuration.  Provide the Foundry test code skeleton and explain how it enforces the property.
```