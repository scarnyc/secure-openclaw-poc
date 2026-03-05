---
name: security-audit
description: Validate all 6 Sentinel security invariants by running targeted tests and scanning code
---

# Security Audit

Run this skill before every commit and PR to verify Sentinel's 6 security invariants.

## Workflow

### Step 1: Run Security Tests

```bash
npm run test -- --grep "invariant|security" --reporter verbose
```

If tests don't exist yet, skip to Step 2 and note which invariants lack test coverage.

### Step 2: Static Scan for Each Invariant

Check each invariant against the current codebase:

| # | Invariant | What to Scan |
|---|-----------|-------------|
| 1 | No credentials in tool responses | Grep `sentinel/hooks/credential-filter.ts` for regex coverage; grep test files for credential pattern assertions |
| 2 | All tool calls audited | Verify every `onBeforeToolCall` path writes to D1 audit log before `next()` |
| 3 | Blocked tool categories enforced | Check `policy-engine.ts` denylist covers filesystem write, network egress, code execution |
| 4 | Memory size caps enforced | Verify `mem-hardening/` checks entry size < 10KB and total DB < 100MB |
| 5 | No credential storage in memory | Verify pre-write scan in `mem-hardening/` rejects API key / token / password patterns |
| 6 | Policy changes require restart | Verify KV policy is read once at startup with no hot-reload path |

### Step 3: Report

Output a table:

```
| # | Invariant | Status | Notes |
|---|-----------|--------|-------|
| 1 | No credentials in responses | PASS/FAIL/NO TEST | ... |
| 2 | All tool calls audited       | PASS/FAIL/NO TEST | ... |
| 3 | Blocked categories enforced  | PASS/FAIL/NO TEST | ... |
| 4 | Memory size caps enforced    | PASS/FAIL/NO TEST | ... |
| 5 | No credential storage        | PASS/FAIL/NO TEST | ... |
| 6 | Policy requires restart      | PASS/FAIL/NO TEST | ... |
```

Flag any FAIL or NO TEST as blocking for commit.
