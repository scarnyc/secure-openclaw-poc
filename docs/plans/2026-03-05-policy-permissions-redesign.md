# Policy & Permissions Redesign — Phase 1.5

**Date:** 2026-03-05
**Status:** Approved
**Approach:** B — Separate Policy Document (`config/policy.json`)

## Problem

Sentinel's Phase 1 MVP has a single global `SentinelConfig` with flat tool classifications. It lacks per-agent scoping, tool groups, workspace containment, and approval allowlists. OpenClaw supports multi-agent configurations with per-agent security policies that Sentinel needs to enforce as the sole trust boundary.

## Decision

Sentinel absorbs OpenClaw's security concepts into its own policy engine. OpenClaw runs fully permissive (all security disabled); Sentinel is the sole gatekeeper. Policy documents live on the host filesystem, outside Docker, inaccessible to the agent process.

### Why Not Alternatives

- **Approach A (extend SentinelConfig inline):** Mixes infrastructure config with security policy. Config grows unwieldy, hard to version/share policies independently.
- **Approach C (TypeScript DSL):** Not declarative — harder to inspect/audit without running code. Overkill for config that rarely changes at runtime.
- **Sentinel as OpenClaw's approval backend (option 3):** Dual security layers create trust boundary confusion — exactly the kind of ambiguity that leads to bypass CVEs.
- **Defense-in-depth layering (option 2):** Two gates make it hard to reason about which layer blocked what. Simpler to have one well-designed gatekeeper.

## MVP Scope (Protect Local Mac Mini)

1. **Workspace scoping** — per-agent filesystem containment (allow-list model replaces deny-list)
2. **Per-agent tool policies** — allow/deny lists keyed by agent ID
3. **Tool groups** — ergonomic grouping (`group:fs`, `group:runtime`, etc.)
4. **Exec approval allowlists** — pattern-based auto-approve to prevent confirmation fatigue

## Deferred to CF Deployment

- Sandbox mode enforcement (schema defined now, enforcement requires Linux)
- Elevated gating (needs real sandbox to escape from)
- Resume tokens (async approval flows for distributed environments)
- JWT authentication (local MVP uses localhost trust)
- OWASP Top 10 / ASVS L2 audit
- NIST AI RMF alignment
- CWE-77/78 hardening
- CF Workers security checklist (W1-W7)
- Replit-style SAST integration (Semgrep)

## Policy Document Schema

### File Structure

```
config/
├── sentinel.json       # Infrastructure (port, paths, LLM)
└── policy.json         # Security policy (agents, groups, workspaces, allowlists)
```

### PolicyDocument Schema

```typescript
PolicyDocumentSchema = z.object({
  version: z.literal(1),
  toolGroups: z.record(z.array(z.string())),
  defaults: DefaultPolicySchema,
  agents: z.record(AgentPolicySchema),
});

DefaultPolicySchema = z.object({
  tools: z.object({
    allow: z.array(z.string()),
    deny: z.array(z.string()),
  }),
  workspace: WorkspaceScopeSchema,
  approval: ApprovalConfigSchema,
});

AgentPolicySchema = z.object({
  tools: z.object({
    allow: z.array(z.string()).optional(),
    deny: z.array(z.string()).optional(),
  }),
  workspace: WorkspaceScopeSchema,
  approval: ApprovalConfigSchema.optional(),
});

WorkspaceScopeSchema = z.object({
  root: z.string().min(1),
  access: z.enum(["ro", "rw"]),
});

ApprovalConfigSchema = z.object({
  ask: z.enum(["always", "on-miss", "never"]),
  allowlist: z.array(z.object({
    pattern: z.string().min(1),
  })).optional(),
});
```

### Default Tool Groups

```json
{
  "toolGroups": {
    "fs":        ["read", "write", "edit", "apply_patch"],
    "runtime":   ["exec", "process"],
    "network":   ["browser", "fetch", "curl"],
    "messaging": ["slack", "discord", "telegram", "whatsapp"],
    "automation": ["sessions_spawn", "sessions_send", "gateway"]
  }
}
```

### Example Policy (Mac Mini)

```json
{
  "version": 1,
  "toolGroups": {
    "fs": ["read", "write", "edit", "apply_patch"],
    "runtime": ["exec", "process"],
    "network": ["browser", "fetch"],
    "messaging": ["slack", "discord", "telegram", "whatsapp"]
  },
  "defaults": {
    "tools": { "allow": ["*"], "deny": ["group:network"] },
    "workspace": { "root": "~/.openclaw/workspace", "access": "rw" },
    "approval": { "ask": "on-miss" }
  },
  "agents": {
    "main": {
      "tools": {
        "allow": ["group:fs", "group:runtime"],
        "deny": ["group:messaging"]
      },
      "workspace": { "root": "~/Code", "access": "rw" },
      "approval": {
        "ask": "on-miss",
        "allowlist": [
          { "pattern": "/opt/homebrew/bin/rg" },
          { "pattern": "/opt/homebrew/bin/fd" },
          { "pattern": "/usr/bin/git *" },
          { "pattern": "/opt/homebrew/bin/node *" }
        ]
      }
    },
    "family": {
      "tools": {
        "allow": ["read", "group:messaging"],
        "deny": ["group:runtime", "write", "edit"]
      },
      "workspace": { "root": "~/.openclaw/workspace-family", "access": "ro" },
      "approval": { "ask": "always" }
    }
  }
}
```

## Classification Flow

```
classify(manifest, policy, config)
│
├─ 1. Resolve agent policy
│     agent = policy.agents[manifest.agentId] ?? BLOCK (unknown agent)
│     Merge: agent inherits missing fields from defaults
│
├─ 2. Expand groups
│     "group:fs" → ["read", "write", "edit", "apply_patch"]
│
├─ 3. Tool gate (deny-wins)
│     if tool in agent.deny → BLOCK
│     if agent.allow != ["*"] && tool not in agent.allow → BLOCK
│
├─ 4. Workspace gate (fs/exec tools only)
│     Extract target path from manifest.parameters
│     Resolve against agent.workspace.root
│     if path escapes workspace root → BLOCK
│     if operation is write && workspace.access == "ro" → BLOCK
│
├─ 5. Existing classification (unchanged)
│     Bash parser (read/write/dangerous)
│     Tool category lookup
│     Dangerous signal detection
│
├─ 6. Approval resolution
│     if tool/command matches allowlist pattern → AUTO_APPROVE
│     else apply ask mode (always/on-miss/never)
│
└─ Return PolicyDecision { action, category, reason }
```

### Workspace Enforcement

- **Path parameter map:** `read→path`, `write→path`, `edit→path`, `exec→cwd`
- **Relative paths** resolve against workspace root
- **`~`** expands to agent's workspace root, not real `$HOME`
- **`..` traversal** that escapes workspace → blocked
- **Symlinks** resolved to real path before boundary check
- **Bash argument scanning** checks file paths in command strings against workspace

### Deny-Wins Rule

If a tool appears in both allow and deny lists (directly or via group expansion), it is denied. This is the safe default.

### Unknown Agent Handling

If `manifest.agentId` is not in `policy.agents`, the request is **blocked**. No implicit fallback to defaults for unrecognized agents.

## Policy Lifecycle

- **Startup:** Load `config/policy.json`, validate with Zod, freeze with `Object.freeze()`. Crash if missing or invalid (no fallback = fail-closed).
- **Runtime:** Immutable. Policy changes require executor restart (Invariant #6).
- **Audit:** Every entry includes `agentId` and `policyVersion` for traceability.

## OpenClaw Integration

OpenClaw runs with all security disabled:

```json
{
  "tools": { "exec": { "security": "full" }, "elevated": { "enabled": true }, "deny": [] },
  "sandbox": { "mode": "off" }
}
```

Agent IDs from OpenClaw's `agents.list[].id` flow into `manifest.agentId`. Sentinel's `policy.json` maps those IDs to permissions. Two concerns fully separated: OpenClaw defines what agents exist; Sentinel defines what agents are allowed to do.

## Trust Boundary

```
HOST (Mac Mini)                          DOCKER
─────────────────────                    ──────────────────────
config/policy.json    ──read at startup→  Executor process
data/vault.enc        ──decrypt at exec→  (in memory only)
data/audit.db         ──append only────→  AuditLogger

                                          Agent process
                                          (NO access to any of the above)
```

Policy, credentials, and audit trail are unreachable from the agent container. Agent communicates only via HTTP POST to `:3141`.

## Changed Files

| Package | File | Change |
|---------|------|--------|
| **types** | `src/policy-document.ts` | NEW — PolicyDocument + sub-schemas |
| **types** | `src/manifest.ts` | EDIT — add `agentId` |
| **types** | `src/audit.ts` | EDIT — add `agentId` + `policyVersion` |
| **policy** | `src/groups.ts` | NEW — group expansion |
| **policy** | `src/workspace.ts` | NEW — path containment |
| **policy** | `src/approval.ts` | NEW — allowlist matching |
| **policy** | `src/classifier.ts` | EDIT — new signature, agent resolution, tool/workspace gates |
| **executor** | `src/server.ts` | EDIT — load policy.json at startup |
| **executor** | `src/router.ts` | EDIT — pass PolicyDocument to classify() |
| **agent** | `src/manifest-builder.ts` | EDIT — require agentId |
| **cli** | TUI | EDIT — pass agent ID |
| **config** | `policy.json` | NEW — default policy |
| **config** | `policy.example.json` | NEW — documented example |

## Unchanged

- Credential filtering (`credential-filter.ts`) — Invariant #1
- Audit logger internals — gains fields but no logic change
- Bash parser (`bash-parser.ts`) — runs as step 5
- Deny-list (`deny-list.ts`) — kept as defense-in-depth
- Docker two-process architecture
- All 163 existing tests

## Testing (~80 new tests)

| Area | Count | Key Tests |
|------|-------|-----------|
| Tool gate | ~8 | Deny-wins, unknown agent blocked, group deny |
| Workspace | ~15 | Path traversal, symlink escape, `~` expansion, read-only |
| Groups | ~10 | Expansion, unknown group rejects at startup |
| Approval | ~12 | Allowlist match, ask modes, empty allowlist |
| Policy lifecycle | ~8 | Missing policy crashes, frozen config, version rejection |
| Schema validation | ~10 | Zod edge cases, partial agent inheritance |
| Integration | ~17 | Full flow through executor with real agents |

**Total:** 163 existing + ~80 new = ~243 tests

## Security Framework Coverage

Detailed checklists in `docs/server-hardening.md`:

| Framework | Phase | Section |
|-----------|-------|---------|
| Replit Vibe Code (MVP items) | 1.5 | §Replit Vibe Code Security Checklist |
| CF Workers (W1-W7) | 2 | §CF Workers Security Checklist |
| Replit Agent (R1-R5) | 2 | §Replit Agent Security Lessons |
| OWASP Top 10 + ASVS L2 | 2 | §General Security Frameworks |
| NIST AI RMF | 2 | §General Security Frameworks |
| CWE-77/78 | 2 | §General Security Frameworks |

## Pre-CF Gate

Must pass before Phase 2 migration:

- [ ] Red team exercise against all 6 security invariants
- [ ] Adversarial testing (prompt injection, manifest forgery, policy bypass)
- [ ] Mutation testing (verify test suite catches injected faults)
- [ ] Security scan (dependencies + code)
- [ ] Penetration test (executor API + trust boundary)
- [ ] SAST scan (Semgrep)
