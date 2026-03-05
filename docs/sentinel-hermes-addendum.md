# Sentinel MVP — Spec Addendum: Hermes Agent Features

> Addendum to sentinel-init-v3.md. Describes changes derived from
> NousResearch/hermes-agent that strengthen the execution layer,
> improve terminal security, enable parallel workloads, and add
> self-improving skill evaluation — without altering architecture
> invariants or the security model.

---

## Context

Hermes Agent (https://github.com/NousResearch/hermes-agent) is Nous Research's
open-source autonomous agent released February 2026. While Sentinel's security
model (deterministic policy engine, zero-knowledge gateway, credential isolation)
is architecturally ahead of Hermes, four implementation patterns from Hermes
strengthen Sentinel's execution layer where code has not yet been written.

This addendum covers:

1. ComputeBackend interface (replaces hard-coded SSH)
2. Bash risk classifier (enriches ManifestMetadata)
3. Subagent session scoping (enables safe parallelism)
4. Skill evaluation and lifecycle (self-healing procedural memory)

All four slot below the policy engine. None require new services, databases,
or deployment targets. None violate existing invariants.

---

## Change 1: ComputeBackend Interface

### What We Had

A single `SSHBridge` class that spawned Claude Code sessions on Remote Compute
(Mac or VPS). Hard-coded to SSH. The MoltWorker orchestrator connected directly
to the remote machine, spawned a process in a scoped workspace, and monitored
it via PID checks.

### What Changes

The SSH bridge becomes one implementation of an abstract `ComputeBackend`
interface. Three backends share one contract:

```typescript
// packages/compute-backend/src/types.ts
import type { PolicyDecision } from '@sentinel/types';

interface ComputeJob {
  job_type: 'code_generate' | 'code_debug' | 'test_run' | 'project_scaffold';
  prd_content?: string;
  workspace_name: string;
  model: string;
  timeout_minutes: number;
}

interface ComputeResult {
  status: 'running' | 'completed' | 'failed';
  pid: number;
  workspace: string;
  exit_code?: number;
  artifact_paths?: string[];
}

interface ComputeBackend {
  spawn(job: ComputeJob): Promise<ComputeResult>;
  checkStatus(pid: number): Promise<ComputeResult>;
  pullArtifacts(workspace: string, localDest: string): Promise<string[]>;
  terminate(pid: number): Promise<void>;
}
```

Three implementations:

| Backend | When to Use | MVP? |
|---------|-------------|------|
| `SSHBackend` | Personal use, Mac or VPS as compute target | Yes |
| `DockerBackend` | Hardened execution — container on remote host via SSH | Yes |
| `ModalBackend` | On-demand serverless for paying customers | No (Phase 2) |

### DockerBackend Hardening (from Hermes)

When `DockerBackend` is selected, the SSH bridge spawns a Docker container on
the remote machine instead of a raw shell session. Container runs with:

- Read-only root filesystem
- All Linux capabilities dropped
- `--security-opt no-new-privileges`
- PID limit of 256 processes
- Persistent workspace via bind mount at `/workspace`
- No network access except explicit allowlist (npm registry, pip, GitHub)

This adds process-level isolation on top of the filesystem scoping we already
had. If the LLM hallucinates `rm -rf /` or tries to read `/etc/shadow`, the
container catches it before the policy engine even needs to intervene.

### Routing Rule

**Remote Compute is only for tasks that require a filesystem, terminal, or code
execution.** The policy engine rejects `ComputeJob` manifests when the action
type does not require compute. Only these action types route to a backend:

- `code_generate` — build an app, write a script
- `code_debug` — fix failing tests, investigate errors
- `test_run` — execute test suites
- `project_scaffold` — initialize a new codebase

Everything else — email drafting, web research, job board scanning, calendar
triage, Slack messages — resolves in the MoltWorker agent loop or via
lightweight subagents. No container startup, no SSH overhead, no PID
monitoring.

### Where It Lives

```
packages/
  compute-backend/
    src/
      types.ts           # ComputeBackend interface, ComputeJob, ComputeResult
      ssh-backend.ts     # SSHBackend implementation (existing logic, extracted)
      docker-backend.ts  # DockerBackend — SSH + Docker spawn
      modal-backend.ts   # Stub for Phase 2
      index.ts           # Factory: resolveBackend(config) → ComputeBackend
    __tests__/
      ssh-backend.test.ts
      docker-backend.test.ts
```

### Value

Decouples orchestration from execution environment. Develop locally against
Docker, run personal workloads on Mac via SSH, offer Modal as a premium tier
later. No orchestration code changes between environments — just config.

---

## Change 2: Bash Risk Classifier

### What We Had

ManifestMetadata included fields like `recipient_domain`, `is_known_contact`,
`amount_range`, and `chain_depth`, but terminal commands were coarsely
categorized. The policy engine lacked granular signals for shell command risk.

### What Changes

A lightweight classifier (pattern derived from Hermes Agent's
`tools/approval.py`) runs in the CLI interceptor before the manifest reaches
the policy engine. It produces structured boolean signals on ManifestMetadata:

```typescript
// Added to packages/types/src/manifest.ts
interface ManifestMetadata {
  // ... existing fields ...

  bash_risk_signals?: {
    has_recursive_delete: boolean;    // rm -rf, find -delete
    has_permission_change: boolean;   // chmod, chown, setfacl
    has_pipe_to_shell: boolean;       // curl|bash, wget|sh
    has_network_exfil: boolean;       // curl -d, nc, scp to unknown host
    modifies_system_files: boolean;   // /etc/*, /usr/*, systemctl
    writes_to_cron: boolean;          // crontab -e, /etc/cron.*
    accesses_env_vars: boolean;       // env, printenv, export, $API_KEY
  };
}
```

The classifier is a pure function — no LLM, no network calls, no dependencies
beyond `@sentinel/types`. It pattern-matches against the raw command string
using regex and keyword detection.

### How the Policy Engine Uses It

The signals feed into existing tier logic as additional scoring inputs:

| Signal | Effect |
|--------|--------|
| `has_pipe_to_shell: true` | Escalate to Tier 2 (confirmation required) |
| `has_recursive_delete: true` | Escalate to Tier 2 |
| `has_network_exfil: true` | Escalate to Tier 3 (MFA required) |
| `accesses_env_vars: true` | Escalate to Tier 1 minimum |
| All signals false | No escalation from bash classifier |

Multiple true signals compound — `has_pipe_to_shell` + `has_network_exfil`
in the same command = Tier 3 (block by default).

### Where It Lives

```
packages/
  bash-classifier/
    src/
      classify.ts        # Pure function: (command: string) => BashRiskSignals
      patterns.ts        # Regex patterns, organized by signal type
      index.ts
    __tests__/
      recursive-delete.test.ts
      pipe-to-shell.test.ts
      network-exfil.test.ts
      permission-change.test.ts
      system-files.test.ts
      cron-access.test.ts
      env-vars.test.ts
      edge-cases.test.ts    # Benign commands that look dangerous
      compound.test.ts      # Multiple signals in one command
```

Promptfoo eval suite gets a new test group: `evals/bash-classifier/`.

### Value

The policy engine gets concrete boolean signals instead of trying to
pattern-match raw command strings. Determinism preserved — same command
always produces the same signals. Exhaustive test coverage catches
false positives (e.g., `cat /etc/hosts` is a read, not a system file
modification).

---

## Change 3: Subagent Session Scoping

### What We Had

The heartbeat ran as a single sequential loop: check projects, triage email,
review calendar, scan job boards. One task at a time. Coding jobs spawned
on Remote Compute had the same session permissions as the main agent loop.

### What Changes

The agent can now spawn subagent sessions with restricted scopes. Each
subagent gets a `session_scope` field on its JWT claims that constrains
what the policy engine will approve for that session.

```typescript
// Added to packages/types/src/policy.ts
interface EvaluationContext {
  // ... existing fields ...

  session_scope: 'full' | 'heartbeat' | 'coding' | 'research';
  workspace_boundary?: string;   // e.g., "/workspaces/a1b2c3/"
  parent_session_id?: string;
  depth: number;                 // Max 2, subagents cannot spawn subagents
}
```

### Scope Constraints

| Scope | Can Do | Cannot Do |
|-------|--------|-----------|
| `full` | Everything | — (main agent loop only) |
| `heartbeat` | Read memory, read email, search web, write daily notes | Write files, send messages, run terminal, access credentials |
| `coding` | Terminal commands, read/write files within workspace boundary | Access messaging channels, write to memory, access credential vault, read outside workspace |
| `research` | Search web, read Browserbase results, write to daily notes | Run terminal commands, access credentials, send messages |

The policy engine enforces these constraints. A manifest from a
`heartbeat`-scoped session that attempts a terminal command gets blocked
regardless of what the bash classifier says about the command. The scope
check runs before the risk tier evaluation.

### Depth Limit

Subagents cannot spawn their own subagents (depth limit of 2). If a
heartbeat check discovers something that needs a coding job, it writes
the finding to the daily note and the main agent loop picks it up on
the next cycle. This prevents runaway delegation chains.

### Cost Implications

Heartbeat subagents run on Haiku (~$0.15/mo). Research subagents run
on Sonnet. Coding subagents run on Sonnet or Opus on Remote Compute.
The main agent loop uses Opus for complex reasoning. Model selection
per scope is configurable in `config.yaml`.

### Where It Lives

Scope enforcement is ~50 lines of rule logic added to the policy engine's
`evaluate()` function in `packages/policy-engine/src/engine.ts`. No new
package needed — it's a new field on an existing input type with new
rules in the existing rule evaluation pipeline.

```
packages/
  policy-engine/
    src/
      rules/
        scope-enforcement.ts   # New rule: check session_scope constraints
    __tests__/
      scope-enforcement.test.ts  # Exhaustive: every scope × every action type
```

### Value

Safe parallelism. Three job boards scanned simultaneously instead of
sequentially. Claude Code sessions isolated from the messaging layer.
Heartbeat checks that can never accidentally trigger a destructive
terminal command no matter what the LLM generates.

---

## Change 4: Skill Evaluation and Lifecycle

### What We Had

The three-tier memory system (knowledge graph + daily notes + MEMORY.md)
captured what the agent learned. But there was no formal process for when
the agent should write a skill, how to validate it before committing, or
how to handle skill staleness over time.

### What Changes

Skill creation, installation, and updates now follow a structured lifecycle
with evaluation gates routed through the policy engine.

### Creation Criteria

The agent synthesizes a new skill document only when it meets at least one
of these conditions:

1. **Completed a complex task** with 5+ tool calls successfully
2. **Hit dead ends and found the working path** — the failure-then-success
   trajectory is the most valuable thing to persist
3. **User corrected the approach** and the corrected version worked
4. **Discovered a non-trivial workflow** — a specific deployment sequence,
   API quirk, or environment-specific configuration

If the task was straightforward (two tool calls, no errors), there is nothing
worth persisting. The agent does not speculatively create skills.

### Validation Before Commit

Before a skill document is committed to the knowledge graph, it emits a
`skill_write` action manifest. The validation pipeline:

1. **Bash classifier scans code blocks** in the skill content for the same
   risk signals it checks on live commands. If the skill contains
   `curl | bash`, `chmod 777`, or references to environment variables,
   those get flagged on ManifestMetadata.

2. **Policy engine evaluates the manifest.** Skill source determines
   the baseline trust level:

   | Source | Trust | Finding Behavior |
   |--------|-------|-----------------|
   | Agent-created (from successful task) | High | Findings → Tier 1 (confirm) |
   | Bundled (ships with Sentinel) | High | Auto-approve |
   | ClawHub / external registry | Low | Any finding → block unless explicit override |

3. **User confirmation** for Tier 1+ decisions arrives via Telegram.
   The message includes: skill name, what triggered creation, and any
   flagged patterns.

### Staleness Detection and Self-Healing

When the agent loads a skill and the procedure fails:

1. Agent flags the skill as potentially stale in the daily note
2. Agent attempts a corrected approach
3. If the corrected approach succeeds, agent emits a `skill_patch` manifest
   with the specific fix (old_string → new_string, same pattern as file
   patch tool)
4. Policy engine evaluates the patch — bash classifier re-scans the new
   content for risk signals
5. If approved, the skill updates in place with a version bump

This prevents the noise accumulation problem that reviewers flagged about
Hermes's long-term memory quality. Skills self-heal instead of going stale
and forcing the agent to rediscover solutions.

### Manifest Types

```typescript
// Added to packages/types/src/manifest.ts
type SkillActionType =
  | 'skill_write'      // New skill creation
  | 'skill_patch'      // Targeted fix to existing skill
  | 'skill_install'    // Install from external registry
  | 'skill_delete';    // Remove a skill

interface SkillManifestMetadata extends ManifestMetadata {
  action_type: SkillActionType;
  skill_name: string;
  skill_source: 'agent_created' | 'bundled' | 'community';
  code_block_count: number;
  bash_risk_signals_in_content?: BashRiskSignals;  // Scan of skill body
  has_external_urls: boolean;
  estimated_token_cost: number;  // How much context this skill consumes when loaded
}
```

### Where It Lives

Skill evaluation logic splits across existing packages:

```
packages/
  bash-classifier/
    src/
      classify-content.ts   # Scan markdown code blocks (reuses classify.ts patterns)

  policy-engine/
    src/
      rules/
        skill-evaluation.ts  # Trust level × finding severity → tier decision
    __tests__/
      skill-evaluation.test.ts

  types/
    src/
      manifest.ts            # SkillManifestMetadata added
```

The skill storage itself remains in claude-mem's knowledge graph as designed
in the original spec. This change only adds evaluation gates around writes.

### Value

Skills become trustworthy over time instead of accumulating noise. Every
skill write passes through the same policy engine as every other action.
Community skills from untrusted sources get the strictest scrutiny. The
agent learns from its mistakes (failure → correction → skill patch) without
human intervention for routine updates.

---

## How the Updated System Works: End-to-End Example

You message Sentinel on Telegram at 9am: "Find senior AI PM roles at
agentic AI companies and draft applications for the top 3."

**Step 1 — Context injection.** MoltWorker receives the message. claude-mem
injects relevant context: your resume highlights ($116M value, 100M+
customers, 10 AI PMs hired), target criteria ($200k+, NYC or remote),
companies to skip (ASAPP, Intuit, Optimal Dynamics, DataCamp), and any
existing skills for job applications.

**Step 2 — Parallel research subagents.** The agent spawns three research
subagents (scope: `research`, model: Sonnet) — one for LinkedIn, one for
Indeed, one for company career pages via Browserbase. Each emits manifests
for web search and browser navigation. Policy engine auto-approves (Tier 0).
The subagents run concurrently but cannot access terminal, credentials, or
messaging. Results write to the daily note.

**Step 3 — Synthesis in main loop.** Research subagents complete. The main
agent loop (Opus) consolidates findings, cross-references against claude-mem
to confirm none of the companies are on the reject list, and selects the
top 3 roles.

**Step 4 — Cover letter generation routes to Remote Compute.** The agent
emits a `ComputeJob` manifest with `job_type: code_generate`. The policy
engine confirms: action type requires compute (valid), session scope is
`full` (valid), bash classifier has no signals on the PRD content. Decision:
Tier 1, sends Telegram confirmation — "Generate cover letters for [Company A
— Senior AI PM], [Company B — Head of AI Product], [Company C — Director,
Agentic Products]? Y/N."

**Step 5 — You approve.** The `DockerBackend` SSHs into your VPS, spawns
a hardened Docker container, runs Claude Code with the PRD. Container has
read-only root, no capabilities, PID limit 256. Claude Code writes drafts
to `/workspace/output/`. The heartbeat checks the PID every 30 minutes via
the `ComputeBackend.checkStatus()` interface.

**Step 6 — Completion and delivery.** Heartbeat detects exit code 0. Calls
`pullArtifacts()` to SCP the drafts back. Updates daily note: "Generated
3 cover letters, workspace: cover-letters-a1b2c3." Sends drafts to your
Telegram for review. Policy engine: sending content to your own Telegram =
Tier 0, auto-approved.

**Step 7 — Skill creation triggered.** The task involved 8+ tool calls
across 3 subagents and a coding session. The agent synthesizes a skill
document: "Job Application Pipeline — parallel search across LinkedIn,
Indeed, and career pages; consolidate with claude-mem history check;
generate via Claude Code on Remote Compute." The skill includes the
specific Browserbase navigation patterns that worked and the PRD template
that produced good cover letters.

The `skill_write` manifest goes through the policy engine. Bash classifier
scans the code blocks in the skill — finds references to `claude` CLI but
no dangerous patterns. Source: `agent_created` (high trust), no findings.
Decision: Tier 0, auto-approved. Skill commits to the knowledge graph.

**Step 8 — Next time.** A week later you say "Apply to 3 more roles."
The agent loads the skill, skips the trial-and-error discovery phase, and
executes the proven pipeline directly. If Indeed's UI changed and the
Browserbase navigation fails, the agent flags the skill as stale, finds
the working path, and emits a `skill_patch` manifest to update the
navigation selectors. The skill self-heals.

---

## Updated Timeline Impact

These four changes add approximately 3-4 days to the original 4-5 week plan:

| Week | Original Scope | Added Work |
|------|---------------|------------|
| 1-2 | Security Gateway, policy engine, credential vault, manifest redactor, JWT auth | Scaffold `ComputeBackend` interface and `bash-classifier` package (both pure functions, no external deps) |
| 3 | Deploy MoltWorker, SSH bridge to Remote Compute, heartbeat | Add `DockerBackend` implementation, wire `session_scope` into policy engine evaluate(), add scope-enforcement rule (~50 LOC) |
| 4 | Integration testing, Promptfoo evals | Add bash-classifier eval suite, scope-enforcement tests, skill-evaluation tests |
| 5 | Browserbase integration, Telegram UX polish | Add skill lifecycle gates (skill_write/skill_patch manifest types, trust level routing) |

No new services. No new databases. No new deployment targets. Every change
is either a new pure-function package, a new field on an existing type, or
a new rule in the existing policy engine.

---

## Packages Added or Modified

### New Packages

| Package | Purpose | Dependencies |
|---------|---------|-------------|
| `@sentinel/compute-backend` | Abstract execution environment | `@sentinel/types` only |
| `@sentinel/bash-classifier` | Terminal command risk signals | `@sentinel/types` only |

### Modified Packages

| Package | Change |
|---------|--------|
| `@sentinel/types` | Add `BashRiskSignals`, `ComputeJob`, `ComputeResult`, `SkillManifestMetadata`, `session_scope` and `workspace_boundary` to `EvaluationContext` |
| `@sentinel/policy-engine` | Add `scope-enforcement` rule, `skill-evaluation` rule, integrate `bash_risk_signals` into tier scoring |

### Updated Dependency Graph

```
@sentinel/types ← (everything depends on this)
  ↑
@sentinel/bash-classifier ← @sentinel/types
  ↑
@sentinel/policy-engine ← @sentinel/types + @sentinel/bash-classifier
  ↑
@sentinel/compute-backend ← @sentinel/types
  ↑
apps/gateway ← policy-engine + schema-registry + audit-logger + compute-backend
  ↑
apps/cli ← policy-engine + credential-vault + manifest-redactor + bash-classifier
  ↑
apps/dashboard ← (calls gateway API only)
```

---

## References

- Hermes Agent repository: https://github.com/NousResearch/hermes-agent
- Hermes terminal backends: `tools/environments/` (local, docker, ssh, singularity, modal)
- Hermes command approval: `tools/approval.py` (dangerous command classifier)
- Hermes subagent delegation: `delegate_task` tool with depth limit and toolset restrictions
- Hermes skill lifecycle: `skill_manage` tool with create/patch/edit/delete actions
- agentskills.io standard: https://agentskills.io/specification
