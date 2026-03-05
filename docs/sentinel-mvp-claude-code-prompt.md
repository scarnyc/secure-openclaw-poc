# Sentinel MVP — Claude Code Init Prompt

> Copy everything below into a fresh Claude Code session with `/init`

---

## Project Overview

You are building **Sentinel**, a secure local AI personal assistant with a coding-first agent. The core innovation is **process isolation between the agent (untrusted) and the executor (trusted)** — two separate processes where the agent NEVER has access to credentials, and all sensitive actions are confirmed via a deterministic UI that renders actual parameters, not agent-generated summaries.

This is an MVP. No cloud deployment. No multi-tenancy. No billing. Everything runs locally. The goal is a working system the developer uses daily, and a portfolio piece demonstrating security architecture that would have prevented every OpenClaw CVE in 2026.

## Architecture — Two Process Model

```
┌─────────────────────────┐         ┌──────────────────────────────┐
│     AGENT PROCESS        │  HTTP   │      EXECUTOR PROCESS         │
│     (untrusted)          │◄──────►│      (trusted)                │
│                          │ :3141  │                               │
│  • LLM API calls         │        │  • Credential Vault           │
│  • Reasoning / planning  │        │  • Tool execution             │
│  • Tool call generation  │        │  • Action classification      │
│  • Context management    │        │  • Confirmation routing       │
│  • A2A task coordination │        │  • Audit logging              │
│                          │        │  • Subprocess management      │
│  ❌ NO credentials       │        │  ✅ Decrypts creds at exec    │
│  ❌ NO direct tool exec  │        │  ✅ Clears creds after exec   │
│  ❌ NO file system write* │        │  ✅ Writes audit log          │
└─────────────────────────┘         └──────────────────────────────┘
                                              │
                                    ┌─────────▼──────────┐
                                    │  CONFIRMATION TUI   │
                                    │  (terminal-based)   │
                                    │                     │
                                    │  Shows ACTUAL params │
                                    │  not agent summary  │
                                    └─────────────────────┘

* Agent can read files freely. Write/edit operations route through executor.
```

The two processes communicate over local HTTP on port 3141. The agent process sends **Action Manifests** (typed JSON describing what it wants to do). The executor process validates, classifies, optionally confirms with the user, executes, and returns sanitized results.

## Tech Stack

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Language | TypeScript (strict mode) | Type safety for security-critical code |
| Runtime | Node.js 22+ (LTS) | Stable, good subprocess support |
| Package manager | pnpm | Workspace support for monorepo |
| Build | tsup | Fast, simple TypeScript bundling |
| Monorepo | pnpm workspaces | Minimal config, no turborepo overhead for MVP |
| HTTP framework | Hono | Lightweight, works in Node now, portable to edge later |
| LLM SDK | @anthropic-ai/sdk | Claude as primary model |
| Terminal UI | @clack/prompts + chalk | Beautiful terminal confirmations |
| Encryption | Node.js native crypto | AES-256-GCM, no external deps |
| Database | better-sqlite3 | Local audit log + config, zero setup |
| Process management | Node child_process + execa | Subprocess execution for tools |
| Testing | vitest | Fast, TypeScript-native |
| Linting | biome | Fast, replaces eslint + prettier |

## Project Structure

```
sentinel/
├── package.json                    # Root workspace config
├── pnpm-workspace.yaml
├── tsconfig.base.json              # Shared TS config
├── biome.json
├── vitest.workspace.ts
│
├── packages/
│   ├── types/                      # Shared type definitions
│   │   ├── package.json
│   │   └── src/
│   │       ├── manifest.ts         # ActionManifest, ActionType, ToolCall
│   │       ├── policy.ts           # PolicyDecision, ActionCategory
│   │       ├── config.ts           # SentinelConfig, ToolClassification
│   │       ├── audit.ts            # AuditEntry types
│   │       ├── a2a.ts              # AgentCard, Task, Artifact (A2A stub)
│   │       └── index.ts
│   │
│   ├── crypto/                     # Credential vault + encryption
│   │   ├── package.json
│   │   └── src/
│   │       ├── vault.ts            # CredentialVault class
│   │       ├── encryption.ts       # AES-256-GCM encrypt/decrypt
│   │       ├── key-derivation.ts   # PBKDF2 master password → key
│   │       └── index.ts
│   │
│   ├── policy/                     # Action classification engine
│   │   ├── package.json
│   │   └── src/
│   │       ├── classifier.ts       # Classifies actions as read/write/dangerous
│   │       ├── rules.ts            # Default classification rules
│   │       ├── bash-parser.ts      # Bash command risk analysis
│   │       └── index.ts
│   │
│   ├── audit/                      # Audit logging
│   │   ├── package.json
│   │   └── src/
│   │       ├── logger.ts           # Append-only audit log (SQLite)
│   │       ├── queries.ts          # Read/search audit entries
│   │       └── index.ts
│   │
│   ├── executor/                   # TRUSTED PROCESS — executes tools
│   │   ├── package.json
│   │   └── src/
│   │       ├── server.ts           # Hono HTTP server on :3141
│   │       ├── router.ts           # Route manifests → classify → confirm → execute
│   │       ├── tools/
│   │       │   ├── bash.ts         # Shell command execution
│   │       │   ├── read-file.ts    # File reading
│   │       │   ├── write-file.ts   # File writing
│   │       │   ├── edit-file.ts    # File editing (str_replace style)
│   │       │   ├── browse.ts       # Stub — Phase 2
│   │       │   └── index.ts        # Tool registry
│   │       ├── confirmation.ts     # TUI confirmation renderer
│   │       ├── credential-inject.ts # Decrypt + inject + clear pattern
│   │       └── index.ts
│   │
│   ├── agent/                      # UNTRUSTED PROCESS — LLM reasoning
│   │   ├── package.json
│   │   └── src/
│   │       ├── loop.ts             # Core agent loop: reason → act → observe
│   │       ├── llm.ts              # Anthropic SDK wrapper, streaming
│   │       ├── context.ts          # Context window management
│   │       ├── manifest-builder.ts # Converts tool calls → ActionManifests
│   │       ├── executor-client.ts  # HTTP client to executor on :3141
│   │       ├── system-prompt.ts    # Agent system prompt with tool definitions
│   │       └── index.ts
│   │
│   └── cli/                        # CLI entry point + process orchestration
│       ├── package.json
│       └── src/
│           ├── main.ts             # Entry: starts both processes, handles lifecycle
│           ├── commands/
│           │   ├── chat.ts         # Interactive agent session
│           │   ├── vault.ts        # Manage credentials (add/remove/list services)
│           │   ├── audit.ts        # View audit log
│           │   ├── config.ts       # Edit action classifications
│           │   └── init.ts         # First-run setup (master password, etc.)
│           └── process-manager.ts  # Spawn/monitor agent + executor processes
│
├── config/
│   ├── default-classifications.json # Default read/write/dangerous mappings
│   └── sentinel.example.json        # Example user config
│
├── data/                           # Created at runtime (gitignored)
│   ├── vault.enc                   # Encrypted credential store
│   ├── audit.db                    # SQLite audit database
│   └── sentinel.json               # User config
│
└── AGENTS.md                       # Instructions for AI agents working on this repo
```

## Build Order

Build packages in this exact order. Run `pnpm typecheck && pnpm test` between each step. Do not proceed if either fails.

### Step 1: `packages/types`
All shared type definitions. No runtime code, only TypeScript types and interfaces.

**Key types to define:**

```typescript
// manifest.ts
export type ActionCategory = 'read' | 'write' | 'dangerous';

export interface ActionManifest {
  id: string;                    // uuid v4
  timestamp: string;             // ISO 8601
  tool: ToolName;                // 'bash' | 'read_file' | 'write_file' | 'edit_file'
  parameters: Record<string, unknown>;
  category?: ActionCategory;     // Set by policy engine, not agent
  sessionId: string;
}

export type ToolName = 'bash' | 'read_file' | 'write_file' | 'edit_file';

export interface ToolResult {
  manifestId: string;
  success: boolean;
  output?: string;
  error?: string;
  duration_ms: number;
}

// policy.ts
export interface PolicyDecision {
  action: 'auto_approve' | 'confirm' | 'block';
  category: ActionCategory;
  reason: string;
}

// config.ts — THE KEY CONFIGURATION SURFACE
export interface ToolClassification {
  tool: ToolName;
  defaultCategory: ActionCategory;
  overrides?: ClassificationOverride[];
}

export interface ClassificationOverride {
  condition: string;  // e.g., "args_match:--network" or "path_prefix:/etc"
  category: ActionCategory;
  reason: string;
}

export interface SentinelConfig {
  executor: {
    port: number;          // default 3141
    host: string;          // default 127.0.0.1
  };
  classifications: ToolClassification[];
  autoApproveReadOps: boolean;  // default true
  auditLogPath: string;
  vaultPath: string;
  llm: {
    provider: 'anthropic';
    model: string;         // default 'claude-sonnet-4-5-20250514'
    maxTokens: number;
  };
}

// audit.ts
export interface AuditEntry {
  id: string;
  timestamp: string;
  manifestId: string;
  tool: ToolName;
  category: ActionCategory;
  decision: PolicyDecision['action'];
  parameters_summary: string;  // Truncated, no secrets
  result: 'success' | 'failure' | 'denied_by_user' | 'blocked_by_policy';
  duration_ms?: number;
  sessionId: string;
}

// a2a.ts — STUB for future phases
export interface AgentCard {
  name: string;
  description: string;
  url: string;
  capabilities: AgentCapability[];
  version: string;
}

export interface AgentCapability {
  name: string;
  description: string;
  inputSchema?: Record<string, unknown>;
}

export interface A2ATask {
  id: string;
  status: 'submitted' | 'working' | 'completed' | 'failed';
  capability: string;
  input: Record<string, unknown>;
  output?: Record<string, unknown>;
  artifacts?: A2AArtifact[];
}

export interface A2AArtifact {
  name: string;
  mimeType: string;
  data: string;
}
```

### Step 2: `packages/crypto`
Credential vault implementation. This is security-critical code — be precise.

**Encryption spec:**
- Key derivation: PBKDF2 with SHA-512, 600,000 iterations, 32-byte salt
- Encryption: AES-256-GCM with 12-byte IV, 16-byte auth tag
- Storage format: JSON file with `{ salt, iv, authTag, ciphertext }` all base64 encoded
- Master password never stored — derived key lives in memory only during executor lifetime
- Each credential entry: `{ serviceId, type: 'oauth' | 'api_key' | 'token', data: encrypted_blob, createdAt, expiresAt? }`

**CredentialVault API:**
```typescript
class CredentialVault {
  static async create(vaultPath: string, masterPassword: string): Promise<CredentialVault>;
  static async open(vaultPath: string, masterPassword: string): Promise<CredentialVault>;
  async store(serviceId: string, credentialType: string, data: Record<string, string>): Promise<void>;
  async retrieve(serviceId: string): Promise<Record<string, string>>;  // Decrypts on access
  async remove(serviceId: string): Promise<void>;
  async list(): Promise<Array<{ serviceId: string; type: string; createdAt: string }>>;  // No secrets in listing
  async wipe(): Promise<void>;  // Emergency: delete everything
  destroy(): void;  // Clear decrypted material from memory
}
```

**Acceptance criteria:**
- GIVEN a new vault, WHEN I store and retrieve a credential, THEN the plaintext matches
- GIVEN a vault file on disk, WHEN I open it with the wrong password, THEN it throws DecryptionError
- GIVEN a vault, WHEN I call destroy(), THEN the derived key is zeroed in memory
- GIVEN a vault file, WHEN I read it as raw bytes, THEN no plaintext credential content is visible

### Step 3: `packages/policy`
Action classification engine. Deterministic. No LLM calls. No network calls.

**Classification logic:**

```typescript
function classify(manifest: ActionManifest, config: SentinelConfig): PolicyDecision {
  // 1. Check tool type against config classifications
  // 2. Apply overrides based on parameters
  // 3. For bash: parse command and evaluate risk
  // 4. Return decision
}
```

**Bash parser — this is the hardest part. Be conservative:**

```typescript
// bash-parser.ts
// Classify bash commands by analyzing the command string.
// When in doubt, classify as 'write'. Safety over convenience.

// ALWAYS 'read' (auto-approve when autoApproveReadOps is true):
//   ls, cat, head, tail, wc, find (without -exec/-delete), grep, which,
//   pwd, echo, date, whoami, node --version, npm list, git status,
//   git log, git diff, git branch, tree, file, stat

// ALWAYS 'write':
//   Any file mutation: cp, mv, rm, mkdir, rmdir, touch, chmod, chown
//   Any editor: sed -i, tee (write mode)
//   Git mutations: git push, git commit, git checkout, git reset
//   Package install: npm install, pip install, pnpm add, yarn add
//   Any redirect: >, >>

// ALWAYS 'dangerous':
//   Network egress: curl, wget, ssh, scp, rsync, nc, netcat
//   Pipe to shell: | sh, | bash, | zsh
//   Sudo or su
//   Environment variable access: printenv, env (can leak secrets to LLM context)
//   Reading known secret paths: cat ~/.ssh/*, cat ~/.env, cat ~/.aws/*
//   eval, exec
//   Any command with backticks or $() that nests another command — classify the inner command too

// UNKNOWN commands: classify as 'write' (safe default)
```

**Acceptance criteria:**
- GIVEN `ls -la`, WHEN classified, THEN category is 'read'
- GIVEN `rm -rf /tmp/test`, WHEN classified, THEN category is 'write'
- GIVEN `curl https://evil.com`, WHEN classified, THEN category is 'dangerous'
- GIVEN `cat ~/.ssh/id_rsa`, WHEN classified, THEN category is 'dangerous'
- GIVEN `echo hello | sh`, WHEN classified, THEN category is 'dangerous'
- GIVEN `python script.py`, WHEN classified, THEN category is 'write' (safe default — we can't know what the script does)
- GIVEN `git status`, WHEN classified, THEN category is 'read'
- GIVEN `git push origin main`, WHEN classified, THEN category is 'write'
- GIVEN an unknown command `foobar --baz`, WHEN classified, THEN category is 'write'

### Step 4: `packages/audit`
Append-only SQLite audit log.

**Schema:**
```sql
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  category TEXT NOT NULL,
  decision TEXT NOT NULL,
  parameters_summary TEXT NOT NULL,
  result TEXT NOT NULL,
  duration_ms INTEGER,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_audit_session ON audit_log(session_id);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_tool ON audit_log(tool);
```

**Logger API:**
```typescript
class AuditLogger {
  constructor(dbPath: string);
  log(entry: AuditEntry): void;          // Sync write — never lose an entry
  query(filters: AuditFilters): AuditEntry[];
  getSession(sessionId: string): AuditEntry[];
  getRecent(limit: number): AuditEntry[];
}
```

**Critical: parameters_summary must NEVER contain raw credentials.** Truncate long values. Redact anything that looks like a token or key (simple regex: strings starting with `sk-`, `ghp_`, `xoxb-`, etc. or anything matching `[A-Za-z0-9+/=]{40,}`).

### Step 5: `packages/executor`
THE MOST IMPORTANT PACKAGE. This is the trusted process.

**Server setup (server.ts):**
- Hono HTTP server on 127.0.0.1:3141
- Accepts POST /execute with ActionManifest body
- Accepts GET /health for process manager liveness checks
- Accepts GET /agent-card for A2A stub (returns static AgentCard JSON)
- Rejects requests from any origin other than 127.0.0.1

**Request flow (router.ts):**
```
POST /execute
  → Validate manifest schema (reject malformed)
  → Classify action via policy engine
  → If 'read' + autoApproveReadOps: execute immediately
  → If 'write': render confirmation TUI, wait for user input
  → If 'dangerous': render confirmation TUI with ⚠️ WARNING, wait for user input
  → If user approves: execute tool, return result
  → If user denies: return denied result
  → Log everything to audit log regardless of outcome
```

**Confirmation renderer (confirmation.ts):**
This is what the user sees. It MUST show actual parameters, never agent-generated text.

```
┌─────────────────────────────────────────────────┐
│  ⚠️  WRITE ACTION REQUESTED                     │
│                                                  │
│  Tool:    bash                                   │
│  Command: git push origin main                   │
│  CWD:     /Users/will/projects/sentinel          │
│                                                  │
│  Category: write                                 │
│  Reason:   git mutation (push)                   │
│                                                  │
│  [y] Approve  [n] Deny  [a] Always approve this  │
└─────────────────────────────────────────────────┘
```

For file writes, show the full file path and a content preview (first 20 lines).
For bash, show the full command string — never truncate commands.
For edits, show the file path, old string (truncated at 5 lines), new string (truncated at 5 lines).

**The "Always approve this" option:** Adds a classification override to the user's config that auto-approves this specific pattern in future. E.g., if the user always-approves `git push origin main`, it adds an override rule. This is how the system learns the user's preferences without ML.

**Tool implementations (tools/):**

Each tool executor follows this pattern:
```typescript
async function executeBash(params: BashParams, vault?: CredentialVault): Promise<ToolResult> {
  // 1. If tool needs credentials (future: email, calendar), inject from vault
  // 2. Execute in subprocess with timeout (default 30s, configurable)
  // 3. Capture stdout + stderr
  // 4. Clear any injected credentials from environment
  // 5. Return sanitized result (scan output for credential patterns, warn if found)
  // 6. Audit log the execution
}
```

**bash.ts specifics:**
- Use execa for subprocess management
- Stream stdout/stderr to the agent in real-time (SSE or chunked response)
- Enforce timeout (default 30s, 300s for long-running tasks like builds)
- Kill process group on timeout (not just the process — prevent orphaned children)
- Working directory: respect CWD from manifest, default to user's current directory
- Environment: inherit user's env BUT strip any SENTINEL_* internal vars

### Step 6: `packages/agent`
The untrusted process. Calls the LLM, generates tool calls, sends manifests to executor.

**Agent loop (loop.ts):**
```typescript
async function agentLoop(userMessage: string, context: ConversationContext): Promise<void> {
  // 1. Add user message to context
  // 2. Call LLM with system prompt + context + tool definitions
  // 3. If LLM returns text: display to user
  // 4. If LLM returns tool_use: 
  //    a. Build ActionManifest from tool call
  //    b. POST to executor at http://127.0.0.1:3141/execute
  //    c. Receive result (may block while user confirms)
  //    d. Add tool result to context
  //    e. Go to step 2 (continue reasoning)
  // 5. If LLM returns end_turn: done
}
```

**System prompt (system-prompt.ts):**
```typescript
const SYSTEM_PROMPT = `You are Sentinel, a secure AI coding assistant.

You have access to the following tools:
- bash: Execute shell commands
- read_file: Read file contents
- write_file: Create or overwrite a file
- edit_file: Edit a file by replacing a specific string

You are running on the user's local machine. You can help with:
- Writing, editing, and debugging code
- Running tests and build commands  
- Navigating and understanding codebases
- General programming tasks

Security context: Your tool calls are routed through a security gateway.
Read operations are auto-approved. Write operations require user confirmation.
You do NOT have direct access to credentials, API keys, or OAuth tokens.
Do not attempt to read files like ~/.env, ~/.ssh/*, ~/.aws/* as these
will be flagged as dangerous operations.

Be direct, concise, and helpful. Ask clarifying questions when the task
is ambiguous. Show your reasoning for complex problems.`;
```

**LLM integration (llm.ts):**
- Use @anthropic-ai/sdk with streaming
- Tool definitions match the four core tools
- Handle streaming text display (print tokens as they arrive)
- Handle tool_use blocks → manifest builder
- Context window management: keep last N messages, summarize older context when approaching limit
- Model default: claude-sonnet-4-5-20250514 (good balance of speed + capability for coding)

**Executor client (executor-client.ts):**
- HTTP client to 127.0.0.1:3141
- POST /execute with ActionManifest
- Handle streaming responses (for long-running bash commands)
- Timeout: match executor's tool timeout + 10s buffer
- Retry: NO retries on failure (security: don't retry denied actions)
- Health check: GET /health before first request, fail fast if executor is down

### Step 7: `packages/cli`
Entry point. Orchestrates everything.

**main.ts — Process lifecycle:**
```typescript
// 1. Parse CLI args (command: chat | vault | audit | config | init)
// 2. If first run (!exists(data/sentinel.json)): run init flow
// 3. Load config
// 4. For 'chat' command:
//    a. Prompt for master password (vault unlock)
//    b. Fork executor process (child_process.fork)
//    c. Wait for executor health check to pass
//    d. Fork agent process
//    e. Pipe user stdin to agent
//    f. Handle SIGINT/SIGTERM: graceful shutdown of both processes
// 5. For 'vault' command: manage credentials directly
// 6. For 'audit' command: query and display audit log
// 7. For 'config' command: edit classifications
```

**commands/init.ts — First run:**
```
Welcome to Sentinel 🛡️

Sentinel is a secure AI assistant that keeps your credentials
isolated from the AI model. Let's set things up.

Step 1: Create a master password for your credential vault
  > ********

Step 2: Configure your AI provider
  Provider: Anthropic (more coming soon)
  API key: sk-ant-... 
  (This will be stored in your encrypted vault, not in env vars)

Step 3: Choose your default security level
  [1] Standard — reads auto-approve, writes confirm (recommended)
  [2] Strict — everything confirms
  [3] Relaxed — only dangerous actions confirm

Setup complete! Run `sentinel chat` to start.
```

**commands/chat.ts — Interactive session:**
- Rich terminal UI with clear separation between:
  - Agent output (normal text)
  - Tool execution (dimmed, shows tool name + brief params)
  - Confirmation prompts (highlighted, user must respond)
  - System messages (status, errors)
- Input: multi-line support (Shift+Enter or paste detection)
- Commands: /exit, /audit (show recent actions), /clear, /model (switch model)

## Critical Implementation Notes

### The Interceptor Pattern — MOST IMPORTANT
The executor's router.ts is the ENTIRE security boundary. Every tool call goes through it. If this file has a bug, the security model is broken. Write comprehensive tests.

### No Credential Leakage to Agent
The agent process receives tool results but NEVER receives credentials. If a bash command outputs something that looks like a credential (e.g., the user runs `cat .env` which was classified as dangerous and they approved), log a WARNING in the audit log but still return the output — the user explicitly approved it.

### Streaming for Long Operations
Bash commands can run for minutes (npm install, test suites, builds). The executor must stream output back to the agent in real-time, not buffer the entire result. Use chunked transfer encoding or SSE.

### Graceful Shutdown
When the user hits Ctrl+C:
1. Send SIGTERM to agent process
2. Wait 2s for agent to finish current LLM call
3. Send SIGTERM to executor process  
4. Executor finishes any in-progress tool execution
5. Executor flushes audit log
6. Executor calls vault.destroy() (clear decrypted keys from memory)
7. Exit cleanly

### A2A Stub
The executor serves GET /agent-card returning a static JSON AgentCard describing Sentinel's capabilities. This is enough to demo A2A discovery. Full task lifecycle (submit task, poll status, receive artifacts) is Phase 2 — just define the types in packages/types/src/a2a.ts for now.

## What NOT To Build

- ❌ Cloud deployment, hosted gateway, or any remote infrastructure
- ❌ Multi-tenancy, user accounts, or authentication beyond master password
- ❌ Billing, Stripe integration, or usage metering
- ❌ Browser automation (Phase 2)
- ❌ Email/calendar integration (Phase 3 — requires OAuth flow design)
- ❌ Mobile push notifications or out-of-band MFA
- ❌ PII scanner or manifest redaction
- ❌ Hash-chained audit logs (simple append-only is fine)
- ❌ Multiple LLM providers (Anthropic only for MVP)
- ❌ Web dashboard UI (terminal only for MVP)
- ❌ OS keychain integration (encrypted file is fine)
- ❌ x402 commerce protocol

## Testing Strategy

- `packages/crypto`: Unit tests for encrypt/decrypt round-trip, wrong password rejection, memory clearing
- `packages/policy`: Unit tests for EVERY bash classification example listed above, plus property-based tests for the override system
- `packages/audit`: Unit tests for log/query, test that credential-like strings are redacted in summaries
- `packages/executor`: Integration tests using a mock agent client that sends manifests and verifies confirmation flow
- `packages/agent`: Unit tests for manifest builder, mock executor for the agent loop

**The policy package has the most critical tests.** If the bash parser misclassifies `curl` as a read, the security model fails. Every classification rule must have at least 3 test cases.

## Success Criteria

The MVP is done when:
1. `sentinel init` sets up the vault and config
2. `sentinel chat` starts a working coding session with Claude
3. `ls`, `cat`, `grep` execute immediately without confirmation
4. `git push`, `npm install`, file writes show a confirmation prompt
5. `curl`, `ssh`, pipe-to-shell show a ⚠️ dangerous warning
6. User can deny any action and the agent handles the denial gracefully
7. `sentinel audit` shows a complete log of all actions taken
8. `sentinel vault list` shows stored services without exposing secrets
9. GET http://127.0.0.1:3141/agent-card returns a valid AgentCard JSON
10. All tests pass with >90% coverage on crypto and policy packages
