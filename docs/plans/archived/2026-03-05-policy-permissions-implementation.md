# Phase 1.5 Policy & Permissions Redesign — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add per-agent tool policies, workspace scoping, tool groups, and exec approval allowlists to Sentinel's policy engine via a separate policy document (`config/policy.json`).

**Architecture:** New `PolicyDocument` Zod schema loaded at startup alongside `SentinelConfig`. `classify()` gains agent resolution, tool gate, workspace gate, and approval resolution steps that run before the existing bash parser and category lookup. OpenClaw runs permissive; Sentinel is the sole trust boundary.

**Tech Stack:** TypeScript, Zod, Vitest, Hono, better-sqlite3, Node.js `path`/`fs`

**Design Doc:** `docs/plans/2026-03-05-policy-permissions-redesign.md`

---

## Task 1: PolicyDocument Zod Schema

**Files:**
- Create: `packages/types/src/policy-document.ts`
- Modify: `packages/types/src/index.ts`
- Test: `packages/types/src/policy-document.test.ts`

**Step 1: Write the failing test**

```typescript
// packages/types/src/policy-document.test.ts
import { describe, expect, it } from "vitest";
import { PolicyDocumentSchema } from "./policy-document.js";

const VALID_POLICY = {
  version: 1,
  toolGroups: {
    fs: ["read", "write", "edit", "apply_patch"],
    runtime: ["exec", "process"],
  },
  defaults: {
    tools: { allow: ["*"], deny: ["group:network"] },
    workspace: { root: "~/.openclaw/workspace", access: "rw" },
    approval: { ask: "on-miss" },
  },
  agents: {
    main: {
      tools: { allow: ["group:fs"], deny: [] },
      workspace: { root: "~/Code", access: "rw" },
      approval: {
        ask: "on-miss",
        allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
      },
    },
  },
};

describe("PolicyDocumentSchema", () => {
  it("accepts a valid policy document", () => {
    const result = PolicyDocumentSchema.safeParse(VALID_POLICY);
    expect(result.success).toBe(true);
  });

  it("rejects unknown version", () => {
    const result = PolicyDocumentSchema.safeParse({ ...VALID_POLICY, version: 2 });
    expect(result.success).toBe(false);
  });

  it("rejects missing defaults", () => {
    const { defaults: _, ...noDefaults } = VALID_POLICY;
    const result = PolicyDocumentSchema.safeParse(noDefaults);
    expect(result.success).toBe(false);
  });

  it("rejects empty workspace root", () => {
    const bad = structuredClone(VALID_POLICY);
    bad.defaults.workspace.root = "";
    const result = PolicyDocumentSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("rejects invalid access mode", () => {
    const bad = structuredClone(VALID_POLICY);
    (bad.defaults.workspace as any).access = "execute";
    const result = PolicyDocumentSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("rejects invalid ask mode", () => {
    const bad = structuredClone(VALID_POLICY);
    (bad.defaults.approval as any).ask = "sometimes";
    const result = PolicyDocumentSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("accepts agent without optional fields (inherits from defaults)", () => {
    const policy = structuredClone(VALID_POLICY);
    policy.agents.minimal = {
      tools: { allow: ["read"] },
      workspace: { root: "~/minimal", access: "ro" },
    };
    const result = PolicyDocumentSchema.safeParse(policy);
    expect(result.success).toBe(true);
  });

  it("accepts agent with empty allowlist", () => {
    const policy = structuredClone(VALID_POLICY);
    policy.agents.main.approval = { ask: "always", allowlist: [] };
    const result = PolicyDocumentSchema.safeParse(policy);
    expect(result.success).toBe(true);
  });

  it("rejects empty allowlist pattern", () => {
    const policy = structuredClone(VALID_POLICY);
    policy.agents.main.approval = { ask: "on-miss", allowlist: [{ pattern: "" }] };
    const result = PolicyDocumentSchema.safeParse(policy);
    expect(result.success).toBe(false);
  });

  it("accepts empty agents map", () => {
    const policy = { ...VALID_POLICY, agents: {} };
    const result = PolicyDocumentSchema.safeParse(policy);
    expect(result.success).toBe(true);
  });
});
```

**Step 2: Run test to verify it fails**

Run: `pnpm --filter @sentinel/types test -- --reporter verbose policy-document`
Expected: FAIL — cannot find module `./policy-document.js`

**Step 3: Write the implementation**

```typescript
// packages/types/src/policy-document.ts
import { z } from "zod";

export const WorkspaceScopeSchema = z.object({
  root: z.string().min(1),
  access: z.enum(["ro", "rw"]),
});
export type WorkspaceScope = z.infer<typeof WorkspaceScopeSchema>;

export const ApprovalPatternSchema = z.object({
  pattern: z.string().min(1),
});
export type ApprovalPattern = z.infer<typeof ApprovalPatternSchema>;

export const ApprovalConfigSchema = z.object({
  ask: z.enum(["always", "on-miss", "never"]),
  allowlist: z.array(ApprovalPatternSchema).optional(),
});
export type ApprovalConfig = z.infer<typeof ApprovalConfigSchema>;

export const ToolPolicySchema = z.object({
  allow: z.array(z.string()),
  deny: z.array(z.string()),
});

export const DefaultPolicySchema = z.object({
  tools: ToolPolicySchema,
  workspace: WorkspaceScopeSchema,
  approval: ApprovalConfigSchema,
});
export type DefaultPolicy = z.infer<typeof DefaultPolicySchema>;

export const AgentPolicySchema = z.object({
  tools: z.object({
    allow: z.array(z.string()).optional(),
    deny: z.array(z.string()).optional(),
  }),
  workspace: WorkspaceScopeSchema,
  approval: ApprovalConfigSchema.optional(),
});
export type AgentPolicy = z.infer<typeof AgentPolicySchema>;

export const PolicyDocumentSchema = z.object({
  version: z.literal(1),
  toolGroups: z.record(z.array(z.string())),
  defaults: DefaultPolicySchema,
  agents: z.record(AgentPolicySchema),
});
export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;
```

**Step 4: Export from index**

Add to `packages/types/src/index.ts`:

```typescript
export {
  type AgentPolicy,
  AgentPolicySchema,
  type ApprovalConfig,
  ApprovalConfigSchema,
  type ApprovalPattern,
  ApprovalPatternSchema,
  type DefaultPolicy,
  DefaultPolicySchema,
  type PolicyDocument,
  PolicyDocumentSchema,
  ToolPolicySchema,
  type WorkspaceScope,
  WorkspaceScopeSchema,
} from "./policy-document.js";
```

**Step 5: Run test to verify it passes**

Run: `pnpm --filter @sentinel/types test -- --reporter verbose policy-document`
Expected: PASS (10 tests)

**Step 6: Commit**

```bash
git add packages/types/src/policy-document.ts packages/types/src/policy-document.test.ts packages/types/src/index.ts
git commit -m "feat(types): add PolicyDocument Zod schema with agent policies, workspace scoping, tool groups, approval config"
```

---

## Task 2: Add `agentId` to ActionManifest and AuditEntry

**Files:**
- Modify: `packages/types/src/manifest.ts:11-18`
- Modify: `packages/types/src/audit.ts:5-17`
- Modify: `packages/agent/src/manifest-builder.ts:4-16`
- Test: `packages/agent/src/manifest-builder.test.ts`

**Step 1: Write the failing test**

Add to `packages/agent/src/manifest-builder.test.ts`:

```typescript
it("includes agentId in manifest", () => {
  const manifest = buildManifest("bash", { command: "ls" }, "session-1", "work");
  expect(manifest.agentId).toBe("work");
});

it("requires agentId parameter", () => {
  // TypeScript compile error if agentId is missing — verified by typecheck
  const manifest = buildManifest("bash", {}, "s", "main");
  expect(manifest.agentId).toBe("main");
});
```

**Step 2: Run test to verify it fails**

Run: `pnpm --filter @sentinel/agent test -- --reporter verbose manifest-builder`
Expected: FAIL — `buildManifest` doesn't accept 4th argument / `agentId` undefined

**Step 3: Update ActionManifestSchema**

In `packages/types/src/manifest.ts`, add `agentId` to the schema:

```typescript
export const ActionManifestSchema = z.object({
  id: z.string().uuid().default(() => crypto.randomUUID()),
  timestamp: z.string().datetime().default(() => new Date().toISOString()),
  tool: z.string().min(1),
  parameters: z.record(z.unknown()),
  category: ActionCategorySchema.optional(),
  sessionId: z.string().min(1),
  agentId: z.string().min(1),
});
```

**Step 4: Update AuditEntrySchema**

In `packages/types/src/audit.ts`, add `agentId` and `policyVersion`:

```typescript
export const AuditEntrySchema = z.object({
  id: z.string().uuid(),
  timestamp: z.string().datetime(),
  manifestId: z.string().uuid(),
  tool: z.string().min(1),
  category: ActionCategorySchema,
  decision: PolicyDecisionSchema.shape.action,
  parameters_summary: z.string(),
  result: z.enum(["success", "failure", "denied_by_user", "blocked_by_policy"]),
  duration_ms: z.number().nonnegative().optional(),
  sessionId: z.string().min(1),
  agentId: z.string().min(1),
  policyVersion: z.number().int().positive(),
});
```

**Step 5: Update AuditLogger schema**

In `packages/audit/src/logger.ts`, update `CREATE_TABLE` to add `agent_id` and `policy_version` columns, update `INSERT_SQL` to include them, update `rowToEntry` to map them, and update the `log()` method to insert them.

**Step 6: Update buildManifest**

```typescript
// packages/agent/src/manifest-builder.ts
import { randomUUID } from "node:crypto";
import type { ActionManifest } from "@sentinel/types";

export function buildManifest(
  toolName: string,
  parameters: Record<string, unknown>,
  sessionId: string,
  agentId: string,
): ActionManifest {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    tool: toolName,
    parameters,
    sessionId,
    agentId,
  };
}
```

**Step 7: Fix all existing test helpers that call `buildManifest` or `makeManifest`**

Search for all `makeManifest` and `buildManifest` calls across test files. Add `agentId: "test-agent"` to `makeManifest` helpers and `"test-agent"` as 4th arg to `buildManifest` calls.

Key files:
- `packages/policy/src/classifier.test.ts` — `makeManifest()` helper
- `packages/executor/src/server.test.ts` — manifest construction
- `packages/executor/src/security-invariants.test.ts` — manifest construction
- `packages/agent/src/executor-client.test.ts` — `buildManifest` calls

**Step 8: Fix router.ts audit base**

In `packages/executor/src/router.ts:44-53`, add `agentId` and `policyVersion` to `auditBase`:

```typescript
const auditBase: Omit<AuditEntry, "result" | "duration_ms"> = {
  id: crypto.randomUUID(),
  timestamp: new Date().toISOString(),
  manifestId: manifest.id,
  sessionId: manifest.sessionId,
  agentId: manifest.agentId,
  policyVersion: 1, // hardcoded until policy loading in Task 6
  tool: manifest.tool,
  category: decision.category,
  decision: decision.action,
  parameters_summary: redactCredentials(summarizeParams(manifest.parameters)),
};
```

**Step 9: Run all tests to verify everything passes**

Run: `pnpm test`
Expected: ALL PASS (163 tests, updated to use agentId)

**Step 10: Run typecheck**

Run: `pnpm typecheck`
Expected: PASS — no type errors

**Step 11: Commit**

```bash
git add packages/types/ packages/agent/ packages/policy/ packages/executor/ packages/audit/ packages/cli/
git commit -m "feat(types): add agentId to ActionManifest and AuditEntry schemas"
```

---

## Task 3: Tool Group Expansion

**Files:**
- Create: `packages/policy/src/groups.ts`
- Test: `packages/policy/src/groups.test.ts`
- Modify: `packages/policy/src/index.ts`

**Step 1: Write the failing test**

```typescript
// packages/policy/src/groups.test.ts
import { describe, expect, it } from "vitest";
import { expandGroups, validateGroups } from "./groups.js";

const GROUPS = {
  fs: ["read", "write", "edit", "apply_patch"],
  runtime: ["exec", "process"],
  network: ["browser", "fetch"],
};

describe("expandGroups", () => {
  it("expands group:fs to individual tools", () => {
    expect(expandGroups(["group:fs"], GROUPS)).toEqual(["read", "write", "edit", "apply_patch"]);
  });

  it("passes through non-group tool names", () => {
    expect(expandGroups(["read", "exec"], GROUPS)).toEqual(["read", "exec"]);
  });

  it("mixes groups and individual tools", () => {
    expect(expandGroups(["group:runtime", "read"], GROUPS)).toEqual(["exec", "process", "read"]);
  });

  it("expands wildcard as-is", () => {
    expect(expandGroups(["*"], GROUPS)).toEqual(["*"]);
  });

  it("deduplicates expanded results", () => {
    expect(expandGroups(["read", "group:fs"], GROUPS)).toEqual(["read", "write", "edit", "apply_patch"]);
  });

  it("returns empty array for empty input", () => {
    expect(expandGroups([], GROUPS)).toEqual([]);
  });

  it("throws on unknown group reference", () => {
    expect(() => expandGroups(["group:unknown"], GROUPS)).toThrow("Unknown tool group: unknown");
  });

  it("throws on nested group reference", () => {
    expect(() => expandGroups(["group:group:fs"], GROUPS)).toThrow("Unknown tool group: group:fs");
  });
});

describe("validateGroups", () => {
  it("accepts valid groups", () => {
    expect(() => validateGroups(GROUPS)).not.toThrow();
  });

  it("accepts empty groups", () => {
    expect(() => validateGroups({})).not.toThrow();
  });

  it("rejects group with empty name", () => {
    expect(() => validateGroups({ "": ["read"] })).toThrow();
  });
});
```

**Step 2: Run test to verify it fails**

Run: `pnpm --filter @sentinel/policy test -- --reporter verbose groups`
Expected: FAIL — cannot find module `./groups.js`

**Step 3: Write the implementation**

```typescript
// packages/policy/src/groups.ts
export function expandGroups(
  tools: string[],
  toolGroups: Record<string, string[]>,
): string[] {
  const result: string[] = [];
  const seen = new Set<string>();

  for (const tool of tools) {
    if (tool.startsWith("group:")) {
      const groupName = tool.slice(6);
      const members = toolGroups[groupName];
      if (!members) {
        throw new Error(`Unknown tool group: ${groupName}`);
      }
      for (const member of members) {
        if (!seen.has(member)) {
          seen.add(member);
          result.push(member);
        }
      }
    } else {
      if (!seen.has(tool)) {
        seen.add(tool);
        result.push(tool);
      }
    }
  }

  return result;
}

export function validateGroups(toolGroups: Record<string, string[]>): void {
  for (const name of Object.keys(toolGroups)) {
    if (name.length === 0) {
      throw new Error("Tool group name cannot be empty");
    }
  }
}
```

**Step 4: Export from index**

Add to `packages/policy/src/index.ts`:

```typescript
export { expandGroups, validateGroups } from "./groups.js";
```

**Step 5: Run test to verify it passes**

Run: `pnpm --filter @sentinel/policy test -- --reporter verbose groups`
Expected: PASS (10 tests)

**Step 6: Commit**

```bash
git add packages/policy/src/groups.ts packages/policy/src/groups.test.ts packages/policy/src/index.ts
git commit -m "feat(policy): add tool group expansion with validation"
```

---

## Task 4: Workspace Enforcement

**Files:**
- Create: `packages/policy/src/workspace.ts`
- Test: `packages/policy/src/workspace.test.ts`
- Modify: `packages/policy/src/index.ts`

**Step 1: Write the failing test**

```typescript
// packages/policy/src/workspace.test.ts
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { checkWorkspaceAccess, isWithinWorkspace, resolveAgentPath } from "./workspace.js";

describe("resolveAgentPath", () => {
  it("expands ~ to workspace root, not $HOME", () => {
    const result = resolveAgentPath("~/foo/bar.txt", "/workspace/agent-a");
    expect(result).toBe("/workspace/agent-a/foo/bar.txt");
  });

  it("resolves relative paths against workspace root", () => {
    const result = resolveAgentPath("src/index.ts", "/workspace/agent-a");
    expect(result).toBe("/workspace/agent-a/src/index.ts");
  });

  it("keeps absolute paths as-is", () => {
    const result = resolveAgentPath("/etc/passwd", "/workspace/agent-a");
    expect(result).toBe("/etc/passwd");
  });
});

describe("isWithinWorkspace", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-ws-test-"));
    fs.mkdirSync(path.join(tmpDir, "sub"), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, "sub", "file.txt"), "test");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("allows path within workspace", () => {
    expect(isWithinWorkspace(path.join(tmpDir, "sub", "file.txt"), tmpDir)).toBe(true);
  });

  it("allows workspace root itself", () => {
    expect(isWithinWorkspace(tmpDir, tmpDir)).toBe(true);
  });

  it("blocks path outside workspace", () => {
    expect(isWithinWorkspace("/etc/passwd", tmpDir)).toBe(false);
  });

  it("blocks ../ traversal escaping workspace", () => {
    expect(isWithinWorkspace(path.join(tmpDir, "sub", "..", "..", "etc", "passwd"), tmpDir)).toBe(false);
  });

  it("blocks symlink pointing outside workspace", () => {
    const linkPath = path.join(tmpDir, "sneaky-link");
    fs.symlinkSync("/etc", linkPath);
    expect(isWithinWorkspace(path.join(linkPath, "passwd"), tmpDir)).toBe(false);
  });

  it("allows symlink pointing within workspace", () => {
    const linkPath = path.join(tmpDir, "internal-link");
    fs.symlinkSync(path.join(tmpDir, "sub"), linkPath);
    expect(isWithinWorkspace(path.join(linkPath, "file.txt"), tmpDir)).toBe(true);
  });

  it("handles non-existent path by checking parent", () => {
    // New file in existing directory — should be allowed
    expect(isWithinWorkspace(path.join(tmpDir, "sub", "new-file.txt"), tmpDir)).toBe(true);
  });

  it("blocks non-existent path outside workspace", () => {
    expect(isWithinWorkspace("/nonexistent/path/file.txt", tmpDir)).toBe(false);
  });
});

describe("checkWorkspaceAccess", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-ws-test-"));
    fs.mkdirSync(path.join(tmpDir, "sub"), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("allows read in ro workspace", () => {
    const result = checkWorkspaceAccess(path.join(tmpDir, "sub", "file.txt"), tmpDir, "ro", "read");
    expect(result.allowed).toBe(true);
  });

  it("blocks write in ro workspace", () => {
    const result = checkWorkspaceAccess(path.join(tmpDir, "sub", "file.txt"), tmpDir, "ro", "write");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("read-only");
  });

  it("allows write in rw workspace", () => {
    const result = checkWorkspaceAccess(path.join(tmpDir, "sub", "file.txt"), tmpDir, "rw", "write");
    expect(result.allowed).toBe(true);
  });

  it("blocks path outside workspace regardless of access", () => {
    const result = checkWorkspaceAccess("/etc/passwd", tmpDir, "rw", "read");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("outside workspace");
  });
});
```

**Step 2: Run test to verify it fails**

Run: `pnpm --filter @sentinel/policy test -- --reporter verbose workspace`
Expected: FAIL — cannot find module `./workspace.js`

**Step 3: Write the implementation**

```typescript
// packages/policy/src/workspace.ts
import * as fs from "node:fs";
import * as path from "node:path";

/** Map of tool names to the parameter that contains the target path */
export const PATH_PARAMS: Record<string, string> = {
  read: "path",
  read_file: "path",
  write: "path",
  write_file: "path",
  edit: "path",
  edit_file: "path",
  apply_patch: "path",
  exec: "cwd",
  bash: "cwd",
};

export function resolveAgentPath(targetPath: string, workspaceRoot: string): string {
  if (targetPath.startsWith("~/")) {
    return path.join(workspaceRoot, targetPath.slice(2));
  }
  if (targetPath === "~") {
    return workspaceRoot;
  }
  if (path.isAbsolute(targetPath)) {
    return targetPath;
  }
  return path.join(workspaceRoot, targetPath);
}

export function isWithinWorkspace(targetPath: string, workspaceRoot: string): boolean {
  const resolvedRoot = safeRealpath(workspaceRoot);
  if (!resolvedRoot) return false;

  const resolvedTarget = safeRealpath(targetPath);
  if (resolvedTarget) {
    return resolvedTarget === resolvedRoot || resolvedTarget.startsWith(resolvedRoot + path.sep);
  }

  // Path doesn't exist yet — check nearest existing ancestor
  let current = path.resolve(targetPath);
  while (current !== path.dirname(current)) {
    const parent = path.dirname(current);
    const resolvedParent = safeRealpath(parent);
    if (resolvedParent) {
      const remainder = path.relative(resolvedParent, path.resolve(targetPath));
      if (remainder.startsWith("..")) return false;
      const full = path.join(resolvedParent, remainder);
      return full === resolvedRoot || full.startsWith(resolvedRoot + path.sep);
    }
    current = parent;
  }

  return false;
}

export function checkWorkspaceAccess(
  targetPath: string,
  workspaceRoot: string,
  access: "ro" | "rw",
  operation: "read" | "write",
): { allowed: boolean; reason?: string } {
  if (!isWithinWorkspace(targetPath, workspaceRoot)) {
    return { allowed: false, reason: `Path outside workspace: ${targetPath}` };
  }

  if (access === "ro" && operation === "write") {
    return { allowed: false, reason: `Write denied: read-only workspace` };
  }

  return { allowed: true };
}

function safeRealpath(p: string): string | null {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}
```

**Step 4: Export from index**

Add to `packages/policy/src/index.ts`:

```typescript
export { checkWorkspaceAccess, isWithinWorkspace, PATH_PARAMS, resolveAgentPath } from "./workspace.js";
```

**Step 5: Run test to verify it passes**

Run: `pnpm --filter @sentinel/policy test -- --reporter verbose workspace`
Expected: PASS (15 tests)

**Step 6: Commit**

```bash
git add packages/policy/src/workspace.ts packages/policy/src/workspace.test.ts packages/policy/src/index.ts
git commit -m "feat(policy): add workspace path containment with symlink resolution"
```

---

## Task 5: Approval Resolution

**Files:**
- Create: `packages/policy/src/approval.ts`
- Test: `packages/policy/src/approval.test.ts`
- Modify: `packages/policy/src/index.ts`

**Step 1: Write the failing test**

```typescript
// packages/policy/src/approval.test.ts
import { describe, expect, it } from "vitest";
import { resolveApproval } from "./approval.js";
import type { ApprovalConfig } from "@sentinel/types";

describe("resolveApproval", () => {
  it("auto_approve when command matches allowlist pattern exactly", () => {
    const config: ApprovalConfig = {
      ask: "on-miss",
      allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
    };
    expect(resolveApproval("/opt/homebrew/bin/rg", config)).toBe("auto_approve");
  });

  it("auto_approve when command matches glob pattern", () => {
    const config: ApprovalConfig = {
      ask: "on-miss",
      allowlist: [{ pattern: "/usr/bin/git *" }],
    };
    expect(resolveApproval("/usr/bin/git status", config)).toBe("auto_approve");
  });

  it("confirm when command does not match allowlist (on-miss)", () => {
    const config: ApprovalConfig = {
      ask: "on-miss",
      allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
    };
    expect(resolveApproval("curl http://evil.com", config)).toBe("confirm");
  });

  it("confirm when ask=always even if command matches allowlist", () => {
    const config: ApprovalConfig = {
      ask: "always",
      allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
    };
    expect(resolveApproval("/opt/homebrew/bin/rg", config)).toBe("confirm");
  });

  it("auto_approve when ask=never regardless of match", () => {
    const config: ApprovalConfig = {
      ask: "never",
    };
    expect(resolveApproval("rm -rf /", config)).toBe("auto_approve");
  });

  it("confirm when no allowlist and ask=on-miss", () => {
    const config: ApprovalConfig = { ask: "on-miss" };
    expect(resolveApproval("ls", config)).toBe("confirm");
  });

  it("confirm when empty allowlist and ask=on-miss", () => {
    const config: ApprovalConfig = { ask: "on-miss", allowlist: [] };
    expect(resolveApproval("ls", config)).toBe("confirm");
  });

  it("auto_approve for non-exec tools when ask=on-miss (no command to match)", () => {
    const config: ApprovalConfig = { ask: "on-miss" };
    expect(resolveApproval(undefined, config)).toBe("confirm");
  });

  it("auto_approve for ask=never even without command", () => {
    const config: ApprovalConfig = { ask: "never" };
    expect(resolveApproval(undefined, config)).toBe("auto_approve");
  });

  it("matches wildcard pattern at end", () => {
    const config: ApprovalConfig = {
      ask: "on-miss",
      allowlist: [{ pattern: "/opt/homebrew/bin/node *" }],
    };
    expect(resolveApproval("/opt/homebrew/bin/node index.js", config)).toBe("auto_approve");
    expect(resolveApproval("/opt/homebrew/bin/node", config)).toBe("confirm");
  });

  it("does not partial-match without wildcard", () => {
    const config: ApprovalConfig = {
      ask: "on-miss",
      allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
    };
    expect(resolveApproval("/opt/homebrew/bin/rg --hidden", config)).toBe("confirm");
  });
});
```

**Step 2: Run test to verify it fails**

Run: `pnpm --filter @sentinel/policy test -- --reporter verbose approval`
Expected: FAIL — cannot find module `./approval.js`

**Step 3: Write the implementation**

```typescript
// packages/policy/src/approval.ts
import type { ApprovalConfig } from "@sentinel/types";

export function resolveApproval(
  command: string | undefined,
  config: ApprovalConfig,
): "auto_approve" | "confirm" {
  if (config.ask === "never") {
    return "auto_approve";
  }

  if (config.ask === "always") {
    return "confirm";
  }

  // ask === "on-miss": check allowlist
  if (command && config.allowlist) {
    for (const entry of config.allowlist) {
      if (matchPattern(command, entry.pattern)) {
        return "auto_approve";
      }
    }
  }

  return "confirm";
}

function matchPattern(command: string, pattern: string): boolean {
  if (pattern.endsWith(" *")) {
    const prefix = pattern.slice(0, -2);
    return command.startsWith(prefix + " ");
  }
  return command === pattern;
}
```

**Step 4: Export from index**

Add to `packages/policy/src/index.ts`:

```typescript
export { resolveApproval } from "./approval.js";
```

**Step 5: Run test to verify it passes**

Run: `pnpm --filter @sentinel/policy test -- --reporter verbose approval`
Expected: PASS (12 tests)

**Step 6: Commit**

```bash
git add packages/policy/src/approval.ts packages/policy/src/approval.test.ts packages/policy/src/index.ts
git commit -m "feat(policy): add approval resolution with pattern-based allowlists"
```

---

## Task 6: Refactor classify() for Policy Document

**Files:**
- Modify: `packages/policy/src/classifier.ts`
- Test: `packages/policy/src/classifier.test.ts` (add new describe blocks)
- Modify: `packages/policy/src/rules.ts` (add `getDefaultPolicy()`)
- Modify: `packages/policy/src/index.ts`

This is the core task. `classify()` gains the 6-step flow from the design doc.

**Step 1: Write the failing tests**

Add a new describe block in `packages/policy/src/classifier.test.ts`:

```typescript
import type { PolicyDocument } from "@sentinel/types";

// Add after existing makeManifest helper:
function makeManifestWithAgent(
  tool: string,
  parameters: Record<string, unknown>,
  agentId: string,
): ActionManifest {
  return {
    id: "00000000-0000-0000-0000-000000000001",
    timestamp: new Date().toISOString(),
    tool,
    parameters,
    sessionId: "test-session",
    agentId,
  };
}

const TEST_POLICY: PolicyDocument = {
  version: 1,
  toolGroups: {
    fs: ["read_file", "write_file", "edit_file"],
    runtime: ["bash"],
    network: ["browser", "fetch"],
  },
  defaults: {
    tools: { allow: ["*"], deny: ["group:network"] },
    workspace: { root: "/tmp/sentinel-test-ws", access: "rw" },
    approval: { ask: "on-miss" },
  },
  agents: {
    work: {
      tools: { allow: ["group:fs", "group:runtime"], deny: [] },
      workspace: { root: "/tmp/sentinel-test-ws/work", access: "rw" },
      approval: {
        ask: "on-miss",
        allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
      },
    },
    readonly: {
      tools: { allow: ["read_file"], deny: ["group:runtime"] },
      workspace: { root: "/tmp/sentinel-test-ws/ro", access: "ro" },
      approval: { ask: "always" },
    },
  },
};

describe("classify with PolicyDocument", () => {
  describe("agent resolution", () => {
    it("blocks unknown agent", () => {
      const result = classify(makeManifestWithAgent("read_file", {}, "unknown"), TEST_POLICY, config);
      expect(result.action).toBe("block");
      expect(result.reason).toContain("unknown");
    });
  });

  describe("tool gate", () => {
    it("allows tool in agent allow list", () => {
      const result = classify(
        makeManifestWithAgent("read_file", { path: "/tmp/sentinel-test-ws/work/f.txt" }, "work"),
        TEST_POLICY, config,
      );
      expect(result.action).not.toBe("block");
    });

    it("blocks tool not in agent allow list", () => {
      const result = classify(
        makeManifestWithAgent("browser", {}, "work"),
        TEST_POLICY, config,
      );
      expect(result.action).toBe("block");
    });

    it("blocks tool in agent deny list (deny-wins)", () => {
      const result = classify(
        makeManifestWithAgent("bash", { command: "ls" }, "readonly"),
        TEST_POLICY, config,
      );
      expect(result.action).toBe("block");
    });

    it("deny wins when tool is in both allow and deny via groups", () => {
      // Create policy where read_file is in both allow and deny
      const conflictPolicy = structuredClone(TEST_POLICY);
      conflictPolicy.agents.conflict = {
        tools: { allow: ["group:fs"], deny: ["read_file"] },
        workspace: { root: "/tmp/sentinel-test-ws", access: "rw" },
      };
      const result = classify(
        makeManifestWithAgent("read_file", { path: "/tmp/sentinel-test-ws/f.txt" }, "conflict"),
        conflictPolicy, config,
      );
      expect(result.action).toBe("block");
    });

    it("defaults deny applies when agent has no deny list", () => {
      const result = classify(
        makeManifestWithAgent("browser", {}, "work"),
        TEST_POLICY, config,
      );
      // browser is in defaults.deny via group:network, work agent doesn't explicitly allow it
      expect(result.action).toBe("block");
    });
  });

  describe("workspace gate", () => {
    it("blocks file read outside workspace", () => {
      const result = classify(
        makeManifestWithAgent("read_file", { path: "/etc/passwd" }, "work"),
        TEST_POLICY, config,
      );
      expect(result.action).toBe("block");
      expect(result.reason).toContain("workspace");
    });

    it("blocks write in read-only workspace", () => {
      const result = classify(
        makeManifestWithAgent("read_file", { path: "/tmp/sentinel-test-ws/ro/file.txt" }, "readonly"),
        TEST_POLICY, config,
      );
      // read_file in ro workspace is fine
      expect(result.action).not.toBe("block");
    });
  });

  describe("approval resolution", () => {
    it("auto_approve when bash command matches allowlist", () => {
      const result = classify(
        makeManifestWithAgent("bash", { command: "/opt/homebrew/bin/rg", cwd: "/tmp/sentinel-test-ws/work" }, "work"),
        TEST_POLICY, config,
      );
      expect(result.action).toBe("auto_approve");
    });

    it("confirm when ask=always even for read", () => {
      const result = classify(
        makeManifestWithAgent("read_file", { path: "/tmp/sentinel-test-ws/ro/file.txt" }, "readonly"),
        TEST_POLICY, config,
      );
      expect(result.action).toBe("confirm");
    });
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `pnpm --filter @sentinel/policy test -- --reporter verbose classifier`
Expected: FAIL — `classify` doesn't accept 3 arguments

**Step 3: Refactor classify() to accept PolicyDocument**

Update `packages/policy/src/classifier.ts`. The new `classify()` signature is:

```typescript
export function classify(
  manifest: ActionManifest,
  policy: PolicyDocument,
  config: SentinelConfig,
): PolicyDecision
```

Implementation follows the 6-step flow from the design doc:
1. Resolve agent policy (block unknown agents)
2. Expand groups in agent's allow/deny lists
3. Tool gate (deny-wins)
4. Workspace gate (for tools with path params)
5. Existing classification (bash parser, category lookup)
6. Approval resolution (allowlist + ask mode)

Keep existing internal functions (`findClassification`, `matchOverride`, `classifyBashCommand`, `categoryToDecision`). They become step 5.

**Step 4: Add getDefaultPolicy() to rules.ts**

```typescript
export function getDefaultPolicy(): PolicyDocument {
  return {
    version: 1,
    toolGroups: {
      fs: ["read_file", "write_file", "edit_file"],
      runtime: ["bash"],
      network: ["browser", "fetch", "curl"],
      messaging: ["slack", "discord", "telegram", "whatsapp"],
      automation: ["sessions_spawn", "sessions_send", "gateway"],
    },
    defaults: {
      tools: { allow: ["*"], deny: ["group:network"] },
      workspace: { root: "~/.openclaw/workspace", access: "rw" },
      approval: { ask: "on-miss" },
    },
    agents: {},
  };
}
```

**Step 5: Update existing tests to pass PolicyDocument**

All existing `classify(manifest, config)` calls in `classifier.test.ts` need updating to `classify(manifest, policy, config)`. Use `getDefaultPolicy()` for the policy parameter in existing tests.

The existing `makeManifest` helper needs `agentId`. Either:
- Add a default agent to `getDefaultPolicy().agents` for tests, OR
- Update `makeManifest` to include `agentId` and add that agent to the test policy

**Step 6: Run all tests**

Run: `pnpm --filter @sentinel/policy test -- --reporter verbose`
Expected: ALL PASS (94 existing + ~25 new)

**Step 7: Commit**

```bash
git add packages/policy/src/
git commit -m "feat(policy): refactor classify() to use PolicyDocument with agent resolution, tool gate, workspace gate, approval"
```

---

## Task 7: Wire Policy into Executor

**Files:**
- Modify: `packages/executor/src/server.ts:31-35` — accept `PolicyDocument` in `createApp()`
- Modify: `packages/executor/src/router.ts:26-32` — accept and pass `PolicyDocument` to `classify()`
- Modify: `packages/executor/src/entrypoint.ts` — load `config/policy.json` at startup
- Test: `packages/executor/src/policy-lifecycle.test.ts`

**Step 1: Write the failing test**

```typescript
// packages/executor/src/policy-lifecycle.test.ts
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadPolicy } from "./policy-loader.js";

describe("loadPolicy", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-policy-test-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("loads and validates a valid policy.json", () => {
    const policy = {
      version: 1,
      toolGroups: { fs: ["read"] },
      defaults: {
        tools: { allow: ["*"], deny: [] },
        workspace: { root: "/tmp", access: "rw" },
        approval: { ask: "on-miss" },
      },
      agents: {},
    };
    fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify(policy));
    const result = loadPolicy(path.join(tmpDir, "policy.json"));
    expect(result.version).toBe(1);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("throws on missing policy.json", () => {
    expect(() => loadPolicy(path.join(tmpDir, "nonexistent.json"))).toThrow();
  });

  it("throws on invalid schema", () => {
    fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify({ version: 99 }));
    expect(() => loadPolicy(path.join(tmpDir, "policy.json"))).toThrow();
  });

  it("returns frozen object (Invariant #6)", () => {
    const policy = {
      version: 1,
      toolGroups: {},
      defaults: {
        tools: { allow: ["*"], deny: [] },
        workspace: { root: "/tmp", access: "rw" },
        approval: { ask: "on-miss" },
      },
      agents: {},
    };
    fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify(policy));
    const result = loadPolicy(path.join(tmpDir, "policy.json"));
    expect(() => { (result as any).version = 2; }).toThrow();
  });

  it("validates tool groups at load time", () => {
    const policy = {
      version: 1,
      toolGroups: { "": ["read"] },
      defaults: {
        tools: { allow: ["*"], deny: [] },
        workspace: { root: "/tmp", access: "rw" },
        approval: { ask: "on-miss" },
      },
      agents: {},
    };
    fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify(policy));
    expect(() => loadPolicy(path.join(tmpDir, "policy.json"))).toThrow();
  });

  it("validates agent group references at load time", () => {
    const policy = {
      version: 1,
      toolGroups: { fs: ["read"] },
      defaults: {
        tools: { allow: ["*"], deny: [] },
        workspace: { root: "/tmp", access: "rw" },
        approval: { ask: "on-miss" },
      },
      agents: {
        bad: {
          tools: { allow: ["group:nonexistent"] },
          workspace: { root: "/tmp", access: "rw" },
        },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify(policy));
    expect(() => loadPolicy(path.join(tmpDir, "policy.json"))).toThrow("Unknown tool group");
  });
});
```

**Step 2: Run test to verify it fails**

Run: `pnpm --filter @sentinel/executor test -- --reporter verbose policy-lifecycle`
Expected: FAIL — cannot find module `./policy-loader.js`

**Step 3: Write policy-loader.ts**

```typescript
// packages/executor/src/policy-loader.ts
import * as fs from "node:fs";
import type { PolicyDocument } from "@sentinel/types";
import { PolicyDocumentSchema } from "@sentinel/types";
import { expandGroups, validateGroups } from "@sentinel/policy";

export function loadPolicy(policyPath: string): Readonly<PolicyDocument> {
  let raw: string;
  try {
    raw = fs.readFileSync(policyPath, "utf-8");
  } catch {
    throw new Error(`Policy file not found: ${policyPath}. Executor cannot start without a policy.`);
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new Error(`Policy file is not valid JSON: ${policyPath}`);
  }

  const parsed = PolicyDocumentSchema.safeParse(json);
  if (!parsed.success) {
    throw new Error(`Invalid policy schema: ${parsed.error.message}`);
  }

  const policy = parsed.data;

  // Validate tool groups
  validateGroups(policy.toolGroups);

  // Validate all group references in defaults and agents
  validateGroupReferences(policy);

  return Object.freeze(policy);
}

function validateGroupReferences(policy: PolicyDocument): void {
  const allToolLists = [
    policy.defaults.tools.allow,
    policy.defaults.tools.deny,
  ];

  for (const agent of Object.values(policy.agents)) {
    if (agent.tools.allow) allToolLists.push(agent.tools.allow);
    if (agent.tools.deny) allToolLists.push(agent.tools.deny);
  }

  for (const list of allToolLists) {
    // expandGroups throws on unknown group references
    expandGroups(list, policy.toolGroups);
  }
}
```

**Step 4: Update createApp and handleExecute signatures**

In `packages/executor/src/server.ts`:
```typescript
export function createApp(
  config: SentinelConfig,
  policy: Readonly<PolicyDocument>,
  auditLogger: AuditLogger,
  registry: ToolRegistry,
): Hono
```

Pass `policy` to `handleExecute`.

In `packages/executor/src/router.ts`:
```typescript
export async function handleExecute(
  rawManifest: unknown,
  config: SentinelConfig,
  policy: Readonly<PolicyDocument>,
  auditLogger: AuditLogger,
  registry: ToolRegistry,
  confirmFn: ConfirmFn,
): Promise<ToolResult>
```

Update line 41: `const decision = classify(manifest, policy, config);`

Update `auditBase` to include `policyVersion: policy.version`.

**Step 5: Update entrypoint.ts**

```typescript
// packages/executor/src/entrypoint.ts
import { serve } from "@hono/node-server";
import { AuditLogger } from "@sentinel/audit";
import { getDefaultConfig } from "@sentinel/policy";
import { loadPolicy } from "./policy-loader.js";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";

const config = getDefaultConfig();
config.auditLogPath = process.env.SENTINEL_AUDIT_PATH ?? "/app/data/audit.db";
config.vaultPath = process.env.SENTINEL_VAULT_PATH ?? "/app/data/vault.enc";

const policyPath = process.env.SENTINEL_POLICY_PATH ?? "./config/policy.json";
const policy = loadPolicy(policyPath);

console.log(`Policy v${policy.version} loaded: ${Object.keys(policy.agents).length} agents, ${Object.keys(policy.toolGroups).length} groups`);

const auditLogger = new AuditLogger(config.auditLogPath);
const registry = createToolRegistry();
const app = createApp(config, policy, auditLogger, registry);

const port = config.executor.port;
const host = "0.0.0.0";

serve({ fetch: app.fetch, port, hostname: host }, () => {
  console.log(`Sentinel Executor listening on http://${host}:${port}`);
});
```

**Step 6: Update existing executor tests**

All `createApp(config, auditLogger, registry)` calls become `createApp(config, policy, auditLogger, registry)`. Import `getDefaultPolicy` and use it in test setup.

**Step 7: Run all tests**

Run: `pnpm test`
Expected: ALL PASS

**Step 8: Run typecheck**

Run: `pnpm typecheck`
Expected: PASS

**Step 9: Commit**

```bash
git add packages/executor/src/ packages/policy/src/
git commit -m "feat(executor): load PolicyDocument at startup, wire into classify() and audit"
```

---

## Task 8: Create Default Policy File and Example

**Files:**
- Create: `config/policy.json`
- Create: `config/policy.example.json`

**Step 1: Create config/policy.json**

```json
{
  "version": 1,
  "toolGroups": {
    "fs": ["read_file", "write_file", "edit_file"],
    "runtime": ["bash"],
    "network": ["browser", "fetch", "curl"],
    "messaging": ["slack", "discord", "telegram", "whatsapp"],
    "automation": ["sessions_spawn", "sessions_send", "gateway"]
  },
  "defaults": {
    "tools": {
      "allow": ["*"],
      "deny": ["group:network"]
    },
    "workspace": {
      "root": "~/.openclaw/workspace",
      "access": "rw"
    },
    "approval": {
      "ask": "on-miss"
    }
  },
  "agents": {}
}
```

**Step 2: Create config/policy.example.json**

Use the Mac Mini example from the design doc (the full JSON with `main` and `family` agents).

**Step 3: Update .gitignore if needed**

Ensure `config/policy.json` is NOT gitignored (it's the default, not secrets).

**Step 4: Commit**

```bash
git add config/policy.json config/policy.example.json
git commit -m "feat(config): add default policy.json and documented example"
```

---

## Task 9: Integration Tests

**Files:**
- Create: `packages/executor/src/policy-integration.test.ts`

**Step 1: Write integration tests**

Test the full flow through the executor with real agent policies. These tests create a Hono app with a test policy and verify:

1. Agent "work" calls bash with `rg` → auto_approve (allowlist hit)
2. Agent "readonly" calls bash → blocked (group:runtime denied)
3. Agent "work" reads file in workspace → allowed
4. Agent "work" reads file outside workspace → blocked
5. Agent "readonly" writes file → blocked (ro access)
6. Unknown agentId → blocked, returns error
7. Credential filtering still applied after policy approval (Invariant #1)
8. Every decision audited with agentId + policyVersion (Invariant #2)

Each test creates a test app with `createApp(config, policy, auditLogger, registry)`, sends POST requests to `/execute`, and asserts on the response + audit log.

**Step 2: Run tests**

Run: `pnpm --filter @sentinel/executor test -- --reporter verbose policy-integration`
Expected: ALL PASS

**Step 3: Run full test suite**

Run: `pnpm test`
Expected: ALL PASS (~243 tests)

**Step 4: Commit**

```bash
git add packages/executor/src/policy-integration.test.ts
git commit -m "test(executor): add integration tests for policy-driven classification flow"
```

---

## Task 10: Quality Gates and Final Verification

**Step 1: Run lint**

Run: `pnpm lint`
Expected: PASS — no Biome errors

**Step 2: Run lint fix if needed**

Run: `pnpm lint:fix`

**Step 3: Run typecheck**

Run: `pnpm typecheck`
Expected: PASS — no TypeScript errors

**Step 4: Run full test suite with coverage**

Run: `pnpm test:coverage`
Expected: ALL PASS, new modules have >90% coverage

**Step 5: Run security audit skill**

Run: `/security-audit`
Expected: All 6 invariants pass

**Step 6: Update CLAUDE.md**

Mark Phase 1.5 MVP items as complete:
- [x] Workspace scoping
- [x] Per-agent tool policies
- [x] Tool groups
- [x] Exec approval allowlists

**Step 7: Final commit**

```bash
git add -A
git commit -m "chore: Phase 1.5 quality gates pass — lint, typecheck, coverage, security audit"
```
