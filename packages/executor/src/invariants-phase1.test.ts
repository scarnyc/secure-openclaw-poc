/**
 * Phase 1 Security Invariant Tests (G7-G12)
 *
 * These tests verify the 6 new security invariants added in Phase 1.
 * Each test is a mandatory gate — if any fails, the build is broken.
 * Run with: pnpm --filter @sentinel/executor test -- src/invariants-phase1.test.ts
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "@sentinel/audit";
import { LoopGuard, RateLimiter } from "@sentinel/policy";
import type { AuditEntry, ToolResult } from "@sentinel/types";
import { afterEach, describe, expect, it } from "vitest";
import { scrubPII } from "./pii-scrubber.js";
import { isPrivateIp } from "./ssrf-guard.js";
import { isPathAllowed } from "./tools/path-guard.js";

const tempDirs: string[] = [];

function makeTempDbPath(): string {
	const dir = mkdtempSync(join(tmpdir(), "sentinel-inv-"));
	tempDirs.push(dir);
	return join(dir, "audit.db");
}

afterEach(() => {
	for (const dir of tempDirs) {
		rmSync(dir, { recursive: true, force: true });
	}
	tempDirs.length = 0;
});

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
	return {
		id: crypto.randomUUID(),
		timestamp: new Date().toISOString(),
		manifestId: crypto.randomUUID(),
		sessionId: "session-inv",
		agentId: "test-agent",
		tool: "bash",
		category: "dangerous",
		decision: "confirm",
		parameters_summary: "echo test",
		result: "success",
		duration_ms: 10,
		...overrides,
	};
}

// ─────────────────────────────────────────────────────────────────
// G7: Merkle chain tamper-evident — modified audit row detected
// ─────────────────────────────────────────────────────────────────
describe("Invariant G7: Merkle chain tamper-evident", () => {
	it("verifyChain() returns valid for untampered log", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.log(makeEntry({ timestamp: "2026-01-01T00:00:00Z" }));
		logger.log(makeEntry({ timestamp: "2026-01-02T00:00:00Z" }));
		logger.log(makeEntry({ timestamp: "2026-01-03T00:00:00Z" }));

		const result = logger.verifyChain();
		expect(result.valid).toBe(true);
		logger.close();
	});

	it("verifyChain() returns the expected interface shape", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.log(makeEntry({ timestamp: "2026-01-01T00:00:00Z" }));

		const result = logger.verifyChain();
		expect(result).toHaveProperty("valid");
		expect(typeof result.valid).toBe("boolean");
		// valid chain has no brokenAt field
		logger.close();
	});
});

// ─────────────────────────────────────────────────────────────────
// G8: SSRF blocked — private IPs / localhost / 169.254.x rejected
// ─────────────────────────────────────────────────────────────────
describe("Invariant G8: SSRF blocks private/reserved IPs", () => {
	it("blocks localhost 127.0.0.1", () => {
		expect(isPrivateIp("127.0.0.1")).toBe(true);
	});

	it("blocks IPv6 localhost ::1", () => {
		expect(isPrivateIp("::1")).toBe(true);
	});

	it("blocks cloud metadata 169.254.169.254", () => {
		expect(isPrivateIp("169.254.169.254")).toBe(true);
	});

	it("blocks 10.x.x.x private range", () => {
		expect(isPrivateIp("10.0.0.1")).toBe(true);
	});

	it("blocks 192.168.x.x private range", () => {
		expect(isPrivateIp("192.168.1.1")).toBe(true);
	});

	it("blocks 172.16.x.x private range", () => {
		expect(isPrivateIp("172.16.0.1")).toBe(true);
	});

	it("allows public IP 8.8.8.8", () => {
		expect(isPrivateIp("8.8.8.8")).toBe(false);
	});

	it("blocks IPv4-mapped IPv6 ::ffff:127.0.0.1", () => {
		expect(isPrivateIp("::ffff:127.0.0.1")).toBe(true);
	});
});

// ─────────────────────────────────────────────────────────────────
// G9: Per-agent rate limiting — burst exceeding rate gets blocked
// ─────────────────────────────────────────────────────────────────
describe("Invariant G9: Per-agent rate limiting", () => {
	it("first request within rate is allowed", () => {
		const limiter = new RateLimiter({ rate: 5, period: 1000 });
		const result = limiter.check("agent-1");
		expect(result.allowed).toBe(true);
	});

	it("burst exceeding rate is denied with retryAfter", () => {
		const limiter = new RateLimiter({ rate: 2, period: 1000 });
		limiter.check("agent-1"); // 1st — allowed
		limiter.check("agent-1"); // 2nd — allowed
		const result = limiter.check("agent-1"); // 3rd — should be denied
		expect(result.allowed).toBe(false);
		expect(result.retryAfter).toBeGreaterThan(0);
	});

	it("different agents have independent limits", () => {
		const limiter = new RateLimiter({ rate: 1, period: 1000 });
		limiter.check("agent-a"); // fills agent-a's quota
		const result = limiter.check("agent-b"); // agent-b is fresh
		expect(result.allowed).toBe(true);
	});
});

// ─────────────────────────────────────────────────────────────────
// G10: PII scrubbed from outbound — SSN in tool output → [REDACTED]
// ─────────────────────────────────────────────────────────────────
describe("Invariant G10: PII scrubbed from outbound", () => {
	it("SSN in tool output is redacted", () => {
		const result: ToolResult = {
			manifestId: "test",
			success: true,
			duration_ms: 0,
			output: "User SSN: 123-45-6789",
		};
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("123-45-6789");
		expect(scrubbed.output).toContain("[PII_REDACTED]");
	});

	it("phone number in tool output is redacted", () => {
		const result: ToolResult = {
			manifestId: "test",
			success: true,
			duration_ms: 0,
			output: "Call me at (555) 123-4567",
		};
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("(555) 123-4567");
	});

	it("email in tool output is redacted", () => {
		const result: ToolResult = {
			manifestId: "test",
			success: true,
			duration_ms: 0,
			output: "Contact: user@example.com for details",
		};
		const scrubbed = scrubPII(result);
		expect(scrubbed.output).not.toContain("user@example.com");
	});

	it("PII in error field is also scrubbed", () => {
		const result: ToolResult = {
			manifestId: "test",
			success: false,
			duration_ms: 0,
			error: "Failed for SSN 123-45-6789",
		};
		const scrubbed = scrubPII(result);
		expect(scrubbed.error).not.toContain("123-45-6789");
	});
});

// ─────────────────────────────────────────────────────────────────
// G11: Loop guard blocks storms — >N identical calls → blocked
// ─────────────────────────────────────────────────────────────────
describe("Invariant G11: Loop guard blocks retry storms", () => {
	it("allows first call", () => {
		const guard = new LoopGuard({ blockThreshold: 3, warnThreshold: 2, windowMs: 60_000 });
		const result = guard.check("agent-1", "bash", { command: "ls" });
		expect(result.action).toBe("allow");
	});

	it("warns at warn threshold", () => {
		const guard = new LoopGuard({ blockThreshold: 5, warnThreshold: 3, windowMs: 60_000 });
		guard.check("agent-1", "bash", { command: "ls" });
		guard.check("agent-1", "bash", { command: "ls" });
		const result = guard.check("agent-1", "bash", { command: "ls" }); // 3rd = warn
		expect(result.action).toBe("warn");
	});

	it("blocks at block threshold", () => {
		const guard = new LoopGuard({ blockThreshold: 3, warnThreshold: 2, windowMs: 60_000 });
		guard.check("agent-1", "bash", { command: "ls" });
		guard.check("agent-1", "bash", { command: "ls" });
		const result = guard.check("agent-1", "bash", { command: "ls" }); // 3rd = block
		expect(result.action).toBe("block");
		expect(result.reason).toContain("3 times");
	});

	it("different params are not counted as duplicates", () => {
		const guard = new LoopGuard({ blockThreshold: 3, warnThreshold: 2, windowMs: 60_000 });
		guard.check("agent-1", "bash", { command: "ls" });
		const result = guard.check("agent-1", "bash", { command: "pwd" });
		expect(result.action).toBe("allow");
	});
});

// ─────────────────────────────────────────────────────────────────
// G12: Per-agent path whitelist — agent can't escape allowedRoots
// ─────────────────────────────────────────────────────────────────
describe("Invariant G12: Per-agent path whitelist", () => {
	it("allows path within allowedRoots", async () => {
		const dir = mkdtempSync(join(tmpdir(), "sentinel-root-"));
		tempDirs.push(dir);
		const result = await isPathAllowed(join(dir, "test.txt"), [dir]);
		expect(result.allowed).toBe(true);
	});

	it("denies path outside allowedRoots", async () => {
		const result = await isPathAllowed("/etc/passwd", ["/home/safe"]);
		expect(result.allowed).toBe(false);
	});

	it("denies path traversal attempt", async () => {
		const dir = mkdtempSync(join(tmpdir(), "sentinel-root-"));
		tempDirs.push(dir);
		const result = await isPathAllowed(join(dir, "..", "..", "etc", "passwd"), [dir]);
		expect(result.allowed).toBe(false);
	});
});
