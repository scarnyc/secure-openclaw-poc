import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AuditEntry } from "@sentinel/types";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLogger } from "./logger.js";

function makeTempDbPath(): string {
	const dir = mkdtempSync(join(tmpdir(), "sentinel-audit-"));
	tempDirs.push(dir);
	return join(dir, "audit.db");
}

const tempDirs: string[] = [];

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
		sessionId: "session-1",
		agentId: "test-agent",
		tool: "bash",
		category: "dangerous",
		decision: "confirm",
		parameters_summary: "ls -la /tmp",
		result: "success",
		duration_ms: 42,
		...overrides,
	};
}

describe("AuditLogger", () => {
	it("log + query round-trip", () => {
		const logger = new AuditLogger(makeTempDbPath());
		const entry = makeEntry();
		logger.log(entry);

		const results = logger.query({});
		expect(results).toHaveLength(1);
		expect(results[0].id).toBe(entry.id);
		expect(results[0].tool).toBe("bash");
		expect(results[0].sessionId).toBe("session-1");
		logger.close();
	});

	it("automatically redacts credentials in parameters_summary", () => {
		const logger = new AuditLogger(makeTempDbPath());
		const entry = makeEntry({
			parameters_summary:
				"curl -H 'Authorization: Bearer sk-ant-api03-secret123abc456def' https://api.example.com",
		});
		logger.log(entry);

		const results = logger.query({});
		expect(results[0].parameters_summary).not.toContain("sk-ant-");
		expect(results[0].parameters_summary).toContain("[REDACTED]");
		logger.close();
	});

	it("getSession returns only matching session entries", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.log(makeEntry({ sessionId: "session-A" }));
		logger.log(makeEntry({ sessionId: "session-B" }));
		logger.log(makeEntry({ sessionId: "session-A" }));

		const sessionA = logger.getSession("session-A");
		expect(sessionA).toHaveLength(2);
		expect(sessionA.every((e) => e.sessionId === "session-A")).toBe(true);

		const sessionB = logger.getSession("session-B");
		expect(sessionB).toHaveLength(1);
		logger.close();
	});

	it("getRecent returns correct limit, ordered by timestamp desc", () => {
		const logger = new AuditLogger(makeTempDbPath());
		const entries = [
			makeEntry({ timestamp: "2026-01-01T00:00:00.000Z" }),
			makeEntry({ timestamp: "2026-01-02T00:00:00.000Z" }),
			makeEntry({ timestamp: "2026-01-03T00:00:00.000Z" }),
		];
		for (const e of entries) {
			logger.log(e);
		}

		const recent = logger.getRecent(2);
		expect(recent).toHaveLength(2);
		expect(recent[0].timestamp).toBe("2026-01-03T00:00:00.000Z");
		expect(recent[1].timestamp).toBe("2026-01-02T00:00:00.000Z");
		logger.close();
	});

	it("query filters by tool", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.log(makeEntry({ tool: "bash" }));
		logger.log(makeEntry({ tool: "read_file" }));
		logger.log(makeEntry({ tool: "bash" }));

		const bashOnly = logger.query({ tool: "bash" });
		expect(bashOnly).toHaveLength(2);
		expect(bashOnly.every((e) => e.tool === "bash")).toBe(true);
		logger.close();
	});

	it("query filters by category", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.log(makeEntry({ category: "read" }));
		logger.log(makeEntry({ category: "dangerous" }));

		const reads = logger.query({ category: "read" });
		expect(reads).toHaveLength(1);
		expect(reads[0].category).toBe("read");
		logger.close();
	});

	it("query filters by decision", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.log(makeEntry({ decision: "block" }));
		logger.log(makeEntry({ decision: "auto_approve" }));

		const blocked = logger.query({ decision: "block" });
		expect(blocked).toHaveLength(1);
		expect(blocked[0].decision).toBe("block");
		logger.close();
	});

	it("query filters by date range", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.log(makeEntry({ timestamp: "2026-01-01T00:00:00.000Z" }));
		logger.log(makeEntry({ timestamp: "2026-06-15T00:00:00.000Z" }));
		logger.log(makeEntry({ timestamp: "2026-12-31T00:00:00.000Z" }));

		const midYear = logger.query({
			from: "2026-03-01T00:00:00.000Z",
			to: "2026-09-01T00:00:00.000Z",
		});
		expect(midYear).toHaveLength(1);
		expect(midYear[0].timestamp).toBe("2026-06-15T00:00:00.000Z");
		logger.close();
	});

	it("empty DB operations don't error", () => {
		const logger = new AuditLogger(makeTempDbPath());
		expect(logger.query({})).toEqual([]);
		expect(logger.getSession("nonexistent")).toEqual([]);
		expect(logger.getRecent(10)).toEqual([]);
		logger.close();
	});

	it("close() doesn't error on double close", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.close();
		expect(() => logger.close()).not.toThrow();
	});

	it("throws after close when trying to log", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.close();
		expect(() => logger.log(makeEntry())).toThrow("AuditLogger is closed");
	});

	it("handles entry without duration_ms", () => {
		const logger = new AuditLogger(makeTempDbPath());
		const entry = makeEntry({ duration_ms: undefined });
		logger.log(entry);

		const results = logger.query({});
		expect(results[0].duration_ms).toBeUndefined();
		logger.close();
	});
});
