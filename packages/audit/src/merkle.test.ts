import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AuditEntry } from "@sentinel/types";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLogger, computeEntryHash } from "./logger.js";

function makeTempDbPath(): string {
	const dir = mkdtempSync(join(tmpdir(), "sentinel-merkle-"));
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

describe("Merkle hash-chain audit log", () => {
	it("fresh DB → log entry → entry_hash is non-empty", () => {
		const dbPath = makeTempDbPath();
		const logger = new AuditLogger(dbPath);
		const entry = makeEntry();
		logger.log(entry);

		// Read the raw row to check entry_hash
		const db = new Database(dbPath);
		const row = db.prepare("SELECT entry_hash FROM audit_log WHERE id = ?").get(entry.id) as {
			entry_hash: string;
		};
		db.close();

		expect(row.entry_hash).toBeTruthy();
		expect(row.entry_hash.length).toBe(64); // SHA-256 hex = 64 chars
		logger.close();
	});

	it("first entry has prev_hash = '' (empty string)", () => {
		const dbPath = makeTempDbPath();
		const logger = new AuditLogger(dbPath);
		const entry = makeEntry();
		logger.log(entry);

		const db = new Database(dbPath);
		const row = db.prepare("SELECT prev_hash FROM audit_log WHERE id = ?").get(entry.id) as {
			prev_hash: string;
		};
		db.close();

		expect(row.prev_hash).toBe("");
		logger.close();
	});

	it("log 3 entries → verifyChain() returns valid", () => {
		const logger = new AuditLogger(makeTempDbPath());
		logger.log(makeEntry({ timestamp: "2026-01-01T00:00:00.000Z" }));
		logger.log(makeEntry({ timestamp: "2026-01-02T00:00:00.000Z" }));
		logger.log(makeEntry({ timestamp: "2026-01-03T00:00:00.000Z" }));

		const result = logger.verifyChain();
		expect(result.valid).toBe(true);
		logger.close();
	});

	it("log 3 entries → tamper middle entry → verifyChain() returns invalid with brokenAt", () => {
		const dbPath = makeTempDbPath();
		const logger = new AuditLogger(dbPath);
		const e1 = makeEntry({ timestamp: "2026-01-01T00:00:00.000Z" });
		const e2 = makeEntry({ timestamp: "2026-01-02T00:00:00.000Z" });
		const e3 = makeEntry({ timestamp: "2026-01-03T00:00:00.000Z" });
		logger.log(e1);
		logger.log(e2);
		logger.log(e3);

		// Tamper with the middle entry's result
		const db = new Database(dbPath);
		db.prepare("UPDATE audit_log SET result = 'failure' WHERE id = ?").run(e2.id);
		db.close();

		const result = logger.verifyChain();
		expect(result.valid).toBe(false);
		if (!result.valid) expect(result.brokenAt).toBe(e2.id);
		logger.close();
	});

	it("entry_hash is deterministic (same inputs → same hash)", () => {
		const entry: AuditEntry = {
			id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			timestamp: "2026-01-01T00:00:00.000Z",
			manifestId: "11111111-2222-3333-4444-555555555555",
			sessionId: "session-det",
			agentId: "agent-det",
			tool: "bash",
			category: "dangerous",
			decision: "confirm",
			parameters_summary: "echo hello",
			result: "success",
			duration_ms: 10,
		};
		const prevHash = "abc123";

		const hash1 = computeEntryHash(entry, prevHash);
		const hash2 = computeEntryHash(entry, prevHash);

		expect(hash1).toBe(hash2);
		expect(hash1.length).toBe(64);
	});

	it("second entry's prev_hash equals first entry's entry_hash", () => {
		const dbPath = makeTempDbPath();
		const logger = new AuditLogger(dbPath);
		const e1 = makeEntry({ timestamp: "2026-01-01T00:00:00.000Z" });
		const e2 = makeEntry({ timestamp: "2026-01-02T00:00:00.000Z" });
		logger.log(e1);
		logger.log(e2);

		const db = new Database(dbPath);
		const row1 = db.prepare("SELECT entry_hash FROM audit_log WHERE id = ?").get(e1.id) as {
			entry_hash: string;
		};
		const row2 = db.prepare("SELECT prev_hash FROM audit_log WHERE id = ?").get(e2.id) as {
			prev_hash: string;
		};
		db.close();

		expect(row2.prev_hash).toBe(row1.entry_hash);
		logger.close();
	});

	it("tampered entry_hash column is detected by verifyChain", () => {
		const dbPath = makeTempDbPath();
		const logger = new AuditLogger(dbPath);
		const e1 = makeEntry({ timestamp: "2026-01-01T00:00:00.000Z" });
		logger.log(e1);

		// Tamper with the entry_hash directly
		const db = new Database(dbPath);
		db.prepare("UPDATE audit_log SET entry_hash = 'tampered' WHERE id = ?").run(e1.id);
		db.close();

		const result = logger.verifyChain();
		expect(result.valid).toBe(false);
		if (!result.valid) expect(result.brokenAt).toBe(e1.id);
		logger.close();
	});

	it("tampered parameters_summary is detected by verifyChain", () => {
		const dbPath = makeTempDbPath();
		const logger = new AuditLogger(dbPath);
		const e1 = makeEntry({
			timestamp: "2026-01-01T00:00:00.000Z",
			parameters_summary: "original command",
		});
		logger.log(e1);

		const db = new Database(dbPath);
		db.prepare("UPDATE audit_log SET parameters_summary = 'tampered command' WHERE id = ?").run(
			e1.id,
		);
		db.close();

		const result = logger.verifyChain();
		expect(result.valid).toBe(false);
		if (!result.valid) expect(result.brokenAt).toBe(e1.id);
		logger.close();
	});

	it("tampered agentId is detected by verifyChain", () => {
		const dbPath = makeTempDbPath();
		const logger = new AuditLogger(dbPath);
		const e1 = makeEntry({ timestamp: "2026-01-01T00:00:00.000Z", agentId: "real-agent" });
		logger.log(e1);

		const db = new Database(dbPath);
		db.prepare("UPDATE audit_log SET agent_id = 'fake-agent' WHERE id = ?").run(e1.id);
		db.close();

		const result = logger.verifyChain();
		expect(result.valid).toBe(false);
		if (!result.valid) expect(result.brokenAt).toBe(e1.id);
		logger.close();
	});

	it("existing tests still work — log + query round-trip preserves behavior", () => {
		const logger = new AuditLogger(makeTempDbPath());
		const entry = makeEntry();
		logger.log(entry);

		const results = logger.query({});
		expect(results).toHaveLength(1);
		expect(results[0].id).toBe(entry.id);
		expect(results[0].tool).toBe("bash");
		logger.close();
	});
});
