import { createHash } from "node:crypto";
import type { AuditEntry } from "@sentinel/types";
import Database from "better-sqlite3";
import { type AuditFilters, buildFilterQuery } from "./queries.js";
import { redactCredentials } from "./redact.js";

const CREATE_TABLE = `
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT 'unknown',
  tool TEXT NOT NULL,
  category TEXT NOT NULL,
  decision TEXT NOT NULL,
  parameters_summary TEXT NOT NULL,
  result TEXT NOT NULL,
  duration_ms INTEGER,
  prev_hash TEXT NOT NULL DEFAULT '',
  entry_hash TEXT NOT NULL DEFAULT '',
  created_at TEXT DEFAULT (datetime('now'))
)`;

const CREATE_INDEX_SESSION =
	"CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id)";
const CREATE_INDEX_TIMESTAMP =
	"CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)";
const CREATE_INDEX_TOOL = "CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool)";

const INSERT_SQL = `
INSERT INTO audit_log (id, timestamp, manifest_id, session_id, agent_id, tool, category, decision, parameters_summary, result, duration_ms, prev_hash, entry_hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

interface AuditRow {
	id: string;
	timestamp: string;
	manifest_id: string;
	session_id: string;
	agent_id: string;
	tool: string;
	category: string;
	decision: string;
	parameters_summary: string;
	result: string;
	duration_ms: number | null;
	prev_hash: string;
	entry_hash: string;
	created_at: string;
}

export type ChainVerification = { valid: true } | { valid: false; brokenAt: string };

/**
 * Compute a SHA-256 hash for an audit entry, chaining to the previous entry's hash.
 * Uses JSON serialization to prevent delimiter injection (second-preimage attacks).
 * Covers ALL security-relevant fields: id, timestamp, manifestId, sessionId, agentId,
 * tool, category, decision, parameters_summary, result.
 */
export function computeEntryHash(entry: AuditEntry, prevHash: string): string {
	const data = JSON.stringify([
		prevHash,
		entry.id,
		entry.timestamp,
		entry.manifestId,
		entry.sessionId,
		entry.agentId,
		entry.tool,
		entry.category,
		entry.decision,
		entry.parameters_summary,
		entry.result,
	]);
	return createHash("sha256").update(data).digest("hex");
}

function rowToEntry(row: AuditRow): AuditEntry {
	return {
		id: row.id,
		timestamp: row.timestamp,
		manifestId: row.manifest_id,
		sessionId: row.session_id,
		agentId: row.agent_id,
		tool: row.tool,
		category: row.category as AuditEntry["category"],
		decision: row.decision as AuditEntry["decision"],
		parameters_summary: row.parameters_summary,
		result: row.result as AuditEntry["result"],
		duration_ms: row.duration_ms ?? undefined,
	};
}

export class AuditLogger {
	private db: Database.Database | null;
	private insertStmt: Database.Statement;
	private getLastHashStmt: Database.Statement;

	constructor(dbPath: string) {
		const db = new Database(dbPath);
		db.pragma("journal_mode = WAL");
		db.exec(CREATE_TABLE);
		this.migrateIfNeeded(db);
		db.exec(CREATE_INDEX_SESSION);
		db.exec(CREATE_INDEX_TIMESTAMP);
		db.exec(CREATE_INDEX_TOOL);

		this.db = db;
		this.insertStmt = db.prepare(INSERT_SQL);
		this.getLastHashStmt = db.prepare(
			"SELECT entry_hash FROM audit_log ORDER BY rowid DESC LIMIT 1",
		);
	}

	log(entry: AuditEntry): void {
		const db = this.getDb();
		const redacted = redactCredentials(entry.parameters_summary);

		const logTransaction = db.transaction(() => {
			const lastRow = this.getLastHashStmt.get() as { entry_hash: string } | undefined;
			const prevHash = lastRow?.entry_hash ?? "";
			const entryHash = computeEntryHash(entry, prevHash);

			this.insertStmt.run(
				entry.id,
				entry.timestamp,
				entry.manifestId,
				entry.sessionId,
				entry.agentId,
				entry.tool,
				entry.category,
				entry.decision,
				redacted,
				entry.result,
				entry.duration_ms ?? null,
				prevHash,
				entryHash,
			);
		});

		logTransaction();
	}

	query(filters: AuditFilters): AuditEntry[] {
		const db = this.getDb();
		const { sql, params } = buildFilterQuery(filters);
		const rows = db.prepare(sql).all(...params) as AuditRow[];
		return rows.map(rowToEntry);
	}

	getSession(sessionId: string): AuditEntry[] {
		const db = this.getDb();
		const rows = db
			.prepare("SELECT * FROM audit_log WHERE session_id = ? ORDER BY timestamp ASC")
			.all(sessionId) as AuditRow[];
		return rows.map(rowToEntry);
	}

	getRecent(limit: number): AuditEntry[] {
		const db = this.getDb();
		const rows = db
			.prepare("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?")
			.all(limit) as AuditRow[];
		return rows.map(rowToEntry);
	}

	verifyChain(): ChainVerification {
		const db = this.getDb();
		// Select ALL fields included in computeEntryHash to ensure tamper detection
		const rows = db
			.prepare(
				"SELECT id, timestamp, manifest_id, session_id, agent_id, tool, category, decision, parameters_summary, result, prev_hash, entry_hash FROM audit_log ORDER BY rowid ASC",
			)
			.all() as Array<{
			id: string;
			timestamp: string;
			manifest_id: string;
			session_id: string;
			agent_id: string;
			tool: string;
			category: string;
			decision: string;
			parameters_summary: string;
			result: string;
			prev_hash: string;
			entry_hash: string;
		}>;

		let expectedPrevHash = "";
		for (const row of rows) {
			const entry: AuditEntry = {
				id: row.id,
				timestamp: row.timestamp,
				manifestId: row.manifest_id,
				sessionId: row.session_id,
				agentId: row.agent_id,
				tool: row.tool,
				category: row.category as AuditEntry["category"],
				decision: row.decision as AuditEntry["decision"],
				parameters_summary: row.parameters_summary,
				result: row.result as AuditEntry["result"],
			};

			if (row.prev_hash !== expectedPrevHash) {
				return { valid: false, brokenAt: row.id };
			}

			const expectedHash = computeEntryHash(entry, row.prev_hash);
			if (row.entry_hash !== expectedHash) {
				return { valid: false, brokenAt: row.id };
			}

			expectedPrevHash = row.entry_hash;
		}

		return { valid: true };
	}

	close(): void {
		if (this.db) {
			this.db.close();
			this.db = null;
		}
	}

	// SENTINEL: migrate existing DBs that lack Merkle hash-chain columns
	private migrateIfNeeded(db: Database.Database): void {
		const columns = db.pragma("table_info(audit_log)") as Array<{ name: string }>;
		const columnNames = columns.map((c) => c.name);
		try {
			if (!columnNames.includes("prev_hash")) {
				db.exec("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''");
			}
			if (!columnNames.includes("entry_hash")) {
				db.exec("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''");
			}
		} catch (migrationError) {
			throw new Error(
				`Failed to migrate audit_log for Merkle hash-chain columns: ${migrationError instanceof Error ? migrationError.message : String(migrationError)}`,
			);
		}
	}

	private getDb(): Database.Database {
		if (!this.db) {
			throw new Error("AuditLogger is closed");
		}
		return this.db;
	}
}
