import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { sign as ed25519Sign, verify as ed25519Verify, generateKeyPair } from "@sentinel/crypto";
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
  signature TEXT,
  source TEXT,
  created_at TEXT DEFAULT (datetime('now'))
)`;

const CREATE_META_TABLE = `
CREATE TABLE IF NOT EXISTS audit_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
)`;

const CREATE_INDEX_SESSION =
	"CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id)";
const CREATE_INDEX_TIMESTAMP =
	"CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)";
const CREATE_INDEX_TOOL = "CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool)";

const INSERT_SQL = `
INSERT INTO audit_log (id, timestamp, manifest_id, session_id, agent_id, tool, category, decision, parameters_summary, result, duration_ms, prev_hash, entry_hash, signature, source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

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
	signature: string | null;
	source: string | null;
	created_at: string;
}

export type ChainVerification = { valid: true } | { valid: false; brokenAt: string };

export interface VerifyChainOptions {
	publicKey?: Buffer;
	strictSignatures?: boolean;
}

/**
 * Compute a SHA-256 hash for an audit entry, chaining to the previous entry's hash.
 * Uses JSON serialization to prevent delimiter injection (second-preimage attacks).
 * Covers ALL security-relevant fields: id, timestamp, manifestId, sessionId, agentId,
 * tool, category, decision, parameters_summary, result.
 * Note: signature is deliberately excluded — it signs the entry_hash (circular dependency).
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
		signature: row.signature ?? undefined,
		source: (row.source as AuditEntry["source"]) ?? undefined,
	};
}

export class AuditLogger {
	private db: Database.Database | null;
	private insertStmt: Database.Statement;
	private getLastHashStmt: Database.Statement;
	private signingKey: Buffer;

	constructor(dbPath: string, signingKey?: Buffer) {
		const db = new Database(dbPath);
		db.pragma("journal_mode = WAL");
		db.exec(CREATE_TABLE);
		this.migrateIfNeeded(db);
		db.exec(CREATE_META_TABLE);
		db.exec(CREATE_INDEX_SESSION);
		db.exec(CREATE_INDEX_TIMESTAMP);
		db.exec(CREATE_INDEX_TOOL);

		this.db = db;

		if (signingKey) {
			this.signingKey = signingKey;
		} else {
			this.signingKey = this.loadOrGenerateSigningKey(db);
		}

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

			// Always recompute signature (ignore caller-supplied values).
			// Signing failure must not prevent audit logging (Invariant #2 > Invariant #7).
			let signature: string | null = null;
			try {
				signature = ed25519Sign(entryHash, this.signingKey);
			} catch (signErr) {
				console.error(
					`[audit] Ed25519 signing failed for entry ${entry.id}: ${signErr instanceof Error ? signErr.message : String(signErr)}`,
				);
			}

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
				signature,
				entry.source ?? null,
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

	verifyChain(options?: VerifyChainOptions | Buffer): ChainVerification {
		const opts: VerifyChainOptions = Buffer.isBuffer(options)
			? { publicKey: options }
			: (options ?? {});

		const db = this.getDb();
		// Select ALL fields included in computeEntryHash to ensure tamper detection
		const rows = db
			.prepare(
				"SELECT id, timestamp, manifest_id, session_id, agent_id, tool, category, decision, parameters_summary, result, prev_hash, entry_hash, signature FROM audit_log ORDER BY rowid ASC",
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
			signature: string | null;
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
				signature: row.signature ?? undefined,
			};

			if (row.prev_hash !== expectedPrevHash) {
				return { valid: false, brokenAt: row.id };
			}

			const expectedHash = computeEntryHash(entry, row.prev_hash);
			if (row.entry_hash !== expectedHash) {
				return { valid: false, brokenAt: row.id };
			}

			// Verify Ed25519 signature when public key provided
			if (opts.publicKey) {
				if (row.signature) {
					try {
						const valid = ed25519Verify(row.entry_hash, row.signature, opts.publicKey);
						if (!valid) {
							return { valid: false, brokenAt: row.id };
						}
					} catch {
						// Malformed signature or key — treat as verification failure for this entry
						return { valid: false, brokenAt: row.id };
					}
				} else if (opts.strictSignatures) {
					return { valid: false, brokenAt: row.id };
				}
			}

			expectedPrevHash = row.entry_hash;
		}

		return { valid: true };
	}

	/** Get the public key used for signing (auto-generated or explicit). */
	getSigningPublicKey(): Buffer | undefined {
		// If explicit key was provided, we don't have the public key
		// (caller should already know it)
		// If auto-generated, read from audit_meta
		const db = this.getDb();
		const row = db
			.prepare("SELECT value FROM audit_meta WHERE key = ?")
			.get("auto_signing_public_key") as { value: string } | undefined;
		return row ? Buffer.from(row.value, "hex") : undefined;
	}

	close(): void {
		// SENTINEL: Zeroize signing key buffer to minimize credential exposure window
		if (this.signingKey) {
			this.signingKey.fill(0);
		}
		if (this.db) {
			this.db.close();
			this.db = null;
		}
	}

	// SENTINEL: auto-generate Ed25519 keypair when no explicit signingKey provided.
	// Key stored in separate file (not in audit DB) to prevent co-location with signed data.
	private loadOrGenerateSigningKey(db: Database.Database): Buffer {
		// Key file lives alongside the audit DB but is a separate file
		const dbPath = (db as unknown as { name: string }).name;
		const keyDir = dirname(dbPath);
		const privateKeyPath = join(keyDir, "audit-signing.key");
		const publicKeyPath = join(keyDir, "audit-signing.pub");

		// Check for key file first
		if (existsSync(privateKeyPath)) {
			const privateKeyHex = readFileSync(privateKeyPath, "utf-8").trim();
			// Store public key in audit_meta if not already there (migration path)
			if (existsSync(publicKeyPath)) {
				const pubHex = readFileSync(publicKeyPath, "utf-8").trim();
				const insertMeta = db.prepare(
					"INSERT OR REPLACE INTO audit_meta (key, value) VALUES (?, ?)",
				);
				insertMeta.run("auto_signing_public_key", pubHex);
			}
			return Buffer.from(privateKeyHex, "hex");
		}

		// Migrate from old in-DB storage
		const existingDbKey = db
			.prepare("SELECT value FROM audit_meta WHERE key = ?")
			.get("auto_signing_private_key") as { value: string } | undefined;

		if (existingDbKey) {
			// Migrate: write to file, remove from DB
			writeFileSync(privateKeyPath, existingDbKey.value, { mode: 0o600 });
			const existingPubKey = db
				.prepare("SELECT value FROM audit_meta WHERE key = ?")
				.get("auto_signing_public_key") as { value: string } | undefined;
			if (existingPubKey) {
				writeFileSync(publicKeyPath, existingPubKey.value, { mode: 0o644 });
			}
			db.prepare("DELETE FROM audit_meta WHERE key = ?").run("auto_signing_private_key");
			return Buffer.from(existingDbKey.value, "hex");
		}

		// Generate new keypair
		const { publicKey, privateKey } = generateKeyPair();

		writeFileSync(privateKeyPath, privateKey.toString("hex"), { mode: 0o600 });
		writeFileSync(publicKeyPath, publicKey.toString("hex"), { mode: 0o644 });

		// Store public key in audit_meta for easy retrieval by getSigningPublicKey()
		const insertMeta = db.prepare("INSERT OR REPLACE INTO audit_meta (key, value) VALUES (?, ?)");
		insertMeta.run("auto_signing_public_key", publicKey.toString("hex"));

		return privateKey;
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
			// SENTINEL: migrate for Ed25519 manifest signing (Wave 2.1)
			if (!columnNames.includes("signature")) {
				db.exec("ALTER TABLE audit_log ADD COLUMN signature TEXT");
			}
			// SENTINEL: migrate for multi-source audit (Wave 2.3 — OpenClaw integration)
			if (!columnNames.includes("source")) {
				db.exec("ALTER TABLE audit_log ADD COLUMN source TEXT");
			}
		} catch (migrationError) {
			throw new Error(
				`Failed to migrate audit_log columns: ${migrationError instanceof Error ? migrationError.message : String(migrationError)}`,
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
