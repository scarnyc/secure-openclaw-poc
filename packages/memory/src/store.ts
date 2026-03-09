import { createHash, randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import type { Embedder } from "./embedder.js";
import { MemoryQuotaError } from "./errors.js";
import {
	type CreateObservation,
	type CreateSummaryInput,
	CreateSummarySchema,
	type Observation,
	type Scope,
	type SearchInput,
	type SearchQuery,
	SearchQuerySchema,
	type Summary,
} from "./schema.js";
import { validateObservation } from "./validator.js";

const CREATE_OBSERVATIONS = `
CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY,
  project TEXT NOT NULL,
  session_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT 'claude-code',
  source TEXT NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  concepts TEXT NOT NULL DEFAULT '[]',
  files_involved TEXT NOT NULL DEFAULT '[]',
  created_at TEXT DEFAULT (datetime('now'))
)`;

const CREATE_SUMMARIES = `
CREATE TABLE IF NOT EXISTS summaries (
  id TEXT PRIMARY KEY,
  project TEXT NOT NULL,
  source TEXT NOT NULL,
  scope TEXT NOT NULL,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  title TEXT NOT NULL,
  investigated TEXT NOT NULL DEFAULT '[]',
  learned TEXT NOT NULL DEFAULT '[]',
  completed TEXT NOT NULL DEFAULT '[]',
  next_steps TEXT NOT NULL DEFAULT '[]',
  observation_ids TEXT NOT NULL DEFAULT '[]',
  created_at TEXT DEFAULT (datetime('now'))
)`;

const CREATE_STORAGE_STATS = `
CREATE TABLE IF NOT EXISTS storage_stats (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  total_bytes INTEGER NOT NULL DEFAULT 0
)`;

const CREATE_FTS = `
CREATE VIRTUAL TABLE IF NOT EXISTS observations_fts USING fts5(
  content_id UNINDEXED,
  title,
  content,
  concepts,
  tokenize = 'porter'
)`;

const CREATE_INDEX_PROJECT = "CREATE INDEX IF NOT EXISTS idx_obs_project ON observations(project)";
const CREATE_INDEX_AGENT = "CREATE INDEX IF NOT EXISTS idx_obs_agent ON observations(agent_id)";
const CREATE_INDEX_SESSION =
	"CREATE INDEX IF NOT EXISTS idx_obs_session ON observations(session_id)";
const CREATE_INDEX_HASH = "CREATE INDEX IF NOT EXISTS idx_obs_hash ON observations(content_hash)";
const CREATE_INDEX_CREATED =
	"CREATE INDEX IF NOT EXISTS idx_obs_created ON observations(created_at)";
const CREATE_INDEX_SUMMARY_SCOPE =
	"CREATE INDEX IF NOT EXISTS idx_sum_scope ON summaries(scope, period_start, period_end)";
const CREATE_INDEX_SUMMARY_PROJECT =
	"CREATE INDEX IF NOT EXISTS idx_sum_project ON summaries(project)";

interface ObservationRow {
	id: string;
	project: string;
	session_id: string;
	agent_id: string;
	source: string;
	type: string;
	title: string;
	content: string;
	content_hash: string;
	concepts: string;
	files_involved: string;
	created_at: string;
}

interface SummaryRow {
	id: string;
	project: string;
	source: string;
	scope: string;
	period_start: string;
	period_end: string;
	title: string;
	investigated: string;
	learned: string;
	completed: string;
	next_steps: string;
	observation_ids: string;
	created_at: string;
}

export interface MemoryStoreConfig {
	maxTotalBytes?: number;
	dedupWindowSeconds?: number;
	embedder?: Embedder;
}

const DEFAULT_MAX_TOTAL_BYTES = 104_857_600; // 100MB
const DEFAULT_DEDUP_WINDOW_SECONDS = 30;

function rowToObservation(row: ObservationRow): Observation {
	return {
		id: row.id,
		project: row.project,
		sessionId: row.session_id,
		agentId: row.agent_id,
		source: row.source as Observation["source"],
		type: row.type as Observation["type"],
		title: row.title,
		content: row.content,
		contentHash: row.content_hash,
		concepts: JSON.parse(row.concepts) as string[],
		filesInvolved: JSON.parse(row.files_involved) as string[],
		createdAt: row.created_at,
	};
}

function rowToSummary(row: SummaryRow): Summary {
	return {
		id: row.id,
		project: row.project,
		source: row.source as Summary["source"],
		scope: row.scope as Summary["scope"],
		periodStart: row.period_start,
		periodEnd: row.period_end,
		title: row.title,
		investigated: JSON.parse(row.investigated) as string[],
		learned: JSON.parse(row.learned) as string[],
		completed: JSON.parse(row.completed) as string[],
		nextSteps: JSON.parse(row.next_steps) as string[],
		observationIds: JSON.parse(row.observation_ids) as string[],
		createdAt: row.created_at,
	};
}

function computeContentHash(content: string): string {
	return createHash("sha256").update(content).digest("hex");
}

export class MemoryStore {
	private db: Database.Database | null;
	private maxTotalBytes: number;
	private dedupWindowSeconds: number;
	private embedder: Embedder | null;
	private vecEnabled: boolean;

	// Prepared statements
	private insertObsStmt: Database.Statement;
	private insertFtsStmt: Database.Statement;
	private getByIdStmt: Database.Statement;
	private dedupCheckStmt: Database.Statement;
	private updateStorageStmt: Database.Statement;
	private getStorageStmt: Database.Statement;
	private insertSummaryStmt: Database.Statement;
	private insertVecStmt: Database.Statement | null = null;

	constructor(dbPath: string, config: MemoryStoreConfig = {}) {
		this.maxTotalBytes = config.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
		this.dedupWindowSeconds = config.dedupWindowSeconds ?? DEFAULT_DEDUP_WINDOW_SECONDS;
		this.embedder = config.embedder ?? null;
		this.vecEnabled = false;

		const db = new Database(dbPath);
		db.pragma("journal_mode = WAL");

		db.exec(CREATE_OBSERVATIONS);
		db.exec(CREATE_SUMMARIES);
		db.exec(CREATE_STORAGE_STATS);
		db.exec(CREATE_FTS);
		db.exec(CREATE_INDEX_PROJECT);
		db.exec(CREATE_INDEX_AGENT);
		db.exec(CREATE_INDEX_SESSION);
		db.exec(CREATE_INDEX_HASH);
		db.exec(CREATE_INDEX_CREATED);
		db.exec(CREATE_INDEX_SUMMARY_SCOPE);
		db.exec(CREATE_INDEX_SUMMARY_PROJECT);

		// Load sqlite-vec extension if embedder is provided
		if (this.embedder) {
			try {
				const sqliteVec = require("sqlite-vec");
				sqliteVec.load(db);
				db.exec(
					`CREATE VIRTUAL TABLE IF NOT EXISTS observations_vec USING vec0(
						observation_id TEXT NOT NULL,
						embedding float[384]
					)`,
				);
				this.insertVecStmt = db.prepare(
					"INSERT INTO observations_vec (observation_id, embedding) VALUES (?, ?)",
				);
				this.vecEnabled = true;
			} catch {
				// sqlite-vec not available — fall back to FTS5 only
				this.vecEnabled = false;
			}
		}

		// Initialize storage stats row if not exists
		db.prepare("INSERT OR IGNORE INTO storage_stats (id, total_bytes) VALUES (1, 0)").run();

		this.db = db;

		this.insertObsStmt = db.prepare(`
			INSERT INTO observations (id, project, session_id, agent_id, source, type, title, content, content_hash, concepts, files_involved)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`);

		this.insertFtsStmt = db.prepare(`
			INSERT INTO observations_fts (content_id, title, content, concepts)
			VALUES (?, ?, ?, ?)
		`);

		this.getByIdStmt = db.prepare("SELECT * FROM observations WHERE id = ?");

		this.dedupCheckStmt = db.prepare(
			"SELECT id FROM observations WHERE content_hash = ? AND created_at > datetime('now', '-' || ? || ' seconds')",
		);

		this.updateStorageStmt = db.prepare(
			"UPDATE storage_stats SET total_bytes = total_bytes + ? WHERE id = 1",
		);

		this.getStorageStmt = db.prepare("SELECT total_bytes FROM storage_stats WHERE id = 1");

		this.insertSummaryStmt = db.prepare(`
			INSERT INTO summaries (id, project, source, scope, period_start, period_end, title, investigated, learned, completed, next_steps, observation_ids)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`);
	}

	observe(input: CreateObservation): string {
		const db = this.getDb();
		const validation = validateObservation(input);
		if (!validation.valid) {
			throw new Error(validation.reason);
		}
		const sanitized = validation.sanitized;
		const hash = computeContentHash(sanitized.content);

		// Dedup check
		if (this.dedupWindowSeconds > 0) {
			const existing = this.dedupCheckStmt.get(hash, this.dedupWindowSeconds) as
				| { id: string }
				| undefined;
			if (existing) {
				return existing.id;
			}
		}

		// Quota check
		const contentBytes = Buffer.byteLength(sanitized.content, "utf-8");
		const currentBytes = this.getStorageBytes();
		if (currentBytes + contentBytes > this.maxTotalBytes) {
			throw new MemoryQuotaError(
				`Storage quota exceeded: ${currentBytes + contentBytes} > ${this.maxTotalBytes} bytes`,
			);
		}

		const id = randomUUID();
		const conceptsJson = JSON.stringify(sanitized.concepts);
		const filesJson = JSON.stringify(sanitized.filesInvolved);

		const insertTransaction = db.transaction(() => {
			this.insertObsStmt.run(
				id,
				sanitized.project,
				sanitized.sessionId,
				sanitized.agentId,
				sanitized.source,
				sanitized.type,
				sanitized.title,
				sanitized.content,
				hash,
				conceptsJson,
				filesJson,
			);

			this.insertFtsStmt.run(id, sanitized.title, sanitized.content, sanitized.concepts.join(" "));

			this.updateStorageStmt.run(contentBytes);
		});

		insertTransaction();
		return id;
	}

	getById(id: string): Observation | undefined {
		this.getDb();
		const row = this.getByIdStmt.get(id) as ObservationRow | undefined;
		return row ? rowToObservation(row) : undefined;
	}

	search(input: SearchInput): Observation[] {
		const db = this.getDb();
		const query = SearchQuerySchema.parse(input);

		if (query.query) {
			return this.ftsSearch(db, query);
		}
		return this.filterSearch(db, query);
	}

	getRecentByAgent(project: string, agentId: string, limit: number): Observation[] {
		const db = this.getDb();
		const rows = db
			.prepare(
				"SELECT * FROM observations WHERE project = ? AND agent_id = ? ORDER BY created_at DESC LIMIT ?",
			)
			.all(project, agentId, limit) as ObservationRow[];
		return rows.map(rowToObservation);
	}

	getObservationsBySession(sessionId: string): Observation[] {
		const db = this.getDb();
		const rows = db
			.prepare("SELECT * FROM observations WHERE session_id = ? ORDER BY created_at ASC")
			.all(sessionId) as ObservationRow[];
		return rows.map(rowToObservation);
	}

	writeSummary(rawInput: CreateSummaryInput): string {
		this.getDb();
		const input = CreateSummarySchema.parse(rawInput);
		const id = randomUUID();
		this.insertSummaryStmt.run(
			id,
			input.project,
			input.source,
			input.scope,
			input.periodStart,
			input.periodEnd,
			input.title,
			JSON.stringify(input.investigated),
			JSON.stringify(input.learned),
			JSON.stringify(input.completed),
			JSON.stringify(input.nextSteps),
			JSON.stringify(input.observationIds),
		);
		return id;
	}

	getSummariesByPeriod(scope: Scope, range: { start: string; end: string }): Summary[] {
		const db = this.getDb();
		const rows = db
			.prepare(
				"SELECT * FROM summaries WHERE scope = ? AND period_start >= ? AND period_end <= ? ORDER BY created_at ASC",
			)
			.all(scope, range.start, range.end) as SummaryRow[];
		return rows.map(rowToSummary);
	}

	hasSummaryForPeriod(scope: Scope, range: { start: string; end: string }): boolean {
		const db = this.getDb();
		const row = db
			.prepare(
				"SELECT 1 FROM summaries WHERE scope = ? AND period_start >= ? AND period_end <= ? LIMIT 1",
			)
			.get(scope, range.start, range.end);
		return row !== undefined;
	}

	getRecentSummaries(project: string, limit: number): Summary[] {
		const db = this.getDb();
		const rows = db
			.prepare("SELECT * FROM summaries WHERE project = ? ORDER BY created_at DESC LIMIT ?")
			.all(project, limit) as SummaryRow[];
		return rows.map(rowToSummary);
	}

	pruneObservations(retentionDays: number): number {
		const db = this.getDb();
		const result = db
			.prepare(
				`DELETE FROM observations WHERE created_at < datetime('now', '-' || ? || ' days')
				 AND id NOT IN (
					SELECT json_each.value FROM summaries, json_each(summaries.observation_ids)
				 )`,
			)
			.run(retentionDays);
		return result.changes;
	}

	async observeWithEmbedding(input: CreateObservation): Promise<string> {
		const id = this.observe(input);

		if (this.embedder && this.vecEnabled && this.insertVecStmt) {
			const obs = this.getById(id);
			if (obs) {
				const text = `${obs.title} ${obs.content}`;
				const embedding = await this.embedder.embed(text);
				const buffer = Buffer.from(embedding.buffer);
				this.insertVecStmt.run(id, buffer);
			}
		}

		return id;
	}

	async vectorSearch(queryText: string, limit: number): Promise<Observation[]> {
		const db = this.getDb();
		if (!this.embedder || !this.vecEnabled) {
			return [];
		}

		const queryEmbedding = await this.embedder.embed(queryText);
		const buffer = Buffer.from(queryEmbedding.buffer);

		const rows = db
			.prepare(
				`SELECT o.* FROM observations o
				 JOIN observations_vec v ON v.observation_id = o.id
				 WHERE v.embedding MATCH ? AND k = ?`,
			)
			.all(buffer, limit) as ObservationRow[];

		return rows.map(rowToObservation);
	}

	async hybridSearch(input: SearchInput): Promise<Observation[]> {
		const db = this.getDb();
		const query = SearchQuerySchema.parse(input);
		const limit = query.limit;

		// Get FTS5 results
		const ftsResults = query.query ? this.ftsSearch(db, { ...query, limit: limit * 2 }) : [];

		// Get vector results if embedder is available
		let vecResults: Observation[] = [];
		if (this.embedder && this.vecEnabled && query.query) {
			vecResults = await this.vectorSearch(query.query, limit * 2);
		}

		// If only one source has results, return it directly
		if (ftsResults.length === 0) return vecResults.slice(0, limit);
		if (vecResults.length === 0) return ftsResults.slice(0, limit);

		// Reciprocal Rank Fusion (RRF) with k=60
		const RRF_K = 60;
		const scores = new Map<string, { score: number; obs: Observation }>();

		for (let i = 0; i < ftsResults.length; i++) {
			const obs = ftsResults[i];
			const existing = scores.get(obs.id);
			const rrfScore = 1 / (RRF_K + i + 1);
			if (existing) {
				existing.score += rrfScore;
			} else {
				scores.set(obs.id, { score: rrfScore, obs });
			}
		}

		for (let i = 0; i < vecResults.length; i++) {
			const obs = vecResults[i];
			const existing = scores.get(obs.id);
			const rrfScore = 1 / (RRF_K + i + 1);
			if (existing) {
				existing.score += rrfScore;
			} else {
				scores.set(obs.id, { score: rrfScore, obs });
			}
		}

		return [...scores.values()]
			.sort((a, b) => b.score - a.score)
			.slice(0, limit)
			.map((entry) => entry.obs);
	}

	getStorageBytes(): number {
		this.getDb();
		const row = this.getStorageStmt.get() as { total_bytes: number };
		return row.total_bytes;
	}

	close(): void {
		if (this.db) {
			this.db.close();
			this.db = null;
		}
	}

	private ftsSearch(db: Database.Database, query: SearchQuery): Observation[] {
		const conditions: string[] = [];
		const params: unknown[] = [];

		conditions.push("observations_fts MATCH ?");
		params.push(query.query);

		const filterConditions: string[] = [];
		const filterParams: unknown[] = [];

		if (query.project) {
			filterConditions.push("o.project = ?");
			filterParams.push(query.project);
		}
		if (query.agentId) {
			filterConditions.push("o.agent_id = ?");
			filterParams.push(query.agentId);
		}
		if (query.type) {
			filterConditions.push("o.type = ?");
			filterParams.push(query.type);
		}
		if (query.source) {
			filterConditions.push("o.source = ?");
			filterParams.push(query.source);
		}
		if (query.fromDate) {
			filterConditions.push("o.created_at >= ?");
			filterParams.push(query.fromDate);
		}
		if (query.toDate) {
			filterConditions.push("o.created_at <= ?");
			filterParams.push(query.toDate);
		}

		let filterClause = "";
		if (filterConditions.length > 0) {
			filterClause = `AND ${filterConditions.join(" AND ")}`;
		}

		const sql = `
			SELECT o.* FROM observations o
			JOIN observations_fts f ON f.content_id = o.id
			WHERE ${conditions.join(" AND ")}
			${filterClause}
			ORDER BY rank
			LIMIT ? OFFSET ?
		`;

		const allParams = [...params, ...filterParams, query.limit ?? 20, query.offset ?? 0];
		const rows = db.prepare(sql).all(...allParams) as ObservationRow[];
		return rows.map(rowToObservation);
	}

	private filterSearch(db: Database.Database, query: SearchQuery): Observation[] {
		const conditions: string[] = [];
		const params: unknown[] = [];

		if (query.project) {
			conditions.push("project = ?");
			params.push(query.project);
		}
		if (query.agentId) {
			conditions.push("agent_id = ?");
			params.push(query.agentId);
		}
		if (query.type) {
			conditions.push("type = ?");
			params.push(query.type);
		}
		if (query.source) {
			conditions.push("source = ?");
			params.push(query.source);
		}
		if (query.fromDate) {
			conditions.push("created_at >= ?");
			params.push(query.fromDate);
		}
		if (query.toDate) {
			conditions.push("created_at <= ?");
			params.push(query.toDate);
		}

		const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

		const sql = `SELECT * FROM observations ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`;
		params.push(query.limit ?? 20, query.offset ?? 0);

		const rows = db.prepare(sql).all(...params) as ObservationRow[];
		return rows.map(rowToObservation);
	}

	private getDb(): Database.Database {
		if (!this.db) {
			throw new Error("MemoryStore is closed");
		}
		return this.db;
	}
}
