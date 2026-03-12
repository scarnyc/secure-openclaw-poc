import Database from "better-sqlite3";

export interface RateLimiterConfig {
	rate: number; // max requests allowed
	period: number; // time window in milliseconds
	dbPath?: string; // Optional SQLite path for persistence
	maxAgents?: number; // Max tracked agents before LRU eviction (default 1000)
}

export interface RateLimitResult {
	allowed: boolean;
	retryAfter?: number; // milliseconds until next allowed request
}

export class RateLimiter {
	private readonly emissionInterval: number;
	private readonly period: number;
	private readonly maxAgents: number;
	private readonly tats: Map<string, number> = new Map();
	private db?: Database.Database;
	private dirty: Set<string> = new Set();
	private flushInterval?: ReturnType<typeof setInterval>;
	private upsertStmt?: Database.Statement;

	constructor(config: RateLimiterConfig) {
		if (config.rate <= 0 || config.period <= 0) {
			throw new Error("rate and period must be positive");
		}
		this.emissionInterval = config.period / config.rate;
		this.period = config.period;
		this.maxAgents = config.maxAgents ?? 1000;
		if (this.maxAgents < 1) {
			throw new Error("maxAgents must be positive");
		}

		if (config.dbPath) {
			this.db = new Database(config.dbPath);
			this.db.pragma("journal_mode = WAL");
			this.db.exec(`CREATE TABLE IF NOT EXISTS rate_limiter_state (
				agent_id TEXT PRIMARY KEY,
				tat REAL NOT NULL,
				updated_at TEXT DEFAULT (datetime('now'))
			)`);

			this.upsertStmt = this.db.prepare(
				"INSERT OR REPLACE INTO rate_limiter_state (agent_id, tat, updated_at) VALUES (?, ?, datetime('now'))",
			);

			// Load existing state — skip expired TATs
			const now = Date.now();
			const rows = this.db.prepare("SELECT agent_id, tat FROM rate_limiter_state").all() as Array<{
				agent_id: string;
				tat: number;
			}>;
			for (const row of rows) {
				if (row.tat > now - this.period) {
					this.tats.set(row.agent_id, row.tat);
				}
			}

			// Write-behind: flush dirty entries every 1 second
			this.flushInterval = setInterval(() => this.flush(), 1000);
			if (this.flushInterval.unref) {
				this.flushInterval.unref();
			}
		}
	}

	check(agentId: string): RateLimitResult {
		const now = Date.now();
		const previousTat = this.tats.get(agentId) ?? now;
		const newTat = Math.max(now, previousTat) + this.emissionInterval;

		if (newTat - now > this.period) {
			return { allowed: false, retryAfter: newTat - now - this.period };
		}

		this.tats.set(agentId, newTat);
		if (this.db) {
			this.dirty.add(agentId);
		}
		this.evictIfNeeded();
		return { allowed: true };
	}

	private evictIfNeeded(): void {
		while (this.tats.size > this.maxAgents) {
			const oldest = this.tats.keys().next().value;
			if (oldest !== undefined) {
				this.tats.delete(oldest);
				this.dirty.delete(oldest);
			}
		}
	}

	reset(agentId?: string): void {
		if (agentId !== undefined) {
			this.tats.delete(agentId);
			this.dirty.delete(agentId);
			if (this.db) {
				this.db.prepare("DELETE FROM rate_limiter_state WHERE agent_id = ?").run(agentId);
			}
		} else {
			this.tats.clear();
			this.dirty.clear();
			if (this.db) {
				this.db.exec("DELETE FROM rate_limiter_state");
			}
		}
	}

	/** Flush dirty TAT entries to SQLite. */
	private flush(): void {
		if (!this.db || this.dirty.size === 0) return;

		try {
			const flushTransaction = this.db.transaction(() => {
				for (const agentId of this.dirty) {
					const tat = this.tats.get(agentId);
					if (tat !== undefined) {
						this.upsertStmt?.run(agentId, tat);
					}
				}
			});
			flushTransaction();
		} catch (err) {
			console.error(
				`[rate-limiter] Failed to flush state to SQLite: ${err instanceof Error ? err.message : String(err)}`,
			);
			// Continue with in-memory state — rate limiting still functional
		}
		this.dirty.clear();
	}

	/** Flush pending writes and close the database. */
	close(): void {
		if (this.flushInterval) {
			clearInterval(this.flushInterval);
			this.flushInterval = undefined;
		}
		this.flush();
		if (this.db) {
			this.db.close();
			this.db = undefined;
		}
	}
}
