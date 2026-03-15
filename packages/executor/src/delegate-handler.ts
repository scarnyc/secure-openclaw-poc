import type { ToolResult } from "@sentinel/types";
import { DelegateCodeParamsSchema } from "@sentinel/types";
import Database from "better-sqlite3";

const CREATE_DELEGATION_TABLE = `
CREATE TABLE IF NOT EXISTS delegation_queue (
  id TEXT PRIMARY KEY,
  created_at TEXT DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'pending',
  task TEXT NOT NULL,
  worktree_name TEXT,
  allowed_tools TEXT NOT NULL,
  max_budget_usd REAL NOT NULL,
  timeout_seconds INTEGER NOT NULL,
  agent_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  result_pr_url TEXT,
  completed_at TEXT
)`;

export interface DelegationEntry {
	id: string;
	task: string;
	worktreeName?: string;
	allowedTools: string[];
	maxBudgetUsd: number;
	timeoutSeconds: number;
	agentId: string;
	sessionId: string;
	status: "pending" | "running" | "completed" | "failed";
}

export class DelegationQueue {
	private db: Database.Database;
	private insertStmt: Database.Statement;

	constructor(dbPath: string) {
		this.db = new Database(dbPath);
		this.db.pragma("journal_mode = WAL");
		this.db.exec(CREATE_DELEGATION_TABLE);
		this.insertStmt = this.db.prepare(`
			INSERT INTO delegation_queue (id, task, worktree_name, allowed_tools, max_budget_usd, timeout_seconds, agent_id, session_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`);
	}

	enqueue(entry: DelegationEntry): void {
		this.insertStmt.run(
			entry.id,
			entry.task,
			entry.worktreeName ?? null,
			JSON.stringify(entry.allowedTools),
			entry.maxBudgetUsd,
			entry.timeoutSeconds,
			entry.agentId,
			entry.sessionId,
		);
	}

	getPending(): DelegationEntry[] {
		const rows = this.db
			.prepare("SELECT * FROM delegation_queue WHERE status = 'pending' ORDER BY created_at ASC")
			.all() as Array<Record<string, unknown>>;
		return rows.map(rowToDelegation);
	}

	updateStatus(id: string, status: string, prUrl?: string): void {
		if (prUrl) {
			this.db
				.prepare(
					"UPDATE delegation_queue SET status = ?, result_pr_url = ?, completed_at = datetime('now') WHERE id = ?",
				)
				.run(status, prUrl, id);
		} else {
			this.db.prepare("UPDATE delegation_queue SET status = ? WHERE id = ?").run(status, id);
		}
	}

	close(): void {
		this.db.close();
	}
}

function rowToDelegation(row: Record<string, unknown>): DelegationEntry {
	return {
		id: row.id as string,
		task: row.task as string,
		worktreeName: (row.worktree_name as string) ?? undefined,
		allowedTools: JSON.parse(row.allowed_tools as string) as string[],
		maxBudgetUsd: row.max_budget_usd as number,
		timeoutSeconds: row.timeout_seconds as number,
		agentId: row.agent_id as string,
		sessionId: row.session_id as string,
		status: row.status as DelegationEntry["status"],
	};
}

/**
 * Handle delegate.code tool — validates params, enqueues delegation, returns pending result.
 * The actual Claude Code spawning is handled by the CLI delegation poller, not the executor.
 */
export function createDelegateHandler(queue: DelegationQueue) {
	return async (
		params: Record<string, unknown>,
		manifestId: string,
		agentId: string,
		sessionId: string,
	): Promise<ToolResult> => {
		const start = Date.now();
		const parsed = DelegateCodeParamsSchema.safeParse(params);
		if (!parsed.success) {
			return {
				manifestId,
				success: false,
				error: `Invalid delegate.code params: ${parsed.error.message}`,
				duration_ms: Date.now() - start,
			};
		}

		const delegationId = crypto.randomUUID();
		const entry: DelegationEntry = {
			id: delegationId,
			task: parsed.data.task,
			worktreeName: parsed.data.worktreeName,
			allowedTools: parsed.data.allowedTools,
			maxBudgetUsd: parsed.data.maxBudgetUsd,
			timeoutSeconds: parsed.data.timeoutSeconds,
			agentId,
			sessionId,
			status: "pending",
		};

		queue.enqueue(entry);

		return {
			manifestId,
			success: true,
			output: JSON.stringify({
				delegationId,
				status: "pending",
				message: "Task queued for delegation to Claude Code",
			}),
			duration_ms: Date.now() - start,
		};
	};
}
