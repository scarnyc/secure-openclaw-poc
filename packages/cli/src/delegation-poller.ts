import { execFile } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

export interface ActiveDelegation {
	delegationId: string;
	pid: number;
	startedAt: string;
	task: string;
}

export interface DelegationPollerOptions {
	executorUrl: string;
	authToken?: string;
	dataDir: string;
	pollIntervalMs: number;
}

const ACTIVE_FILE = "active-delegations.json";

export class DelegationPoller {
	private readonly options: DelegationPollerOptions;
	private timer: ReturnType<typeof setInterval> | null = null;

	constructor(options: DelegationPollerOptions) {
		this.options = options;
	}

	start(): void {
		if (this.timer) return;
		this.timer = setInterval(() => this.poll(), this.options.pollIntervalMs);
		this.timer.unref();
		// Initial poll
		this.poll();
	}

	stop(): void {
		if (this.timer) {
			clearInterval(this.timer);
			this.timer = null;
		}
	}

	async poll(): Promise<void> {
		try {
			const pending = await this.fetchPending();
			for (const delegation of pending) {
				await this.spawnClaudeCode(delegation);
			}
		} catch (error) {
			console.error(
				`[delegation-poller] Poll failed: ${error instanceof Error ? error.message : "Unknown"}`,
			);
		}
	}

	private async fetchPending(): Promise<
		Array<{
			id: string;
			task: string;
			allowedTools: string[];
			maxBudgetUsd: number;
			worktreeName?: string;
		}>
	> {
		const headers: Record<string, string> = { "Content-Type": "application/json" };
		if (this.options.authToken) {
			headers.Authorization = `Bearer ${this.options.authToken}`;
		}

		const res = await fetch(`${this.options.executorUrl}/pending-delegations`, {
			headers,
		});

		if (!res.ok) return [];
		return (await res.json()) as Array<{
			id: string;
			task: string;
			allowedTools: string[];
			maxBudgetUsd: number;
			worktreeName?: string;
		}>;
	}

	private async spawnClaudeCode(delegation: {
		id: string;
		task: string;
		allowedTools: string[];
		maxBudgetUsd: number;
		worktreeName?: string;
	}): Promise<void> {
		const args = [
			"-p",
			delegation.task,
			"--output-format",
			"json",
			"--max-budget-usd",
			String(delegation.maxBudgetUsd),
		];

		if (delegation.allowedTools.length > 0) {
			args.push("--allowedTools", delegation.allowedTools.join(","));
		}

		if (delegation.worktreeName) {
			args.push("--worktree", delegation.worktreeName);
		}

		const child = execFile("claude", args, { timeout: 900_000 }, (error, stdout) => {
			if (error) {
				console.error(
					`[delegation-poller] Claude Code failed for ${delegation.id}: ${error.message}`,
				);
				this.updateStatus(delegation.id, "failed");
			} else {
				console.log(`[delegation-poller] Claude Code completed for ${delegation.id}`);
				this.updateStatus(delegation.id, "completed");
			}
			this.removeActive(delegation.id);
		});

		if (child.pid) {
			this.trackActive({
				delegationId: delegation.id,
				pid: child.pid,
				startedAt: new Date().toISOString(),
				task: delegation.task,
			});
		}
	}

	private trackActive(delegation: ActiveDelegation): void {
		const active = this.loadActive();
		active.push(delegation);
		this.saveActive(active);
	}

	private removeActive(delegationId: string): void {
		const active = this.loadActive().filter((d) => d.delegationId !== delegationId);
		this.saveActive(active);
	}

	private loadActive(): ActiveDelegation[] {
		const path = resolve(this.options.dataDir, ACTIVE_FILE);
		try {
			return JSON.parse(readFileSync(path, "utf-8")) as ActiveDelegation[];
		} catch {
			return [];
		}
	}

	private saveActive(active: ActiveDelegation[]): void {
		const path = resolve(this.options.dataDir, ACTIVE_FILE);
		writeFileSync(path, JSON.stringify(active, null, "\t"));
	}

	private async updateStatus(delegationId: string, status: string): Promise<void> {
		try {
			const headers: Record<string, string> = { "Content-Type": "application/json" };
			if (this.options.authToken) {
				headers.Authorization = `Bearer ${this.options.authToken}`;
			}
			await fetch(`${this.options.executorUrl}/delegation-status/${delegationId}`, {
				method: "POST",
				headers,
				body: JSON.stringify({ status }),
			});
		} catch {
			// Best-effort status update
		}
	}
}
