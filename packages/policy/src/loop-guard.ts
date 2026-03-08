import { createHash } from "node:crypto";

export interface LoopGuardConfig {
	maxHistorySize: number;
	warnThreshold: number;
	blockThreshold: number;
	windowMs: number;
}

export type LoopAction = "allow" | "warn" | "block";

export interface LoopCheckResult {
	action: LoopAction;
	reason?: string;
	duplicateCount: number;
}

interface HistoryEntry {
	hash: string;
	timestamp: number;
}

const DEFAULT_CONFIG: LoopGuardConfig = {
	maxHistorySize: 30,
	warnThreshold: 3,
	blockThreshold: 5,
	windowMs: 60_000,
};

function stableStringify(obj: unknown): string {
	if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
	if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(",")}]`;
	const sorted = Object.keys(obj as Record<string, unknown>).sort();
	const entries = sorted.map(
		(k) => `${JSON.stringify(k)}:${stableStringify((obj as Record<string, unknown>)[k])}`,
	);
	return `{${entries.join(",")}}`;
}

function fingerprint(tool: string, params: Record<string, unknown>): string {
	return createHash("sha256").update(stableStringify({ tool, params })).digest("hex");
}

export class LoopGuard {
	private readonly config: LoopGuardConfig;
	private readonly history: Map<string, HistoryEntry[]> = new Map();

	constructor(config?: Partial<LoopGuardConfig>) {
		const merged = { ...DEFAULT_CONFIG, ...config };
		if (merged.warnThreshold >= merged.blockThreshold) {
			throw new Error("warnThreshold must be less than blockThreshold");
		}
		if (merged.maxHistorySize < 1 || merged.windowMs < 1) {
			throw new Error("maxHistorySize and windowMs must be positive");
		}
		this.config = Object.freeze(merged);
	}

	check(agentId: string, tool: string, params: Record<string, unknown>): LoopCheckResult {
		const now = Date.now();
		const hash = fingerprint(tool, params);

		// Get or create agent history
		let entries = this.history.get(agentId) ?? [];

		// Remove expired entries outside the sliding window
		const cutoff = now - this.config.windowMs;
		entries = entries.filter((e) => e.timestamp > cutoff);

		// Add current entry
		entries.push({ hash, timestamp: now });

		// Trim to maxHistorySize (remove oldest)
		if (entries.length > this.config.maxHistorySize) {
			entries = entries.slice(entries.length - this.config.maxHistorySize);
		}

		// Store updated history
		this.history.set(agentId, entries);

		// Count duplicates of this hash in the window
		const duplicateCount = entries.filter((e) => e.hash === hash).length;

		// Determine action based on escalation thresholds
		let action: LoopAction = "allow";
		let reason: string | undefined;

		if (duplicateCount >= this.config.blockThreshold) {
			action = "block";
			reason = `Tool "${tool}" called ${duplicateCount} times in ${this.config.windowMs}ms window (block threshold: ${this.config.blockThreshold})`;
		} else if (duplicateCount >= this.config.warnThreshold) {
			action = "warn";
			reason = `Tool "${tool}" called ${duplicateCount} times in ${this.config.windowMs}ms window (warn threshold: ${this.config.warnThreshold})`;
		}

		return { action, duplicateCount, reason };
	}

	reset(agentId?: string): void {
		if (agentId !== undefined) {
			this.history.delete(agentId);
		} else {
			this.history.clear();
		}
	}
}
