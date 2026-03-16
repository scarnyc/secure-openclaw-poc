/**
 * Response types intentionally duplicated from @sentinel/types (zero-dependency SDK).
 * Source of truth: packages/types/src/classify.ts, packages/types/src/filter-output.ts
 * Keep in sync manually — check upstream on major version bumps.
 */

type ActionCategory = "read" | "write" | "write-irreversible" | "dangerous";

/** Classification response from /classify */
export interface ClassifyResponse {
	decision: "auto_approve" | "confirm" | "block";
	category: ActionCategory;
	manifestId: string;
	reason?: string;
}

/** Filter output response from /filter-output */
export interface FilterResponse {
	filtered: string;
	redactedCount: number;
}

/** Confirmation response from /confirm-only */
export interface ConfirmResponse {
	decision: "auto_approve" | "confirm" | "block" | "approved" | "denied";
	category?: ActionCategory;
	reason?: string;
	manifestId: string;
}

/** Pending confirmation entry from /pending-confirmations */
export interface PendingConfirmation {
	manifestId: string;
	tool: string;
	parameters: Record<string, unknown>;
	category: ActionCategory;
	reason?: string;
}

/** Health check response */
export interface HealthResponse {
	status: "ok" | "unreachable" | (string & {});
	version?: string;
}

/** Guard client configuration */
export interface GuardClientOptions {
	/** Executor base URL (e.g., "http://localhost:3141") */
	executorUrl: string;
	/** Bearer auth token for executor API */
	authToken?: string;
	/** Request timeout in milliseconds (default: 30000) */
	timeoutMs?: number;
	/** Confirmation poll timeout (default: 330000 — matches executor's 5-min + buffer) */
	confirmationTimeoutMs?: number;
}
