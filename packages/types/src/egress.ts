import { z } from "zod";

// ---------------------------------------------------------------------------
// Placeholder pattern — agent embeds these in requests; egress proxy replaces
// with real credential values from vault via useCredential().
// Format: SENTINEL_PLACEHOLDER_{SERVICE_ID}__{FIELD_NAME}
// Double-underscore (__) separates serviceId from field. ServiceId is
// alphanumeric only (no underscores); field may contain underscores.
// Example: SENTINEL_PLACEHOLDER_TELEGRAM__BOT_TOKEN
// ---------------------------------------------------------------------------

/** Matches SENTINEL_PLACEHOLDER_<serviceId>__<field> tokens in request text. */
export const PLACEHOLDER_PATTERN = /SENTINEL_PLACEHOLDER_([A-Za-z0-9]+)__([A-Za-z0-9_]+)/g;

/**
 * Reserved metadata key within vault credential entries.
 * Comma-separated list of allowed destination domains for this credential.
 */
export const ALLOWED_DOMAINS_KEY = "_allowedDomains";

// ---------------------------------------------------------------------------
// Egress domain binding — declares which vault service is bound to which domains.
// Stored in SentinelConfig so the executor can enforce at proxy time.
// ---------------------------------------------------------------------------

export const EgressBindingSchema = z.object({
	/** Vault service ID (must match a stored credential). */
	serviceId: z.string().min(1),
	/** Allowed destination domains for this credential. */
	allowedDomains: z.array(z.string().min(1)).min(1),
});
export type EgressBinding = z.infer<typeof EgressBindingSchema>;

export const EgressConfigSchema = z.object({
	/** Per-service domain bindings. Key is a friendly name, value is the binding. */
	bindings: z.array(EgressBindingSchema).default([]),
	/** Maximum response body size in bytes (defense against unbounded downloads). */
	maxResponseBytes: z
		.number()
		.positive()
		.default(10 * 1024 * 1024), // 10MB
});
export type EgressConfig = z.infer<typeof EgressConfigSchema>;

// ---------------------------------------------------------------------------
// Egress request schema — what the agent sends to /proxy/egress/*
// ---------------------------------------------------------------------------

export const EgressRequestSchema = z.object({
	/** Full destination URL (https only; may contain SENTINEL_PLACEHOLDER_* tokens). */
	url: z.string().url(),
	/** HTTP method. */
	method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"),
	/** Request headers (may contain SENTINEL_PLACEHOLDER_* tokens). */
	headers: z.record(z.string()).default({}),
	/** Request body (may contain SENTINEL_PLACEHOLDER_* tokens). */
	body: z.string().optional(),
	/** Agent ID for audit attribution. */
	agentId: z.string().min(1).default("unknown"),
	/** Session ID for audit attribution. */
	sessionId: z.string().min(1).default("unknown"),
});
export type EgressRequest = z.infer<typeof EgressRequestSchema>;
