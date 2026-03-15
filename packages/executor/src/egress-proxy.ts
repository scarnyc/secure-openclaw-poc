import type { AuditLogger } from "@sentinel/audit";
import { type CredentialVault, useCredential } from "@sentinel/crypto";
import {
	type EgressBinding,
	EgressRequestSchema,
	PLACEHOLDER_PATTERN,
	redactAllCredentialsWithEncoding,
} from "@sentinel/types";
import type { Context } from "hono";
import { checkSsrf, SsrfError } from "./ssrf-guard.js";

/** Default max response body size: 10 MB. */
const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

/** Upstream fetch timeout. */
const UPSTREAM_TIMEOUT_MS = 60_000;

/** Response headers safe to forward back to the agent. */
const ALLOWED_RESPONSE_HEADERS = new Set([
	"content-type",
	"content-length",
	"content-encoding",
	"retry-after",
	"x-request-id",
	"x-ratelimit-limit",
	"x-ratelimit-remaining",
	"x-ratelimit-reset",
]);

/**
 * Build a domain → serviceId lookup from egress bindings.
 * Multiple domains can map to the same serviceId.
 */
function buildDomainMap(bindings: EgressBinding[]): Map<string, string> {
	const map = new Map<string, string>();
	for (const binding of bindings) {
		for (const domain of binding.allowedDomains) {
			map.set(domain.toLowerCase(), binding.serviceId);
		}
	}
	return map;
}

/**
 * Replace all SENTINEL_PLACEHOLDER_<serviceId>_<field> tokens in text
 * with real credential values from vault.
 *
 * Returns the substituted text. Throws if a referenced credential is missing.
 */
async function substitutePlaceholders(
	text: string,
	vault: CredentialVault,
	allowedServiceId: string,
): Promise<string> {
	// Collect unique serviceId+field pairs to resolve
	const matches: Array<{ full: string; serviceId: string; field: string }> = [];
	const seen = new Set<string>();
	const re = new RegExp(PLACEHOLDER_PATTERN.source, PLACEHOLDER_PATTERN.flags);
	let match: RegExpExecArray | null = null;
	// biome-ignore lint/suspicious/noAssignInExpressions: standard regex exec loop
	while ((match = re.exec(text)) !== null) {
		const key = `${match[1]}:${match[2]}`;
		if (!seen.has(key)) {
			seen.add(key);
			matches.push({ full: match[0], serviceId: match[1], field: match[2] });
		}
	}

	if (matches.length === 0) return text;

	// Security: only allow placeholders for the domain-bound service
	for (const m of matches) {
		if (m.serviceId !== allowedServiceId) {
			throw new EgressSecurityError(
				`Placeholder references service "${m.serviceId}" but domain is bound to "${allowedServiceId}"`,
			);
		}
	}

	// Resolve all from vault in a single useCredential call
	let result = text;
	await useCredential(vault, allowedServiceId, (cred) => {
		for (const m of matches) {
			const value = cred[m.field];
			if (value === undefined) {
				throw new EgressSecurityError(
					`Credential field "${m.field}" not found in vault service "${m.serviceId}"`,
				);
			}
			// Replace all occurrences of this placeholder
			result = result.replaceAll(m.full, value);
		}
	});

	return result;
}

export class EgressSecurityError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "EgressSecurityError";
	}
}

/**
 * Creates an egress proxy handler for /proxy/egress.
 *
 * The agent sends a JSON body describing the outbound request. The proxy:
 * 1. Validates the request schema
 * 2. Checks the destination domain against configured egress bindings
 * 3. Runs SSRF guard on the destination URL
 * 4. Substitutes SENTINEL_PLACEHOLDER_* tokens with real vault credentials
 * 5. Forwards the request to the destination
 * 6. Filters the response (credential redaction)
 * 7. Audits the transaction
 */
export function createEgressProxyHandler(
	vault: CredentialVault | undefined,
	auditLogger: AuditLogger,
	bindings: EgressBinding[],
	maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
): (c: Context) => Promise<Response> {
	const domainMap = buildDomainMap(bindings);

	return async (c: Context): Promise<Response> => {
		const proxyStart = Date.now();
		const reqId = crypto.randomUUID().slice(0, 8);

		// Parse and validate request body
		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			return c.json({ error: "Invalid JSON body" }, 400);
		}

		const parsed = EgressRequestSchema.safeParse(body);
		if (!parsed.success) {
			return c.json({ error: `Invalid egress request: ${parsed.error.message}` }, 400);
		}

		const egressReq = parsed.data;

		// HTTPS only — no plaintext credential transmission
		let targetUrl: URL;
		try {
			targetUrl = new URL(egressReq.url);
		} catch {
			return c.json({ error: "Invalid destination URL" }, 400);
		}

		if (targetUrl.protocol !== "https:") {
			return c.json({ error: "Egress proxy requires HTTPS destinations" }, 400);
		}

		const targetHost = targetUrl.hostname.toLowerCase();
		console.log(`[egress-proxy][${reqId}] ${egressReq.method} ${targetHost}${targetUrl.pathname}`);

		// Domain binding check — destination must be in configured bindings
		const boundServiceId = domainMap.get(targetHost);
		if (!boundServiceId) {
			auditLog(
				auditLogger,
				reqId,
				egressReq.method,
				targetHost,
				targetUrl.pathname,
				"block",
				"blocked_by_policy",
				proxyStart,
				egressReq.agentId,
				egressReq.sessionId,
			);
			return c.json({ error: `Blocked: ${targetHost} is not a bound egress domain` }, 403);
		}

		// SSRF guard — prevent requests to private IPs
		try {
			await checkSsrf(egressReq.url);
		} catch (error) {
			if (error instanceof SsrfError) {
				auditLog(
					auditLogger,
					reqId,
					egressReq.method,
					targetHost,
					targetUrl.pathname,
					"block",
					"blocked_by_policy",
					proxyStart,
					egressReq.agentId,
					egressReq.sessionId,
				);
				return c.json({ error: "Blocked: SSRF protection" }, 403);
			}
			console.error(
				`[egress-proxy][${reqId}] SSRF check failed: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "SSRF check failed" }, 500);
		}

		// Substitute placeholders in headers and body
		if (!vault) {
			auditLog(
				auditLogger,
				reqId,
				egressReq.method,
				targetHost,
				targetUrl.pathname,
				"block",
				"failure",
				proxyStart,
				egressReq.agentId,
				egressReq.sessionId,
			);
			return c.json({ error: "Egress proxy requires credential vault" }, 500);
		}

		let forwardUrl: string;
		let forwardHeaders: Record<string, string>;
		let forwardBody: string | undefined;

		try {
			// Substitute in URL (SSRF check already ran on raw URL)
			forwardUrl = await substitutePlaceholders(egressReq.url, vault, boundServiceId);

			// Substitute in headers
			forwardHeaders = {};
			for (const [key, value] of Object.entries(egressReq.headers)) {
				const lower = key.toLowerCase();
				// Skip hop-by-hop headers
				if (lower === "host" || lower === "connection") continue;
				forwardHeaders[key] = await substitutePlaceholders(value, vault, boundServiceId);
			}

			// Substitute in body
			if (egressReq.body) {
				forwardBody = await substitutePlaceholders(egressReq.body, vault, boundServiceId);
			}
		} catch (error) {
			if (error instanceof EgressSecurityError) {
				console.error(`[egress-proxy][${reqId}] Credential substitution failed: ${error.message}`);
				auditLog(
					auditLogger,
					reqId,
					egressReq.method,
					targetHost,
					targetUrl.pathname,
					"block",
					"blocked_by_policy",
					proxyStart,
					egressReq.agentId,
					egressReq.sessionId,
				);
				return c.json({ error: "Credential substitution failed" }, 403);
			}
			// Don't leak vault errors
			console.error(`[egress-proxy][${reqId}] Credential substitution failed`);
			auditLog(
				auditLogger,
				reqId,
				egressReq.method,
				targetHost,
				targetUrl.pathname,
				"block",
				"failure",
				proxyStart,
				egressReq.agentId,
				egressReq.sessionId,
			);
			return c.json({ error: "Egress proxy credential error" }, 500);
		}

		// Forward request to destination
		const fetchController = new AbortController();
		const fetchTimer = setTimeout(() => {
			console.error(
				`[egress-proxy][${reqId}] upstream fetch timed out after ${UPSTREAM_TIMEOUT_MS}ms`,
			);
			fetchController.abort();
		}, UPSTREAM_TIMEOUT_MS);

		try {
			const upstreamResponse = await fetch(forwardUrl, {
				method: egressReq.method,
				headers: forwardHeaders,
				body: forwardBody,
				signal: fetchController.signal,
			});
			clearTimeout(fetchTimer);

			// Read response body with size limit
			const chunks: Uint8Array[] = [];
			let totalSize = 0;

			if (upstreamResponse.body) {
				const reader = upstreamResponse.body.getReader();
				try {
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						totalSize += value.byteLength;
						if (totalSize > maxResponseBytes) {
							reader.cancel();
							auditLog(
								auditLogger,
								reqId,
								egressReq.method,
								targetHost,
								targetUrl.pathname,
								"block",
								"blocked_by_policy",
								proxyStart,
								egressReq.agentId,
								egressReq.sessionId,
							);
							return c.json({ error: `Response body exceeds ${maxResponseBytes} byte limit` }, 502);
						}
						chunks.push(value);
					}
				} finally {
					reader.releaseLock();
				}
			}

			const rawBody = new TextDecoder().decode(
				chunks.length === 1
					? chunks[0]
					: chunks.reduce((acc, chunk) => {
							const merged = new Uint8Array(acc.length + chunk.length);
							merged.set(acc);
							merged.set(chunk, acc.length);
							return merged;
						}, new Uint8Array(0)),
			);

			// Filter credentials from response before returning to agent
			const filteredBody = redactAllCredentialsWithEncoding(rawBody);

			// Filter response headers
			const responseHeaders = new Headers();
			for (const [key, value] of upstreamResponse.headers.entries()) {
				if (ALLOWED_RESPONSE_HEADERS.has(key.toLowerCase())) {
					responseHeaders.set(key, value);
				}
			}
			// Content-Length may have changed after redaction
			responseHeaders.delete("content-length");

			const duration = Date.now() - proxyStart;
			console.log(`[egress-proxy][${reqId}] ${upstreamResponse.status} (${duration}ms)`);
			auditLog(
				auditLogger,
				reqId,
				egressReq.method,
				targetHost,
				targetUrl.pathname,
				"auto_approve",
				upstreamResponse.status < 400 ? "success" : "failure",
				proxyStart,
				egressReq.agentId,
				egressReq.sessionId,
			);

			return new Response(filteredBody, {
				status: upstreamResponse.status,
				headers: responseHeaders,
			});
		} catch (error) {
			clearTimeout(fetchTimer);
			console.error(
				`[egress-proxy][${reqId}] Upstream request failed (${Date.now() - proxyStart}ms): ${error instanceof Error ? error.message : "Unknown"}`,
			);
			auditLog(
				auditLogger,
				reqId,
				egressReq.method,
				targetHost,
				targetUrl.pathname,
				"auto_approve",
				"failure",
				proxyStart,
				egressReq.agentId,
				egressReq.sessionId,
			);
			return c.json({ error: "Egress proxy upstream error" }, 502);
		}
	};
}

type AuditDecision = "auto_approve" | "confirm" | "block" | "allow";
type AuditResult =
	| "success"
	| "failure"
	| "pending"
	| "denied_by_user"
	| "blocked_by_policy"
	| "blocked_by_rate_limit"
	| "blocked_by_loop_guard"
	| "loop_guard_warning";

/** Best-effort audit logging helper. */
function auditLog(
	logger: AuditLogger,
	_reqId: string,
	method: string,
	host: string,
	path: string,
	decision: AuditDecision,
	result: AuditResult,
	startTime: number,
	agentId = "unknown",
	sessionId = "unknown",
): void {
	try {
		logger.log({
			id: crypto.randomUUID(),
			timestamp: new Date().toISOString(),
			manifestId: crypto.randomUUID(),
			sessionId,
			agentId,
			tool: "egress_proxy",
			category: "write",
			decision,
			parameters_summary: `${method} ${host}${path}`,
			result,
			duration_ms: Date.now() - startTime,
		});
	} catch (auditErr) {
		console.error(
			`[egress-proxy] Audit logging failed: ${auditErr instanceof Error ? auditErr.message : "Unknown"}`,
		);
	}
}
