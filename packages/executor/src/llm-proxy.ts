import type { AuditLogger } from "@sentinel/audit";
import { type CredentialVault, useCredential } from "@sentinel/crypto";
import { redactAllCredentialsWithEncoding } from "@sentinel/types";
import type { Context } from "hono";
import { createIpPinnedFetch } from "./ip-pinned-fetch.js";
import { createSseCredentialFilter } from "./sse-credential-filter.js";
import { checkSsrf, SsrfError } from "./ssrf-guard.js";

const ALLOWED_RESPONSE_HEADERS = new Set([
	"content-type",
	"content-length",
	"content-encoding",
	"transfer-encoding",
	"x-request-id",
	"request-id",
	"retry-after",
	"x-ratelimit-limit",
	"x-ratelimit-remaining",
	"x-ratelimit-reset",
	"openai-organization",
	"openai-processing-ms",
	"anthropic-ratelimit-requests-limit",
	"anthropic-ratelimit-requests-remaining",
	"anthropic-ratelimit-requests-reset",
	"anthropic-ratelimit-tokens-limit",
	"anthropic-ratelimit-tokens-remaining",
	"anthropic-ratelimit-tokens-reset",
]);

const ALLOWED_LLM_HOSTS = new Set([
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
]);

/**
 * Map of LLM provider hostnames to their required API key env var names.
 * The proxy injects the appropriate key from executor env or vault.
 */
const HOST_AUTH_HEADERS: Record<
	string,
	{ envVar: string; headerName: string; prefix?: string; vaultServiceId: string }
> = {
	"api.anthropic.com": {
		envVar: "ANTHROPIC_API_KEY",
		headerName: "x-api-key",
		vaultServiceId: "anthropic",
	},
	"api.openai.com": {
		envVar: "OPENAI_API_KEY",
		headerName: "Authorization",
		prefix: "Bearer ",
		vaultServiceId: "openai",
	},
	"generativelanguage.googleapis.com": {
		envVar: "GEMINI_API_KEY",
		headerName: "x-goog-api-key",
		vaultServiceId: "gemini",
	},
};

/** Upstream fetch timeout — prevents indefinite hangs from DNS, TLS, or slow responses. */
const UPSTREAM_TIMEOUT_MS = 60_000;

const debug =
	process.env.SENTINEL_DEBUG === "true"
		? (reqId: string, msg: string) => console.log(`[llm-proxy][${reqId}] ${msg}`)
		: () => {};

/**
 * Creates an LLM proxy handler. When vault is provided, attempts vault-based
 * key retrieval first (Buffer is zeroed after use), falling back to process.env.
 *
 * Agent sends: POST /proxy/llm/<downstream-path> with an optional `x-llm-host`
 * header to select the provider (default: api.anthropic.com).
 */
export function createLlmProxyHandler(
	vault?: CredentialVault,
	auditLogger?: AuditLogger,
): (c: Context) => Promise<Response> {
	return async (c: Context): Promise<Response> => {
		const proxyStart = Date.now();
		const reqId = crypto.randomUUID().slice(0, 8);

		// Extract the downstream path (everything after /proxy/llm)
		const url = new URL(c.req.url);
		const proxyPrefix = "/proxy/llm";
		let downstreamPath = url.pathname.slice(proxyPrefix.length);

		// Provider-prefixed routing: /proxy/llm/anthropic/v1/messages
		// Maps provider name to host and strips the prefix from downstream path
		const PROVIDER_HOSTS: Record<string, string> = {
			anthropic: "api.anthropic.com",
			openai: "api.openai.com",
			gemini: "generativelanguage.googleapis.com",
		};
		let targetHost = c.req.header("x-llm-host") ?? "";
		for (const [prefix, host] of Object.entries(PROVIDER_HOSTS)) {
			if (downstreamPath.startsWith(`/${prefix}/`) || downstreamPath === `/${prefix}`) {
				targetHost = host;
				downstreamPath = downstreamPath.slice(`/${prefix}`.length) || "/";
				break;
			}
		}
		// Default to Anthropic if no provider prefix and no x-llm-host header
		if (!targetHost) {
			targetHost = "api.anthropic.com";
		}

		console.log(`[llm-proxy][${reqId}] ${c.req.method} ${targetHost}${downstreamPath}`);

		if (!downstreamPath || downstreamPath === "/") {
			return c.json({ error: "Missing downstream path" }, 400);
		}

		if (!ALLOWED_LLM_HOSTS.has(targetHost)) {
			// SENTINEL: M8 — Audit blocked host requests
			if (auditLogger) {
				try {
					auditLogger.log({
						id: crypto.randomUUID(),
						timestamp: new Date().toISOString(),
						manifestId: crypto.randomUUID(),
						sessionId: "system",
						agentId: "agent",
						tool: "llm_proxy",
						category: "read",
						decision: "block",
						parameters_summary: `${c.req.method} ${targetHost}${downstreamPath}`,
						result: "blocked_by_policy",
						duration_ms: Date.now() - proxyStart,
					});
				} catch (auditErr) {
					console.error(
						`[llm-proxy] Audit logging failed: ${auditErr instanceof Error ? auditErr.message : "Unknown"}`,
					);
				}
			}
			return c.json({ error: `Blocked: ${targetHost} is not an allowed LLM host` }, 403);
		}

		const targetUrl = `https://${targetHost}${downstreamPath}`;

		// Build forwarded headers (strip hop-by-hop, add auth)
		const forwardHeaders = new Headers();
		for (const [key, value] of c.req.raw.headers.entries()) {
			const lower = key.toLowerCase();
			// Skip hop-by-hop and proxy-specific headers
			if (
				lower === "host" ||
				lower === "connection" ||
				lower === "x-llm-host" ||
				lower === "content-length" ||
				lower === "authorization" ||
				lower === "x-api-key" ||
				lower === "x-goog-api-key"
			) {
				continue;
			}
			forwardHeaders.set(key, value);
		}

		// SENTINEL: SSRF guard — verify target URL doesn't resolve to private IPs (Phase 1)
		// DNS rebinding defense: SSRF allowlist + IP-pinned fetch via undici Agent when resolved IPs available
		let ssrfResolvedIps: string[] | undefined;
		try {
			debug(reqId, "SSRF check starting");
			const ssrfResult = await checkSsrf(targetUrl);
			ssrfResolvedIps = ssrfResult?.resolvedIps;
			debug(reqId, `SSRF check passed (${Date.now() - proxyStart}ms)`);
		} catch (error) {
			if (error instanceof SsrfError) {
				// SENTINEL: M8 — Audit SSRF-blocked requests
				if (auditLogger) {
					try {
						auditLogger.log({
							id: crypto.randomUUID(),
							timestamp: new Date().toISOString(),
							manifestId: crypto.randomUUID(),
							sessionId: "system",
							agentId: "agent",
							tool: "llm_proxy",
							category: "read",
							decision: "block",
							parameters_summary: `${c.req.method} ${targetHost}${downstreamPath} [SSRF]`,
							result: "blocked_by_policy",
							duration_ms: Date.now() - proxyStart,
						});
					} catch (auditErr) {
						console.error(
							`[llm-proxy] Audit logging failed: ${auditErr instanceof Error ? auditErr.message : "Unknown"}`,
						);
					}
				}
				return c.json({ error: "Blocked: SSRF protection" }, 403);
			}
			console.error(
				`[llm-proxy] SSRF check failed unexpectedly: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "SSRF check failed" }, 500);
		}

		// SENTINEL: Inject API key — prefer vault (useCredential) over process.env
		// Credential retrieval is separated from fetch to avoid catching fetch errors
		// in the vault error handler (which would cause duplicate requests + misleading logs).
		const authConfig = HOST_AUTH_HEADERS[targetHost];
		if (authConfig) {
			let credentialSet = false;
			if (vault) {
				try {
					await useCredential(vault, authConfig.vaultServiceId, (cred) => {
						// OAuth tokens (sk-ant-oat*) use Authorization: Bearer
						// API keys (sk-ant-api*) use x-api-key
						if (targetHost === "api.anthropic.com" && cred.key.startsWith("sk-ant-oat")) {
							forwardHeaders.set("Authorization", `Bearer ${cred.key}`);
						} else {
							const value = authConfig.prefix ? `${authConfig.prefix}${cred.key}` : cred.key;
							forwardHeaders.set(authConfig.headerName, value);
						}
						credentialSet = true;
					});
				} catch (error) {
					if (error instanceof Error && error.message.startsWith("No credential found")) {
						// Key not in vault — fall through to env var path
					} else {
						// SENTINEL: L5 — Never log error.message (may contain credential info)
						console.error("[llm-proxy] Vault credential retrieval failed");
						// SENTINEL: M8 — Audit credential retrieval failure
						if (auditLogger) {
							try {
								auditLogger.log({
									id: crypto.randomUUID(),
									timestamp: new Date().toISOString(),
									manifestId: crypto.randomUUID(),
									sessionId: "system",
									agentId: "agent",
									tool: "llm_proxy",
									category: "read",
									decision: "block",
									parameters_summary: `${c.req.method} ${targetHost}${downstreamPath} [credential-error]`,
									result: "failure",
									duration_ms: Date.now() - proxyStart,
								});
							} catch (auditErr) {
								console.error(
									`[llm-proxy] Audit logging failed: ${auditErr instanceof Error ? auditErr.message : "Unknown"}`,
								);
							}
						}
						return c.json({ error: "LLM proxy credential error" }, 500);
					}
				}
			}

			// env var fallback (existing behavior for non-vault deployments)
			if (!credentialSet) {
				const apiKey = process.env[authConfig.envVar];
				if (!apiKey) {
					return c.json({ error: "LLM proxy configuration error" }, 500);
				}
				const value = authConfig.prefix ? `${authConfig.prefix}${apiKey}` : apiKey;
				forwardHeaders.set(authConfig.headerName, value);
			}
		}

		// Single fetch path for both vault and env var credentials
		// Read body upfront to avoid ReadableStream compatibility issues with undici
		const requestBody = c.req.method !== "GET" ? await c.req.text() : undefined;
		debug(reqId, `body=${requestBody ? requestBody.length : 0}B`);
		// Use globalThis.fetch directly — undici IP-pinned fetch causes hangs in Node 22 Alpine
		const pinnedFetch = globalThis.fetch;
		// SENTINEL: Abort upstream after timeout to prevent indefinite hangs
		const fetchController = new AbortController();
		const fetchTimer = setTimeout(() => {
			console.error(
				`[llm-proxy][${reqId}] upstream fetch timed out after ${UPSTREAM_TIMEOUT_MS}ms`,
			);
			fetchController.abort();
		}, UPSTREAM_TIMEOUT_MS);
		try {
			const upstreamResponse = await pinnedFetch(targetUrl, {
				method: c.req.method,
				headers: forwardHeaders,
				body: requestBody,
				signal: fetchController.signal,
			});
			clearTimeout(fetchTimer);

			// Filter response headers — only forward allowlisted headers to agent
			const responseHeaders = new Headers();
			for (const [key, value] of upstreamResponse.headers.entries()) {
				if (ALLOWED_RESPONSE_HEADERS.has(key.toLowerCase())) {
					responseHeaders.set(key, value);
				}
			}

			// SENTINEL: Streaming vs non-streaming response handling.
			// SSE streams are piped through createSseCredentialFilter() which redacts
			// credential patterns from data: lines while preserving event boundaries.
			// This is defense-in-depth — the tool-output filter also catches credentials
			// after the agent processes each tool result.
			const contentType = upstreamResponse.headers.get("content-type") ?? "";
			const isStreaming = contentType.includes("text/event-stream");

			if (isStreaming) {
				// Remove content-length and transfer-encoding — streaming through TransformStream
				// changes body size; stale transfer-encoding from upstream could conflict with
				// the runtime's own chunked encoding on the transformed stream.
				responseHeaders.delete("content-length");
				responseHeaders.delete("transfer-encoding");

				// SENTINEL: M8 — Audit streaming LLM proxy requests (C1 fix)
				if (auditLogger) {
					try {
						auditLogger.log({
							id: crypto.randomUUID(),
							timestamp: new Date().toISOString(),
							manifestId: crypto.randomUUID(),
							sessionId: "system",
							agentId: "agent",
							tool: "llm_proxy",
							category: "read",
							decision: "auto_approve",
							parameters_summary: `${c.req.method} ${targetHost}${downstreamPath} [streaming]`,
							result: upstreamResponse.status < 400 ? "success" : "failure",
							duration_ms: Date.now() - proxyStart,
						});
					} catch (auditErr) {
						console.error(
							`[llm-proxy] Audit logging failed: ${auditErr instanceof Error ? auditErr.message : "Unknown"}`,
						);
					}
				}

				const filteredStream = upstreamResponse.body
					? upstreamResponse.body.pipeThrough(createSseCredentialFilter())
					: null;

				return new Response(filteredStream, {
					status: upstreamResponse.status,
					headers: responseHeaders,
				});
			}

			// Non-streaming: filter credential patterns from response body.
			// Prevents LLM API error messages from leaking credentials (e.g., "Invalid API key: sk-ant-...").
			const rawBody = await upstreamResponse.text();
			const filteredBody = redactAllCredentialsWithEncoding(rawBody);

			// Remove stale content-length — body size may have changed after redaction.
			// The Response constructor will compute the correct value.
			responseHeaders.delete("content-length");

			const duration = Date.now() - proxyStart;
			console.log(`[llm-proxy][${reqId}] ${upstreamResponse.status} (${duration}ms)`);

			// SENTINEL: M8 — Audit LLM proxy requests (metadata only, no body content)
			if (auditLogger) {
				try {
					auditLogger.log({
						id: crypto.randomUUID(),
						timestamp: new Date().toISOString(),
						manifestId: crypto.randomUUID(),
						sessionId: "system",
						agentId: "agent",
						tool: "llm_proxy",
						category: "read",
						decision: "auto_approve",
						parameters_summary: `${c.req.method} ${targetHost}${downstreamPath}`,
						result: upstreamResponse.status < 400 ? "success" : "failure",
						duration_ms: duration,
					});
				} catch (auditErr) {
					console.error(
						`[llm-proxy] Audit logging failed: ${auditErr instanceof Error ? auditErr.message : "Unknown"}`,
					);
				}
			}

			return new Response(filteredBody, {
				status: upstreamResponse.status,
				headers: responseHeaders,
			});
		} catch (error) {
			clearTimeout(fetchTimer);
			// Log details server-side but return generic message to untrusted agent
			// to avoid leaking internal network topology (IPs, DNS, ports)
			console.error(
				`[llm-proxy][${reqId}] Upstream request failed (${Date.now() - proxyStart}ms): ${error instanceof Error ? `${error.message} ${error.cause ? JSON.stringify(error.cause) : ""}` : "Unknown"}`,
			);
			// SENTINEL: M8 — Audit upstream errors
			if (auditLogger) {
				try {
					auditLogger.log({
						id: crypto.randomUUID(),
						timestamp: new Date().toISOString(),
						manifestId: crypto.randomUUID(),
						sessionId: "system",
						agentId: "agent",
						tool: "llm_proxy",
						category: "read",
						decision: "auto_approve",
						parameters_summary: `${c.req.method} ${targetHost}${downstreamPath} [upstream-error]`,
						result: "failure",
						duration_ms: Date.now() - proxyStart,
					});
				} catch (auditErr) {
					console.error(
						`[llm-proxy] Audit logging failed: ${auditErr instanceof Error ? auditErr.message : "Unknown"}`,
					);
				}
			}
			return c.json({ error: "LLM proxy upstream error" }, 502);
		} finally {
			// Clean up auth header from forwardHeaders (both vault and env paths)
			if (authConfig) {
				forwardHeaders.delete(authConfig.headerName);
			}
		}
	};
}
