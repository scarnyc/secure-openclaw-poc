import { type CredentialVault, useCredential } from "@sentinel/crypto";
import { redactAllCredentialsWithEncoding } from "@sentinel/types";
import type { Context } from "hono";
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
const HOST_AUTH_HEADERS: Record<string, { envVar: string; headerName: string; prefix?: string }> = {
	"api.anthropic.com": {
		envVar: "ANTHROPIC_API_KEY",
		headerName: "x-api-key",
	},
	"api.openai.com": {
		envVar: "OPENAI_API_KEY",
		headerName: "Authorization",
		prefix: "Bearer ",
	},
	"generativelanguage.googleapis.com": {
		envVar: "GEMINI_API_KEY",
		headerName: "x-goog-api-key",
	},
};

/**
 * Creates an LLM proxy handler. When vault is provided, attempts vault-based
 * key retrieval first (Buffer is zeroed after use), falling back to process.env.
 *
 * Agent sends: POST /proxy/llm/<downstream-path> with an optional `x-llm-host`
 * header to select the provider (default: api.anthropic.com).
 */
export function createLlmProxyHandler(vault?: CredentialVault): (c: Context) => Promise<Response> {
	return async (c: Context): Promise<Response> => {
		// Extract the downstream path (everything after /proxy/llm)
		const url = new URL(c.req.url);
		const proxyPrefix = "/proxy/llm";
		const downstreamPath = url.pathname.slice(proxyPrefix.length);

		if (!downstreamPath || downstreamPath === "/") {
			return c.json({ error: "Missing downstream path" }, 400);
		}

		// Determine target host from x-llm-host header (default: api.anthropic.com)
		const targetHost = c.req.header("x-llm-host") ?? "api.anthropic.com";

		if (!ALLOWED_LLM_HOSTS.has(targetHost)) {
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
		// DNS rebinding defense: fixed 3-host TLS allowlist mitigates; full IP pinning requires undici Agent (future work)
		let ssrfResolvedIps: string[] | undefined;
		try {
			const ssrfResult = await checkSsrf(targetUrl);
			ssrfResolvedIps = ssrfResult?.resolvedIps;
		} catch (error) {
			if (error instanceof SsrfError) {
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
					await useCredential(vault, `llm/${targetHost}`, (cred) => {
						const value = authConfig.prefix ? `${authConfig.prefix}${cred.key}` : cred.key;
						forwardHeaders.set(authConfig.headerName, value);
						credentialSet = true;
					});
				} catch (error) {
					if (error instanceof Error && error.message.startsWith("No credential found")) {
						// Key not in vault — fall through to env var path
					} else {
						console.error(
							`[llm-proxy] Vault credential failed for llm/${targetHost}: ${error instanceof Error ? error.message : "Unknown"}`,
						);
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
		// TODO: IP-pinned fetch via undici Agent using ssrfResolvedIps for DNS rebinding defense
		void ssrfResolvedIps; // retained for future IP-pinned fetch (requires undici Agent)
		try {
			const upstreamResponse = await fetch(targetUrl, {
				method: c.req.method,
				headers: forwardHeaders,
				body: c.req.method !== "GET" ? c.req.raw.body : undefined,
				duplex: "half",
			});

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
				// Remove content-length — streaming through TransformStream changes body size
				responseHeaders.delete("content-length");

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

			return new Response(filteredBody, {
				status: upstreamResponse.status,
				headers: responseHeaders,
			});
		} catch (error) {
			// Log details server-side but return generic message to untrusted agent
			// to avoid leaking internal network topology (IPs, DNS, ports)
			console.error(
				`[llm-proxy] Upstream request failed: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "LLM proxy upstream error" }, 502);
		} finally {
			// Clean up auth header from forwardHeaders (both vault and env paths)
			if (authConfig) {
				forwardHeaders.delete(authConfig.headerName);
			}
		}
	};
}
