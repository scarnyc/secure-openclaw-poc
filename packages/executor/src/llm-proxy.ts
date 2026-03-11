import type { CredentialVault } from "@sentinel/crypto";
import type { Context } from "hono";
import { checkSsrf, SsrfError } from "./ssrf-guard.js";

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
 * Retrieve API key from vault as Buffer, extract the key string, then zero the Buffer.
 * Returns undefined if vault doesn't have the key.
 *
 * Vault stores credentials as JSON: { key: "sk-..." }
 * The Buffer is zeroed immediately after extracting the string value.
 * The resulting string is a short-lived local — better than process.env lifetime.
 */
function getKeyFromVault(vault: CredentialVault, targetHost: string): string | undefined {
	const serviceId = `llm/${targetHost}`;
	try {
		const buf = vault.retrieveBuffer(serviceId);
		try {
			const parsed: Record<string, string> = JSON.parse(buf.toString("utf8"));
			return parsed.key;
		} finally {
			buf.fill(0);
		}
	} catch {
		// Key not in vault — caller should fall back to env
		return undefined;
	}
}

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

		// SENTINEL: Inject API key — prefer vault Buffer over process.env
		// Vault keys are zeroed after extraction; env vars persist for process lifetime
		const authConfig = HOST_AUTH_HEADERS[targetHost];
		if (authConfig) {
			let apiKey: string | undefined;

			if (vault) {
				apiKey = getKeyFromVault(vault, targetHost);
			}
			if (!apiKey) {
				apiKey = process.env[authConfig.envVar];
			}

			if (!apiKey) {
				return c.json({ error: "LLM proxy configuration error" }, 500);
			}
			const value = authConfig.prefix ? `${authConfig.prefix}${apiKey}` : apiKey;
			forwardHeaders.set(authConfig.headerName, value);
		}

		// SENTINEL: SSRF guard — verify target URL doesn't resolve to private IPs (Phase 1)
		try {
			await checkSsrf(targetUrl);
		} catch (error) {
			if (error instanceof SsrfError) {
				return c.json({ error: "Blocked: SSRF protection" }, 403);
			}
			console.error(
				`[llm-proxy] SSRF check failed unexpectedly: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "SSRF check failed" }, 500);
		}

		try {
			const upstreamResponse = await fetch(targetUrl, {
				method: c.req.method,
				headers: forwardHeaders,
				body: c.req.method !== "GET" ? c.req.raw.body : undefined,
				duplex: "half",
			});

			// Stream the response back to the agent
			return new Response(upstreamResponse.body, {
				status: upstreamResponse.status,
				headers: upstreamResponse.headers,
			});
		} catch (error) {
			// Log details server-side but return generic message to untrusted agent
			// to avoid leaking internal network topology (IPs, DNS, ports)
			console.error(
				`[llm-proxy] Upstream request failed: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			return c.json({ error: "LLM proxy upstream error" }, 502);
		}
	};
}

/** Backward-compatible handler using env vars only (no vault). */
export const handleLlmProxy = createLlmProxyHandler();
