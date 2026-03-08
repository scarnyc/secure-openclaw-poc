import type { Context } from "hono";
import { checkSsrf, SsrfError } from "./ssrf-guard.js";

const ALLOWED_LLM_HOSTS = new Set([
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
]);

/**
 * Map of LLM provider hostnames to their required API key env var names.
 * The proxy injects the appropriate key from executor env.
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
 * LLM proxy handler. Forwards requests to allowlisted LLM API hosts,
 * injecting the appropriate API key from executor environment.
 *
 * Agent sends: POST /proxy/llm/<downstream-path> with an optional `x-llm-host`
 * header to select the provider (default: api.anthropic.com).
 *
 * This is designed to work with the Anthropic SDK's baseURL parameter.
 * When the agent sets `baseURL=http://executor:3141/proxy/llm`,
 * the SDK sends requests to `/proxy/llm/v1/messages` etc.
 * We extract the path and forward to the real Anthropic API.
 */
// NOTE: API keys from process.env are V8 immutable strings — cannot be zeroed.
// Vault-based Buffer keys (zeroable) deferred to Phase 1.
export async function handleLlmProxy(c: Context): Promise<Response> {
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

	// Inject API key from executor env
	const authConfig = HOST_AUTH_HEADERS[targetHost];
	if (authConfig) {
		const apiKey = process.env[authConfig.envVar];
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
}
