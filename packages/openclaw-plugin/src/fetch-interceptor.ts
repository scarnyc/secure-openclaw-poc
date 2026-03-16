/**
 * Egress fetch interceptor for OpenClaw Docker deployments.
 *
 * In Docker, the OpenClaw gateway container runs on `sentinel-internal` with
 * NO internet access. ALL outbound HTTP to external domains must route through
 * the executor's `/proxy/egress` endpoint, which handles SSRF protection,
 * credential injection, and response redaction.
 *
 * This module monkey-patches globalThis.fetch to intercept requests to
 * configured egress domains and route them through the proxy. Internal hosts
 * (executor, localhost) pass through unchanged. Unknown external domains also
 * pass through — they will fail on the Docker internal network (fail-closed).
 */

const INTERNAL_HOSTS = new Set(["executor", "localhost", "127.0.0.1", "0.0.0.0"]);

export interface FetchInterceptorConfig {
	/** Executor base URL, e.g. "http://executor:3141" */
	executorUrl: string;
	/** Sentinel auth token for executor API */
	authToken: string;
	/** List of external domains to route through egress proxy */
	egressDomains: string[];
	/** Agent ID for audit attribution */
	agentId?: string;
	/** Session ID for audit attribution */
	sessionId?: string;
	/** Optional logger — defaults to console.log */
	logger?: (msg: string) => void;
}

/**
 * Normalize headers from various formats (Headers, plain object, array of
 * tuples) into a Record<string, string>.
 */
function normalizeHeaders(
	headers: Headers | Record<string, string> | Array<[string, string]> | undefined,
): Record<string, string> {
	const result: Record<string, string> = {};
	if (!headers) return result;

	if (headers instanceof Headers) {
		headers.forEach((value, key) => {
			result[key] = value;
		});
	} else if (Array.isArray(headers)) {
		for (const entry of headers) {
			result[entry[0]] = entry[1];
		}
	} else {
		for (const [key, value] of Object.entries(headers)) {
			result[key] = value;
		}
	}
	return result;
}

/**
 * Install a fetch interceptor that routes requests to configured egress
 * domains through the Sentinel executor's `/proxy/egress` endpoint.
 *
 * @returns A cleanup function that restores the original globalThis.fetch.
 */
export function installFetchInterceptor(config: FetchInterceptorConfig): () => void {
	const {
		executorUrl,
		authToken,
		egressDomains,
		agentId = "openclaw-gateway",
		sessionId = "default",
		logger = console.log,
	} = config;
	const baseUrl = executorUrl.replace(/\/+$/, "");
	const originalFetch = globalThis.fetch;

	// Pre-compute lowercase domain set for fast lookup
	const egressDomainSet = new Set(egressDomains.map((d) => d.toLowerCase()));

	const interceptingFetch: typeof globalThis.fetch = async (input, init) => {
		// Extract URL string from input
		const url =
			typeof input === "string"
				? input
				: input instanceof URL
					? input.toString()
					: (input as Request).url;

		// Only intercept http(s) URLs
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			// Non-parseable URL — pass through
			return originalFetch(input, init);
		}

		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
			return originalFetch(input, init);
		}

		const hostname = parsed.hostname.toLowerCase();

		// Internal hosts: pass through unchanged
		if (INTERNAL_HOSTS.has(hostname)) {
			return originalFetch(input, init);
		}

		// Not an egress domain: pass through (will fail-closed on Docker internal network)
		if (!egressDomainSet.has(hostname)) {
			return originalFetch(input, init);
		}

		// Route through egress proxy
		let method = "GET";
		let headers: Record<string, string> = {};
		let body: string | undefined;

		if (input instanceof Request) {
			method = input.method;
			input.headers.forEach((value, key) => {
				headers[key] = value;
			});
			// Clone to avoid consuming the body
			const cloned = input.clone();
			const bodyText = await cloned.text();
			if (bodyText) {
				body = bodyText;
			}
		} else {
			method = init?.method ?? "GET";
			headers = normalizeHeaders(
				init?.headers as Headers | Record<string, string> | Array<[string, string]> | undefined,
			);
			if (init?.body !== undefined && init?.body !== null) {
				body = typeof init.body === "string" ? init.body : String(init.body);
			}
		}

		const egressRequest = {
			url: parsed.toString(),
			method: method.toUpperCase(),
			headers,
			...(body !== undefined ? { body } : {}),
			agentId,
			sessionId,
		};

		logger(`[fetch-interceptor] Routing ${method} ${hostname} through egress proxy`);

		return originalFetch(`${baseUrl}/proxy/egress`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${authToken}`,
			},
			body: JSON.stringify(egressRequest),
		});
	};

	globalThis.fetch = interceptingFetch;

	return () => {
		globalThis.fetch = originalFetch;
	};
}
