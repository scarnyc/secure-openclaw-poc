import { createHash, timingSafeEqual } from "node:crypto";
import type { Context, Next } from "hono";

/**
 * Creates Hono middleware that validates Bearer token using constant-time comparison.
 * If no token is configured, all requests pass through (auth disabled).
 *
 * SHA-256 hashing ensures equal-length buffers for timingSafeEqual,
 * preventing timing-based token length leakage.
 */
export function createAuthMiddleware(configuredToken: string | undefined) {
	// Pre-compute the configured token hash once (avoids rehashing on every request)
	const configuredHash = configuredToken
		? createHash("sha256").update(configuredToken).digest()
		: null;

	return async (c: Context, next: Next) => {
		// If no token configured, skip auth
		if (!configuredHash) {
			return next();
		}

		const authHeader = c.req.header("Authorization");
		const apiKeyHeader = c.req.header("x-api-key");

		let providedToken: string | undefined;
		if (authHeader) {
			const match = authHeader.match(/^Bearer\s+(\S+)$/);
			if (!match) {
				return c.json({ error: "Invalid authorization format" }, 401);
			}
			providedToken = match[1];
		} else if (apiKeyHeader) {
			// Support x-api-key header (used by Anthropic SDK and OpenClaw)
			providedToken = apiKeyHeader;
		}

		if (!providedToken) {
			return c.json({ error: "Authorization required" }, 401);
		}

		// Use SHA-256 hash to ensure equal length for timingSafeEqual
		const providedHash = createHash("sha256").update(providedToken).digest();

		if (!timingSafeEqual(providedHash, configuredHash)) {
			return c.json({ error: "Invalid token" }, 401);
		}

		return next();
	};
}
