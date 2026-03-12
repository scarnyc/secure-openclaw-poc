import { createHmac, timingSafeEqual } from "node:crypto";
import type { MiddlewareHandler } from "hono";

export const SIGNATURE_HEADER = "X-Sentinel-Signature";

/**
 * Hono middleware that HMAC-SHA256 signs response bodies.
 * SSE responses get a "streaming" marker (integrity via mTLS for streaming).
 */
export function createResponseSigner(secret: Buffer): MiddlewareHandler {
	return async (c, next) => {
		await next();

		const contentType = c.res.headers.get("content-type") ?? "";

		if (contentType.includes("text/event-stream")) {
			// SSE: integrity is handled by mTLS, just add marker
			c.res.headers.set(SIGNATURE_HEADER, "streaming");
			return;
		}

		// Read body, compute HMAC, re-create response with signature header
		const body = await c.res.text();
		const hmac = createHmac("sha256", secret).update(body).digest("hex");

		const headers = new Headers(c.res.headers);
		headers.set(SIGNATURE_HEADER, hmac);
		c.res = new Response(body, {
			status: c.res.status,
			headers,
		});
	};
}

/**
 * Verify response HMAC signature (for agent-side validation).
 * Uses constant-time comparison to prevent timing attacks.
 */
export function verifyResponseSignature(body: string, signature: string, secret: Buffer): boolean {
	const expected = createHmac("sha256", secret).update(body).digest("hex");

	if (signature.length !== expected.length) {
		return false;
	}

	return timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
