import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Generate an HMAC-SHA256 token for a confirmation URL.
 * Token encodes the manifestId and expiry — the URL itself becomes the credential.
 * Time-limited to match the 5-minute confirmation timeout.
 */
export function generateConfirmToken(
	manifestId: string,
	expiresAt: number,
	secret: Buffer,
): string {
	const payload = `${manifestId}:${expiresAt}`;
	return createHmac("sha256", secret).update(payload).digest("hex");
}

/**
 * Verify an HMAC-SHA256 confirmation token.
 * Returns true if the token is valid and not expired.
 */
export function verifyConfirmToken(
	manifestId: string,
	token: string,
	expiresAt: number,
	secret: Buffer,
): boolean {
	if (Date.now() > expiresAt) {
		return false; // Token expired
	}

	// Reject non-hex input — Buffer.from(hex) silently truncates at first invalid char
	if (!/^[0-9a-f]{64}$/.test(token)) {
		return false;
	}

	const expected = generateConfirmToken(manifestId, expiresAt, secret);

	// Constant-time comparison to prevent timing attacks
	const expectedBuf = Buffer.from(expected, "hex");
	const providedBuf = Buffer.from(token, "hex");

	if (expectedBuf.length !== providedBuf.length) {
		return false;
	}

	return timingSafeEqual(expectedBuf, providedBuf);
}
