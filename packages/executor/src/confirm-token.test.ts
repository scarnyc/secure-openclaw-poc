import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { generateConfirmToken, verifyConfirmToken } from "./confirm-token.js";

describe("confirm-token", () => {
	const secret = randomBytes(32);
	const manifestId = "test-manifest-123";
	const expiresAt = Date.now() + 300_000; // 5 minutes from now

	it("generates a hex string token", () => {
		const token = generateConfirmToken(manifestId, expiresAt, secret);
		expect(token).toMatch(/^[0-9a-f]{64}$/); // SHA-256 = 64 hex chars
	});

	it("verifies a valid token", () => {
		const token = generateConfirmToken(manifestId, expiresAt, secret);
		expect(verifyConfirmToken(manifestId, token, expiresAt, secret)).toBe(true);
	});

	it("rejects a token with wrong manifestId", () => {
		const token = generateConfirmToken(manifestId, expiresAt, secret);
		expect(verifyConfirmToken("wrong-id", token, expiresAt, secret)).toBe(false);
	});

	it("rejects a token with wrong secret", () => {
		const token = generateConfirmToken(manifestId, expiresAt, secret);
		const wrongSecret = randomBytes(32);
		expect(verifyConfirmToken(manifestId, token, expiresAt, wrongSecret)).toBe(false);
	});

	it("rejects an expired token", () => {
		const pastExpiry = Date.now() - 1000; // already expired
		const token = generateConfirmToken(manifestId, pastExpiry, secret);
		expect(verifyConfirmToken(manifestId, token, pastExpiry, secret)).toBe(false);
	});

	it("rejects a tampered expiry", () => {
		const token = generateConfirmToken(manifestId, expiresAt, secret);
		const tamperedExpiry = expiresAt + 60_000; // extended expiry
		expect(verifyConfirmToken(manifestId, token, tamperedExpiry, secret)).toBe(false);
	});

	it("produces different tokens for different manifestIds", () => {
		const token1 = generateConfirmToken("id-1", expiresAt, secret);
		const token2 = generateConfirmToken("id-2", expiresAt, secret);
		expect(token1).not.toBe(token2);
	});

	it("produces different tokens for different expiry times", () => {
		const token1 = generateConfirmToken(manifestId, expiresAt, secret);
		const token2 = generateConfirmToken(manifestId, expiresAt + 1, secret);
		expect(token1).not.toBe(token2);
	});
});
