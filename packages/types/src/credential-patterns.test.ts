import { describe, expect, it } from "vitest";
import { redactAllCredentials } from "./credential-patterns.js";

describe("redactAllCredentials", () => {
	describe("Google OAuth patterns", () => {
		it("redacts Google OAuth2 access tokens (ya29.*)", () => {
			const input = "Authorization: ya29.a0ARrdaM8_Wn3EfCnXoP_abc123-def456";
			const result = redactAllCredentials(input);
			expect(result).not.toContain("ya29.");
			expect(result).toContain("[REDACTED]");
		});

		it("redacts Google OAuth2 refresh tokens (1//...)", () => {
			const input =
				"refresh_token: 1//0e2fGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz01234567";
			const result = redactAllCredentials(input);
			expect(result).not.toContain("1//");
			expect(result).toContain("[REDACTED]");
		});

		it("redacts Google OAuth2 authorization codes (4/...)", () => {
			const input = "code=4/0AeAswp3_Wn3EfCnXoP_abc123-def456_ghijk789012345678";
			const result = redactAllCredentials(input);
			expect(result).not.toContain("4/0AeAswp3");
			expect(result).toContain("[REDACTED]");
		});

		it("does not false-positive on short strings starting with 4/", () => {
			const input = "Page 4/10 of results";
			const result = redactAllCredentials(input);
			expect(result).toBe("Page 4/10 of results");
		});
	});

	// Regression: existing patterns still work
	describe("existing patterns regression", () => {
		it("still redacts Anthropic keys", () => {
			expect(redactAllCredentials("key: sk-ant-abc123-test")).toContain("[REDACTED]");
		});

		it("still redacts OpenAI keys", () => {
			expect(redactAllCredentials("key: sk-abcdefghijklmnopqrstuv")).toContain("[REDACTED]");
		});

		it("still redacts AWS keys", () => {
			expect(redactAllCredentials("AKIAIOSFODNN7EXAMPLE")).toContain("[REDACTED]");
		});
	});
});
