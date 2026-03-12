import { describe, expect, it } from "vitest";
import { redactAllCredentials, redactAllCredentialsWithEncoding } from "./credential-patterns.js";

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

describe("redactAllCredentialsWithEncoding", () => {
	it("detects base64-encoded Anthropic API key", () => {
		const key = "sk-ant-abc123-testkey-for-encoding";
		const encoded = Buffer.from(key).toString("base64");
		const input = `data: ${encoded}`;
		const result = redactAllCredentialsWithEncoding(input);
		expect(result).toContain("[REDACTED_ENCODED]");
		expect(result).not.toContain(encoded);
	});

	it("detects URL-encoded API key", () => {
		const input = "key=sk-ant-abc123%2Dtestkey%2Dfor%2Durl";
		const result = redactAllCredentialsWithEncoding(input);
		// After URL decoding, sk-ant-abc123-testkey-for-url should be detected
		expect(result).toContain("[REDACTED");
	});

	it("passes through non-credential base64 (image data)", () => {
		// Random base64 that doesn't decode to a credential pattern
		const imageData = "iVBORw0KGgoAAAANSUhEUg==";
		const input = `img: ${imageData}`;
		const result = redactAllCredentialsWithEncoding(input);
		expect(result).toContain(imageData);
	});

	it("ignores short base64 strings (<20 chars)", () => {
		const input = "token: abc123def456";
		const result = redactAllCredentialsWithEncoding(input);
		expect(result).toBe(input);
	});

	it("handles invalid base64 without crashing", () => {
		const input = "data: !!not-valid-base64-but-long-enough-to-match!!";
		expect(() => redactAllCredentialsWithEncoding(input)).not.toThrow();
	});

	it("existing plaintext detection still works (regression)", () => {
		const input = "key: sk-ant-abc123-testkey";
		const result = redactAllCredentialsWithEncoding(input);
		expect(result).toContain("[REDACTED]");
		expect(result).not.toContain("sk-ant");
	});

	it("handles invalid percent-encoding without crashing", () => {
		const input = "key=%ZZinvalid%encoding%here";
		expect(() => redactAllCredentialsWithEncoding(input)).not.toThrow();
	});

	it("detects double-encoded credential (base64 of URL-encoded key)", () => {
		// URL-encode then base64-encode an API key
		const key = "sk-ant-abc123-testkey-for-double";
		const urlEncoded = encodeURIComponent(key);
		const doubleEncoded = Buffer.from(urlEncoded).toString("base64");
		const input = `data: ${doubleEncoded}`;
		const result = redactAllCredentialsWithEncoding(input);
		// Base64 pass should decode to URL-encoded form, which contains the literal key
		expect(result).toContain("[REDACTED");
	});

	it("does not corrupt non-credential percent-encoded segments", () => {
		const input = "path=%2Fusr%2Flocal%2Fbin&name=hello%20world";
		const result = redactAllCredentialsWithEncoding(input);
		// Non-credential segments should pass through unchanged
		expect(result).toContain("path=%2Fusr%2Flocal%2Fbin");
	});

	it("does not cause performance regression on normal strings", () => {
		const normalText = "Hello, this is a normal email body without any encoded content. ".repeat(
			100,
		);
		const start = Date.now();
		redactAllCredentialsWithEncoding(normalText);
		const elapsed = Date.now() - start;
		expect(elapsed).toBeLessThan(100); // Should be well under 100ms
	});
});
