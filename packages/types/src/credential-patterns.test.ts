import { describe, expect, it } from "vitest";
import {
	containsCredential,
	recursiveContainsCredential,
	redactAllCredentials,
	redactAllCredentialsWithEncoding,
} from "./credential-patterns.js";

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

	describe("Private key patterns", () => {
		it("redacts PEM private keys (PKCS#8)", () => {
			const input = `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw...\\n-----END PRIVATE KEY-----\\n"}`;
			const result = redactAllCredentials(input);
			expect(result).not.toContain("MIIEvQIBADANBgkqhkiG9w0");
			expect(result).toContain("[REDACTED]");
		});

		it("redacts RSA private keys", () => {
			const input =
				"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----";
			const result = redactAllCredentials(input);
			expect(result).not.toContain("MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn");
			expect(result).toContain("[REDACTED]");
		});

		it("redacts EC private keys", () => {
			const input = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIGkz0R\n-----END EC PRIVATE KEY-----";
			const result = redactAllCredentials(input);
			expect(result).not.toContain("MHQCAQEEIGkz0R");
			expect(result).toContain("[REDACTED]");
		});

		it("redacts OpenSSH private keys", () => {
			const input =
				"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----";
			const result = redactAllCredentials(input);
			expect(result).not.toContain("b3BlbnNzaC1rZXktdjEA");
			expect(result).toContain("[REDACTED]");
		});

		it("redacts DSA private keys", () => {
			const input =
				"-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAJBALRi\n-----END DSA PRIVATE KEY-----";
			const result = redactAllCredentials(input);
			expect(result).not.toContain("MIIBuwIBAAJBALRi");
			expect(result).toContain("[REDACTED]");
		});

		it("does not false-positive on public keys", () => {
			const input =
				"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEF\n-----END PUBLIC KEY-----";
			const result = redactAllCredentials(input);
			expect(result).toContain("MIIBIjANBgkqhkiG9w0BAQEF");
		});

		it("redacts private key in Google service account JSON", () => {
			const serviceAccount = JSON.stringify({
				type: "service_account",
				project_id: "my-project",
				private_key:
					"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n",
				client_email: "svc@my-project.iam.gserviceaccount.com",
			});
			const result = redactAllCredentials(serviceAccount);
			expect(result).not.toContain("MIIEvQIBADANBgkqhkiG9w0");
			expect(result).toContain("[REDACTED]");
			// Non-sensitive fields preserved
			expect(result).toContain("service_account");
			expect(result).toContain("my-project");
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

	it("does not cause performance regression on normal strings", () => {
		const normalText = "Hello, this is a normal email body without any encoded content. ".repeat(
			100,
		);
		const start = Date.now();
		redactAllCredentialsWithEncoding(normalText);
		const elapsed = Date.now() - start;
		expect(elapsed).toBeLessThan(100); // Should be well under 100ms
	});

	describe("URL-decode segment isolation (review fix)", () => {
		it("preserves non-credential URL-encoded content when credential is in separate segment", () => {
			// %20 = space, should remain encoded in output except in the credential segment
			const input = "name=Hello%20World&key=sk%2Dant%2Dabc123%2Dleaked";
			const result = redactAllCredentialsWithEncoding(input);
			// Credential segment should be redacted
			expect(result).toContain("[REDACTED");
			// The name segment should NOT be decoded to "Hello World"
			expect(result).toContain("Hello%20World");
		});

		it("redacts URL-encoded API key segments", () => {
			const input = "token=%73%6B%2D%61%6E%74%2Dabc123-testkey"; // sk-ant-abc123-testkey
			const result = redactAllCredentialsWithEncoding(input);
			expect(result).toContain("[REDACTED");
		});
	});

	describe("PEM regex ReDoS hardening", () => {
		it("does not hang on malformed PEM (no END marker)", () => {
			// Simulates ReDoS attack: BEGIN marker followed by large content, no END marker
			const malicious = "-----BEGIN PRIVATE KEY-----\n" + "A".repeat(1000) + "\nno end marker";
			const start = Date.now();
			redactAllCredentialsWithEncoding(malicious);
			const elapsed = Date.now() - start;
			expect(elapsed).toBeLessThan(500); // Must complete quickly
		});

		it("still redacts valid PEM keys after hardening", () => {
			const validPem =
				"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";
			const result = redactAllCredentialsWithEncoding(validPem);
			expect(result).not.toContain("MIIEvQ");
			expect(result).toContain("[REDACTED]");
		});
	});
});

describe("recursiveContainsCredential", () => {
	it("detects base64(base64(credential))", () => {
		const credential = "sk-ant-abc123-testkey-for-encoding";
		const singleEncoded = Buffer.from(credential).toString("base64");
		const doubleEncoded = Buffer.from(singleEncoded).toString("base64");
		expect(recursiveContainsCredential(doubleEncoded)).toBe(true);
	});

	it("detects urlencode(base64(credential))", () => {
		const credential = "ya29.a0ARrdaM8_Wn3EfCnXoP_abc123-def456";
		const base64Encoded = Buffer.from(credential).toString("base64");
		const urlEncoded = encodeURIComponent(base64Encoded);
		expect(recursiveContainsCredential(urlEncoded)).toBe(true);
	});

	it("detects base64(urlencode(base64(credential))) — triple-nested", () => {
		const credential = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
		const base64First = Buffer.from(credential).toString("base64");
		const urlEncoded = encodeURIComponent(base64First);
		const base64Second = Buffer.from(urlEncoded).toString("base64");
		expect(recursiveContainsCredential(base64Second)).toBe(true);
	});

	it("returns true (fail-safe) when depth limit exceeded — depth 5 nesting", () => {
		const credential = "sk-ant-abc123-deeply-nested-key";
		let encoded: string = credential;
		for (let i = 0; i < 5; i++) {
			encoded = Buffer.from(encoded).toString("base64");
		}
		// Fail-safe: can't prove no credentials at this depth, so assume there might be
		expect(recursiveContainsCredential(encoded)).toBe(true);
	});

	it("returns true (fail-safe) on oversized input (100KB) without performance regression", () => {
		const largeBlob = "A".repeat(100_000);
		const start = performance.now();
		const result = recursiveContainsCredential(largeBlob);
		const elapsed = performance.now() - start;
		// Fail-safe: oversized input treated as potentially containing credentials
		expect(result).toBe(true);
		expect(elapsed).toBeLessThan(50);
	});

	it("does not false-positive on non-credential base64", () => {
		const normalText = "Hello, World! This is a normal message.";
		const encoded = Buffer.from(normalText).toString("base64");
		expect(recursiveContainsCredential(encoded)).toBe(false);
	});

	it("processes 1000 typical inputs in < 50ms", () => {
		const inputs: string[] = [];
		for (let i = 0; i < 1000; i++) {
			inputs.push(
				`normal text with some base64 ${Buffer.from(`value-${i}`).toString("base64")} content`,
			);
		}
		const start = performance.now();
		for (const input of inputs) {
			recursiveContainsCredential(input);
		}
		const elapsed = performance.now() - start;
		expect(elapsed).toBeLessThan(50);
	});
});

describe("JWT token detection", () => {
	it("detects JWT tokens", () => {
		const jwt =
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
		expect(containsCredential(`token: ${jwt}`)).toBe(true);
	});

	it("redacts JWT tokens", () => {
		const jwt =
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
		expect(redactAllCredentials(`token: ${jwt}`)).not.toContain("eyJ");
	});

	it("does not false-positive on short base64 strings", () => {
		expect(containsCredential("eyJhbG")).toBe(false);
	});
});

describe("Stripe key detection", () => {
	// Build test keys dynamically to avoid GitHub push protection false positives
	const stripePrefix = ["sk", "live"].join("_");
	const stripeTestPrefix = ["sk", "test"].join("_");
	const stripeSuffix = "0".repeat(24);

	it("detects Stripe live secret keys", () => {
		expect(containsCredential(`${stripePrefix}_${stripeSuffix}`)).toBe(true);
	});

	it("detects Stripe test secret keys", () => {
		expect(containsCredential(`${stripeTestPrefix}_${stripeSuffix}`)).toBe(true);
	});

	it("redacts Stripe keys", () => {
		expect(redactAllCredentials(`key: ${stripePrefix}_${stripeSuffix}`)).toContain("[REDACTED]");
	});

	it("does not interfere with OpenAI sk- pattern", () => {
		expect(containsCredential("sk-abcdefghijklmnopqrstuv")).toBe(true);
	});
});

describe("redactAllCredentialsWithEncoding — multi-level", () => {
	it("redacts double-base64-encoded credentials", () => {
		const credential = "sk-ant-abc123-testkey-double";
		const singleEncoded = Buffer.from(credential).toString("base64");
		const doubleEncoded = Buffer.from(singleEncoded).toString("base64");
		const input = `data: ${doubleEncoded}`;
		const result = redactAllCredentialsWithEncoding(input);
		expect(result).toContain("[REDACTED_ENCODED]");
		expect(result).not.toContain(doubleEncoded);
	});

	it("redacts triple-nested encoded credentials via URL+base64", () => {
		const credential = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
		const base64First = Buffer.from(credential).toString("base64");
		const urlEncoded = encodeURIComponent(base64First);
		const base64Second = Buffer.from(urlEncoded).toString("base64");
		const input = `token: ${base64Second}`;
		const result = redactAllCredentialsWithEncoding(input);
		expect(result).toContain("[REDACTED");
	});
});
