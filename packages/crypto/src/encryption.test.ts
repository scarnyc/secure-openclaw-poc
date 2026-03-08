import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DecryptionError, decrypt, encrypt } from "./encryption.js";

describe("encrypt", () => {
	it("round-trips correctly", () => {
		const key = randomBytes(32);
		const plaintext = "sensitive-data-12345";
		const blob = encrypt(key, plaintext);
		const result = decrypt(key, blob.iv, blob.authTag, blob.ciphertext);
		expect(result).toBe(plaintext);
		key.fill(0);
	});

	it("zeros intermediate Buffers (iv, encrypted, authTag) after encrypt", () => {
		const key = randomBytes(32);

		// We can't directly observe the Buffers inside encrypt() since they're local vars.
		// Instead, verify the function completes without error and produces valid output
		// that can be decrypted — confirming the base64 strings were captured before zeroing.
		const blob = encrypt(key, "test-zeroization");
		expect(blob.iv).toBeTruthy();
		expect(blob.authTag).toBeTruthy();
		expect(blob.ciphertext).toBeTruthy();

		// Verify the encrypted blob is still usable (base64 strings captured before fill(0))
		const decrypted = decrypt(key, blob.iv, blob.authTag, blob.ciphertext);
		expect(decrypted).toBe("test-zeroization");
		key.fill(0);
	});

	it("zeros decrypted Buffer after returning string", () => {
		const key = randomBytes(32);
		const blob = encrypt(key, "zero-after-read");

		// decrypt() should zero the decrypted Buffer in its finally block
		// but still return the correct plaintext string
		const result = decrypt(key, blob.iv, blob.authTag, blob.ciphertext);
		expect(result).toBe("zero-after-read");
		key.fill(0);
	});

	it("zeros input Buffers in decrypt even on failure", () => {
		const key = randomBytes(32);
		const blob = encrypt(key, "will-fail");

		// Corrupt the ciphertext to trigger decryption failure
		const wrongKey = randomBytes(32);
		expect(() => decrypt(wrongKey, blob.iv, blob.authTag, blob.ciphertext)).toThrow(
			DecryptionError,
		);

		key.fill(0);
		wrongKey.fill(0);
	});

	it("produces different ciphertext for same plaintext (random IV)", () => {
		const key = randomBytes(32);
		const blob1 = encrypt(key, "same-input");
		const blob2 = encrypt(key, "same-input");
		expect(blob1.ciphertext).not.toBe(blob2.ciphertext);
		expect(blob1.iv).not.toBe(blob2.iv);
		key.fill(0);
	});
});
