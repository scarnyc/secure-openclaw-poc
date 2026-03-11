import { describe, expect, it } from "vitest";
import { deriveKey, generateSalt } from "./key-derivation.js";

describe("deriveKey", () => {
	it("derives consistent key from string password", async () => {
		const salt = generateSalt();
		const key1 = await deriveKey("test-password", salt);
		const key2 = await deriveKey("test-password", salt);
		expect(key1.equals(key2)).toBe(true);
		expect(key1.length).toBe(32);
		key1.fill(0);
		key2.fill(0);
	});

	it("accepts Buffer password and derives same key as equivalent string", async () => {
		const salt = generateSalt();
		const password = "buffer-password-test";
		const passwordBuf = Buffer.from(password, "utf8");

		const keyFromString = await deriveKey(password, salt);
		const keyFromBuffer = await deriveKey(passwordBuf, salt);

		expect(keyFromString.equals(keyFromBuffer)).toBe(true);
		expect(keyFromBuffer.length).toBe(32);

		keyFromString.fill(0);
		keyFromBuffer.fill(0);
		passwordBuf.fill(0);
	});

	it("Buffer password can be zeroed after deriveKey returns", async () => {
		const salt = generateSalt();
		const passwordBuf = Buffer.from("zero-after-derive", "utf8");

		const key = await deriveKey(passwordBuf, salt);
		// Zero the password Buffer — key should still be valid
		passwordBuf.fill(0);
		expect(passwordBuf.every((byte) => byte === 0)).toBe(true);
		expect(key.length).toBe(32);

		key.fill(0);
	});
});
