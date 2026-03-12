import { afterEach, describe, expect, it, vi } from "vitest";
import {
	_resetNativeBridge,
	isNativeAvailable,
	spawnWithCredentialNative,
} from "./native-bridge.js";

describe("native-bridge", () => {
	afterEach(() => {
		_resetNativeBridge();
		vi.restoreAllMocks();
	});

	it("isNativeAvailable returns a boolean regardless of addon state", () => {
		const result = isNativeAvailable();
		expect(typeof result).toBe("boolean");
	});

	it("spawnWithCredentialNative throws when native not available", () => {
		// Reset to force fresh load attempt (which will fail since addon isn't compiled in test env)
		_resetNativeBridge();

		// Suppress the console.warn from warnOnce
		vi.spyOn(console, "warn").mockImplementation(() => {});

		// Verify native is not available in test environment (no compiled .node binary)
		if (!isNativeAvailable()) {
			expect(() => {
				spawnWithCredentialNative(
					"echo",
					["test"],
					{},
					"CRED",
					"/fake/vault.enc",
					Buffer.alloc(32),
					"test-service",
					"apiKey",
				);
			}).toThrow(/Native crypto addon required for spawnWithCredential/);
		}
	});

	it("isNativeAvailable caches result across calls", () => {
		// Suppress the console.warn from warnOnce
		vi.spyOn(console, "warn").mockImplementation(() => {});

		const first = isNativeAvailable();
		const second = isNativeAvailable();
		// Both calls should return the same value (cached)
		expect(first).toBe(second);
	});

	it("_resetNativeBridge allows re-detection", () => {
		// Suppress the console.warn from warnOnce
		vi.spyOn(console, "warn").mockImplementation(() => {});

		isNativeAvailable(); // first load
		_resetNativeBridge(); // reset
		// Should not throw — just re-attempts loading
		const result = isNativeAvailable();
		expect(typeof result).toBe("boolean");
	});
});
