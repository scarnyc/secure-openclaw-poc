import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const currentDir = dirname(fileURLToPath(import.meta.url));

// Check if the native .node binary exists for this platform
const NATIVE_AVAILABLE = (() => {
	try {
		const possiblePaths = [
			join(currentDir, "..", "crypto-native.darwin-arm64.node"),
			join(currentDir, "..", "crypto-native.linux-x64-musl.node"),
		];
		return possiblePaths.some((p) => existsSync(p));
	} catch {
		return false;
	}
})();

const TEST_PASSWORD = "test-master-password-for-crypto-native";
const TEST_SERVICE_ID = "test-service";
const TEST_CREDENTIAL = { apiKey: "sk-test-12345", secret: "my-secret-value" };

const testDir = join(tmpdir(), "sentinel-crypto-native-test");
const vaultPath = join(testDir, "vault.enc");

// Dynamic module references — populated in beforeAll when native binary is available
// biome-ignore lint/suspicious/noExplicitAny: dynamic import types resolved at runtime
let nativeModule: any;
// biome-ignore lint/suspicious/noExplicitAny: dynamic import types resolved at runtime
let cryptoModule: any;

describe("@sentinel/crypto-native", () => {
	beforeAll(async () => {
		if (!NATIVE_AVAILABLE) return;

		nativeModule = await import("../index.js");
		cryptoModule = await import("@sentinel/crypto");

		mkdirSync(testDir, { recursive: true });

		// Create a vault using the Node.js API (source of truth for format)
		const vault = await cryptoModule.CredentialVault.create(vaultPath, TEST_PASSWORD);
		await vault.store(TEST_SERVICE_ID, "api_key", TEST_CREDENTIAL);
		vault.destroy();
	});

	afterAll(() => {
		try {
			rmSync(testDir, { recursive: true, force: true });
		} catch {
			// ignore cleanup errors
		}
	});

	it.skipIf(!NATIVE_AVAILABLE)("round-trip: JS vault create -> Rust decrypt -> matches", () => {
		const { deriveKeyNative, useCredentialNative } = nativeModule;

		// Read salt from vault file created by Node.js
		const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));

		// Derive key using Rust PBKDF2
		const derivedKey = deriveKeyNative(TEST_PASSWORD, vaultData.salt);

		// Decrypt the credential using Rust
		const resultBuf = useCredentialNative(vaultPath, derivedKey, TEST_SERVICE_ID);
		const parsed = JSON.parse(Buffer.from(resultBuf).toString("utf8"));

		expect(parsed).toEqual(TEST_CREDENTIAL);
		expect(parsed.apiKey).toBe("sk-test-12345");
		expect(parsed.secret).toBe("my-secret-value");
	});

	it.skipIf(!NATIVE_AVAILABLE)("Buffer contents match expected credential fields", () => {
		const { deriveKeyNative, useCredentialNative } = nativeModule;

		const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));
		const derivedKey = deriveKeyNative(TEST_PASSWORD, vaultData.salt);

		const resultBuf = useCredentialNative(vaultPath, derivedKey, TEST_SERVICE_ID);
		const parsed = JSON.parse(Buffer.from(resultBuf).toString("utf8"));

		expect(typeof parsed.apiKey).toBe("string");
		expect(typeof parsed.secret).toBe("string");
		expect(Object.keys(parsed).sort()).toEqual(["apiKey", "secret"]);
	});

	it.skipIf(!NATIVE_AVAILABLE)("wrong derived key -> throws DecryptionError", () => {
		const { deriveKeyNative, useCredentialNative } = nativeModule;

		// Derive key with wrong password and a dummy 32-byte salt (base64)
		const wrongKey = deriveKeyNative(
			"wrong-password",
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		);

		expect(() => {
			useCredentialNative(vaultPath, wrongKey, TEST_SERVICE_ID);
		}).toThrow(/Decryption failed|Invalid vault password/);
	});

	it.skipIf(!NATIVE_AVAILABLE)("missing serviceId -> throws ServiceNotFound", () => {
		const { deriveKeyNative, useCredentialNative } = nativeModule;

		const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));
		const derivedKey = deriveKeyNative(TEST_PASSWORD, vaultData.salt);

		expect(() => {
			useCredentialNative(vaultPath, derivedKey, "nonexistent-service");
		}).toThrow(/Service not found: nonexistent-service/);
	});

	it.skipIf(!NATIVE_AVAILABLE)("vault file not found -> throws IoError", () => {
		const { deriveKeyNative, useCredentialNative } = nativeModule;

		const fakeKey = deriveKeyNative("password", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

		expect(() => {
			useCredentialNative("/nonexistent/path/vault.enc", fakeKey, "test");
		}).toThrow(/IO error/);
	});

	it.skipIf(!NATIVE_AVAILABLE)(
		"verifier check catches wrong password (correct salt, wrong password)",
		() => {
			const { deriveKeyNative, useCredentialNative } = nativeModule;

			// Use the correct salt from the vault but derive with wrong password
			const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));
			const wrongKey = deriveKeyNative("wrong-password-here", vaultData.salt);

			expect(() => {
				useCredentialNative(vaultPath, wrongKey, TEST_SERVICE_ID);
			}).toThrow(/Decryption failed|Invalid vault password/);
		},
	);

	it.skipIf(!NATIVE_AVAILABLE)(
		"spawnWithCredential injects env correctly — credential in subprocess, not in JS",
		() => {
			const { deriveKeyNative, spawnWithCredential } = nativeModule;

			const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));
			const derivedKey = deriveKeyNative(TEST_PASSWORD, vaultData.salt);

			// Use printenv to verify the credential appears as an env var in the subprocess
			const result = spawnWithCredential(
				"printenv",
				["TEST_CRED_VAR"],
				{ PATH: process.env.PATH ?? "/usr/bin" },
				"TEST_CRED_VAR",
				vaultPath,
				derivedKey,
				TEST_SERVICE_ID,
				"apiKey",
				undefined,
			);

			expect(result.exitCode).toBe(0);
			// Credential value appears in subprocess stdout
			expect(result.stdout.trim()).toBe("sk-test-12345");
			// Verify it returned a plain object, not a Buffer or other type
			expect(typeof result.stdout).toBe("string");
			expect(typeof result.stderr).toBe("string");
			expect(typeof result.exitCode).toBe("number");
		},
	);

	it.skipIf(!NATIVE_AVAILABLE)("spawnWithCredential — missing field throws FieldNotFound", () => {
		const { deriveKeyNative, spawnWithCredential } = nativeModule;

		const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));
		const derivedKey = deriveKeyNative(TEST_PASSWORD, vaultData.salt);

		expect(() => {
			spawnWithCredential(
				"echo",
				["test"],
				{},
				"CRED",
				vaultPath,
				derivedKey,
				TEST_SERVICE_ID,
				"nonexistentField",
				undefined,
			);
		}).toThrow(/Field not found: nonexistentField/);
	});

	it.skipIf(!NATIVE_AVAILABLE)("spawnWithCredential — invalid command returns IoError", () => {
		const { deriveKeyNative, spawnWithCredential } = nativeModule;

		const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));
		const derivedKey = deriveKeyNative(TEST_PASSWORD, vaultData.salt);

		expect(() => {
			spawnWithCredential(
				"/nonexistent/binary",
				[],
				{},
				"CRED",
				vaultPath,
				derivedKey,
				TEST_SERVICE_ID,
				"apiKey",
				undefined,
			);
		}).toThrow(/Failed to spawn/);
	});

	it.skipIf(!NATIVE_AVAILABLE)(
		"spawnWithCredential — timeout kills long-running subprocess",
		() => {
			const { deriveKeyNative, spawnWithCredential } = nativeModule;

			const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));
			const derivedKey = deriveKeyNative(TEST_PASSWORD, vaultData.salt);

			// Use sleep 60 with a 500ms timeout — should throw Timeout error
			expect(() => {
				spawnWithCredential(
					"sleep",
					["60"],
					{ PATH: process.env.PATH ?? "/usr/bin" },
					"UNUSED_CRED",
					vaultPath,
					derivedKey,
					TEST_SERVICE_ID,
					"apiKey",
					500, // 500ms timeout
				);
			}).toThrow(/timed out/i);
		},
	);

	it.skipIf(!NATIVE_AVAILABLE)(
		"spawnWithCredential — completes before timeout when fast enough",
		() => {
			const { deriveKeyNative, spawnWithCredential } = nativeModule;

			const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));
			const derivedKey = deriveKeyNative(TEST_PASSWORD, vaultData.salt);

			// Use echo with a generous timeout — should succeed
			const result = spawnWithCredential(
				"echo",
				["timeout-test"],
				{ PATH: process.env.PATH ?? "/usr/bin" },
				"UNUSED_CRED",
				vaultPath,
				derivedKey,
				TEST_SERVICE_ID,
				"apiKey",
				5000, // 5s timeout — more than enough for echo
			);

			expect(result.exitCode).toBe(0);
			expect(result.stdout.trim()).toBe("timeout-test");
		},
	);

	it.skipIf(!NATIVE_AVAILABLE)("spawnWithCredential — env vars are passed to subprocess", () => {
		const { deriveKeyNative, spawnWithCredential } = nativeModule;

		const vaultData = JSON.parse(readFileSync(vaultPath, "utf8"));
		const derivedKey = deriveKeyNative(TEST_PASSWORD, vaultData.salt);

		// env_clear() means only explicitly passed env vars are available
		const result = spawnWithCredential(
			"printenv",
			["CUSTOM_VAR"],
			{ PATH: process.env.PATH ?? "/usr/bin", CUSTOM_VAR: "hello-world" },
			"UNUSED_CRED",
			vaultPath,
			derivedKey,
			TEST_SERVICE_ID,
			"apiKey",
			undefined,
		);

		expect(result.exitCode).toBe(0);
		expect(result.stdout.trim()).toBe("hello-world");
	});
});
