import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { useCredential } from "./use-credential.js";
import { CredentialVault } from "./vault.js";

describe("useCredential", () => {
	const tempDirs: string[] = [];

	async function makeVault(): Promise<CredentialVault> {
		const dir = await mkdtemp(join(tmpdir(), "sentinel-usecred-"));
		tempDirs.push(dir);
		const vaultPath = join(dir, "vault.json");
		const vault = await CredentialVault.create(vaultPath, "test-pass");
		await vault.store("test-service", "api_key", { key: "sk-secret-123" });
		return vault;
	}

	afterEach(async () => {
		for (const dir of tempDirs) {
			await rm(dir, { recursive: true, force: true });
		}
		tempDirs.length = 0;
	});

	it("zeroes buffer after successful callback", async () => {
		const vault = await makeVault();
		let capturedBuf: Buffer | undefined;

		const origRetrieve = vault.retrieveBuffer.bind(vault);
		vault.retrieveBuffer = (serviceId: string) => {
			const buf = origRetrieve(serviceId);
			capturedBuf = buf;
			return buf;
		};

		const result = await useCredential(vault, "test-service", (cred) => {
			expect(cred.key).toBe("sk-secret-123");
			return "callback-result";
		});

		expect(result).toBe("callback-result");
		expect(capturedBuf).toBeDefined();
		expect(capturedBuf?.every((b) => b === 0)).toBe(true);

		vault.destroy();
	});

	it("zeroes buffer when callback throws", async () => {
		const vault = await makeVault();
		let capturedBuf: Buffer | undefined;

		const origRetrieve = vault.retrieveBuffer.bind(vault);
		vault.retrieveBuffer = (serviceId: string) => {
			const buf = origRetrieve(serviceId);
			capturedBuf = buf;
			return buf;
		};

		await expect(
			useCredential(vault, "test-service", () => {
				throw new Error("callback-error");
			}),
		).rejects.toThrow("callback-error");

		expect(capturedBuf).toBeDefined();
		expect(capturedBuf?.every((b) => b === 0)).toBe(true);

		vault.destroy();
	});

	it("zeroes buffer when async callback rejects", async () => {
		const vault = await makeVault();
		let capturedBuf: Buffer | undefined;

		const origRetrieve = vault.retrieveBuffer.bind(vault);
		vault.retrieveBuffer = (serviceId: string) => {
			const buf = origRetrieve(serviceId);
			capturedBuf = buf;
			return buf;
		};

		await expect(
			useCredential(vault, "test-service", async () => {
				await new Promise((resolve) => setTimeout(resolve, 5));
				throw new Error("async-fail");
			}),
		).rejects.toThrow("async-fail");

		expect(capturedBuf).toBeDefined();
		expect(capturedBuf?.every((b) => b === 0)).toBe(true);

		vault.destroy();
	});

	it("works with async callbacks", async () => {
		const vault = await makeVault();

		const result = await useCredential(vault, "test-service", async (cred) => {
			await new Promise((resolve) => setTimeout(resolve, 10));
			return `async-${cred.key}`;
		});

		expect(result).toBe("async-sk-secret-123");

		vault.destroy();
	});

	it("throws when serviceId not found", async () => {
		const vault = await makeVault();

		await expect(useCredential(vault, "nonexistent", () => "nope")).rejects.toThrow(
			"No credential found for service: nonexistent",
		);

		vault.destroy();
	});

	it("propagates return value from callback", async () => {
		const vault = await makeVault();

		const result = await useCredential(vault, "test-service", (cred) => ({
			transformed: cred.key.toUpperCase(),
			length: cred.key.length,
		}));

		expect(result).toEqual({
			transformed: "SK-SECRET-123",
			length: 13,
		});

		vault.destroy();
	});

	it("validates required keys", async () => {
		const vault = await makeVault();

		const result = await useCredential(vault, "test-service", ["key"] as const, (cred) => cred.key);

		expect(result).toBe("sk-secret-123");

		vault.destroy();
	});

	it("throws on missing required key", async () => {
		const vault = await makeVault();

		await expect(
			useCredential(vault, "test-service", ["key", "nonexistent"] as const, (cred) => cred.key),
		).rejects.toThrow('Missing required field "nonexistent"');

		vault.destroy();
	});

	it("throws with context on malformed JSON", async () => {
		const vault = await makeVault();
		vault.retrieveBuffer = () => Buffer.from("not-json");

		await expect(useCredential(vault, "test-service", () => "nope")).rejects.toThrow(
			'Failed to parse credential for service "test-service"',
		);

		vault.destroy();
	});

	it("freezes parsed credential object", async () => {
		const vault = await makeVault();

		await expect(
			useCredential(vault, "test-service", (cred) => {
				(cred as Record<string, string>).newProp = "x";
				return "should-not-reach";
			}),
		).rejects.toThrow(TypeError);

		vault.destroy();
	});
});
