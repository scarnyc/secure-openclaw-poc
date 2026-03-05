import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DecryptionError } from "./encryption.js";
import { CredentialVault } from "./vault.js";

describe("CredentialVault", () => {
	const tempDirs: string[] = [];

	async function makeTempVaultPath(): Promise<string> {
		const dir = await mkdtemp(join(tmpdir(), "sentinel-vault-"));
		tempDirs.push(dir);
		return join(dir, "vault.json");
	}

	afterEach(async () => {
		for (const dir of tempDirs) {
			await rm(dir, { recursive: true, force: true });
		}
		tempDirs.length = 0;
	});

	it("store + retrieve round-trip: plaintext matches", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault = await CredentialVault.create(vaultPath, "master-pass-123");

		const creds = { apiKey: "sk-test-abc123", secret: "super-secret-value" };
		await vault.store("openai", "api_key", creds);

		const retrieved = await vault.retrieve("openai");
		expect(retrieved).toEqual(creds);

		vault.destroy();
	});

	it("wrong password throws DecryptionError", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault = await CredentialVault.create(vaultPath, "correct-password");
		vault.destroy();

		await expect(CredentialVault.open(vaultPath, "wrong-password")).rejects.toThrow(
			DecryptionError,
		);
	});

	it("destroy() zeros derived key buffer", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault = await CredentialVault.create(vaultPath, "test-pass");

		// Access internal derivedKey for test verification
		// biome-ignore lint/suspicious/noExplicitAny: testing private field
		const key = (vault as any).derivedKey as Buffer;
		expect(key.some((b: number) => b !== 0)).toBe(true);

		vault.destroy();
		expect(key.every((b: number) => b === 0)).toBe(true);
	});

	it("raw vault file contains no plaintext credential content", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault = await CredentialVault.create(vaultPath, "test-pass");

		const secretValue = "my-super-secret-api-key-12345";
		await vault.store("github", "token", { token: secretValue });
		vault.destroy();

		const raw = await readFile(vaultPath, "utf8");
		expect(raw).not.toContain(secretValue);
		expect(raw).not.toContain("my-super-secret");
	});

	it("list() returns metadata without secrets", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault = await CredentialVault.create(vaultPath, "test-pass");

		await vault.store("openai", "api_key", { key: "sk-secret" });
		await vault.store("github", "token", { token: "ghp-secret" });

		const listing = await vault.list();
		expect(listing).toHaveLength(2);

		for (const item of listing) {
			expect(item).toHaveProperty("serviceId");
			expect(item).toHaveProperty("type");
			expect(item).toHaveProperty("createdAt");
			expect(item).not.toHaveProperty("data");
			expect(JSON.stringify(item)).not.toContain("sk-secret");
			expect(JSON.stringify(item)).not.toContain("ghp-secret");
		}

		vault.destroy();
	});

	it("remove() deletes entry, subsequent retrieve() fails", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault = await CredentialVault.create(vaultPath, "test-pass");

		await vault.store("slack", "oauth", { token: "xoxb-123" });
		await vault.remove("slack");

		await expect(vault.retrieve("slack")).rejects.toThrow("No credential found");

		vault.destroy();
	});

	it("wipe() removes all entries", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault = await CredentialVault.create(vaultPath, "test-pass");

		await vault.store("openai", "api_key", { key: "sk-1" });
		await vault.store("github", "token", { token: "ghp-1" });

		await vault.wipe();

		const listing = await vault.list();
		expect(listing).toHaveLength(0);

		await expect(vault.retrieve("openai")).rejects.toThrow();
		await expect(vault.retrieve("github")).rejects.toThrow();

		vault.destroy();
	});

	it("open() restores vault and retrieves stored credentials", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault1 = await CredentialVault.create(vaultPath, "persist-pass");
		await vault1.store("aws", "api_key", {
			accessKey: "AKIA123",
			secretKey: "wJalrXUt",
		});
		vault1.destroy();

		const vault2 = await CredentialVault.open(vaultPath, "persist-pass");
		const creds = await vault2.retrieve("aws");
		expect(creds).toEqual({ accessKey: "AKIA123", secretKey: "wJalrXUt" });
		vault2.destroy();
	});
});
