import { readFile, writeFile } from "node:fs/promises";
import type { EncryptedBlob } from "./encryption.js";
import { DecryptionError, decrypt, encrypt } from "./encryption.js";
import { deriveKey, generateSalt } from "./key-derivation.js";

const VERIFIER_PLAINTEXT = "sentinel-vault-v1";

interface VaultEntry {
	type: string;
	data: EncryptedBlob;
	createdAt: string;
}

interface VaultFile {
	version: 1;
	salt: string;
	verifier: EncryptedBlob;
	entries: Record<string, VaultEntry>;
}

export class CredentialVault {
	private derivedKey: Buffer;
	private vaultPath: string;
	private data: VaultFile;

	private constructor(vaultPath: string, derivedKey: Buffer, data: VaultFile) {
		this.vaultPath = vaultPath;
		this.derivedKey = derivedKey;
		this.data = data;
	}

	static async create(vaultPath: string, masterPassword: string): Promise<CredentialVault> {
		const salt = generateSalt();
		const key = await deriveKey(masterPassword, salt);
		const verifier = encrypt(key, VERIFIER_PLAINTEXT);

		const data: VaultFile = {
			version: 1,
			salt: salt.toString("base64"),
			verifier,
			entries: {},
		};

		await writeFile(vaultPath, JSON.stringify(data, null, "\t"), "utf8");
		return new CredentialVault(vaultPath, key, data);
	}

	static async open(vaultPath: string, masterPassword: string): Promise<CredentialVault> {
		const raw = await readFile(vaultPath, "utf8");
		const data: VaultFile = JSON.parse(raw);

		const salt = Buffer.from(data.salt, "base64");
		const key = await deriveKey(masterPassword, salt);

		// Validate password by decrypting verifier
		const verified = decrypt(
			key,
			data.verifier.iv,
			data.verifier.authTag,
			data.verifier.ciphertext,
		);
		if (verified !== VERIFIER_PLAINTEXT) {
			throw new DecryptionError("Invalid master password");
		}

		return new CredentialVault(vaultPath, key, data);
	}

	async store(
		serviceId: string,
		credentialType: string,
		data: Record<string, string>,
	): Promise<void> {
		const blob = encrypt(this.derivedKey, JSON.stringify(data));
		this.data.entries[serviceId] = {
			type: credentialType,
			data: blob,
			createdAt: new Date().toISOString(),
		};
		await this.save();
	}

	async retrieve(serviceId: string): Promise<Record<string, string>> {
		const entry = this.data.entries[serviceId];
		if (!entry) {
			throw new Error(`No credential found for service: ${serviceId}`);
		}
		const plaintext = decrypt(
			this.derivedKey,
			entry.data.iv,
			entry.data.authTag,
			entry.data.ciphertext,
		);
		return JSON.parse(plaintext);
	}

	async remove(serviceId: string): Promise<void> {
		delete this.data.entries[serviceId];
		await this.save();
	}

	async list(): Promise<Array<{ serviceId: string; type: string; createdAt: string }>> {
		return Object.entries(this.data.entries).map(([serviceId, entry]) => ({
			serviceId,
			type: entry.type,
			createdAt: entry.createdAt,
		}));
	}

	async wipe(): Promise<void> {
		this.data.entries = {};
		await this.save();
	}

	destroy(): void {
		this.derivedKey.fill(0);
	}

	private async save(): Promise<void> {
		await writeFile(this.vaultPath, JSON.stringify(this.data, null, "\t"), "utf8");
	}
}
