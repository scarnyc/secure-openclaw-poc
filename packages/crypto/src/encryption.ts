import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export class DecryptionError extends Error {
	constructor(message = "Decryption failed") {
		super(message);
		this.name = "DecryptionError";
	}
}

export interface EncryptedBlob {
	iv: string;
	authTag: string;
	ciphertext: string;
}

export function encrypt(key: Buffer, plaintext: string): EncryptedBlob {
	const iv = randomBytes(IV_LENGTH);
	const cipher = createCipheriv(ALGORITHM, key, iv);

	const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const authTag = cipher.getAuthTag();

	return {
		iv: iv.toString("base64"),
		authTag: authTag.toString("base64"),
		ciphertext: encrypted.toString("base64"),
	};
}

export function decrypt(key: Buffer, iv: string, authTag: string, ciphertext: string): string {
	try {
		const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(iv, "base64"));
		decipher.setAuthTag(Buffer.from(authTag, "base64"));

		const decrypted = Buffer.concat([
			decipher.update(Buffer.from(ciphertext, "base64")),
			decipher.final(),
		]);

		return decrypted.toString("utf8");
	} catch {
		throw new DecryptionError();
	}
}
