import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { warnOnce } from "./warn-once.js";

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
	let encrypted: Buffer | undefined;
	let authTag: Buffer | undefined;
	try {
		const cipher = createCipheriv(ALGORITHM, key, iv);
		encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
		authTag = cipher.getAuthTag();
		return {
			iv: iv.toString("base64"),
			authTag: authTag.toString("base64"),
			ciphertext: encrypted.toString("base64"),
		};
	} finally {
		iv.fill(0);
		if (encrypted) encrypted.fill(0);
		if (authTag) authTag.fill(0);
	}
}

/**
 * Decrypt and return raw Buffer. Caller MUST zero the returned Buffer after use.
 * Unlike decrypt(), this avoids creating an intermediate V8 string that cannot be zeroed.
 */
export function decryptToBuffer(
	key: Buffer,
	iv: string,
	authTag: string,
	ciphertext: string,
): Buffer {
	const ivBuf = Buffer.from(iv, "base64");
	const authTagBuf = Buffer.from(authTag, "base64");
	const ciphertextBuf = Buffer.from(ciphertext, "base64");
	let partial: Buffer | undefined;
	try {
		const decipher = createDecipheriv(ALGORITHM, key, ivBuf);
		decipher.setAuthTag(authTagBuf);
		partial = decipher.update(ciphertextBuf);
		const final = decipher.final();
		const result = Buffer.concat([partial, final]);
		// Zero intermediates now that we have the combined result
		partial.fill(0);
		final.fill(0);
		return result;
	} catch (err) {
		if (err instanceof DecryptionError) throw err;
		throw new DecryptionError();
	} finally {
		// Zero partial decrypted data if final() threw (auth tag mismatch)
		if (partial) partial.fill(0);
		ivBuf.fill(0);
		authTagBuf.fill(0);
		ciphertextBuf.fill(0);
	}
}

/**
 * @deprecated Use `decryptToBuffer()` or `useCredential()` instead.
 * Returns a V8 immutable string that cannot be zeroed from memory.
 */
export function decrypt(key: Buffer, iv: string, authTag: string, ciphertext: string): string {
	warnOnce(
		"decrypt",
		"[sentinel/crypto] decrypt() is deprecated — use decryptToBuffer() or useCredential()",
	);

	const ivBuf = Buffer.from(iv, "base64");
	const authTagBuf = Buffer.from(authTag, "base64");
	const ciphertextBuf = Buffer.from(ciphertext, "base64");
	try {
		const decipher = createDecipheriv(ALGORITHM, key, ivBuf);
		decipher.setAuthTag(authTagBuf);
		const decrypted = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);
		try {
			// S2: Return value is a V8 immutable string — cannot be zeroed from memory.
			// Callers needing zeroable output should use decryptToBuffer() instead.
			return decrypted.toString("utf8");
		} finally {
			decrypted.fill(0);
		}
	} catch (err) {
		if (err instanceof DecryptionError) throw err;
		throw new DecryptionError();
	} finally {
		ivBuf.fill(0);
		authTagBuf.fill(0);
		ciphertextBuf.fill(0);
	}
}
