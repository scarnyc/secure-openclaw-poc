import { pbkdf2, randomBytes } from "node:crypto";

const ITERATIONS = 600_000;
const KEY_LENGTH = 32;
const SALT_LENGTH = 32;
const DIGEST = "sha512";

export function generateSalt(): Buffer {
	return randomBytes(SALT_LENGTH);
}

export function deriveKey(password: string | Buffer, salt: Buffer): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		pbkdf2(password, salt, ITERATIONS, KEY_LENGTH, DIGEST, (err, key) => {
			if (err) reject(err);
			else resolve(key);
		});
	});
}
