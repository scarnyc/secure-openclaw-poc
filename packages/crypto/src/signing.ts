import {
	createPrivateKey,
	createPublicKey,
	sign as cryptoSign,
	verify as cryptoVerify,
	generateKeyPairSync,
} from "node:crypto";

/**
 * Generate an Ed25519 key pair for manifest signing.
 */
export function generateKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
		publicKeyEncoding: { type: "spki", format: "der" },
		privateKeyEncoding: { type: "pkcs8", format: "der" },
	});
	return { publicKey: Buffer.from(publicKey), privateKey: Buffer.from(privateKey) };
}

/**
 * Sign data with an Ed25519 private key. Returns hex-encoded signature.
 */
export function sign(data: string, privateKey: Buffer): string {
	const key = createPrivateKey({ key: privateKey, format: "der", type: "pkcs8" });
	const signature = cryptoSign(null, Buffer.from(data), key);
	return signature.toString("hex");
}

/**
 * Verify an Ed25519 signature. Returns true if valid.
 */
export function verify(data: string, signature: string, publicKey: Buffer): boolean {
	const key = createPublicKey({ key: publicKey, format: "der", type: "spki" });
	return cryptoVerify(null, Buffer.from(data), key, Buffer.from(signature, "hex"));
}
