import { existsSync } from "node:fs";
import { chmod, unlink } from "node:fs/promises";
import { createServer, type Server } from "node:net";

const MAX_PASSWORD_LENGTH = 1024; // 1KB max password size

export interface VaultPasswordResult {
	password: Buffer;
}

/**
 * Creates a UDS server that listens for exactly one connection, receives the vault
 * password bytes, then cleans up. Times out after 30 seconds.
 *
 * @param socketPath - Path for the Unix domain socket (e.g., data/vault.sock)
 * @param timeoutMs - Timeout in milliseconds (default: 30000)
 * @returns Promise resolving to the received password Buffer
 */
export async function receiveVaultPassword(
	socketPath: string,
	timeoutMs = 30_000,
): Promise<VaultPasswordResult> {
	// Clean up stale socket
	if (existsSync(socketPath)) {
		await unlink(socketPath);
	}

	return new Promise<VaultPasswordResult>((resolve, reject) => {
		const server: Server = createServer();
		let resolved = false;

		const timeout = setTimeout(() => {
			if (!resolved) {
				resolved = true;
				server.close();
				cleanupSocket(socketPath);
				reject(new Error(`Vault password receive timed out after ${timeoutMs}ms`));
			}
		}, timeoutMs);
		// Don't keep process alive for timeout
		if (timeout.unref) timeout.unref();

		server.listen(socketPath, () => {
			// Set socket permissions to owner-only (0o600)
			chmod(socketPath, 0o600).catch((err) => {
				console.warn(
					`[vault-password] Failed to set socket permissions to 0o600: ${err instanceof Error ? err.message : String(err)}`,
				);
				if (process.env.SENTINEL_DOCKER === "true" && !resolved) {
					resolved = true;
					server.close();
					cleanupSocket(socketPath);
					reject(
						new Error(
							`Security: cannot set socket permissions in Docker mode: ${err instanceof Error ? err.message : String(err)}`,
						),
					);
				}
			});
		});

		server.on("connection", (socket) => {
			const chunks: Buffer[] = [];

			socket.on("data", (chunk: Buffer) => {
				chunks.push(chunk);
				const totalSize = chunks.reduce((sum, c) => sum + c.length, 0);
				if (totalSize > MAX_PASSWORD_LENGTH) {
					socket.destroy();
					if (!resolved) {
						resolved = true;
						clearTimeout(timeout);
						server.close();
						cleanupSocket(socketPath);
						reject(new Error(`Vault password exceeds maximum size (${MAX_PASSWORD_LENGTH} bytes)`));
					}
				}
			});

			socket.on("end", () => {
				if (!resolved) {
					resolved = true;
					clearTimeout(timeout);
					server.close();
					cleanupSocket(socketPath);
					const password = Buffer.concat(chunks);
					resolve({ password });
				}
				socket.destroy();
			});

			socket.on("error", (err) => {
				if (!resolved) {
					resolved = true;
					clearTimeout(timeout);
					server.close();
					cleanupSocket(socketPath);
					reject(err);
				}
			});

			// Only accept one connection
			server.close();
		});

		server.on("error", (err) => {
			if (!resolved) {
				resolved = true;
				clearTimeout(timeout);
				cleanupSocket(socketPath);
				reject(err);
			}
		});
	});
}

async function cleanupSocket(socketPath: string): Promise<void> {
	try {
		if (existsSync(socketPath)) {
			await unlink(socketPath);
		}
	} catch (err) {
		console.warn(
			`[vault-password] Socket cleanup failed for ${socketPath}: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
}
