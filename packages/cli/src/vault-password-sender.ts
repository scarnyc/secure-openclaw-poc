import { connect } from "node:net";

/**
 * Send vault password to executor via Unix domain socket.
 *
 * @param socketPath - Path to the Unix domain socket
 * @param password - Vault password to send
 * @param timeoutMs - Timeout in milliseconds (default: 5000)
 */
export async function sendVaultPassword(
	socketPath: string,
	password: Buffer,
	timeoutMs = 5_000,
): Promise<void> {
	return new Promise<void>((resolve, reject) => {
		const client = connect(socketPath, () => {
			client.end(password, () => {
				resolve();
			});
		});

		const timeout = setTimeout(() => {
			client.destroy();
			reject(new Error("Vault password send timed out"));
		}, timeoutMs);

		client.on("error", (err) => {
			clearTimeout(timeout);
			reject(err);
		});

		client.on("close", () => {
			clearTimeout(timeout);
		});
	});
}
