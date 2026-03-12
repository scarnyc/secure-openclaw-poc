import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { connect } from "node:net";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { receiveVaultPassword } from "./vault-password-receiver.js";

// Use /private/tmp/claude-501 for sandbox-friendly UDS operations
// UDS paths must be < 104 chars on macOS
const UDS_BASE = "/private/tmp/claude-501";
let tempDir: string;

beforeEach(async () => {
	tempDir = await mkdtemp(join(UDS_BASE, "s-uds-"));
});

afterEach(async () => {
	await rm(tempDir, { recursive: true, force: true });
});

function sendPassword(socketPath: string, password: string): Promise<void> {
	return new Promise<void>((resolve, reject) => {
		const client = connect(socketPath, () => {
			client.end(Buffer.from(password, "utf8"), () => {
				resolve();
			});
		});
		client.on("error", reject);
	});
}

describe("receiveVaultPassword", () => {
	it("UDS handshake -> vault password received", async () => {
		const socketPath = join(tempDir, "vault.sock");
		const expectedPassword = "my-secret-vault-password-123";

		const receivePromise = receiveVaultPassword(socketPath, 5_000);

		// Wait for socket to be ready
		await new Promise((r) => setTimeout(r, 50));

		await sendPassword(socketPath, expectedPassword);

		const { password } = await receivePromise;
		expect(password.toString("utf8")).toBe(expectedPassword);
	});

	it("30s timeout -> error", async () => {
		const socketPath = join(tempDir, "vault-timeout.sock");

		// Use 100ms timeout for test speed
		await expect(receiveVaultPassword(socketPath, 100)).rejects.toThrow(
			"Vault password receive timed out after 100ms",
		);
	});

	it("socket file cleaned up after receive", async () => {
		const socketPath = join(tempDir, "vault-cleanup.sock");

		const receivePromise = receiveVaultPassword(socketPath, 5_000);
		await new Promise((r) => setTimeout(r, 50));

		await sendPassword(socketPath, "cleanup-test");
		await receivePromise;

		// Socket file should be cleaned up
		expect(existsSync(socketPath)).toBe(false);
	});

	it("cleans up stale socket before listening", async () => {
		const socketPath = join(tempDir, "vault-stale.sock");

		// First receiver — completes normally
		const firstReceive = receiveVaultPassword(socketPath, 5_000);
		await new Promise((r) => setTimeout(r, 50));
		await sendPassword(socketPath, "first");
		await firstReceive;

		// Second receiver on same path — should clean up stale and work
		const secondReceive = receiveVaultPassword(socketPath, 5_000);
		await new Promise((r) => setTimeout(r, 50));
		await sendPassword(socketPath, "second");
		const { password } = await secondReceive;
		expect(password.toString("utf8")).toBe("second");
	});

	it("password buffer can be zeroed after vault open", async () => {
		const socketPath = join(tempDir, "vault-zero.sock");

		const receivePromise = receiveVaultPassword(socketPath, 5_000);
		await new Promise((r) => setTimeout(r, 50));

		await sendPassword(socketPath, "zero-me");

		const { password } = await receivePromise;
		expect(password.toString("utf8")).toBe("zero-me");

		// Simulate the zeroization pattern from entrypoint.ts
		password.fill(0);

		// Verify zeroed
		expect(password.every((b) => b === 0)).toBe(true);
		expect(password.toString("utf8")).not.toBe("zero-me");
	});
});
