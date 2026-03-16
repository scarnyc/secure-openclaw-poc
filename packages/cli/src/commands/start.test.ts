import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { stopTunnel } from "./start.js";

describe("stopTunnel", () => {
	const testDir = join(tmpdir(), `sentinel-cli-test-${Date.now()}`);
	const dataDir = join(testDir, "data");

	if (!existsSync(dataDir)) {
		mkdirSync(dataDir, { recursive: true });
	}

	afterEach(() => {
		// Clean up any leftover PID files
		const pidPath = join(dataDir, "cloudflared.pid");
		try {
			const { unlinkSync } = require("node:fs");
			unlinkSync(pidPath);
		} catch {
			// already gone
		}
	});

	it("does not throw when PID file does not exist", () => {
		expect(() => stopTunnel(testDir)).not.toThrow();
	});

	it("handles ESRCH (dead process) gracefully", () => {
		// Write a PID that almost certainly doesn't exist
		const pidPath = join(dataDir, "cloudflared.pid");
		writeFileSync(pidPath, "999999999", "utf-8");

		expect(() => stopTunnel(testDir)).not.toThrow();
	});
});
