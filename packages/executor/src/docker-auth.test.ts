import type { SentinelConfig } from "@sentinel/types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ensureDockerAuth } from "./docker-auth.js";

function makeConfig(overrides: Partial<SentinelConfig> = {}): SentinelConfig {
	return {
		executor: { port: 3141, host: "0.0.0.0" },
		classifications: [],
		autoApproveReadOps: false,
		auditLogPath: "/tmp/audit.db",
		vaultPath: "/tmp/vault.enc",
		gwsDefaultDeny: false,
		llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
		...overrides,
	};
}

describe("ensureDockerAuth", () => {
	const originalEnv = process.env.SENTINEL_DOCKER;

	beforeEach(() => {
		delete process.env.SENTINEL_DOCKER;
	});

	afterEach(() => {
		if (originalEnv !== undefined) {
			process.env.SENTINEL_DOCKER = originalEnv;
		} else {
			delete process.env.SENTINEL_DOCKER;
		}
	});

	it("generates a 64-char hex token in Docker mode when no authToken", () => {
		process.env.SENTINEL_DOCKER = "true";
		const config = makeConfig();
		const result = ensureDockerAuth(config);

		expect(result.authToken).toBeDefined();
		expect(result.authToken).toHaveLength(64);
		expect(result.authToken).toMatch(/^[0-9a-f]{64}$/);
	});

	it("preserves existing authToken in Docker mode", () => {
		process.env.SENTINEL_DOCKER = "true";
		const config = makeConfig({ authToken: "my-existing-token" });
		const result = ensureDockerAuth(config);

		expect(result.authToken).toBe("my-existing-token");
	});

	it("does not generate token outside Docker mode", () => {
		const config = makeConfig();
		const result = ensureDockerAuth(config);

		expect(result.authToken).toBeUndefined();
	});

	it("does not generate token when SENTINEL_DOCKER is not 'true'", () => {
		process.env.SENTINEL_DOCKER = "false";
		const config = makeConfig();
		const result = ensureDockerAuth(config);

		expect(result.authToken).toBeUndefined();
	});

	it("generates unique tokens on each call", () => {
		process.env.SENTINEL_DOCKER = "true";
		const result1 = ensureDockerAuth(makeConfig());
		const result2 = ensureDockerAuth(makeConfig());

		expect(result1.authToken).not.toBe(result2.authToken);
	});

	it("does not mutate the original config", () => {
		process.env.SENTINEL_DOCKER = "true";
		const config = makeConfig();
		const result = ensureDockerAuth(config);

		expect(config.authToken).toBeUndefined();
		expect(result.authToken).toBeDefined();
		expect(result).not.toBe(config);
	});

	it("logs a message when generating a token", () => {
		process.env.SENTINEL_DOCKER = "true";
		const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		ensureDockerAuth(makeConfig());

		expect(consoleSpy).toHaveBeenCalledWith(
			expect.stringContaining("Docker mode: auto-generated auth token"),
		);
		consoleSpy.mockRestore();
	});
});
