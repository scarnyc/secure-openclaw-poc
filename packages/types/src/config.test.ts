import { describe, expect, it } from "vitest";
import { GwsIntegrityConfigSchema, SentinelConfigSchema } from "./config.js";

describe("GwsIntegrityConfigSchema", () => {
	it("parses with defaults when empty object provided", () => {
		const result = GwsIntegrityConfigSchema.parse({});
		expect(result.verifyBinary).toBe(false);
		expect(result.pinnedVersionPolicy).toBe("minimum");
		expect(result.vulnerableVersions).toEqual([]);
	});

	it("preserves all fields when explicitly set", () => {
		const result = GwsIntegrityConfigSchema.parse({
			verifyBinary: true,
			expectedSha256: "a".repeat(64),
			pinnedVersion: "1.0.0",
			pinnedVersionPolicy: "exact",
		});
		expect(result.verifyBinary).toBe(true);
		expect(result.expectedSha256).toBe("a".repeat(64));
		expect(result.pinnedVersion).toBe("1.0.0");
		expect(result.pinnedVersionPolicy).toBe("exact");
	});
});

describe("SentinelConfigSchema — gwsDefaultDeny", () => {
	const BASE = {
		executor: { port: 3141, host: "127.0.0.1" },
		classifications: [],
		autoApproveReadOps: true,
		auditLogPath: "/data/audit.db",
		vaultPath: "/data/vault.enc",
		llm: { provider: "anthropic" as const, model: "claude-sonnet-4-20250514", maxTokens: 4096 },
	};

	it("defaults gwsDefaultDeny to false when not provided", () => {
		const result = SentinelConfigSchema.parse(BASE);
		expect(result.gwsDefaultDeny).toBe(false);
	});

	it("accepts gwsDefaultDeny: true", () => {
		const result = SentinelConfigSchema.parse({ ...BASE, gwsDefaultDeny: true });
		expect(result.gwsDefaultDeny).toBe(true);
	});

	it("accepts gwsDefaultDeny: false explicitly", () => {
		const result = SentinelConfigSchema.parse({ ...BASE, gwsDefaultDeny: false });
		expect(result.gwsDefaultDeny).toBe(false);
	});
});
