import type { SentinelConfig } from "@sentinel/types";
import { describe, expect, it } from "vitest";
import { applyDockerDefaults, type DockerDefaultsEnv } from "./docker-defaults.js";

const BASE_CONFIG: SentinelConfig = {
	executor: { port: 3141, host: "127.0.0.1" },
	classifications: [],
	autoApproveReadOps: true,
	auditLogPath: "/app/data/audit.db",
	vaultPath: "/app/data/vault.enc",
	gwsDefaultDeny: false,
	llm: { provider: "anthropic", model: "claude-sonnet-4-20250514", maxTokens: 4096 },
};

describe("applyDockerDefaults", () => {
	describe("G2: Docker forces GWS binary verification", () => {
		it("returns fatal when SENTINEL_DOCKER=true but no SHA256", () => {
			const env: DockerDefaultsEnv = { SENTINEL_DOCKER: "true" };
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.fatal).toContain("SENTINEL_GWS_SHA256");
		});

		it("sets verifyBinary=true and expectedSha256 from env", () => {
			const sha = "a".repeat(64);
			const env: DockerDefaultsEnv = {
				SENTINEL_DOCKER: "true",
				SENTINEL_GWS_SHA256: sha,
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.fatal).toBeUndefined();
			expect(result.config.gwsIntegrity?.verifyBinary).toBe(true);
			expect(result.config.gwsIntegrity?.expectedSha256).toBe(sha);
		});

		it("preserves existing gwsIntegrity fields", () => {
			const sha = "b".repeat(64);
			const config = {
				...BASE_CONFIG,
				gwsIntegrity: {
					verifyBinary: false,
					pinnedVersionPolicy: "exact" as const,
					vulnerableVersions: ["0.9.0"],
					pinnedVersion: "1.0.0",
				},
			};
			const env: DockerDefaultsEnv = {
				SENTINEL_DOCKER: "true",
				SENTINEL_GWS_SHA256: sha,
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(config, env);
			expect(result.config.gwsIntegrity?.pinnedVersion).toBe("1.0.0");
			expect(result.config.gwsIntegrity?.pinnedVersionPolicy).toBe("exact");
			expect(result.config.gwsIntegrity?.vulnerableVersions).toEqual(["0.9.0"]);
		});

		it("uses existing expectedSha256 when env var not set", () => {
			const sha = "c".repeat(64);
			const config = {
				...BASE_CONFIG,
				gwsIntegrity: {
					verifyBinary: false,
					expectedSha256: sha,
					pinnedVersionPolicy: "minimum" as const,
					vulnerableVersions: [],
				},
			};
			const env: DockerDefaultsEnv = {
				SENTINEL_DOCKER: "true",
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(config, env);
			expect(result.fatal).toBeUndefined();
			expect(result.config.gwsIntegrity?.expectedSha256).toBe(sha);
		});

		it("does not modify config when SENTINEL_DOCKER is not true", () => {
			const env: DockerDefaultsEnv = {};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.fatal).toBeUndefined();
			expect(result.config.gwsIntegrity).toBeUndefined();
		});
	});

	describe("G5: gwsDefaultDeny in Docker", () => {
		it("sets gwsDefaultDeny=true in Docker mode (top-level config)", () => {
			const sha = "d".repeat(64);
			const env: DockerDefaultsEnv = {
				SENTINEL_DOCKER: "true",
				SENTINEL_GWS_SHA256: sha,
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.config.gwsDefaultDeny).toBe(true);
		});

		it("overrides existing gwsDefaultDeny=false to true in Docker mode", () => {
			const sha = "d".repeat(64);
			const config = { ...BASE_CONFIG, gwsDefaultDeny: false };
			const env: DockerDefaultsEnv = {
				SENTINEL_DOCKER: "true",
				SENTINEL_GWS_SHA256: sha,
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(config, env);
			expect(result.config.gwsDefaultDeny).toBe(true);
		});

		it("does not set gwsDefaultDeny when not in Docker mode", () => {
			const env: DockerDefaultsEnv = {
				SENTINEL_DOCKER: "1",
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			// SENTINEL_DOCKER="1" is NOT "true" — strict comparison
			expect(result.config.gwsDefaultDeny).toBe(false);
		});
	});

	describe("G5: SENTINEL_GWS_AGENT_SCOPES env var", () => {
		it("parses agent scopes from JSON env var", () => {
			const scopes = { "oc-agent": { allowedServices: ["gmail"] } };
			const env: DockerDefaultsEnv = {
				SENTINEL_GWS_AGENT_SCOPES: JSON.stringify(scopes),
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.config.gwsAgentScopes).toEqual(scopes);
		});

		it("returns fatal on malformed JSON in SENTINEL_GWS_AGENT_SCOPES", () => {
			const env: DockerDefaultsEnv = {
				SENTINEL_GWS_AGENT_SCOPES: '{"agent": invalid}',
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.fatal).toContain("invalid JSON");
		});

		it("returns fatal on valid JSON but invalid schema in SENTINEL_GWS_AGENT_SCOPES", () => {
			const env: DockerDefaultsEnv = {
				SENTINEL_GWS_AGENT_SCOPES: '["not","an","object"]',
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.fatal).toContain("schema validation failed");
		});

		it("does not set gwsAgentScopes when env var not present", () => {
			const env: DockerDefaultsEnv = {
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.config.gwsAgentScopes).toBeUndefined();
		});
	});

	describe("G4: SENTINEL_GWS_ACCOUNT_EMAIL warning", () => {
		it("warns when SENTINEL_GWS_ACCOUNT_EMAIL not set", () => {
			const env: DockerDefaultsEnv = {};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.warnings).toContainEqual(expect.stringContaining("SENTINEL_GWS_ACCOUNT_EMAIL"));
		});

		it("does not warn when SENTINEL_GWS_ACCOUNT_EMAIL is set", () => {
			const env: DockerDefaultsEnv = {
				SENTINEL_GWS_ACCOUNT_EMAIL: "test@example.com",
			};
			const result = applyDockerDefaults(BASE_CONFIG, env);
			expect(result.warnings.filter((w) => w.includes("SENTINEL_GWS_ACCOUNT_EMAIL"))).toHaveLength(
				0,
			);
		});
	});
});
