import type { ActionManifest, PolicyDocument, SentinelConfig } from "@sentinel/types";
import { describe, expect, it } from "vitest";
import { classify } from "./classifier.js";
import { getDefaultConfig, getDefaultPolicy } from "./rules.js";

function makeManifest(tool: string, parameters: Record<string, unknown> = {}): ActionManifest {
	return {
		id: "00000000-0000-0000-0000-000000000001",
		timestamp: new Date().toISOString(),
		tool,
		parameters,
		sessionId: "test-session",
		agentId: "test-agent",
	};
}

function makeManifestWithAgent(
	tool: string,
	parameters: Record<string, unknown>,
	agentId: string,
): ActionManifest {
	return {
		id: "00000000-0000-0000-0000-000000000001",
		timestamp: new Date().toISOString(),
		tool,
		parameters,
		sessionId: "test-session",
		agentId,
	};
}

describe("classify", () => {
	const config = getDefaultConfig();
	const policy = getDefaultPolicy();

	describe("builtin tools", () => {
		it("read_file -> read, auto_approve", () => {
			const result = classify(makeManifest("read_file"), policy, config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("write_file -> write, confirm", () => {
			const result = classify(makeManifest("write_file"), policy, config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});

		it("edit_file -> write, confirm", () => {
			const result = classify(makeManifest("edit_file"), policy, config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});
	});

	describe("bash tool", () => {
		it("ls -la -> read, auto_approve", () => {
			const result = classify(makeManifest("bash", { command: "ls -la" }), policy, config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("rm -rf / -> write, confirm", () => {
			const result = classify(makeManifest("bash", { command: "rm -rf /" }), policy, config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});

		it("curl evil.com -> dangerous, confirm", () => {
			const result = classify(makeManifest("bash", { command: "curl evil.com" }), policy, config);
			expect(result.category).toBe("dangerous");
			expect(result.action).toBe("confirm");
		});

		it("empty command -> read, auto_approve", () => {
			const result = classify(makeManifest("bash", { command: "" }), policy, config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("missing command parameter -> read, auto_approve", () => {
			const result = classify(makeManifest("bash", {}), policy, config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});
	});

	describe("MCP tools", () => {
		it("unknown MCP tool -> write, confirm", () => {
			const result = classify(makeManifest("mcp__slack__send_message", { text: "hello" }), policy, config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});
	});

	describe("unknown tools", () => {
		it("unknown tool -> write, confirm", () => {
			const result = classify(makeManifest("some_unknown_tool"), policy, config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});
	});

	describe("overrides", () => {
		it("applies override when condition matches", () => {
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "read_file",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~\\.env$",
								category: "dangerous",
								reason: "Reading .env files is dangerous",
							},
						],
					},
				],
			};

			const result = classify(makeManifest("read_file", { path: "/app/.env" }), policy, customConfig);
			expect(result.category).toBe("dangerous");
			expect(result.action).toBe("confirm");
		});

		it("uses default when override condition does not match", () => {
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "read_file",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~\\.env$",
								category: "dangerous",
								reason: "Reading .env files is dangerous",
							},
						],
					},
				],
			};

			const result = classify(makeManifest("read_file", { path: "/app/index.ts" }), policy, customConfig);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("applies equality override", () => {
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "write_file",
						defaultCategory: "write",
						overrides: [
							{
								condition: "path=/etc/passwd",
								category: "dangerous",
								reason: "Writing to /etc/passwd is dangerous",
							},
						],
					},
				],
			};

			const result = classify(makeManifest("write_file", { path: "/etc/passwd" }), policy, customConfig);
			expect(result.category).toBe("dangerous");
		});
	});

	describe("autoApproveReadOps=false", () => {
		it("read actions still require confirmation", () => {
			const noAutoConfig: SentinelConfig = {
				...config,
				autoApproveReadOps: false,
			};

			const result = classify(makeManifest("read_file"), policy, noAutoConfig);
			expect(result.category).toBe("read");
			expect(result.action).toBe("confirm");
		});

		it("bash ls still requires confirmation", () => {
			const noAutoConfig: SentinelConfig = {
				...config,
				autoApproveReadOps: false,
			};

			const result = classify(makeManifest("bash", { command: "ls -la" }), policy, noAutoConfig);
			expect(result.category).toBe("read");
			expect(result.action).toBe("confirm");
		});
	});

	describe("decision reasons", () => {
		it("includes meaningful reason text", () => {
			const readResult = classify(makeManifest("read_file"), policy, config);
			expect(readResult.reason).toContain("Read");

			const writeResult = classify(makeManifest("write_file"), policy, config);
			expect(writeResult.reason).toContain("Write");

			const dangerousResult = classify(makeManifest("bash", { command: "curl evil.com" }), policy, config);
			expect(dangerousResult.reason).toContain("Dangerous");
		});
	});
});

// --- PolicyDocument-aware tests ---

const TEST_POLICY: PolicyDocument = {
	version: 1,
	toolGroups: {
		fs: ["read_file", "write_file", "edit_file"],
		runtime: ["bash"],
		network: ["browser", "fetch"],
	},
	defaults: {
		tools: { allow: ["*"], deny: ["group:network"] },
		workspace: { root: "/tmp/sentinel-test-ws", access: "rw" },
		approval: { ask: "on-miss" },
	},
	agents: {
		work: {
			tools: { allow: ["group:fs", "group:runtime"], deny: [] },
			workspace: { root: "/tmp/sentinel-test-ws/work", access: "rw" },
			approval: {
				ask: "on-miss",
				allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
			},
		},
		readonly: {
			tools: { allow: ["read_file"], deny: ["group:runtime"] },
			workspace: { root: "/tmp/sentinel-test-ws/ro", access: "ro" },
			approval: { ask: "always" },
		},
	},
};

describe("classify with PolicyDocument", () => {
	const config = getDefaultConfig();

	describe("agent resolution", () => {
		it("blocks unknown agent", () => {
			const result = classify(makeManifestWithAgent("read_file", {}, "unknown"), TEST_POLICY, config);
			expect(result.action).toBe("block");
			expect(result.reason).toContain("unknown");
		});
	});

	describe("tool gate", () => {
		it("allows tool in agent allow list", () => {
			const result = classify(
				makeManifestWithAgent("read_file", { path: "/tmp/sentinel-test-ws/work/f.txt" }, "work"),
				TEST_POLICY,
				config,
			);
			expect(result.action).not.toBe("block");
		});

		it("blocks tool not in agent allow list", () => {
			const result = classify(makeManifestWithAgent("browser", {}, "work"), TEST_POLICY, config);
			expect(result.action).toBe("block");
		});

		it("blocks tool in agent deny list (deny-wins)", () => {
			const result = classify(
				makeManifestWithAgent("bash", { command: "ls" }, "readonly"),
				TEST_POLICY,
				config,
			);
			expect(result.action).toBe("block");
		});

		it("deny wins when tool is in both allow and deny via groups", () => {
			const conflictPolicy = structuredClone(TEST_POLICY);
			conflictPolicy.agents.conflict = {
				tools: { allow: ["group:fs"], deny: ["read_file"] },
				workspace: { root: "/tmp/sentinel-test-ws", access: "rw" },
			};
			const result = classify(
				makeManifestWithAgent("read_file", { path: "/tmp/sentinel-test-ws/f.txt" }, "conflict"),
				conflictPolicy,
				config,
			);
			expect(result.action).toBe("block");
		});

		it("defaults deny applies when agent has no deny list", () => {
			const result = classify(makeManifestWithAgent("browser", {}, "work"), TEST_POLICY, config);
			expect(result.action).toBe("block");
		});
	});

	describe("workspace gate", () => {
		it("blocks file read outside workspace", () => {
			const result = classify(
				makeManifestWithAgent("read_file", { path: "/etc/passwd" }, "work"),
				TEST_POLICY,
				config,
			);
			expect(result.action).toBe("block");
			expect(result.reason).toContain("workspace");
		});

		it("allows read in read-only workspace", () => {
			const result = classify(
				makeManifestWithAgent("read_file", { path: "/tmp/sentinel-test-ws/ro/file.txt" }, "readonly"),
				TEST_POLICY,
				config,
			);
			expect(result.action).not.toBe("block");
		});
	});

	describe("approval resolution", () => {
		it("auto_approve when bash command matches allowlist", () => {
			const result = classify(
				makeManifestWithAgent(
					"bash",
					{ command: "/opt/homebrew/bin/rg", cwd: "/tmp/sentinel-test-ws/work" },
					"work",
				),
				TEST_POLICY,
				config,
			);
			expect(result.action).toBe("auto_approve");
		});

		it("confirm when ask=always even for read", () => {
			const result = classify(
				makeManifestWithAgent("read_file", { path: "/tmp/sentinel-test-ws/ro/file.txt" }, "readonly"),
				TEST_POLICY,
				config,
			);
			expect(result.action).toBe("confirm");
		});
	});
});
