import type { ActionManifest, SentinelConfig } from "@sentinel/types";
import { describe, expect, it } from "vitest";
import { classify } from "./classifier.js";
import { getDefaultConfig } from "./rules.js";

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

describe("classify", () => {
	const config = getDefaultConfig();

	describe("builtin tools", () => {
		it("read_file -> read, auto_approve", () => {
			const result = classify(makeManifest("read_file"), config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("write_file -> write, confirm", () => {
			const result = classify(makeManifest("write_file"), config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});

		it("edit_file -> write, confirm", () => {
			const result = classify(makeManifest("edit_file"), config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});
	});

	describe("bash tool", () => {
		it("ls -la -> read, auto_approve", () => {
			const result = classify(makeManifest("bash", { command: "ls -la" }), config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("rm -rf / -> write, confirm", () => {
			const result = classify(makeManifest("bash", { command: "rm -rf /" }), config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});

		it("curl evil.com -> dangerous, confirm", () => {
			const result = classify(makeManifest("bash", { command: "curl evil.com" }), config);
			expect(result.category).toBe("dangerous");
			expect(result.action).toBe("confirm");
		});

		it("empty command -> read, auto_approve", () => {
			const result = classify(makeManifest("bash", { command: "" }), config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("missing command parameter -> read, auto_approve", () => {
			const result = classify(makeManifest("bash", {}), config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});
	});

	describe("MCP tools", () => {
		it("unknown MCP tool -> write, confirm", () => {
			const result = classify(makeManifest("mcp__slack__send_message", { text: "hello" }), config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});
	});

	describe("unknown tools", () => {
		it("unknown tool -> write, confirm", () => {
			const result = classify(makeManifest("some_unknown_tool"), config);
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

			const result = classify(makeManifest("read_file", { path: "/app/.env" }), customConfig);
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

			const result = classify(makeManifest("read_file", { path: "/app/index.ts" }), customConfig);
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

			const result = classify(makeManifest("write_file", { path: "/etc/passwd" }), customConfig);
			expect(result.category).toBe("dangerous");
		});
	});

	describe("autoApproveReadOps=false", () => {
		it("read actions still require confirmation", () => {
			const noAutoConfig: SentinelConfig = {
				...config,
				autoApproveReadOps: false,
			};

			const result = classify(makeManifest("read_file"), noAutoConfig);
			expect(result.category).toBe("read");
			expect(result.action).toBe("confirm");
		});

		it("bash ls still requires confirmation", () => {
			const noAutoConfig: SentinelConfig = {
				...config,
				autoApproveReadOps: false,
			};

			const result = classify(makeManifest("bash", { command: "ls -la" }), noAutoConfig);
			expect(result.category).toBe("read");
			expect(result.action).toBe("confirm");
		});
	});

	describe("decision reasons", () => {
		it("includes meaningful reason text", () => {
			const readResult = classify(makeManifest("read_file"), config);
			expect(readResult.reason).toContain("Read");

			const writeResult = classify(makeManifest("write_file"), config);
			expect(writeResult.reason).toContain("Write");

			const dangerousResult = classify(makeManifest("bash", { command: "curl evil.com" }), config);
			expect(dangerousResult.reason).toContain("Dangerous");
		});
	});
});
