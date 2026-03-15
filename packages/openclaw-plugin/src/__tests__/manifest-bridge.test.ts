import { describe, expect, it } from "vitest";
import { buildManifest, type SessionContext } from "../manifest-bridge.js";

const SESSION: SessionContext = {
	sessionId: "test-session-123",
	agentId: "test-agent",
};

describe("buildManifest", () => {
	it("creates a valid manifest from tool call data", () => {
		const manifest = buildManifest("read_file", { path: "/tmp/test.txt" }, "run-1", SESSION);
		expect(manifest.tool).toBe("read_file");
		expect(manifest.parameters).toEqual({ path: "/tmp/test.txt" });
		expect(manifest.sessionId).toBe("test-session-123");
		expect(manifest.agentId).toBe("test-agent");
	});

	it("generates UUID for manifest id", () => {
		const manifest = buildManifest("bash", { command: "ls" }, "run-1", SESSION);
		expect(manifest.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
	});

	it("generates ISO timestamp", () => {
		const manifest = buildManifest("bash", { command: "ls" }, "run-1", SESSION);
		expect(() => new Date(manifest.timestamp).toISOString()).not.toThrow();
	});

	it("uses runId as agentId when agentId not in context", () => {
		const ctx: SessionContext = { sessionId: "s1" };
		const manifest = buildManifest("bash", { command: "ls" }, "run-42", ctx);
		expect(manifest.agentId).toBe("run-42");
	});

	it("rejects empty tool name", () => {
		expect(() => buildManifest("", {}, "run-1", SESSION)).toThrow("Invalid tool name");
	});

	it("rejects tool name starting with number", () => {
		expect(() => buildManifest("1invalid", {}, "run-1", SESSION)).toThrow("Invalid tool name");
	});

	it("rejects tool name with spaces", () => {
		expect(() => buildManifest("bad tool", {}, "run-1", SESSION)).toThrow("Invalid tool name");
	});

	it("accepts tool name with dots and hyphens", () => {
		const manifest = buildManifest("gws.gmail-send", { to: "a@b.c" }, "run-1", SESSION);
		expect(manifest.tool).toBe("gws.gmail-send");
	});
});
