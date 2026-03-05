import { describe, expect, it } from "vitest";
import { buildManifest } from "./manifest-builder.js";

describe("buildManifest", () => {
	it("generates a valid UUID v4 for id", () => {
		const manifest = buildManifest("bash", { command: "ls" }, "session-1");
		expect(manifest.id).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
		);
	});

	it("sets an ISO 8601 timestamp", () => {
		const before = new Date().toISOString();
		const manifest = buildManifest("read_file", { path: "/tmp/x" }, "session-2");
		const after = new Date().toISOString();

		expect(manifest.timestamp).toBeTruthy();
		expect(manifest.timestamp >= before).toBe(true);
		expect(manifest.timestamp <= after).toBe(true);
	});

	it("preserves tool name and parameters", () => {
		const params = { path: "/etc/hosts", encoding: "utf-8" };
		const manifest = buildManifest("read_file", params, "session-3");

		expect(manifest.tool).toBe("read_file");
		expect(manifest.parameters).toEqual(params);
		expect(manifest.sessionId).toBe("session-3");
	});

	it("generates unique ids across calls", () => {
		const m1 = buildManifest("bash", {}, "s");
		const m2 = buildManifest("bash", {}, "s");
		expect(m1.id).not.toBe(m2.id);
	});
});
