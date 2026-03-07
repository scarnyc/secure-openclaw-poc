import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadPolicy } from "./policy-loader.js";

describe("loadPolicy", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-policy-test-"));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it("loads and validates a valid policy.json", () => {
		const policy = {
			version: 1,
			toolGroups: { fs: ["read"] },
			defaults: {
				tools: { allow: ["*"], deny: [] },
				workspace: { root: "/tmp", access: "rw" },
				approval: { ask: "on-miss" },
			},
			agents: {},
		};
		fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify(policy));
		const result = loadPolicy(path.join(tmpDir, "policy.json"));
		expect(result.version).toBe(1);
		expect(Object.isFrozen(result)).toBe(true);
	});

	it("throws on missing policy.json", () => {
		expect(() => loadPolicy(path.join(tmpDir, "nonexistent.json"))).toThrow();
	});

	it("throws on invalid schema", () => {
		fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify({ version: 99 }));
		expect(() => loadPolicy(path.join(tmpDir, "policy.json"))).toThrow();
	});

	it("returns frozen object (Invariant #6)", () => {
		const policy = {
			version: 1,
			toolGroups: {},
			defaults: {
				tools: { allow: ["*"], deny: [] },
				workspace: { root: "/tmp", access: "rw" },
				approval: { ask: "on-miss" },
			},
			agents: {},
		};
		fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify(policy));
		const result = loadPolicy(path.join(tmpDir, "policy.json"));
		expect(() => {
			(result as any).version = 2;
		}).toThrow();
	});

	it("validates tool groups at load time", () => {
		const policy = {
			version: 1,
			toolGroups: { "": ["read"] },
			defaults: {
				tools: { allow: ["*"], deny: [] },
				workspace: { root: "/tmp", access: "rw" },
				approval: { ask: "on-miss" },
			},
			agents: {},
		};
		fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify(policy));
		expect(() => loadPolicy(path.join(tmpDir, "policy.json"))).toThrow();
	});

	it("validates agent group references at load time", () => {
		const policy = {
			version: 1,
			toolGroups: { fs: ["read"] },
			defaults: {
				tools: { allow: ["*"], deny: [] },
				workspace: { root: "/tmp", access: "rw" },
				approval: { ask: "on-miss" },
			},
			agents: {
				bad: {
					tools: { allow: ["group:nonexistent"] },
					workspace: { root: "/tmp", access: "rw" },
				},
			},
		};
		fs.writeFileSync(path.join(tmpDir, "policy.json"), JSON.stringify(policy));
		expect(() => loadPolicy(path.join(tmpDir, "policy.json"))).toThrow("Unknown tool group");
	});
});
