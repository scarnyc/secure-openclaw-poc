import { describe, expect, it } from "vitest";
import { expandGroups, validateGroups } from "./groups.js";

const GROUPS = {
	fs: ["read", "write", "edit", "apply_patch"],
	runtime: ["exec", "process"],
	network: ["browser", "fetch"],
};

describe("expandGroups", () => {
	it("expands group:fs to individual tools", () => {
		expect(expandGroups(["group:fs"], GROUPS)).toEqual(["read", "write", "edit", "apply_patch"]);
	});

	it("passes through non-group tool names", () => {
		expect(expandGroups(["read", "exec"], GROUPS)).toEqual(["read", "exec"]);
	});

	it("mixes groups and individual tools", () => {
		expect(expandGroups(["group:runtime", "read"], GROUPS)).toEqual(["exec", "process", "read"]);
	});

	it("expands wildcard as-is", () => {
		expect(expandGroups(["*"], GROUPS)).toEqual(["*"]);
	});

	it("deduplicates expanded results", () => {
		expect(expandGroups(["read", "group:fs"], GROUPS)).toEqual(["read", "write", "edit", "apply_patch"]);
	});

	it("returns empty array for empty input", () => {
		expect(expandGroups([], GROUPS)).toEqual([]);
	});

	it("throws on unknown group reference", () => {
		expect(() => expandGroups(["group:unknown"], GROUPS)).toThrow("Unknown tool group: unknown");
	});

	it("throws on nested group reference", () => {
		expect(() => expandGroups(["group:group:fs"], GROUPS)).toThrow("Unknown tool group: group:fs");
	});
});

describe("validateGroups", () => {
	it("accepts valid groups", () => {
		expect(() => validateGroups(GROUPS)).not.toThrow();
	});

	it("accepts empty groups", () => {
		expect(() => validateGroups({})).not.toThrow();
	});

	it("rejects group with empty name", () => {
		expect(() => validateGroups({ "": ["read"] })).toThrow();
	});
});
