import { afterEach, describe, expect, it, vi } from "vitest";
import { _resetWarnings, warnOnce } from "./warn-once.js";

describe("warnOnce", () => {
	afterEach(() => {
		_resetWarnings();
		vi.restoreAllMocks();
	});

	it("warns on first call", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		warnOnce("test-key", "test message");
		expect(spy).toHaveBeenCalledOnce();
		expect(spy).toHaveBeenCalledWith("test message");
	});

	it("does not warn on second call with same key", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		warnOnce("dup-key", "first");
		warnOnce("dup-key", "second");
		expect(spy).toHaveBeenCalledOnce();
	});

	it("warns for different keys", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		warnOnce("key-a", "message a");
		warnOnce("key-b", "message b");
		expect(spy).toHaveBeenCalledTimes(2);
	});

	it("_resetWarnings clears state", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		warnOnce("reset-key", "first");
		_resetWarnings();
		warnOnce("reset-key", "second");
		expect(spy).toHaveBeenCalledTimes(2);
	});
});
