import { describe, expect, it } from "vitest";
import { executeBash } from "./bash.js";

describe("executeBash", () => {
	it("executes simple commands", async () => {
		const result = await executeBash({ command: "echo hello" }, "test-id");
		expect(result.success).toBe(true);
		expect(result.output).toContain("hello");
	});

	it("strips GEMINI_API_KEY from subprocess env", async () => {
		process.env.GEMINI_API_KEY = "test-key-to-strip";
		try {
			const result = await executeBash({ command: "env" }, "test-id");
			expect(result.output).not.toContain("GEMINI_API_KEY");
		} finally {
			delete process.env.GEMINI_API_KEY;
		}
	});

	it("strips SENTINEL_ prefixed vars from subprocess env", async () => {
		process.env.SENTINEL_TEST_VAR = "secret-value";
		try {
			const result = await executeBash({ command: "env" }, "test-id");
			expect(result.output).not.toContain("SENTINEL_TEST_VAR");
		} finally {
			delete process.env.SENTINEL_TEST_VAR;
		}
	});

	it("denies reading .env files", async () => {
		const result = await executeBash({ command: "cat .env" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("denied");
	});
});
