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
		expect(result.error).toContain("sensitive file");
	});
});

describe("bash deny-list: destructive rm", () => {
	it("denies rm -rf /", async () => {
		const result = await executeBash({ command: "rm -rf /" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("Destructive recursive deletion");
	});

	it("denies rm -rf ~", async () => {
		const result = await executeBash({ command: "rm -rf ~" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("Destructive recursive deletion");
	});

	it("denies rm -rf $HOME", async () => {
		const result = await executeBash({ command: "rm -rf $HOME" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("Destructive recursive deletion");
	});

	it("denies rm -fr / (reversed flags)", async () => {
		const result = await executeBash({ command: "rm -fr /" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("Destructive recursive deletion");
	});

	it("denies rm --recursive --force /", async () => {
		const result = await executeBash({ command: "rm --recursive --force /" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("Destructive recursive deletion");
	});

	it("denies rm -rf /*", async () => {
		const result = await executeBash({ command: "rm -rf /*" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("Destructive recursive deletion");
	});

	it("allows safe rm (no recursive flag)", async () => {
		const result = await executeBash({ command: "rm file.txt" }, "test-id");
		// Should NOT be denied by our patterns (may fail for other reasons like file not found)
		expect(result.error).not.toContain("Destructive");
	});

	it("allows rm -rf with specific absolute path (not root)", async () => {
		const result = await executeBash({ command: "rm -rf /tmp/mydir" }, "test-id");
		// Should NOT be denied — targeting specific subdir, not root
		if (result.error) {
			expect(result.error).not.toContain("Destructive");
		}
	});
});

describe("bash deny-list: mail commands", () => {
	it("denies mail command", async () => {
		const result = await executeBash({ command: "mail user@example.com" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("Mail commands denied");
	});

	it("denies sendmail command", async () => {
		const result = await executeBash({ command: "sendmail -t" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("Mail commands denied");
	});

	it("allows npm install nodemailer (mail not in command position)", async () => {
		// Use echo to avoid actually running npm install (timeout)
		const result = await executeBash({ command: "echo npm install nodemailer" }, "test-id");
		if (result.error) {
			expect(result.error).not.toContain("Mail commands denied");
		}
	});
});

describe("bash deny-list: DNS exfiltration", () => {
	it("denies dig command", async () => {
		const result = await executeBash({ command: "dig example.com" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("DNS lookup");
	});

	it("denies nslookup command", async () => {
		const result = await executeBash({ command: "nslookup example.com" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("DNS lookup");
	});

	it("denies host command in command position", async () => {
		const result = await executeBash({ command: "host example.com" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("DNS lookup");
	});

	it("allows hostname command (not the host DNS tool)", async () => {
		const result = await executeBash({ command: "hostname" }, "test-id");
		if (result.error) {
			expect(result.error).not.toContain("DNS lookup");
		}
	});

	it("allows echo containing the word host", async () => {
		const result = await executeBash({ command: 'echo "check host"' }, "test-id");
		if (result.error) {
			expect(result.error).not.toContain("DNS lookup");
		}
	});
});
