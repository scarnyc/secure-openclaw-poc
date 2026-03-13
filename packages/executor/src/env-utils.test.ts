import { describe, expect, it } from "vitest";
import { stripSensitiveEnv } from "./env-utils.js";

describe("stripSensitiveEnv", () => {
	const safeEnv: NodeJS.ProcessEnv = {
		PATH: "/usr/bin",
		HOME: "/home/user",
		NODE_ENV: "test",
	};

	it("strips keys with SENTINEL_ prefix", () => {
		const result = stripSensitiveEnv({ ...safeEnv, SENTINEL_SECRET: "x" });
		expect(result).not.toHaveProperty("SENTINEL_SECRET");
	});

	it("strips keys with ANTHROPIC_ prefix", () => {
		const result = stripSensitiveEnv({ ...safeEnv, ANTHROPIC_API_KEY: "sk-ant-123" });
		expect(result).not.toHaveProperty("ANTHROPIC_API_KEY");
	});

	it("strips keys with OPENAI_ prefix", () => {
		const result = stripSensitiveEnv({ ...safeEnv, OPENAI_API_KEY: "sk-123" });
		expect(result).not.toHaveProperty("OPENAI_API_KEY");
	});

	it("strips keys with GEMINI_ prefix", () => {
		const result = stripSensitiveEnv({ ...safeEnv, GEMINI_API_KEY: "gem-123" });
		expect(result).not.toHaveProperty("GEMINI_API_KEY");
	});

	it("strips exact key MOLTBOT_GATEWAY_TOKEN", () => {
		const result = stripSensitiveEnv({ ...safeEnv, MOLTBOT_GATEWAY_TOKEN: "tok" });
		expect(result).not.toHaveProperty("MOLTBOT_GATEWAY_TOKEN");
	});

	it("strips exact keys CF_ACCESS_AUD, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, CF_ACCOUNT_ID", () => {
		const result = stripSensitiveEnv({
			...safeEnv,
			CF_ACCESS_AUD: "aud",
			R2_ACCESS_KEY_ID: "rid",
			R2_SECRET_ACCESS_KEY: "rsec",
			CF_ACCOUNT_ID: "cid",
		});
		expect(result).not.toHaveProperty("CF_ACCESS_AUD");
		expect(result).not.toHaveProperty("R2_ACCESS_KEY_ID");
		expect(result).not.toHaveProperty("R2_SECRET_ACCESS_KEY");
		expect(result).not.toHaveProperty("CF_ACCOUNT_ID");
	});

	it("preserves safe keys like PATH, HOME, NODE_ENV", () => {
		const result = stripSensitiveEnv({
			...safeEnv,
			SENTINEL_SECRET: "x",
			ANTHROPIC_API_KEY: "y",
		});
		expect(result).toHaveProperty("PATH", "/usr/bin");
		expect(result).toHaveProperty("HOME", "/home/user");
		expect(result).toHaveProperty("NODE_ENV", "test");
	});

	it("returns new object (doesn't modify input)", () => {
		const input: NodeJS.ProcessEnv = { ...safeEnv, SENTINEL_KEY: "secret" };
		const result = stripSensitiveEnv(input);
		expect(result).not.toBe(input);
		expect(input).toHaveProperty("SENTINEL_KEY", "secret");
	});
});
