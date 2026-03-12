import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CredentialVault } from "@sentinel/crypto";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createLlmProxyHandler } from "./llm-proxy.js";

// Mock SSRF guard — real DNS resolution is unreliable in tests
vi.mock("./ssrf-guard.js", () => ({
	checkSsrf: vi.fn().mockResolvedValue(undefined),
	SsrfError: class SsrfError extends Error {
		constructor(message?: string) {
			super(message ?? "SSRF blocked");
			this.name = "SsrfError";
		}
	},
}));

let app: Hono;

beforeEach(() => {
	app = new Hono();
	app.all("/proxy/llm/*", createLlmProxyHandler());
	process.env.ANTHROPIC_API_KEY = "sk-ant-test-key";
	process.env.OPENAI_API_KEY = "sk-test-openai-key";
	process.env.GEMINI_API_KEY = "AIzaSyDtestkey123456789012345678901234";
});

afterEach(() => {
	vi.restoreAllMocks();
	delete process.env.ANTHROPIC_API_KEY;
	delete process.env.OPENAI_API_KEY;
	delete process.env.GEMINI_API_KEY;
});

describe("LLM Proxy", () => {
	it("returns 400 for missing downstream path", async () => {
		const res = await app.request("/proxy/llm/", { method: "POST" });
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("Missing downstream path");
	});

	it("blocks requests to non-allowlisted hosts", async () => {
		const res = await app.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"x-llm-host": "evil.com",
			},
			body: JSON.stringify({ prompt: "test" }),
		});
		expect(res.status).toBe(403);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("not an allowed LLM host");
	});

	it("blocks requests to exfiltration hosts", async () => {
		const res = await app.request("/proxy/llm/upload", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"x-llm-host": "attacker-controlled.example.com",
			},
			body: JSON.stringify({ data: "stolen" }),
		});
		expect(res.status).toBe(403);
	});

	it("returns 500 when API key is missing from executor env", async () => {
		delete process.env.ANTHROPIC_API_KEY;
		const fetchSpy = vi.spyOn(globalThis, "fetch");

		const res = await app.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ model: "test" }),
		});
		expect(res.status).toBe(500);
		const body = (await res.json()) as { error: string };
		expect(body.error).toContain("configuration error");
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("allows api.anthropic.com (default host)", async () => {
		const mockResponse = new Response(JSON.stringify({ id: "msg_123" }), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

		const res = await app.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ model: "claude-sonnet-4-20250514", max_tokens: 100 }),
		});

		expect(res.status).toBe(200);
		expect(fetchSpy).toHaveBeenCalledOnce();

		const [calledUrl, calledInit] = fetchSpy.mock.calls[0];
		expect(calledUrl).toBe("https://api.anthropic.com/v1/messages");
		const headers = calledInit?.headers as Headers;
		expect(headers.get("x-api-key")).toBe("sk-ant-test-key");
	});

	it("allows api.openai.com with Bearer auth", async () => {
		const mockResponse = new Response(JSON.stringify({ choices: [] }), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

		const res = await app.request("/proxy/llm/v1/chat/completions", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"x-llm-host": "api.openai.com",
			},
			body: JSON.stringify({ model: "gpt-4o" }),
		});

		expect(res.status).toBe(200);
		const [calledUrl, calledInit] = fetchSpy.mock.calls[0];
		expect(calledUrl).toBe("https://api.openai.com/v1/chat/completions");
		const headers = calledInit?.headers as Headers;
		expect(headers.get("Authorization")).toBe("Bearer sk-test-openai-key");
	});

	it("allows generativelanguage.googleapis.com with x-goog-api-key", async () => {
		const mockResponse = new Response(JSON.stringify({ candidates: [] }), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

		const res = await app.request("/proxy/llm/v1/models/gemini-pro:generateContent", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"x-llm-host": "generativelanguage.googleapis.com",
			},
			body: JSON.stringify({ contents: [] }),
		});

		expect(res.status).toBe(200);
		const [calledUrl, calledInit] = fetchSpy.mock.calls[0];
		expect(calledUrl).toBe(
			"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent",
		);
		const headers = calledInit?.headers as Headers;
		expect(headers.get("x-goog-api-key")).toBe("AIzaSyDtestkey123456789012345678901234");
	});

	it("strips hop-by-hop headers", async () => {
		const mockResponse = new Response("{}", { status: 200 });
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

		await app.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Host: "should-be-stripped",
				Connection: "keep-alive",
			},
			body: JSON.stringify({}),
		});

		expect(fetchSpy).toHaveBeenCalledOnce();
		const headers = fetchSpy.mock.calls[0][1]?.headers as Headers;
		expect(headers.get("Host")).toBeNull();
		expect(headers.get("Connection")).toBeNull();
		expect(headers.get("x-llm-host")).toBeNull();
	});

	it("strips agent-supplied auth headers before forwarding", async () => {
		const mockResponse = new Response("{}", { status: 200 });
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

		await app.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: "Bearer agent-injected-key",
				"x-api-key": "agent-injected-anthropic-key",
				"x-goog-api-key": "agent-injected-gemini-key",
			},
			body: JSON.stringify({ model: "claude-sonnet-4-20250514" }),
		});

		expect(fetchSpy).toHaveBeenCalledOnce();
		const headers = fetchSpy.mock.calls[0][1]?.headers as Headers;
		// Executor injects its own Anthropic key, not the agent's values
		expect(headers.get("x-api-key")).toBe("sk-ant-test-key");
		// Agent-supplied auth headers must not survive
		expect(headers.get("Authorization")).toBeNull();
		expect(headers.get("x-goog-api-key")).toBeNull();
	});

	describe("response header filtering", () => {
		it("forwards safe headers (content-type, x-request-id)", async () => {
			const mockResponse = new Response("{}", {
				status: 200,
				headers: {
					"content-type": "application/json",
					"x-request-id": "req-abc123",
				},
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			expect(res.headers.get("content-type")).toBe("application/json");
			expect(res.headers.get("x-request-id")).toBe("req-abc123");
		});

		it("strips unsafe headers (set-cookie, authorization, x-custom-token)", async () => {
			const mockResponse = new Response("{}", {
				status: 200,
				headers: {
					"content-type": "application/json",
					"set-cookie": "session=secret",
					authorization: "Bearer leaked-token",
					"x-custom-token": "sensitive-data",
				},
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			expect(res.headers.get("set-cookie")).toBeNull();
			expect(res.headers.get("authorization")).toBeNull();
			expect(res.headers.get("x-custom-token")).toBeNull();
		});

		it("preserves Anthropic rate-limit headers", async () => {
			const mockResponse = new Response("{}", {
				status: 200,
				headers: {
					"content-type": "application/json",
					"anthropic-ratelimit-requests-limit": "1000",
					"anthropic-ratelimit-requests-remaining": "999",
					"anthropic-ratelimit-tokens-limit": "100000",
				},
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			expect(res.headers.get("anthropic-ratelimit-requests-limit")).toBe("1000");
			expect(res.headers.get("anthropic-ratelimit-requests-remaining")).toBe("999");
			expect(res.headers.get("anthropic-ratelimit-tokens-limit")).toBe("100000");
		});

		it("preserves OpenAI rate-limit headers", async () => {
			const mockResponse = new Response("{}", {
				status: 200,
				headers: {
					"content-type": "application/json",
					"x-ratelimit-limit": "60",
					"x-ratelimit-remaining": "59",
					"openai-processing-ms": "150",
				},
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			expect(res.headers.get("x-ratelimit-limit")).toBe("60");
			expect(res.headers.get("x-ratelimit-remaining")).toBe("59");
			expect(res.headers.get("openai-processing-ms")).toBe("150");
		});
	});

	describe("response body credential filtering", () => {
		it("redacts credential patterns from response body", async () => {
			const bodyWithCreds = JSON.stringify({
				error: { message: "Invalid API key: sk-ant-abc123-leaked-key-in-error" },
			});
			const mockResponse = new Response(bodyWithCreds, {
				status: 401,
				headers: { "content-type": "application/json" },
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			const text = await res.text();
			expect(text).not.toContain("sk-ant-abc123");
			expect(text).toContain("[REDACTED]");
		});

		it("redacts Google OAuth tokens from response body", async () => {
			const bodyWithToken = JSON.stringify({
				debug: "token ya29.a0ARrdaM_leaked_access_token_1234567890",
			});
			const mockResponse = new Response(bodyWithToken, {
				status: 200,
				headers: { "content-type": "application/json" },
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			const text = await res.text();
			expect(text).not.toContain("ya29.");
			expect(text).toContain("[REDACTED]");
		});

		it("redacts private keys from response body", async () => {
			const bodyWithKey = JSON.stringify({
				content: "Here is a key: -----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----",
			});
			const mockResponse = new Response(bodyWithKey, {
				status: 200,
				headers: { "content-type": "application/json" },
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			const text = await res.text();
			expect(text).not.toContain("MIIEvQ");
			expect(text).not.toContain("BEGIN PRIVATE KEY");
			expect(text).toContain("[REDACTED]");
		});

		it("passes through clean response body unchanged", async () => {
			const cleanBody = JSON.stringify({
				id: "msg_123",
				content: [{ type: "text", text: "Hello world" }],
			});
			const mockResponse = new Response(cleanBody, {
				status: 200,
				headers: { "content-type": "application/json" },
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			const text = await res.text();
			expect(text).toBe(cleanBody);
		});

		it("passes through SSE streaming responses without materializing body", async () => {
			const sseChunks = "data: {\"type\":\"content_block_delta\"}\n\ndata: {\"type\":\"message_stop\"}\n\n";
			const mockResponse = new Response(sseChunks, {
				status: 200,
				headers: { "content-type": "text/event-stream" },
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			expect(res.headers.get("content-type")).toBe("text/event-stream");
			const text = await res.text();
			expect(text).toBe(sseChunks);
		});

		it("removes stale content-length after body filtering", async () => {
			const bodyWithCreds = "Response: sk-ant-abc123-leaked-key-in-error";
			const mockResponse = new Response(bodyWithCreds, {
				status: 200,
				headers: {
					"content-type": "application/json",
					"content-length": String(bodyWithCreds.length),
				},
			});
			vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

			const res = await app.request("/proxy/llm/v1/messages", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			const text = await res.text();
			expect(text).toContain("[REDACTED]");
			// content-length should not match original (stale) value
			const cl = res.headers.get("content-length");
			if (cl) {
				expect(Number(cl)).toBe(text.length);
			}
		});
	});

	it("returns 502 on fetch error", async () => {
		vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("ECONNREFUSED"));

		const res = await app.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});

		expect(res.status).toBe(502);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("LLM proxy upstream error");
	});
});

describe("LLM Proxy with vault-based key retrieval", () => {
	const tempDirs: string[] = [];

	async function makeTempVaultPath(): Promise<string> {
		const dir = await mkdtemp(join(tmpdir(), "sentinel-llm-proxy-"));
		tempDirs.push(dir);
		return join(dir, "vault.json");
	}

	afterEach(async () => {
		vi.restoreAllMocks();
		delete process.env.ANTHROPIC_API_KEY;
		delete process.env.OPENAI_API_KEY;
		for (const dir of tempDirs) {
			await rm(dir, { recursive: true, force: true });
		}
		tempDirs.length = 0;
	});

	it("uses vault key when vault is provided and key exists", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault = await CredentialVault.create(vaultPath, "test-pass");
		await vault.store("llm/api.anthropic.com", "api_key", {
			key: "sk-ant-vault-key-123",
		});

		// No env var set — vault is the only source
		delete process.env.ANTHROPIC_API_KEY;

		const vaultApp = new Hono();
		vaultApp.all("/proxy/llm/*", createLlmProxyHandler(vault));

		const mockResponse = new Response(JSON.stringify({ id: "msg_456" }), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

		const res = await vaultApp.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ model: "claude-sonnet-4-20250514" }),
		});

		expect(res.status).toBe(200);
		expect(fetchSpy).toHaveBeenCalledOnce();
		const headers = fetchSpy.mock.calls[0][1]?.headers as Headers;
		expect(headers.get("x-api-key")).toBe("sk-ant-vault-key-123");

		vault.destroy();
	});

	it("falls back to env when vault is provided but key not stored", async () => {
		const vaultPath = await makeTempVaultPath();
		const vault = await CredentialVault.create(vaultPath, "test-pass");
		// Vault exists but has no LLM keys

		process.env.ANTHROPIC_API_KEY = "sk-ant-env-fallback";

		const vaultApp = new Hono();
		vaultApp.all("/proxy/llm/*", createLlmProxyHandler(vault));

		const mockResponse = new Response("{}", { status: 200 });
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

		const res = await vaultApp.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});

		expect(res.status).toBe(200);
		const headers = fetchSpy.mock.calls[0][1]?.headers as Headers;
		expect(headers.get("x-api-key")).toBe("sk-ant-env-fallback");

		vault.destroy();
	});

	it("createLlmProxyHandler without vault still uses env vars", async () => {
		// No vault provided — should fall back to env vars
		process.env.ANTHROPIC_API_KEY = "sk-ant-compat-key";

		const legacyApp = new Hono();
		legacyApp.all("/proxy/llm/*", createLlmProxyHandler());

		const mockResponse = new Response("{}", { status: 200 });
		const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(mockResponse);

		const res = await legacyApp.request("/proxy/llm/v1/messages", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});

		expect(res.status).toBe(200);
		const headers = fetchSpy.mock.calls[0][1]?.headers as Headers;
		expect(headers.get("x-api-key")).toBe("sk-ant-compat-key");
	});
});
