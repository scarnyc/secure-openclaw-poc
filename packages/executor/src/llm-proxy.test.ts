import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { handleLlmProxy } from "./llm-proxy.js";

let app: Hono;

beforeEach(() => {
	app = new Hono();
	app.all("/proxy/llm/*", handleLlmProxy);
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
