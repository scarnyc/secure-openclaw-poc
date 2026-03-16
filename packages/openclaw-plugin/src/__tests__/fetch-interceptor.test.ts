import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installFetchInterceptor } from "../fetch-interceptor.js";

const EXECUTOR_URL = "http://executor:3141";
const AUTH_TOKEN = "test-auth-token";
const EGRESS_DOMAINS = ["api.telegram.org", "api.openai.com"];

let originalFetch: typeof globalThis.fetch;
let mockFetch: ReturnType<typeof vi.fn>;
let logs: string[];
let cleanup: (() => void) | undefined;

beforeEach(() => {
	originalFetch = globalThis.fetch;
	mockFetch = vi.fn().mockResolvedValue(
		new Response(JSON.stringify({ ok: true }), {
			status: 200,
			statusText: "OK",
			headers: { "Content-Type": "application/json" },
		}),
	);
	globalThis.fetch = mockFetch;
	logs = [];
	cleanup = undefined;
});

afterEach(() => {
	cleanup?.();
	globalThis.fetch = originalFetch;
	vi.restoreAllMocks();
});

describe("installFetchInterceptor", () => {
	it("routes matching domain through egress proxy", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			agentId: "test-agent",
			sessionId: "test-session",
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://api.telegram.org/bot123/sendMessage", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ chat_id: 123, text: "hello" }),
		});

		expect(mockFetch).toHaveBeenCalledOnce();
		const [calledUrl, calledInit] = mockFetch.mock.calls[0] as [string, RequestInit];

		expect(calledUrl).toBe("http://executor:3141/proxy/egress");
		expect(calledInit.method).toBe("POST");

		const egressBody = JSON.parse(calledInit.body as string);
		expect(egressBody.url).toBe("https://api.telegram.org/bot123/sendMessage");
		expect(egressBody.method).toBe("POST");
		expect(egressBody.headers["Content-Type"]).toBe("application/json");
		expect(egressBody.body).toBe(JSON.stringify({ chat_id: 123, text: "hello" }));
		expect(egressBody.agentId).toBe("test-agent");
		expect(egressBody.sessionId).toBe("test-session");
	});

	it("passes through internal hosts unchanged", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("http://executor:3141/health");

		expect(mockFetch).toHaveBeenCalledOnce();
		const [calledUrl] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(calledUrl).toBe("http://executor:3141/health");
	});

	it("passes through localhost unchanged", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("http://localhost:3141/classify");

		expect(mockFetch).toHaveBeenCalledOnce();
		const [calledUrl] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(calledUrl).toBe("http://localhost:3141/classify");
	});

	it("passes through non-egress external domains", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: ["api.telegram.org"],
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://unknown-domain.com/api");

		expect(mockFetch).toHaveBeenCalledOnce();
		const [calledUrl] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(calledUrl).toBe("https://unknown-domain.com/api");
	});

	it("handles Request object input", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		const request = new Request("https://api.telegram.org/bot123/sendMessage", {
			method: "POST",
			headers: { "X-Custom": "value" },
			body: "test-body",
		});

		await globalThis.fetch(request);

		expect(mockFetch).toHaveBeenCalledOnce();
		const [calledUrl, calledInit] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(calledUrl).toBe("http://executor:3141/proxy/egress");

		const egressBody = JSON.parse(calledInit.body as string);
		expect(egressBody.url).toBe("https://api.telegram.org/bot123/sendMessage");
		expect(egressBody.method).toBe("POST");
		expect(egressBody.headers["x-custom"]).toBe("value");
		expect(egressBody.body).toBe("test-body");
	});

	it("domain matching is case-insensitive", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: ["api.telegram.org"],
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://API.Telegram.Org/bot123/getMe");

		expect(mockFetch).toHaveBeenCalledOnce();
		const [calledUrl] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(calledUrl).toBe("http://executor:3141/proxy/egress");
	});

	it("includes auth token in egress proxy request", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: "my-secret-token",
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://api.telegram.org/bot123/getMe");

		const [, calledInit] = mockFetch.mock.calls[0] as [string, RequestInit];
		const headers = calledInit.headers as Record<string, string>;
		expect(headers.Authorization).toBe("Bearer my-secret-token");
		expect(headers["Content-Type"]).toBe("application/json");
	});

	it("preserves original response from egress proxy", async () => {
		const proxyResponse = new Response(JSON.stringify({ result: "proxied" }), {
			status: 200,
			statusText: "OK",
			headers: { "X-Proxy": "sentinel" },
		});
		mockFetch.mockResolvedValue(proxyResponse);

		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch("https://api.telegram.org/bot123/getMe");

		expect(res.status).toBe(200);
		const body = (await res.json()) as { result: string };
		expect(body.result).toBe("proxied");
	});

	it("handles egress proxy errors", async () => {
		const errorResponse = new Response("Bad Gateway", {
			status: 502,
			statusText: "Bad Gateway",
		});
		mockFetch.mockResolvedValue(errorResponse);

		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch("https://api.telegram.org/bot123/getMe");

		expect(res.status).toBe(502);
		const body = await res.text();
		expect(body).toBe("Bad Gateway");
	});

	it("cleanup restores original fetch", () => {
		const savedFetch = globalThis.fetch;

		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		// fetch was patched
		expect(globalThis.fetch).not.toBe(savedFetch);

		// Restore
		cleanup();
		cleanup = undefined;

		expect(globalThis.fetch).toBe(savedFetch);
	});

	it("extracts headers from Headers object in init", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		const headers = new Headers();
		headers.set("X-Custom-Header", "custom-value");
		headers.set("Accept", "application/json");

		await globalThis.fetch("https://api.telegram.org/bot123/getMe", {
			method: "GET",
			headers,
		});

		const [, calledInit] = mockFetch.mock.calls[0] as [string, RequestInit];
		const egressBody = JSON.parse(calledInit.body as string);
		expect(egressBody.headers["x-custom-header"]).toBe("custom-value");
		expect(egressBody.headers.accept).toBe("application/json");
	});

	it("defaults method to GET", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://api.telegram.org/bot123/getMe");

		const [, calledInit] = mockFetch.mock.calls[0] as [string, RequestInit];
		const egressBody = JSON.parse(calledInit.body as string);
		expect(egressBody.method).toBe("GET");
	});

	it("uses default agentId and sessionId when not provided", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://api.telegram.org/bot123/getMe");

		const [, calledInit] = mockFetch.mock.calls[0] as [string, RequestInit];
		const egressBody = JSON.parse(calledInit.body as string);
		expect(egressBody.agentId).toBe("openclaw-gateway");
		expect(egressBody.sessionId).toBe("default");
	});

	it("passes through 127.0.0.1 unchanged", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("http://127.0.0.1:8080/api");

		const [calledUrl] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(calledUrl).toBe("http://127.0.0.1:8080/api");
	});

	it("passes through 0.0.0.0 unchanged", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("http://0.0.0.0:3000/status");

		const [calledUrl] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(calledUrl).toBe("http://0.0.0.0:3000/status");
	});

	it("logs when routing through egress proxy", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://api.telegram.org/bot123/getMe");

		expect(logs).toHaveLength(1);
		expect(logs[0]).toContain("[fetch-interceptor]");
		expect(logs[0]).toContain("api.telegram.org");
		expect(logs[0]).toContain("egress proxy");
	});

	it("does not log for non-egress requests", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("http://executor:3141/health");

		expect(logs).toHaveLength(0);
	});

	it("strips trailing slashes from executor URL", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: "http://executor:3141///",
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://api.telegram.org/bot123/getMe");

		const [calledUrl] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(calledUrl).toBe("http://executor:3141/proxy/egress");
	});

	it("handles headers as array of tuples in init", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://api.openai.com/v1/chat/completions", {
			method: "POST",
			headers: [
				["Content-Type", "application/json"],
				["X-Request-Id", "abc-123"],
			],
			body: '{"model":"gpt-4"}',
		});

		const [, calledInit] = mockFetch.mock.calls[0] as [string, RequestInit];
		const egressBody = JSON.parse(calledInit.body as string);
		expect(egressBody.headers["Content-Type"]).toBe("application/json");
		expect(egressBody.headers["X-Request-Id"]).toBe("abc-123");
	});

	it("omits body field when no body is provided", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch("https://api.telegram.org/bot123/getMe");

		const [, calledInit] = mockFetch.mock.calls[0] as [string, RequestInit];
		const egressBody = JSON.parse(calledInit.body as string);
		expect(egressBody).not.toHaveProperty("body");
	});

	it("handles URL object input", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch(new URL("https://api.telegram.org/bot123/getMe"));

		const [calledUrl] = mockFetch.mock.calls[0] as [string, RequestInit];
		expect(calledUrl).toBe("http://executor:3141/proxy/egress");
	});

	it("routes multiple egress domains correctly", async () => {
		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: ["api.telegram.org", "api.openai.com"],
			logger: (msg) => logs.push(msg),
		});

		// First call — Telegram
		await globalThis.fetch("https://api.telegram.org/bot123/getMe");
		// Second call — OpenAI
		await globalThis.fetch("https://api.openai.com/v1/models");

		expect(mockFetch).toHaveBeenCalledTimes(2);

		for (const call of mockFetch.mock.calls) {
			const [calledUrl] = call as [string, RequestInit];
			expect(calledUrl).toBe("http://executor:3141/proxy/egress");
		}
	});

	it("propagates fetch errors from egress proxy", async () => {
		mockFetch.mockRejectedValue(new Error("connection refused"));

		cleanup = installFetchInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			egressDomains: EGRESS_DOMAINS,
			logger: (msg) => logs.push(msg),
		});

		await expect(globalThis.fetch("https://api.telegram.org/bot123/getMe")).rejects.toThrow(
			"connection refused",
		);
	});
});
