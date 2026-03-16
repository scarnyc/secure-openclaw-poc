import type { EgressBinding } from "@sentinel/types";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	createEgressProxyHandler,
	EgressSecurityError,
	type TelegramInterceptor,
} from "./egress-proxy.js";

// Mock dns to avoid real DNS resolution in SSRF guard
vi.mock("node:dns/promises", () => ({
	default: {
		resolve4: vi.fn().mockResolvedValue(["1.2.3.4"]),
		resolve6: vi.fn().mockRejectedValue(new Error("no AAAA")),
	},
}));

const DEFAULT_BINDINGS: EgressBinding[] = [
	{ serviceId: "TELEGRAM", allowedDomains: ["api.telegram.org"] },
];

function createMockVault(credentialData?: Record<string, string>) {
	const data = credentialData ?? { BOT_TOKEN: "test-token-123" };
	return {
		retrieveBuffer: vi.fn().mockReturnValue(Buffer.from(JSON.stringify(data))),
	};
}

function createTestApp(options?: {
	bindings?: EgressBinding[];
	vault?: ReturnType<typeof createMockVault> | undefined;
	telegramInterceptor?: TelegramInterceptor;
}) {
	const app = new Hono();
	const mockAuditLogger = { log: vi.fn() };
	const bindings = options?.bindings ?? DEFAULT_BINDINGS;
	const vault =
		options?.vault === undefined && !("vault" in (options ?? {}))
			? createMockVault()
			: options?.vault;

	const handler = createEgressProxyHandler(
		vault as any,
		mockAuditLogger as any,
		bindings,
		undefined,
		options?.telegramInterceptor,
	);
	app.post("/proxy/egress", handler);

	return { app, mockAuditLogger, vault };
}

function createMockInterceptor(chatId = 12345): TelegramInterceptor & {
	resolveConfirmation: ReturnType<typeof vi.fn>;
	acknowledgeCallback: ReturnType<typeof vi.fn>;
	isAuthorizedChat: ReturnType<typeof vi.fn>;
} {
	return {
		isAuthorizedChat: vi.fn().mockImplementation((id: number) => id === chatId),
		resolveConfirmation: vi.fn().mockReturnValue(true),
		acknowledgeCallback: vi.fn().mockResolvedValue(undefined),
	};
}

function makeTelegramResponse(updates: unknown[], status = 200): Response {
	return new Response(JSON.stringify({ ok: true, result: updates }), {
		status,
		headers: { "content-type": "application/json" },
	});
}

function makeGetUpdatesRequest(extra?: Record<string, unknown>) {
	return {
		url: "https://api.telegram.org/botSENTINEL_PLACEHOLDER_TELEGRAM__BOT_TOKEN/getUpdates",
		method: "POST" as const,
		body: JSON.stringify({ offset: 0, timeout: 30, ...extra }),
		...extra,
	};
}

async function postEgress(app: Hono, body: Record<string, unknown>): Promise<Response> {
	return app.request("/proxy/egress", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

describe("egress proxy", () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	it("rejects non-HTTPS URLs", async () => {
		const { app } = createTestApp();
		const res = await postEgress(app, {
			url: "http://api.telegram.org/bot123/sendMessage",
		});
		expect(res.status).toBe(400);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.error).toContain("HTTPS");
	});

	it("blocks unbound domains", async () => {
		const { app } = createTestApp();
		const res = await postEgress(app, {
			url: "https://evil.com/steal",
		});
		expect(res.status).toBe(403);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.error).toContain("not a bound egress domain");
	});

	it("blocks private IPs via SSRF guard", async () => {
		// Use dynamic import to override the dns mock for this test
		const dns = await import("node:dns/promises");
		(dns.default.resolve4 as ReturnType<typeof vi.fn>).mockResolvedValue(["10.0.0.1"]);

		const { app } = createTestApp({
			bindings: [{ serviceId: "internal", allowedDomains: ["internal.example.com"] }],
		});
		const res = await postEgress(app, {
			url: "https://internal.example.com/secret",
		});
		expect(res.status).toBe(403);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.error).toContain("SSRF");

		// Restore dns mock
		(dns.default.resolve4 as ReturnType<typeof vi.fn>).mockResolvedValue(["1.2.3.4"]);
	});

	it("substitutes credential placeholders in URL, headers, and body", async () => {
		const mockResponse = new Response(JSON.stringify({ ok: true }), {
			status: 200,
			headers: { "content-type": "application/json" },
		});
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

		const { app } = createTestApp();
		const res = await postEgress(app, {
			url: "https://api.telegram.org/botSENTINEL_PLACEHOLDER_TELEGRAM__BOT_TOKEN/sendMessage",
			method: "POST",
			body: "chat_id=1&text=hello",
		});

		expect(res.status).toBe(200);

		// Verify fetch was called with the substituted URL (token replaced in URL path)
		const mockFetch = globalThis.fetch as ReturnType<typeof vi.fn>;
		expect(mockFetch).toHaveBeenCalled();
		const calledUrl = mockFetch.mock.calls[0][0] as string;
		expect(calledUrl).toBe("https://api.telegram.org/bottest-token-123/sendMessage");
		expect(calledUrl).not.toContain("SENTINEL_PLACEHOLDER");

		vi.stubGlobal("fetch", originalFetch);
	});

	it("blocks cross-service placeholder injection", async () => {
		vi.stubGlobal("fetch", vi.fn());

		const { app } = createTestApp();
		// URL targets telegram domain, but placeholder references a different service
		const res = await postEgress(app, {
			url: "https://api.telegram.org/sendMessage",
			method: "POST",
			headers: {
				Authorization: "Bearer SENTINEL_PLACEHOLDER_GITHUB__TOKEN",
			},
		});
		expect(res.status).toBe(403);
		const json = (await res.json()) as Record<string, unknown>;
		// Error message should be generic (no vault structure leak)
		expect(json.error).toBe("Credential substitution failed");

		vi.stubGlobal("fetch", originalFetch);
	});

	it("filters credentials from upstream response", async () => {
		const fakeKey = ["sk", "ant", "api03", "abc123def456ghi789jkl012"].join("-");
		const mockResponse = new Response(`secret: ${fakeKey}`, {
			status: 200,
			headers: { "content-type": "text/plain" },
		});
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

		const { app } = createTestApp();
		const res = await postEgress(app, {
			url: "https://api.telegram.org/getMe",
		});
		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).not.toContain("sk-ant");
		expect(body).toContain("[REDACTED]");

		vi.stubGlobal("fetch", originalFetch);
	});

	it("returns 500 when vault is undefined", async () => {
		const { app } = createTestApp({ vault: undefined });
		const res = await postEgress(app, {
			url: "https://api.telegram.org/getMe",
		});
		expect(res.status).toBe(500);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.error).toContain("credential vault");
	});
});

describe("Telegram getUpdates interception", () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		vi.stubGlobal("fetch", originalFetch);
	});

	it("replaces confirm callbacks with stubs and calls resolveConfirmation", async () => {
		const interceptor = createMockInterceptor();
		const updates = [
			{
				update_id: 100,
				callback_query: {
					id: "cb1",
					data: "confirm:manifest-abc:approve",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		expect(res.status).toBe(200);
		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.ok).toBe(true);
		expect(json.result).toHaveLength(1);
		expect(json.result[0]).toEqual({ update_id: 100 });

		expect(interceptor.resolveConfirmation).toHaveBeenCalledWith("manifest-abc", true, "telegram");
		expect(interceptor.acknowledgeCallback).toHaveBeenCalledWith("cb1", "Approved", false);
	});

	it("passes non-confirm callbacks through unmodified", async () => {
		const interceptor = createMockInterceptor();
		const updates = [
			{
				update_id: 200,
				callback_query: {
					id: "cb2",
					data: "commands_page_2",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		expect(res.status).toBe(200);
		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.result[0]).toEqual(updates[0]);
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
	});

	it("handles mixed updates — only confirm callbacks stubbed", async () => {
		const interceptor = createMockInterceptor();
		const updates = [
			{ update_id: 1, message: { text: "hello", chat: { id: 12345 } } },
			{
				update_id: 2,
				callback_query: {
					id: "cb-conf",
					data: "confirm:m1:reject",
					message: { chat: { id: 12345 } },
				},
			},
			{
				update_id: 3,
				callback_query: {
					id: "cb-other",
					data: "menu:settings",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.result).toHaveLength(3);
		// Message passes through
		expect(json.result[0]).toEqual(updates[0]);
		// Confirm callback → stub
		expect(json.result[1]).toEqual({ update_id: 2 });
		// Non-confirm callback passes through
		expect(json.result[2]).toEqual(updates[2]);

		expect(interceptor.resolveConfirmation).toHaveBeenCalledWith("m1", false, "telegram");
	});

	it("all-confirm response → all stubs with correct update_ids", async () => {
		const interceptor = createMockInterceptor();
		const updates = [
			{
				update_id: 10,
				callback_query: {
					id: "c1",
					data: "confirm:a:approve",
					message: { chat: { id: 12345 } },
				},
			},
			{
				update_id: 11,
				callback_query: {
					id: "c2",
					data: "confirm:b:reject",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.ok).toBe(true);
		expect(json.result).toEqual([{ update_id: 10 }, { update_id: 11 }]);
		expect(interceptor.resolveConfirmation).toHaveBeenCalledTimes(2);
	});

	it("error response (non-200) → passed through unmodified", async () => {
		const interceptor = createMockInterceptor();
		const errorResponse = new Response(JSON.stringify({ ok: false, description: "Unauthorized" }), {
			status: 401,
			headers: { "content-type": "application/json" },
		});
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(errorResponse));

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		expect(res.status).toBe(401);
		const json = (await res.json()) as { ok: boolean; description: string };
		expect(json.ok).toBe(false);
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
	});

	it("non-getUpdates Telegram calls (sendMessage) → no interception", async () => {
		const interceptor = createMockInterceptor();
		const responseBody = JSON.stringify({ ok: true, result: { message_id: 1 } });
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(
				new Response(responseBody, {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
			),
		);

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, {
			url: "https://api.telegram.org/botSENTINEL_PLACEHOLDER_TELEGRAM__BOT_TOKEN/sendMessage",
			method: "POST",
			body: JSON.stringify({ chat_id: 12345, text: "hello" }),
		});

		expect(res.status).toBe(200);
		const json = (await res.json()) as { ok: boolean; result: unknown };
		expect(json.result).toEqual({ message_id: 1 });
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
	});

	it("non-Telegram egress calls → no interception", async () => {
		const interceptor = createMockInterceptor();
		const responseBody = JSON.stringify({ data: "example" });
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(
				new Response(responseBody, {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
			),
		);

		const { app } = createTestApp({
			bindings: [
				...DEFAULT_BINDINGS,
				{ serviceId: "EXAMPLE", allowedDomains: ["api.example.com"] },
			],
			vault: createMockVault({ API_KEY: "key123" }),
			telegramInterceptor: interceptor,
		});
		const res = await postEgress(app, {
			url: "https://api.example.com/data",
		});

		expect(res.status).toBe(200);
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
	});

	it("unauthorized chat ID → stubbed, answerCallbackQuery called, resolveConfirmation NOT called", async () => {
		const interceptor = createMockInterceptor(99999);
		const updates = [
			{
				update_id: 300,
				callback_query: {
					id: "cb-unauth",
					data: "confirm:m2:approve",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.result[0]).toEqual({ update_id: 300 });
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
		// Pen test Finding 7: answer unauthorized callbacks to prevent re-delivery
		expect(interceptor.acknowledgeCallback).toHaveBeenCalledWith("cb-unauth", "Unauthorized", true);
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("SECURITY: callback from unauthorized chat"),
		);
		warnSpy.mockRestore();
	});

	it("malformed callback data (wrong number of parts) → stubbed, answerCallbackQuery called, not resolved", async () => {
		const interceptor = createMockInterceptor();
		const updates = [
			{
				update_id: 400,
				callback_query: {
					id: "cb-bad",
					data: "confirm:only-two-parts",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.result[0]).toEqual({ update_id: 400 });
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
		expect(interceptor.acknowledgeCallback).toHaveBeenCalledWith(
			"cb-bad",
			"Invalid callback data",
			true,
		);
		expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("Malformed callback data"));
		warnSpy.mockRestore();
	});

	it("answerCallbackQuery failure → logged error, non-blocking", async () => {
		const interceptor = createMockInterceptor();
		interceptor.acknowledgeCallback.mockRejectedValue(new Error("Telegram API down"));
		const updates = [
			{
				update_id: 500,
				callback_query: {
					id: "cb-fail",
					data: "confirm:m3:approve",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		expect(res.status).toBe(200);
		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.result[0]).toEqual({ update_id: 500 });
		expect(interceptor.resolveConfirmation).toHaveBeenCalledWith("m3", true, "telegram");

		// Wait for the fire-and-forget promise to settle
		await vi.waitFor(() => {
			expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("answerCallbackQuery failed"));
		});
		errorSpy.mockRestore();
	});

	it("no TelegramInterceptor configured → all responses pass through unchanged", async () => {
		const updates = [
			{
				update_id: 600,
				callback_query: {
					id: "cb-no-int",
					data: "confirm:m4:approve",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		// No telegramInterceptor passed
		const { app } = createTestApp();
		const res = await postEgress(app, makeGetUpdatesRequest());

		expect(res.status).toBe(200);
		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		// Confirm callback passes through because no interceptor
		expect(json.result[0]).toHaveProperty("callback_query");
	});

	it("re-delivery of already-resolved callback → resolveConfirmation returns false, still stubbed", async () => {
		const interceptor = createMockInterceptor();
		interceptor.resolveConfirmation.mockReturnValue(false);
		const updates = [
			{
				update_id: 700,
				callback_query: {
					id: "cb-dup",
					data: "confirm:m5:approve",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.result[0]).toEqual({ update_id: 700 });
		expect(interceptor.resolveConfirmation).toHaveBeenCalledWith("m5", true, "telegram");

		// acknowledgeCallback should report "timed out" for unresolved
		expect(interceptor.acknowledgeCallback).toHaveBeenCalledWith(
			"cb-dup",
			"Action not found (may have timed out)",
			true,
		);
	});

	it("re-serialized response has valid ok: true and result array structure", async () => {
		const interceptor = createMockInterceptor();
		const updates = [
			{ update_id: 800, message: { text: "hi", chat: { id: 12345 } } },
			{
				update_id: 801,
				callback_query: {
					id: "cb-v",
					data: "confirm:m6:reject",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.ok).toBe(true);
		expect(Array.isArray(json.result)).toBe(true);
		expect(json.result).toHaveLength(2);
		// First update preserved
		expect(json.result[0]).toHaveProperty("message");
		// Second is a stub
		expect(json.result[1]).toEqual({ update_id: 801 });
	});

	it("invalid action (e.g., confirm:id:explode) → stubbed, answerCallbackQuery called, not resolved", async () => {
		const interceptor = createMockInterceptor();
		const updates = [
			{
				update_id: 900,
				callback_query: {
					id: "cb-explode",
					data: "confirm:m7:explode",
					message: { chat: { id: 12345 } },
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.result[0]).toEqual({ update_id: 900 });
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
		expect(interceptor.acknowledgeCallback).toHaveBeenCalledWith(
			"cb-explode",
			"Unknown action",
			true,
		);
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("Unknown action in callback data"),
		);
		warnSpy.mockRestore();
	});

	it("empty updates array → passes through unchanged", async () => {
		const interceptor = createMockInterceptor();
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse([])));

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.ok).toBe(true);
		expect(json.result).toEqual([]);
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
	});

	it("callback_query with missing message field → stubbed as unauthorized, not resolved", async () => {
		const interceptor = createMockInterceptor();
		const updates = [
			{
				update_id: 950,
				callback_query: {
					id: "cb-no-msg",
					data: "confirm:m8:approve",
					// No message field — inline mode edge case
				},
			},
		];
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeTelegramResponse(updates)));

		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		const json = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(json.result[0]).toEqual({ update_id: 950 });
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("SECURITY: callback from unauthorized chat"),
		);
		warnSpy.mockRestore();
	});

	it("ok:false in 200 response → interception skipped with warning", async () => {
		const interceptor = createMockInterceptor();
		const response = new Response(
			JSON.stringify({ ok: false, error_code: 409, description: "Conflict" }),
			{ status: 200, headers: { "content-type": "application/json" } },
		);
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		expect(res.status).toBe(200);
		const json = (await res.json()) as { ok: boolean; error_code: number };
		expect(json.ok).toBe(false);
		expect(json.error_code).toBe(409);
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
		expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("getUpdates returned ok:false"));
		warnSpy.mockRestore();
	});

	it("non-JSON getUpdates response body → interception skipped with warning", async () => {
		const interceptor = createMockInterceptor();
		const response = new Response("<html>502 Bad Gateway</html>", {
			status: 200,
			headers: { "content-type": "text/html" },
		});
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const { app } = createTestApp({ telegramInterceptor: interceptor });
		const res = await postEgress(app, makeGetUpdatesRequest());

		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).toContain("502 Bad Gateway");
		expect(interceptor.resolveConfirmation).not.toHaveBeenCalled();
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("Failed to parse getUpdates response as JSON"),
		);
		warnSpy.mockRestore();
	});

	it("long-poll timeout: getUpdates with timeout > 45 → upstream timeout extended", async () => {
		const interceptor = createMockInterceptor();
		vi.stubGlobal(
			"fetch",
			vi.fn().mockImplementation((_url: string, init: RequestInit) => {
				// Verify the abort signal is set (timeout was applied)
				expect(init.signal).toBeDefined();
				return Promise.resolve(makeTelegramResponse([]));
			}),
		);

		// Use vi.spyOn on setTimeout to capture the timeout value
		const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");

		const { app } = createTestApp({ telegramInterceptor: interceptor });
		await postEgress(app, {
			url: "https://api.telegram.org/botSENTINEL_PLACEHOLDER_TELEGRAM__BOT_TOKEN/getUpdates",
			method: "POST",
			body: JSON.stringify({ offset: 0, timeout: 50 }),
		});

		// Find the timeout call with the extended value (50*1000 + 15000 = 65000)
		const timeoutCalls = setTimeoutSpy.mock.calls;
		const hasExtendedTimeout = timeoutCalls.some(
			(call) => typeof call[1] === "number" && call[1] === 65_000,
		);
		expect(hasExtendedTimeout).toBe(true);

		setTimeoutSpy.mockRestore();
	});
});
