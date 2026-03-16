import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installTelegramInterceptor } from "../telegram-interceptor.js";

const EXECUTOR_URL = "http://localhost:3141";
const AUTH_TOKEN = "test-auth-token";
const BOT_TOKEN = "123456:ABC-DEF";
const GET_UPDATES_URL = `https://api.telegram.org/bot${BOT_TOKEN}/getUpdates`;

/** Helper: create a mock Telegram getUpdates response */
function telegramResponse(updates: unknown[], ok = true) {
	return {
		ok: true,
		status: 200,
		statusText: "OK",
		headers: new Headers({ "Content-Type": "application/json" }),
		json: () => Promise.resolve({ ok, result: updates }),
	};
}

/** Helper: create a Telegram callback_query update */
function callbackUpdate(updateId: number, callbackId: string, data: string) {
	return {
		update_id: updateId,
		callback_query: {
			id: callbackId,
			data,
			from: { id: 12345 },
			message: { chat: { id: 67890 } },
		},
	};
}

/** Helper: create a Telegram message update */
function messageUpdate(updateId: number, text: string) {
	return {
		update_id: updateId,
		message: { message_id: updateId, text, chat: { id: 67890 } },
	};
}

let originalFetch: typeof globalThis.fetch;
let mockFetch: ReturnType<typeof vi.fn>;
let logs: string[];
let cleanup: (() => void) | undefined;

beforeEach(() => {
	originalFetch = globalThis.fetch;
	mockFetch = vi.fn();
	globalThis.fetch = mockFetch;
	logs = [];
	cleanup = undefined;
});

afterEach(() => {
	cleanup?.();
	globalThis.fetch = originalFetch;
	vi.restoreAllMocks();
});

describe("installTelegramInterceptor", () => {
	it("intercepts callback_query with confirm: prefix from getUpdates response", async () => {
		mockFetch.mockResolvedValue(
			telegramResponse([
				callbackUpdate(1, "cb-1", "confirm:manifest-abc:approve"),
				messageUpdate(2, "hello"),
			]),
		);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch(GET_UPDATES_URL);
		const body = (await res.json()) as { ok: boolean; result: unknown[] };

		// Confirm callback removed, message preserved
		expect(body.ok).toBe(true);
		expect(body.result).toHaveLength(1);
		expect(body.result[0]).toMatchObject({ update_id: 2, message: { text: "hello" } });

		// Verify POST to /confirm/manifest-abc was called
		// mockFetch calls: 1 = original getUpdates, 2 = forward to executor, 3 = answerCallbackQuery
		// But since fire-and-forget uses originalFetch (which is mockFetch at install time),
		// we need to wait for microtasks
		await vi.waitFor(() => {
			const calls = mockFetch.mock.calls as Array<[string, RequestInit]>;
			const confirmCall = calls.find(([url]) => url.includes("/confirm/manifest-abc"));
			expect(confirmCall).toBeDefined();
			const parsed = JSON.parse(confirmCall?.[1].body as string);
			expect(parsed).toEqual({ approved: true });
			expect(confirmCall?.[1].headers).toMatchObject({
				Authorization: `Bearer ${AUTH_TOKEN}`,
			});
		});
	});

	it("forwards rejection to executor", async () => {
		mockFetch.mockResolvedValue(
			telegramResponse([callbackUpdate(1, "cb-1", "confirm:abc123:reject")]),
		);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch(GET_UPDATES_URL);

		await vi.waitFor(() => {
			const calls = mockFetch.mock.calls as Array<[string, RequestInit]>;
			const confirmCall = calls.find(([url]) => url.includes("/confirm/abc123"));
			expect(confirmCall).toBeDefined();
			const parsed = JSON.parse(confirmCall?.[1].body as string);
			expect(parsed).toEqual({ approved: false });
		});
	});

	it("removes intercepted callbacks but keeps other updates", async () => {
		mockFetch.mockResolvedValue(
			telegramResponse([
				messageUpdate(1, "first message"),
				callbackUpdate(2, "cb-2", "confirm:id-99:approve"),
				messageUpdate(3, "second message"),
			]),
		);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch(GET_UPDATES_URL);
		const body = (await res.json()) as { ok: boolean; result: Array<{ update_id: number }> };

		expect(body.result).toHaveLength(2);
		expect(body.result[0].update_id).toBe(1);
		expect(body.result[1].update_id).toBe(3);
	});

	it("passes through non-Telegram fetches unchanged", async () => {
		const exampleResponse = {
			ok: true,
			status: 200,
			statusText: "OK",
			headers: new Headers(),
			json: () => Promise.resolve({ data: "example" }),
		};
		mockFetch.mockResolvedValue(exampleResponse);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch("https://example.com/api");
		const body = (await res.json()) as { data: string };

		expect(body.data).toBe("example");
		// Only one fetch call — no interception
		expect(mockFetch).toHaveBeenCalledOnce();
	});

	it("passes through non-getUpdates Telegram calls unchanged", async () => {
		const sendResponse = {
			ok: true,
			status: 200,
			statusText: "OK",
			headers: new Headers(),
			json: () => Promise.resolve({ ok: true, result: { message_id: 42 } }),
		};
		mockFetch.mockResolvedValue(sendResponse);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`);
		const body = (await res.json()) as { ok: boolean; result: { message_id: number } };

		expect(body.result.message_id).toBe(42);
		expect(mockFetch).toHaveBeenCalledOnce();
	});

	it("handles malformed callback data gracefully", async () => {
		mockFetch.mockResolvedValue(
			telegramResponse([
				callbackUpdate(1, "cb-1", "not-a-confirm-pattern"),
				callbackUpdate(2, "cb-2", "confirm:incomplete"),
				callbackUpdate(3, "cb-3", "random:data:here"),
			]),
		);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch(GET_UPDATES_URL);
		const body = (await res.json()) as { ok: boolean; result: unknown[] };

		// All pass through — none match confirm pattern
		expect(body.result).toHaveLength(3);
		// No confirmation forwarded
		expect(mockFetch).toHaveBeenCalledOnce();
	});

	it("handles empty result array", async () => {
		mockFetch.mockResolvedValue(telegramResponse([]));

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch(GET_UPDATES_URL);
		const body = (await res.json()) as { ok: boolean; result: unknown[] };

		expect(body.ok).toBe(true);
		expect(body.result).toHaveLength(0);
	});

	it("cleanup function restores original fetch", () => {
		const savedFetch = globalThis.fetch;

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		// fetch was patched
		expect(globalThis.fetch).not.toBe(savedFetch);

		// Restore
		cleanup();
		cleanup = undefined;

		expect(globalThis.fetch).toBe(savedFetch);
	});

	it("answers callback query via Telegram API", async () => {
		mockFetch.mockResolvedValue(
			telegramResponse([callbackUpdate(1, "cb-answer-test", "confirm:m1:approve")]),
		);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch(GET_UPDATES_URL);

		await vi.waitFor(() => {
			const calls = mockFetch.mock.calls as Array<[string, RequestInit]>;
			const answerCall = calls.find(([url]) => url.includes("answerCallbackQuery"));
			expect(answerCall).toBeDefined();
			expect(answerCall?.[0]).toBe(`https://api.telegram.org/bot${BOT_TOKEN}/answerCallbackQuery`);
			const parsed = JSON.parse(answerCall?.[1].body as string);
			expect(parsed.callback_query_id).toBe("cb-answer-test");
			expect(parsed.text).toBe("Approved");
		});
	});

	it("answers callback query with Rejected text for reject action", async () => {
		mockFetch.mockResolvedValue(
			telegramResponse([callbackUpdate(1, "cb-rej", "confirm:m2:reject")]),
		);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch(GET_UPDATES_URL);

		await vi.waitFor(() => {
			const calls = mockFetch.mock.calls as Array<[string, RequestInit]>;
			const answerCall = calls.find(([url]) => url.includes("answerCallbackQuery"));
			expect(answerCall).toBeDefined();
			const parsed = JSON.parse(answerCall?.[1].body as string);
			expect(parsed.text).toBe("Rejected");
		});
	});

	it("handles fetch errors by propagating them", async () => {
		mockFetch.mockRejectedValue(new Error("Network failure"));

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		await expect(globalThis.fetch(GET_UPDATES_URL)).rejects.toThrow("Network failure");
	});

	it("passes through when Telegram response is not ok (HTTP error)", async () => {
		const errorResponse = {
			ok: false,
			status: 502,
			statusText: "Bad Gateway",
			headers: new Headers(),
			json: () => Promise.resolve({ ok: false, description: "Bad Gateway" }),
		};
		mockFetch.mockResolvedValue(errorResponse);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch(GET_UPDATES_URL);

		// Should return the original response without parsing
		expect(res.ok).toBe(false);
		expect(res.status).toBe(502);
		expect(mockFetch).toHaveBeenCalledOnce();
	});

	it("logs intercepted confirmation details", async () => {
		mockFetch.mockResolvedValue(
			telegramResponse([callbackUpdate(1, "cb-1", "confirm:log-test:approve")]),
		);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		await globalThis.fetch(GET_UPDATES_URL);

		expect(logs).toContainEqual(expect.stringContaining("manifestId=log-test"));
		expect(logs).toContainEqual(expect.stringContaining("action=approve"));
	});

	it("handles callback_query without data field", async () => {
		const updateNoData = {
			update_id: 1,
			callback_query: { id: "cb-no-data", from: { id: 12345 } },
		};
		mockFetch.mockResolvedValue(telegramResponse([updateNoData]));

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch(GET_UPDATES_URL);
		const body = (await res.json()) as { ok: boolean; result: unknown[] };

		// Should pass through — no data to match
		expect(body.result).toHaveLength(1);
		expect(mockFetch).toHaveBeenCalledOnce();
	});

	it("handles multiple confirm callbacks in a single response", async () => {
		mockFetch.mockResolvedValue(
			telegramResponse([
				callbackUpdate(1, "cb-1", "confirm:m-first:approve"),
				callbackUpdate(2, "cb-2", "confirm:m-second:reject"),
				messageUpdate(3, "keep me"),
			]),
		);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const res = await globalThis.fetch(GET_UPDATES_URL);
		const body = (await res.json()) as { ok: boolean; result: unknown[] };

		// Only the message passes through
		expect(body.result).toHaveLength(1);

		// Both confirmations forwarded
		await vi.waitFor(() => {
			const calls = mockFetch.mock.calls as Array<[string, RequestInit]>;
			const confirmCalls = calls.filter(([url]) => url.includes("/confirm/"));
			expect(confirmCalls).toHaveLength(2);

			const firstConfirm = confirmCalls.find(([url]) => url.includes("m-first"));
			expect(firstConfirm).toBeDefined();
			expect(JSON.parse(firstConfirm?.[1].body as string)).toEqual({ approved: true });

			const secondConfirm = confirmCalls.find(([url]) => url.includes("m-second"));
			expect(secondConfirm).toBeDefined();
			expect(JSON.parse(secondConfirm?.[1].body as string)).toEqual({ approved: false });
		});
	});

	it("logs error when confirmation forwarding fails but does not throw", async () => {
		let callCount = 0;
		mockFetch.mockImplementation((_url: string) => {
			callCount++;
			// First call: getUpdates (succeeds)
			if (callCount === 1) {
				return Promise.resolve(
					telegramResponse([callbackUpdate(1, "cb-fail", "confirm:fail-id:approve")]),
				);
			}
			// Subsequent calls: forwarding (fail)
			return Promise.reject(new Error("connection refused"));
		});

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		// Should not throw despite forwarding failures
		const res = await globalThis.fetch(GET_UPDATES_URL);
		const body = (await res.json()) as { ok: boolean; result: unknown[] };
		expect(body.result).toHaveLength(0);

		// Wait for fire-and-forget error logging
		await vi.waitFor(() => {
			expect(
				logs.some((l) => l.includes("Failed to forward") || l.includes("Failed to answer")),
			).toBe(true);
		});
	});

	it("works with Request object input", async () => {
		mockFetch.mockResolvedValue(
			telegramResponse([callbackUpdate(1, "cb-req", "confirm:req-id:approve")]),
		);

		cleanup = installTelegramInterceptor({
			executorUrl: EXECUTOR_URL,
			authToken: AUTH_TOKEN,
			logger: (msg) => logs.push(msg),
		});

		const request = new Request(GET_UPDATES_URL, { method: "POST" });
		const res = await globalThis.fetch(request);
		const body = (await res.json()) as { ok: boolean; result: unknown[] };

		expect(body.result).toHaveLength(0);

		await vi.waitFor(() => {
			const calls = mockFetch.mock.calls as Array<[string | Request, RequestInit]>;
			const confirmCall = calls.find(([url]) => {
				const urlStr = typeof url === "string" ? url : (url as Request).url;
				return urlStr.includes("/confirm/req-id");
			});
			expect(confirmCall).toBeDefined();
		});
	});
});
