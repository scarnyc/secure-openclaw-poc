import type { CredentialVault } from "@sentinel/crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TelegramConfirmRequest } from "./telegram-confirm.js";
import {
	_escapeMarkdownV2,
	_formatParamValue,
	TelegramConfirmAdapter,
} from "./telegram-confirm.js";

// Mock @sentinel/crypto — adapter does dynamic import inside telegramApi
vi.mock("@sentinel/crypto", () => ({
	useCredential: vi.fn(
		async (
			_vault: unknown,
			_serviceId: string,
			_keys: readonly string[],
			fn: (cred: Record<string, string>) => Promise<unknown>,
		) => fn({ BOT_TOKEN: "test-bot-token" }),
	),
}));

function createMockVault(): CredentialVault {
	return {
		retrieveBuffer: vi
			.fn()
			.mockReturnValue(Buffer.from(JSON.stringify({ BOT_TOKEN: "test-bot-token" }))),
	} as unknown as CredentialVault;
}

function makeSendMessageResponse(messageId: number) {
	return new Response(JSON.stringify({ ok: true, result: { message_id: messageId } }), {
		status: 200,
		headers: { "content-type": "application/json" },
	});
}

function makeGetUpdatesResponse(updates: unknown[]) {
	return new Response(JSON.stringify({ ok: true, result: updates }), {
		status: 200,
		headers: { "content-type": "application/json" },
	});
}

function makeErrorResponse(status: number, description: string) {
	return new Response(JSON.stringify({ ok: false, description }), {
		status,
		headers: { "content-type": "application/json" },
	});
}

function baseRequest(overrides?: Partial<TelegramConfirmRequest>): TelegramConfirmRequest {
	return {
		manifestId: "test-manifest-1",
		tool: "file-write",
		parameters: { path: "/tmp/test.txt", content: "hello" },
		category: "write",
		reason: "Writes to filesystem",
		...overrides,
	};
}

/**
 * Create a mock fetch for poll loop tests that returns updates once,
 * then stops the adapter to prevent infinite tight loops.
 */
function createPollMockFetch(
	adapter: TelegramConfirmAdapter,
	updates: unknown[],
	options?: {
		onAnswer?: (body: Record<string, unknown>) => void;
	},
) {
	let delivered = false;
	const callCounts = { getUpdates: 0, answerCallback: 0 };

	const mockFetch = vi.fn().mockImplementation((url: string, reqOptions?: RequestInit) => {
		if (typeof url === "string" && url.includes("getUpdates")) {
			callCounts.getUpdates++;
			if (!delivered) {
				delivered = true;
				return Promise.resolve(makeGetUpdatesResponse(updates));
			}
			// Stop the adapter after delivering updates to prevent OOM from tight loop
			adapter.stop();
			return Promise.resolve(makeGetUpdatesResponse([]));
		}
		if (typeof url === "string" && url.includes("answerCallbackQuery")) {
			callCounts.answerCallback++;
			if (options?.onAnswer && reqOptions?.body) {
				options.onAnswer(JSON.parse(reqOptions.body as string));
			}
			return Promise.resolve(
				new Response(JSON.stringify({ ok: true, result: true }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
			);
		}
		return Promise.resolve(new Response("not found", { status: 404 }));
	});

	return { mockFetch, callCounts };
}

describe("TelegramConfirmAdapter", () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		vi.stubGlobal("fetch", originalFetch);
	});

	describe("constructor", () => {
		it("validates chat ID is a number", () => {
			const vault = createMockVault();
			expect(() => new TelegramConfirmAdapter(vault, "not-a-number")).toThrow(
				'Invalid SENTINEL_TELEGRAM_CHAT_ID: "not-a-number" is not a number',
			);
		});

		it("accepts valid numeric chat ID string", () => {
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123456");
			expect(adapter).toBeInstanceOf(TelegramConfirmAdapter);
		});

		it("does not store bot token as instance property", () => {
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123456");
			const keys = Object.keys(adapter);
			const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(adapter));
			const allKeys = [...keys, ...proto];
			expect(allKeys).not.toContain("botToken");
			expect(allKeys).not.toContain("token");
			for (const key of keys) {
				expect((adapter as unknown as Record<string, unknown>)[key]).not.toBe("test-bot-token");
			}
		});
	});

	describe("sendConfirmation", () => {
		it("calls Telegram sendMessage API with correct chat_id and inline keyboard", async () => {
			const mockFetch = vi.fn().mockResolvedValue(makeSendMessageResponse(42));
			vi.stubGlobal("fetch", mockFetch);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "99887766");
			const req = baseRequest();
			const messageId = await adapter.sendConfirmation(req);

			expect(mockFetch).toHaveBeenCalledOnce();
			const [url, options] = mockFetch.mock.calls[0];
			expect(url).toBe("https://api.telegram.org/bottest-bot-token/sendMessage");
			expect(options.method).toBe("POST");

			const body = JSON.parse(options.body as string);
			expect(body.chat_id).toBe(99887766);
			expect(body.parse_mode).toBe("MarkdownV2");
			expect(body.reply_markup.inline_keyboard).toHaveLength(1);
			expect(body.reply_markup.inline_keyboard[0]).toHaveLength(2);
			expect(body.reply_markup.inline_keyboard[0][0].callback_data).toBe(
				"confirm:test-manifest-1:approve",
			);
			expect(body.reply_markup.inline_keyboard[0][1].callback_data).toBe(
				"confirm:test-manifest-1:reject",
			);
			expect(messageId).toBe(42);
		});

		it("returns message_id from Telegram response", async () => {
			vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeSendMessageResponse(777)));

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			const messageId = await adapter.sendConfirmation(baseRequest());
			expect(messageId).toBe(777);
		});

		it("includes tool, category, and params in message text", async () => {
			const mockFetch = vi.fn().mockResolvedValue(makeSendMessageResponse(1));
			vi.stubGlobal("fetch", mockFetch);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			await adapter.sendConfirmation(baseRequest());

			const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
			const text = body.text as string;
			expect(text).toContain("file\\-write");
			expect(text).toContain("write");
			expect(text).toContain("Parameters");
		});

		it("adds CANNOT BE UNDONE warning for write-irreversible category", async () => {
			const mockFetch = vi.fn().mockResolvedValue(makeSendMessageResponse(1));
			vi.stubGlobal("fetch", mockFetch);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			await adapter.sendConfirmation(baseRequest({ category: "write-irreversible" }));

			const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
			const text = body.text as string;
			expect(text).toContain("CANNOT BE UNDONE");
		});

		it("does not add CANNOT BE UNDONE warning for regular write category", async () => {
			const mockFetch = vi.fn().mockResolvedValue(makeSendMessageResponse(1));
			vi.stubGlobal("fetch", mockFetch);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			await adapter.sendConfirmation(baseRequest({ category: "write" }));

			const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
			const text = body.text as string;
			expect(text).not.toContain("CANNOT BE UNDONE");
		});

		it("rejects manifestId containing colons", async () => {
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			await expect(
				adapter.sendConfirmation(baseRequest({ manifestId: "evil:reject" })),
			).rejects.toThrow("manifestId contains colon");
		});

		it("rejects manifestId that would exceed Telegram 64-byte callback_data limit", async () => {
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			const longId = "a".repeat(60); // confirm: (8) + 60 + :approve (8) = 76 > 64
			await expect(adapter.sendConfirmation(baseRequest({ manifestId: longId }))).rejects.toThrow(
				"64-byte limit",
			);
		});

		it("propagates Telegram API errors (non-200)", async () => {
			vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue(makeErrorResponse(500, "Internal Server Error")),
			);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			await expect(adapter.sendConfirmation(baseRequest())).rejects.toThrow(
				"Telegram sendMessage: 500",
			);
		});

		it("propagates Telegram API errors (ok: false)", async () => {
			vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue(
					new Response(
						JSON.stringify({ ok: false, description: "Bad Request: can't parse entities" }),
						{
							status: 200,
							headers: { "content-type": "application/json" },
						},
					),
				),
			);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			await expect(adapter.sendConfirmation(baseRequest())).rejects.toThrow("can't parse entities");
		});

		it("logs warning when message_id is absent from response", async () => {
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			vi.stubGlobal(
				"fetch",
				vi.fn().mockResolvedValue(
					new Response(JSON.stringify({ ok: true, result: true }), {
						status: 200,
						headers: { "content-type": "application/json" },
					}),
				),
			);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			const result = await adapter.sendConfirmation(baseRequest());

			expect(result).toBeUndefined();
			expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("no message_id returned"));
			warnSpy.mockRestore();
		});
	});

	describe("parameter truncation", () => {
		it("truncates parameter values longer than 200 chars", () => {
			const longValue = "The quick brown fox jumps over the lazy dog. ".repeat(10);
			expect(longValue.length).toBeGreaterThan(200);
			const formatted = _formatParamValue(longValue);
			expect(formatted).toContain("\\.\\.\\.");
		});

		it("does not truncate short parameter values", () => {
			const short = "hello world";
			const formatted = _formatParamValue(short);
			expect(formatted).not.toContain("\\.\\.\\.");
		});
	});

	describe("credential redaction", () => {
		it("redacts API keys in parameter values", () => {
			// Construct dynamically to avoid GitHub push protection
			const fakeKey = ["sk", "ant", "api03", "abc123def456ghi789jkl012"].join("-");
			const formatted = _formatParamValue(fakeKey);
			expect(formatted).not.toContain("sk\\-ant");
			expect(formatted).toContain("REDACTED");
		});

		it("redacts OpenAI keys in parameter values", () => {
			const fakeKey = ["sk", "proj", "abc123def456ghi789jklmnopqrst01234567890ABCDEF"].join("-");
			const formatted = _formatParamValue(`token=${fakeKey}`);
			expect(formatted).toContain("REDACTED");
		});

		it("redacts Telegram bot tokens in parameter values", () => {
			// Telegram tokens: numeric_id:alphanumeric_secret (35 chars)
			const fakeToken = `12345678:${"A".repeat(35)}`;
			const formatted = _formatParamValue(fakeToken);
			expect(formatted).toContain("REDACTED");
		});
	});

	describe("callback handling via pollLoop", () => {
		it("resolves approve callback for matching chat_id", async () => {
			const resolver = vi.fn().mockReturnValue(true);
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "555");
			adapter.bindResolver(resolver);

			const { mockFetch } = createPollMockFetch(adapter, [
				{
					update_id: 100,
					callback_query: {
						id: "cb-1",
						data: "confirm:manifest-abc:approve",
						message: { chat: { id: 555 }, message_id: 10 },
					},
				},
			]);
			vi.stubGlobal("fetch", mockFetch);

			adapter.start();

			await vi.waitFor(
				() => {
					expect(resolver).toHaveBeenCalledWith("manifest-abc", true);
				},
				{ timeout: 2000 },
			);

			adapter.stop();
		});

		it("resolves reject callback", async () => {
			const resolver = vi.fn().mockReturnValue(true);
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "555");
			adapter.bindResolver(resolver);

			const { mockFetch } = createPollMockFetch(adapter, [
				{
					update_id: 200,
					callback_query: {
						id: "cb-2",
						data: "confirm:manifest-xyz:reject",
						message: { chat: { id: 555 }, message_id: 11 },
					},
				},
			]);
			vi.stubGlobal("fetch", mockFetch);

			adapter.start();

			await vi.waitFor(
				() => {
					expect(resolver).toHaveBeenCalledWith("manifest-xyz", false);
				},
				{ timeout: 2000 },
			);

			adapter.stop();
		});

		it("rejects callback from wrong chat_id with warning and answers callback", async () => {
			const resolver = vi.fn().mockReturnValue(true);
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "555");
			adapter.bindResolver(resolver);

			let answerBody: Record<string, unknown> | undefined;
			const { mockFetch, callCounts } = createPollMockFetch(
				adapter,
				[
					{
						update_id: 300,
						callback_query: {
							id: "cb-3",
							data: "confirm:manifest-bad:approve",
							message: { chat: { id: 999 }, message_id: 12 },
						},
					},
				],
				{
					onAnswer: (body) => {
						answerBody = body;
					},
				},
			);
			vi.stubGlobal("fetch", mockFetch);

			adapter.start();

			await vi.waitFor(
				() => {
					expect(callCounts.getUpdates).toBeGreaterThanOrEqual(2);
				},
				{ timeout: 2000 },
			);

			expect(resolver).not.toHaveBeenCalled();
			expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("unauthorized chat 999"));
			// SENTINEL: Verify unauthorized callbacks are answered (Finding 7)
			expect(callCounts.answerCallback).toBeGreaterThanOrEqual(1);
			expect(answerBody?.text).toBe("Unauthorized");

			adapter.stop();
			warnSpy.mockRestore();
		});

		it("answers with error when manifestId is unknown", async () => {
			const resolver = vi.fn().mockReturnValue(false); // Unknown — returns false
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			let answerBody: Record<string, unknown> | undefined;
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "555");
			adapter.bindResolver(resolver);

			const { mockFetch } = createPollMockFetch(
				adapter,
				[
					{
						update_id: 400,
						callback_query: {
							id: "cb-4",
							data: "confirm:unknown-id:approve",
							message: { chat: { id: 555 }, message_id: 13 },
						},
					},
				],
				{
					onAnswer: (body) => {
						answerBody = body;
					},
				},
			);
			vi.stubGlobal("fetch", mockFetch);

			adapter.start();

			await vi.waitFor(
				() => {
					expect(resolver).toHaveBeenCalledWith("unknown-id", true);
				},
				{ timeout: 2000 },
			);

			await vi.waitFor(
				() => {
					expect(answerBody).toBeDefined();
				},
				{ timeout: 2000 },
			);

			expect(answerBody?.show_alert).toBe(true);
			expect(answerBody?.text).toContain("not found");
			expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("Unknown manifestId"));

			adapter.stop();
			warnSpy.mockRestore();
		});

		it("logs malformed confirm: callback data instead of silently dropping", async () => {
			const resolver = vi.fn().mockReturnValue(true);
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "555");
			adapter.bindResolver(resolver);

			const { mockFetch, callCounts } = createPollMockFetch(adapter, [
				{
					update_id: 500,
					callback_query: {
						id: "cb-5",
						data: "confirm:id:approve:extra", // 4 parts — malformed
						message: { chat: { id: 555 }, message_id: 14 },
					},
				},
			]);
			vi.stubGlobal("fetch", mockFetch);

			adapter.start();

			await vi.waitFor(
				() => {
					expect(callCounts.getUpdates).toBeGreaterThanOrEqual(2);
				},
				{ timeout: 2000 },
			);

			expect(resolver).not.toHaveBeenCalled();
			expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("Malformed callback data"));

			adapter.stop();
			warnSpy.mockRestore();
		});

		it("logs unknown action in callback data", async () => {
			const resolver = vi.fn().mockReturnValue(true);
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "555");
			adapter.bindResolver(resolver);

			const { mockFetch, callCounts } = createPollMockFetch(adapter, [
				{
					update_id: 600,
					callback_query: {
						id: "cb-6",
						data: "confirm:some-id:explode", // unknown action
						message: { chat: { id: 555 }, message_id: 15 },
					},
				},
			]);
			vi.stubGlobal("fetch", mockFetch);

			adapter.start();

			await vi.waitFor(
				() => {
					expect(callCounts.getUpdates).toBeGreaterThanOrEqual(2);
				},
				{ timeout: 2000 },
			);

			expect(resolver).not.toHaveBeenCalled();
			expect(warnSpy).toHaveBeenCalledWith(
				expect.stringContaining("Unknown action in callback: explode"),
			);

			adapter.stop();
			warnSpy.mockRestore();
		});

		it("silently ignores non-confirm callback data", async () => {
			const resolver = vi.fn().mockReturnValue(true);
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "555");
			adapter.bindResolver(resolver);

			const { mockFetch, callCounts } = createPollMockFetch(adapter, [
				{
					update_id: 700,
					callback_query: {
						id: "cb-7",
						data: "other:something",
						message: { chat: { id: 555 }, message_id: 16 },
					},
				},
			]);
			vi.stubGlobal("fetch", mockFetch);

			adapter.start();

			await vi.waitFor(
				() => {
					expect(callCounts.getUpdates).toBeGreaterThanOrEqual(2);
				},
				{ timeout: 2000 },
			);

			expect(resolver).not.toHaveBeenCalled();
			// Should NOT warn for non-confirm data — it's expected
			const malformedCalls = warnSpy.mock.calls.filter(
				(call) =>
					typeof call[0] === "string" &&
					(call[0].includes("Malformed") || call[0].includes("Unknown action")),
			);
			expect(malformedCalls).toHaveLength(0);

			adapter.stop();
			warnSpy.mockRestore();
		});
	});

	describe("stop()", () => {
		it("aborts polling after stop is called", async () => {
			let callCount = 0;
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");

			const mockFetch = vi.fn().mockImplementation((url: string) => {
				if (typeof url === "string" && url.includes("getUpdates")) {
					callCount++;
					if (callCount >= 2) {
						adapter.stop();
					}
					return Promise.resolve(makeGetUpdatesResponse([]));
				}
				return Promise.resolve(new Response("not found", { status: 404 }));
			});
			vi.stubGlobal("fetch", mockFetch);

			adapter.start();

			await vi.waitFor(
				() => {
					expect(callCount).toBeGreaterThanOrEqual(2);
				},
				{ timeout: 2000 },
			);

			const countAtStop = callCount;
			await new Promise((r) => setTimeout(r, 50));
			expect(callCount).toBeLessThanOrEqual(countAtStop + 1);
		});
	});

	describe("start() idempotency", () => {
		it("calling start() twice does not spawn two poll loops", async () => {
			let callCount = 0;
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");

			const mockFetch = vi.fn().mockImplementation((url: string) => {
				if (typeof url === "string" && url.includes("getUpdates")) {
					callCount++;
					if (callCount >= 3) {
						adapter.stop();
					}
					return Promise.resolve(makeGetUpdatesResponse([]));
				}
				return Promise.resolve(new Response("not found", { status: 404 }));
			});
			vi.stubGlobal("fetch", mockFetch);

			adapter.start();
			adapter.start(); // Second call should be no-op

			await vi.waitFor(
				() => {
					expect(callCount).toBeGreaterThanOrEqual(3);
				},
				{ timeout: 2000 },
			);

			// If two loops ran, we'd see ~6 calls; with one loop, ~3
			expect(callCount).toBeLessThanOrEqual(5);
		});
	});

	describe("poll loop error handling", () => {
		it("stops after MAX_CONSECUTIVE_ERRORS and resets running flag", async () => {
			vi.useFakeTimers();
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

			// Mock fetch to always fail — simulates permanent error (401 Unauthorized)
			vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeErrorResponse(401, "Unauthorized")));

			adapter.start();

			// Advance timers to drain 10 error cycles (5s delay each)
			for (let i = 0; i < 12; i++) {
				await vi.advanceTimersByTimeAsync(5_100);
			}

			expect(errorSpy).toHaveBeenCalledWith(
				expect.stringContaining("FATAL: 10 consecutive poll failures"),
			);

			// After fatal, start() should be callable again (running was reset)
			let secondStartCalled = false;
			vi.stubGlobal(
				"fetch",
				vi.fn().mockImplementation((url: string) => {
					if (typeof url === "string" && url.includes("getUpdates")) {
						secondStartCalled = true;
						adapter.stop();
						return Promise.resolve(makeGetUpdatesResponse([]));
					}
					return Promise.resolve(new Response("not found", { status: 404 }));
				}),
			);

			adapter.start(); // Should work again since running was reset
			await vi.advanceTimersByTimeAsync(100);

			expect(secondStartCalled).toBe(true);

			vi.useRealTimers();
			errorSpy.mockRestore();
		});
	});

	describe("GWS email recipients", () => {
		it("formats to/cc/bcc lists for GWS write-irreversible emails", async () => {
			const mockFetch = vi.fn().mockResolvedValue(makeSendMessageResponse(1));
			vi.stubGlobal("fetch", mockFetch);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			await adapter.sendConfirmation({
				manifestId: "gws-email-1",
				tool: "gws",
				category: "write-irreversible",
				reason: "Sends email",
				parameters: {
					service: "gmail",
					args: {
						to: ["alice@example.com", "bob@example.com"],
						cc: ["carol@example.com"],
						subject: "Test email",
						body: "Hello world",
					},
				},
			});

			const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
			const text = body.text as string;
			expect(text).toContain("alice@example\\.com");
			expect(text).toContain("bob@example\\.com");
			expect(text).toContain("carol@example\\.com");
			expect(text).toContain("to:");
			expect(text).toContain("cc:");
		});

		it("shows recipient count warning when more than 5 total recipients", async () => {
			const mockFetch = vi.fn().mockResolvedValue(makeSendMessageResponse(1));
			vi.stubGlobal("fetch", mockFetch);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			await adapter.sendConfirmation({
				manifestId: "gws-email-2",
				tool: "gws",
				category: "write-irreversible",
				reason: "Mass email",
				parameters: {
					args: {
						to: ["a@x.com", "b@x.com", "c@x.com"],
						cc: ["d@x.com", "e@x.com"],
						bcc: ["f@x.com"],
					},
				},
			});

			const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
			const text = body.text as string;
			expect(text).toContain("6 recipients total");
		});
	});

	describe("helper exports", () => {
		it("escapeMarkdownV2 escapes special characters", () => {
			expect(_escapeMarkdownV2("hello_world")).toBe("hello\\_world");
			expect(_escapeMarkdownV2("test*bold*")).toBe("test\\*bold\\*");
			expect(_escapeMarkdownV2("a.b")).toBe("a\\.b");
			expect(_escapeMarkdownV2("no-change")).toBe("no\\-change");
			expect(_escapeMarkdownV2("[link](url)")).toBe("\\[link\\]\\(url\\)");
		});

		it("formatParamValue handles objects by JSON-serializing", () => {
			const result = _formatParamValue({ key: "value" });
			expect(result).toContain("key");
			expect(result).toContain("value");
		});

		it("formatParamValue handles plain strings", () => {
			const result = _formatParamValue("simple text");
			expect(result).toBe("simple text");
		});
	});
});
