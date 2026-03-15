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
		) => fn({ key: "test-bot-token" }),
	),
}));

function createMockVault(): CredentialVault {
	return {
		retrieveBuffer: vi.fn().mockReturnValue(Buffer.from(JSON.stringify({ key: "test-bot-token" }))),
	} as unknown as CredentialVault;
}

function makeSendMessageResponse(messageId: number) {
	return new Response(JSON.stringify({ ok: true, result: { message_id: messageId } }), {
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

	describe("public API surface", () => {
		it("chatId is public and accessible as a number", () => {
			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "99887766");
			expect(adapter.chatId).toBe(99887766);
			expect(typeof adapter.chatId).toBe("number");
		});

		it("telegramApi is public and callable externally", async () => {
			const mockFetch = vi.fn().mockResolvedValue(
				new Response(JSON.stringify({ ok: true, result: true }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
			);
			vi.stubGlobal("fetch", mockFetch);

			const vault = createMockVault();
			const adapter = new TelegramConfirmAdapter(vault, "123");
			const result = await adapter.telegramApi("answerCallbackQuery", {
				callback_query_id: "cb-123",
				text: "Done",
			});

			expect(result).toBe(true);
			expect(mockFetch).toHaveBeenCalledOnce();
			const [url] = mockFetch.mock.calls[0];
			expect(url).toBe("https://api.telegram.org/bottest-bot-token/answerCallbackQuery");
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
