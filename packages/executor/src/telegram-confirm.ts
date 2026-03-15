import type { CredentialVault } from "@sentinel/crypto";
import { redactAll } from "@sentinel/types";

const PARAM_TRUNCATE_LIMIT = 200;
const POLL_TIMEOUT_SECONDS = 30;
const POLL_ERROR_DELAY_MS = 5_000;
/** Stop polling after this many consecutive errors (permanent failure assumed) */
const MAX_CONSECUTIVE_ERRORS = 10;
/** Telegram limits callback_data to 64 bytes */
const MAX_CALLBACK_DATA_LENGTH = 64;

export interface TelegramConfirmRequest {
	manifestId: string;
	tool: string;
	parameters: Record<string, unknown>;
	category: string;
	reason: string;
}

interface CallbackQuery {
	id: string;
	data?: string;
	message?: { chat: { id: number }; message_id: number };
}

interface TelegramUpdate {
	update_id: number;
	callback_query?: CallbackQuery;
}

export class TelegramConfirmAdapter {
	private readonly vault: CredentialVault;
	private readonly chatId: number;
	private resolveConfirmation: (id: string, approved: boolean) => boolean;
	private running = false;
	private offset = 0;

	constructor(vault: CredentialVault, chatId: string) {
		const parsed = Number.parseInt(chatId, 10);
		if (Number.isNaN(parsed)) {
			throw new Error(`Invalid SENTINEL_TELEGRAM_CHAT_ID: "${chatId}" is not a number`);
		}
		this.vault = vault;
		this.chatId = parsed;
		// Default no-op — replaced by createApp via bindResolver()
		this.resolveConfirmation = () => false;
	}

	/**
	 * Bind the resolver function from createApp's pendingConfirmations Map.
	 * Must be called before start() for Telegram callbacks to resolve confirmations.
	 */
	bindResolver(fn: (id: string, approved: boolean) => boolean): void {
		this.resolveConfirmation = fn;
	}

	start(): void {
		if (this.running) return;
		this.running = true;
		this.pollLoop().catch((err) => {
			// SENTINEL: Reset running flag so start() can be retried (Finding 2)
			this.running = false;
			console.error(
				`[telegram] FATAL: Poll loop crashed — Telegram confirmations disabled. Error: ${err instanceof Error ? err.message : "Unknown"}`,
			);
		});
	}

	stop(): void {
		this.running = false;
	}

	async sendConfirmation(req: TelegramConfirmRequest): Promise<number | undefined> {
		// SENTINEL: Validate manifestId won't break callback_data parsing (Finding 3)
		if (req.manifestId.includes(":")) {
			throw new Error(
				`manifestId contains colon — incompatible with callback_data format: ${req.manifestId}`,
			);
		}
		const approveData = `confirm:${req.manifestId}:approve`;
		if (approveData.length > MAX_CALLBACK_DATA_LENGTH) {
			throw new Error(
				`callback_data exceeds Telegram's 64-byte limit (${approveData.length} bytes)`,
			);
		}

		const text = this.formatMessage(req);
		const keyboard = {
			inline_keyboard: [
				[
					{ text: "✅ Approve", callback_data: approveData },
					{ text: "❌ Reject", callback_data: `confirm:${req.manifestId}:reject` },
				],
			],
		};

		const result = (await this.telegramApi("sendMessage", {
			chat_id: this.chatId,
			text,
			parse_mode: "MarkdownV2",
			reply_markup: keyboard,
		})) as { message_id?: number } | undefined;

		const messageId = result?.message_id;
		if (messageId !== undefined && messageId !== null) {
			console.log(`[telegram] Confirmation sent for ${req.manifestId} (message_id: ${messageId})`);
		} else {
			// SENTINEL: Finding 5 — log when message_id is absent
			console.warn(`[telegram] Confirmation for ${req.manifestId} sent but no message_id returned`);
		}
		return messageId;
	}

	private formatMessage(req: TelegramConfirmRequest): string {
		const lines: string[] = [
			"⚠ *Action requires confirmation*",
			"━━━━━━━━━━━━━━━━━━━━━",
			`*Tool:* \`${escapeMarkdownV2(req.tool)}\``,
			`*Category:* ${escapeMarkdownV2(req.category)}`,
			`*Reason:* ${escapeMarkdownV2(req.reason)}`,
		];

		if (req.category === "write-irreversible") {
			lines.push("");
			lines.push("⚠ *THIS ACTION CANNOT BE UNDONE*");
		}

		lines.push("");
		lines.push("*Parameters:*");

		// GWS email special handling — show recipients clearly
		if (req.tool === "gws" && req.category === "write-irreversible") {
			const args = req.parameters.args;
			if (args && typeof args === "object" && !Array.isArray(args)) {
				const gwsArgs = args as Record<string, unknown>;
				const recipientKeys = ["to", "cc", "bcc"] as const;
				let totalRecipients = 0;

				// Non-args params
				for (const [key, value] of Object.entries(req.parameters)) {
					if (key === "args") continue;
					lines.push(`  ${escapeMarkdownV2(key)}: ${formatParamValue(value)}`);
				}

				// Args fields with recipient expansion
				for (const [key, value] of Object.entries(gwsArgs)) {
					if (
						recipientKeys.includes(key as (typeof recipientKeys)[number]) &&
						Array.isArray(value)
					) {
						totalRecipients += value.length;
						lines.push(`  ${escapeMarkdownV2(key)}:`);
						for (const recipient of value) {
							lines.push(`    \\- ${escapeMarkdownV2(String(recipient))}`);
						}
					} else {
						lines.push(`  ${escapeMarkdownV2(key)}: ${formatParamValue(value)}`);
					}
				}

				if (totalRecipients > 5) {
					lines.push(`⚠ ${escapeMarkdownV2(`${totalRecipients} recipients total`)}`);
				}
			} else {
				this.appendStandardParams(lines, req.parameters);
			}
		} else {
			this.appendStandardParams(lines, req.parameters);
		}

		lines.push("━━━━━━━━━━━━━━━━━━━━━");
		return lines.join("\n");
	}

	private appendStandardParams(lines: string[], params: Record<string, unknown>): void {
		for (const [key, value] of Object.entries(params)) {
			lines.push(`  ${escapeMarkdownV2(key)}: ${formatParamValue(value)}`);
		}
	}

	private async telegramApi(method: string, body: object): Promise<unknown> {
		const { useCredential } = await import("@sentinel/crypto");
		return useCredential(this.vault, "TELEGRAM", ["BOT_TOKEN"] as const, async (cred) => {
			const res = await fetch(`https://api.telegram.org/bot${cred.BOT_TOKEN}/${method}`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});
			// SENTINEL: Finding 6 — include Telegram's error description for diagnostics
			const data = (await res.json()) as { ok: boolean; result: unknown; description?: string };
			if (!res.ok || !data.ok) {
				throw new Error(
					`Telegram ${method}: ${res.status} — ${data.description ?? "no description"}`,
				);
			}
			return data.result;
		});
	}

	private async pollLoop(): Promise<void> {
		let consecutiveErrors = 0;

		while (this.running) {
			try {
				const updates = (await this.telegramApi("getUpdates", {
					offset: this.offset,
					timeout: POLL_TIMEOUT_SECONDS,
				})) as TelegramUpdate[];

				consecutiveErrors = 0; // Reset on success

				for (const update of updates) {
					this.offset = update.update_id + 1;
					if (update.callback_query) {
						await this.handleCallbackQuery(update.callback_query);
					}
				}

				// Yield to event loop between poll cycles — in production, Telegram's
				// long-poll timeout provides natural rate limiting; this prevents tight
				// loops when the response returns instantly (e.g., in tests)
				await sleep(0);
			} catch (err) {
				if (!this.running) return;
				consecutiveErrors++;
				console.error(
					`[telegram] Poll error (${consecutiveErrors}/${MAX_CONSECUTIVE_ERRORS}): ${err instanceof Error ? err.message : "Unknown"}`,
				);

				// SENTINEL: Finding 4 — stop after N consecutive failures (permanent error assumed)
				if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
					console.error(
						`[telegram] FATAL: ${consecutiveErrors} consecutive poll failures — stopping adapter. Check TELEGRAM vault credentials and network connectivity.`,
					);
					this.running = false;
					return;
				}

				await sleep(POLL_ERROR_DELAY_MS);
			}
		}
	}

	private async handleCallbackQuery(query: CallbackQuery): Promise<void> {
		const chatId = query.message?.chat.id;
		if (chatId !== this.chatId) {
			console.warn(
				`[telegram] SECURITY: callback_query from unauthorized chat ${chatId} (expected ${this.chatId})`,
			);
			// SENTINEL: Finding 7 — answer unauthorized callbacks to prevent Telegram re-delivery
			await this.telegramApi("answerCallbackQuery", {
				callback_query_id: query.id,
				text: "Unauthorized",
				show_alert: true,
			}).catch((answerErr) => {
				console.warn(
					`[telegram] answerCallbackQuery (unauthorized) failed: ${answerErr instanceof Error ? answerErr.message : "Unknown"}`,
				);
			});
			return;
		}

		const data = query.data;
		if (!data?.startsWith("confirm:")) return;

		const parts = data.split(":");
		if (parts.length !== 3) {
			// SENTINEL: Finding 8 — log malformed confirm: callbacks instead of silent drop
			console.warn(`[telegram] Malformed callback data (${parts.length} parts): ${data}`);
			return;
		}

		const manifestId = parts[1];
		const action = parts[2];
		if (action !== "approve" && action !== "reject") {
			console.warn(`[telegram] Unknown action in callback: ${action} (manifestId: ${manifestId})`);
			return;
		}

		const approved = action === "approve";
		const resolved = this.resolveConfirmation(manifestId, approved);

		if (resolved) {
			// SENTINEL: Finding 1 — replace empty catch with logging
			await this.telegramApi("answerCallbackQuery", {
				callback_query_id: query.id,
				text: approved ? "✅ Approved" : "❌ Rejected",
			}).catch((answerErr) => {
				console.warn(
					`[telegram] answerCallbackQuery failed for ${manifestId} (query: ${query.id}): ${answerErr instanceof Error ? answerErr.message : "Unknown"}`,
				);
			});
		} else {
			console.warn(`[telegram] Unknown manifestId in callback: ${manifestId}`);
			await this.telegramApi("answerCallbackQuery", {
				callback_query_id: query.id,
				text: "⚠ Action not found (may have timed out)",
				show_alert: true,
			}).catch((answerErr) => {
				console.warn(
					`[telegram] answerCallbackQuery (alert) failed for ${manifestId} (query: ${query.id}): ${answerErr instanceof Error ? answerErr.message : "Unknown"}`,
				);
			});
		}
	}
}

function formatParamValue(value: unknown): string {
	const raw = typeof value === "string" ? value : JSON.stringify(value);
	// SENTINEL: Credential redaction — defense-in-depth before sending to Telegram
	const redacted = redactAll(raw);
	const truncated =
		redacted.length > PARAM_TRUNCATE_LIMIT
			? `${redacted.slice(0, PARAM_TRUNCATE_LIMIT)}...`
			: redacted;
	return escapeMarkdownV2(truncated);
}

/**
 * Escape special characters for Telegram MarkdownV2 format.
 * See: https://core.telegram.org/bots/api#markdownv2-style
 */
function escapeMarkdownV2(text: string): string {
	return text.replace(/([_*[\]()~`>#+\-=|{}.!\\])/g, "\\$1");
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

// Exported for testing
export { escapeMarkdownV2 as _escapeMarkdownV2, formatParamValue as _formatParamValue };
