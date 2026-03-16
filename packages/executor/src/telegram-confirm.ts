import type { CredentialVault } from "@sentinel/crypto";
import { redactAll } from "@sentinel/types";
import type { TelegramInterceptor } from "./egress-proxy.js";

const PARAM_TRUNCATE_LIMIT = 200;

export interface TelegramConfirmRequest {
	manifestId: string;
	tool: string;
	parameters: Record<string, unknown>;
	category: string;
	reason: string;
	confirmUrl?: string;
}

export class TelegramConfirmAdapter {
	private readonly vault: CredentialVault;
	public readonly chatId: number;
	private readonly confirmBaseUrl: string;

	constructor(vault: CredentialVault, chatId: string, confirmBaseUrl: string) {
		const parsed = Number.parseInt(chatId, 10);
		if (Number.isNaN(parsed)) {
			throw new Error(`Invalid SENTINEL_TELEGRAM_CHAT_ID: "${chatId}" is not a number`);
		}
		this.vault = vault;
		this.chatId = parsed;
		this.confirmBaseUrl = confirmBaseUrl;
	}

	/**
	 * Create a TelegramInterceptor for the egress proxy.
	 * Encapsulates chat ID authorization and callback acknowledgement.
	 * Used in Docker deployment where OpenClaw routes through /proxy/egress.
	 */
	toInterceptor(
		resolveConfirmation: (
			id: string,
			approved: boolean,
			source?: "web" | "api" | "telegram",
		) => boolean,
	): TelegramInterceptor {
		return {
			isAuthorizedChat: (id: number) => id === this.chatId,
			resolveConfirmation,
			acknowledgeCallback: (queryId: string, text: string, showAlert: boolean) =>
				this.telegramApi("answerCallbackQuery", {
					callback_query_id: queryId,
					text,
					show_alert: showAlert,
				}).then(() => {}),
		};
	}

	async sendConfirmation(req: TelegramConfirmRequest): Promise<number | undefined> {
		const text = this.formatMessage(req);

		const result = (await this.telegramApi("sendMessage", {
			chat_id: this.chatId,
			text,
			parse_mode: "MarkdownV2",
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

		lines.push("");
		const linkUrl = req.confirmUrl ?? `${this.confirmBaseUrl}/confirm-ui/${req.manifestId}`;
		lines.push(escapeMarkdownV2(`Review & approve: ${linkUrl}`));
		lines.push("━━━━━━━━━━━━━━━━━━━━━");
		return lines.join("\n");
	}

	private appendStandardParams(lines: string[], params: Record<string, unknown>): void {
		for (const [key, value] of Object.entries(params)) {
			lines.push(`  ${escapeMarkdownV2(key)}: ${formatParamValue(value)}`);
		}
	}

	async telegramApi(method: string, body: object): Promise<unknown> {
		const { useCredential } = await import("@sentinel/crypto");
		return useCredential(this.vault, "telegram_bot", ["key"] as const, async (cred) => {
			const res = await fetch(`https://api.telegram.org/bot${cred.key}/${method}`, {
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

// Exported for testing
export { escapeMarkdownV2 as _escapeMarkdownV2, formatParamValue as _formatParamValue };
