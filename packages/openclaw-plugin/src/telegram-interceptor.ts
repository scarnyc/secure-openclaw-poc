/**
 * Telegram getUpdates interceptor for OpenClaw host deployments.
 *
 * Problem: Both OpenClaw and Sentinel executor poll Telegram getUpdates on the
 * same bot token, causing 409 Conflict errors. Solution: OpenClaw is the sole
 * poller; this module monkey-patches globalThis.fetch to intercept confirmation
 * callback_queries from getUpdates responses and forward them to executor's
 * POST /confirm/{manifestId} endpoint.
 */

const TELEGRAM_GET_UPDATES_PATTERN = /api\.telegram\.org\/bot([^/]+)\/getUpdates/;
const CONFIRM_DATA_PATTERN = /^confirm:(.+):(approve|reject)$/;

export interface TelegramInterceptorConfig {
	/** Executor base URL, e.g. "http://localhost:3141" or "http://executor:3141" */
	executorUrl: string;
	/** Sentinel auth token for executor API */
	authToken: string;
	/** Optional logger — defaults to console.log */
	logger?: (msg: string) => void;
}

/**
 * Install a fetch interceptor that captures Telegram confirmation callbacks
 * from getUpdates responses and forwards them to the Sentinel executor.
 *
 * @returns A cleanup function that restores the original globalThis.fetch.
 */
export function installTelegramInterceptor(config: TelegramInterceptorConfig): () => void {
	const { executorUrl, authToken, logger = console.log } = config;
	const baseUrl = executorUrl.replace(/\/+$/, "");
	const originalFetch = globalThis.fetch;

	const interceptingFetch: typeof globalThis.fetch = async (input, init) => {
		const url =
			typeof input === "string"
				? input
				: input instanceof URL
					? input.toString()
					: (input as Request).url;

		const match = TELEGRAM_GET_UPDATES_PATTERN.exec(url);
		if (!match) {
			return originalFetch(input, init);
		}

		const botToken = match[1];
		const response = await originalFetch(input, init);

		// Don't intercept error responses
		if (!response.ok) {
			return response;
		}

		// Parse the response body
		let body: { ok: boolean; result: TelegramUpdate[] };
		try {
			body = (await response.json()) as { ok: boolean; result: TelegramUpdate[] };
		} catch {
			// JSON parse failed — return a synthetic empty response
			logger("[telegram-interceptor] Failed to parse getUpdates JSON — passing through");
			return new Response(JSON.stringify({ ok: true, result: [] }), {
				status: response.status,
				statusText: response.statusText,
				headers: response.headers,
			});
		}

		if (!body.ok || !Array.isArray(body.result)) {
			// Telegram error response — return reconstructed
			return new Response(JSON.stringify(body), {
				status: response.status,
				statusText: response.statusText,
				headers: response.headers,
			});
		}

		const passThrough: TelegramUpdate[] = [];

		for (const update of body.result) {
			const callbackData = update.callback_query?.data;
			if (!callbackData) {
				passThrough.push(update);
				continue;
			}

			const confirmMatch = CONFIRM_DATA_PATTERN.exec(callbackData);
			if (!confirmMatch) {
				passThrough.push(update);
				continue;
			}

			const manifestId = confirmMatch[1];
			const action = confirmMatch[2] as "approve" | "reject";
			const approved = action === "approve";
			const callbackQueryId = update.callback_query?.id;

			logger(
				`[telegram-interceptor] Intercepted confirmation: manifestId=${manifestId} action=${action}`,
			);

			// Fire-and-forget: forward to executor
			originalFetch(`${baseUrl}/confirm/${manifestId}`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Authorization: `Bearer ${authToken}`,
				},
				body: JSON.stringify({ approved }),
			}).catch((err: unknown) => {
				const msg = err instanceof Error ? err.message : "Unknown";
				logger(`[telegram-interceptor] Failed to forward confirmation ${manifestId}: ${msg}`);
			});

			// Fire-and-forget: answer the callback query so Telegram stops showing the spinner
			originalFetch(`https://api.telegram.org/bot${botToken}/answerCallbackQuery`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					callback_query_id: callbackQueryId,
					text: approved ? "Approved" : "Rejected",
				}),
			}).catch((err: unknown) => {
				const msg = err instanceof Error ? err.message : "Unknown";
				logger(`[telegram-interceptor] Failed to answer callback query: ${msg}`);
			});
		}

		// Return modified response with intercepted callbacks removed
		const modifiedBody = { ...body, result: passThrough };
		return new Response(JSON.stringify(modifiedBody), {
			status: response.status,
			statusText: response.statusText,
			headers: response.headers,
		});
	};

	globalThis.fetch = interceptingFetch;

	// Return cleanup function
	return () => {
		globalThis.fetch = originalFetch;
	};
}

// Internal types matching Telegram's getUpdates response structure
interface CallbackQuery {
	id: string;
	data?: string;
	from?: { id: number };
	message?: { chat?: { id: number } };
}

interface TelegramUpdate {
	update_id: number;
	callback_query?: CallbackQuery;
	message?: unknown;
}
