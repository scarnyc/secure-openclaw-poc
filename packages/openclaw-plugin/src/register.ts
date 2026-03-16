import type { PluginConfig } from "./config.js";
import { installFetchInterceptor } from "./fetch-interceptor.js";
import { createSentinelPlugin } from "./index.js";
import { installTelegramInterceptor } from "./telegram-interceptor.js";

// ---------------------------------------------------------------------------
// OpenClaw Plugin SDK types — aligned with openclaw/dist/plugin-sdk/plugins/types.d.ts
// Defined locally because OpenClaw SDK is not a build dependency.
// ---------------------------------------------------------------------------

/** Event for before_tool_call hook (2nd arg is PluginHookToolContext). */
export interface PluginHookBeforeToolCallEvent {
	toolName: string;
	params: Record<string, unknown>;
	runId?: string;
	toolCallId?: string;
}

/** Context passed as 2nd arg to before_tool_call hook. */
export interface PluginHookToolContext {
	agentId?: string;
	sessionKey?: string;
	sessionId?: string;
	runId?: string;
	toolName: string;
	toolCallId?: string;
}

export interface PluginHookBeforeToolCallResult {
	params?: Record<string, unknown>;
	block?: boolean;
	blockReason?: string;
}

/** Event for tool_result_persist hook. */
export interface PluginHookToolResultPersistEvent {
	toolName?: string;
	toolCallId?: string;
	message: unknown; // AgentMessage — opaque to us
	isSynthetic?: boolean;
}

export interface PluginHookToolResultPersistContext {
	agentId?: string;
	sessionKey?: string;
	toolName?: string;
	toolCallId?: string;
}

export interface PluginHookToolResultPersistResult {
	message?: unknown;
}

/** Event for message_sending hook. */
export interface PluginHookMessageSendingEvent {
	to: string;
	content: string;
	metadata?: Record<string, unknown>;
}

export interface PluginHookMessageContext {
	channelId: string;
	accountId?: string;
	conversationId?: string;
}

export interface PluginHookMessageSendingResult {
	content?: string;
	cancel?: boolean;
}

/** Event for gateway_stop hook. */
export interface PluginHookGatewayStopEvent {
	reason?: string;
}

export interface PluginHookGatewayContext {
	port?: number;
}

/** Plugin runtime — subset of what OpenClaw provides. */
export interface PluginRuntime {
	workspaceDir?: string;
	agentDir?: string;
}

/** Logger interface matching OpenClaw's PluginLogger. */
export interface PluginLogger {
	debug?: (message: string) => void;
	info: (message: string) => void;
	warn: (message: string) => void;
	error: (message: string) => void;
}

/**
 * OpenClaw Plugin API — matches openclaw/dist/plugin-sdk/plugins/types.d.ts.
 * Only the methods we use are typed; the full API has many more.
 */
export interface OpenClawPluginApi {
	id: string;
	name: string;
	config: unknown;
	pluginConfig?: Record<string, unknown>;
	runtime: PluginRuntime;
	logger: PluginLogger;
	// biome-ignore lint/suspicious/noExplicitAny: OpenClaw's real API uses typed overloads per hook; we use any to avoid duplicating all 24 hook signatures
	on(hookName: string, handler: (...args: any[]) => any, opts?: { priority?: number }): void;
}

/**
 * OpenClaw Plugin Definition — the module's default export.
 * OpenClaw calls `register(api)` or `activate(api)` to initialize the plugin.
 */
export interface OpenClawPluginDefinition {
	id?: string;
	name?: string;
	description?: string;
	version?: string;
	register?: (api: OpenClawPluginApi) => void | Promise<void>;
	activate?: (api: OpenClawPluginApi) => void | Promise<void>;
}

// ---------------------------------------------------------------------------
// Plugin Definition — default export for OpenClaw's plugin loader
// ---------------------------------------------------------------------------

/**
 * Sentinel plugin for OpenClaw.
 *
 * Exported as the module's default export so OpenClaw's plugin loader
 * can discover and initialize it. Uses `register(api)` lifecycle hook.
 *
 * Hooks registered:
 * - `before_tool_call` → classifies tool calls via Sentinel executor
 * - `tool_result_persist` → redacts credentials/PII from persisted results
 * - `message_sending` → redacts credentials/PII from outbound messages
 * - `gateway_stop` → cleans up health monitor
 */
const sentinelPlugin: OpenClawPluginDefinition = {
	id: "sentinel",
	name: "@sentinel/openclaw-plugin",
	description:
		"Sentinel security runtime — classification, confirmation, credential isolation, and audit",
	version: "0.1.0",

	register(api: OpenClawPluginApi): void {
		const pluginConfig = api.pluginConfig as Partial<PluginConfig> | undefined;
		const plugin = createSentinelPlugin(pluginConfig);

		// Install appropriate fetch/proxy interceptor based on deployment mode
		let cleanupInterceptor: (() => void) | undefined;
		if (pluginConfig?.executorUrl && pluginConfig?.authToken) {
			if (process.env.SENTINEL_DOCKER) {
				// Docker mode: primary egress goes through executor's CONNECT proxy
				// (HTTPS_PROXY env var set in docker-entrypoint.sh). The fetch interceptor
				// is kept as a fallback for libraries using globalThis.fetch.
				const egressDomains = (process.env.SENTINEL_EGRESS_DOMAINS ?? "")
					.split(",")
					.filter(Boolean);
				cleanupInterceptor = installFetchInterceptor({
					executorUrl: pluginConfig.executorUrl,
					authToken: pluginConfig.authToken,
					egressDomains,
					agentId: "openclaw-gateway",
					logger: (msg) => api.logger.info(`[sentinel] ${msg}`),
				});
				// Also install Telegram interceptor for confirmation forwarding.
				// The CONNECT tunnel is opaque, so confirmation callbacks need to be
				// caught and forwarded to executor when they come through getUpdates.
				const telegramCleanup = installTelegramInterceptor({
					executorUrl: pluginConfig.executorUrl,
					authToken: pluginConfig.authToken,
					logger: (msg) => api.logger.info(`[sentinel] ${msg}`),
				});
				const originalCleanup = cleanupInterceptor;
				cleanupInterceptor = () => {
					telegramCleanup();
					originalCleanup();
				};
				api.logger.info(
					`[sentinel] Docker mode: CONNECT proxy + fetch interceptor (${egressDomains.length} domains) + Telegram forwarder`,
				);
			} else {
				// Host mode: only intercept Telegram getUpdates for confirmation forwarding
				cleanupInterceptor = installTelegramInterceptor({
					executorUrl: pluginConfig.executorUrl,
					authToken: pluginConfig.authToken,
					logger: (msg) => api.logger.info(`[sentinel] ${msg}`),
				});
				api.logger.info("[sentinel] Telegram interceptor installed (host mode)");
			}
		}

		// SENTINEL: Best-effort callback_query hook registration for confirmations.
		// If OpenClaw fires a hook for Telegram callback queries, we catch confirmation
		// callbacks directly (more reliable than fetch interception for node-fetch users).
		if (pluginConfig?.executorUrl && pluginConfig?.authToken) {
			const baseUrl = pluginConfig.executorUrl.replace(/\/+$/, "");
			const token = pluginConfig.authToken;
			const confirmRe = /^confirm:(.+):(approve|reject)$/;

			const forwardConfirmation = (callbackData: string): void => {
				const match = confirmRe.exec(callbackData);
				if (!match) return;
				const manifestId = match[1];
				const approved = match[2] === "approve";
				api.logger.info(
					`[sentinel] Forwarding confirmation: manifestId=${manifestId} approved=${approved}`,
				);
				fetch(`${baseUrl}/confirm/${manifestId}`, {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
						Authorization: `Bearer ${token}`,
					},
					body: JSON.stringify({ approved }),
				}).catch((err: unknown) => {
					api.logger.error(
						`[sentinel] Confirmation forward failed: ${err instanceof Error ? err.message : "Unknown"}`,
					);
				});
			};

			// Try known hook names that might fire for Telegram callback queries
			for (const hookName of ["callback_query", "telegram_callback_query", "update_received"]) {
				try {
					api.on(hookName, (event: Record<string, unknown>) => {
						const cbq = event.callback_query as Record<string, unknown> | undefined;
						const data = cbq?.data ?? event.data ?? event.callbackData;
						if (typeof data === "string" && data.startsWith("confirm:")) {
							forwardConfirmation(data);
						}
					});
				} catch {
					// Hook name not supported — silently skip
				}
			}
		}

		api.logger.info("[sentinel] Registering security hooks...");

		// before_tool_call — classify and optionally block tool calls
		api.on(
			"before_tool_call",
			async (
				event: PluginHookBeforeToolCallEvent,
				ctx: PluginHookToolContext,
			): Promise<PluginHookBeforeToolCallResult> => {
				const result = await plugin.beforeToolCall({
					toolName: event.toolName,
					params: event.params,
					runId: ctx.runId ?? event.runId ?? "unknown",
					session: {
						sessionId: ctx.sessionId ?? "unknown",
						agentId: ctx.agentId,
					},
				});
				return result;
			},
		);

		// tool_result_persist — sanitize tool results before they're written to transcript
		api.on(
			"tool_result_persist",
			(
				event: PluginHookToolResultPersistEvent,
				_ctx: PluginHookToolResultPersistContext,
			): PluginHookToolResultPersistResult => {
				// AgentMessage has a content field — sanitize text content if present
				const msg = event.message as Record<string, unknown> | undefined;
				if (msg && typeof msg.content === "string") {
					return {
						message: { ...msg, content: plugin.sanitizeOutput(msg.content) },
					};
				}
				// If content is an array of blocks, sanitize text blocks
				if (msg && Array.isArray(msg.content)) {
					const sanitized = (msg.content as Array<Record<string, unknown>>).map((block) => {
						if (block.type === "text" && typeof block.text === "string") {
							return { ...block, text: plugin.sanitizeOutput(block.text) };
						}
						return block;
					});
					return { message: { ...msg, content: sanitized } };
				}
				return {};
			},
		);

		// message_sending — sanitize outbound messages
		api.on(
			"message_sending",
			(
				event: PluginHookMessageSendingEvent,
				_ctx: PluginHookMessageContext,
			): PluginHookMessageSendingResult => {
				return { content: plugin.sanitizeOutput(event.content) };
			},
		);

		// gateway_stop — cleanup
		api.on(
			"gateway_stop",
			(_event: PluginHookGatewayStopEvent, _ctx: PluginHookGatewayContext): void => {
				cleanupInterceptor?.();
				plugin.stop();
				api.logger.info("[sentinel] Plugin stopped");
			},
		);

		api.logger.info(
			"[sentinel] Security hooks registered (before_tool_call, tool_result_persist, message_sending, gateway_stop)",
		);
	},
};

export default sentinelPlugin;

/**
 * Named export for programmatic use (e.g., tests).
 * For OpenClaw plugin loading, the default export is used.
 */
export function registerSentinelPlugin(
	api: OpenClawPluginApi,
	config?: Partial<PluginConfig>,
): void {
	const pluginConfig = config ?? (api.pluginConfig as Partial<PluginConfig> | undefined);
	const plugin = createSentinelPlugin(pluginConfig);

	// Install appropriate fetch/proxy interceptor based on deployment mode
	let cleanupInterceptor: (() => void) | undefined;
	if (pluginConfig?.executorUrl && pluginConfig?.authToken) {
		if (process.env.SENTINEL_DOCKER) {
			// Docker mode: CONNECT proxy (HTTPS_PROXY) + fetch interceptor fallback
			const egressDomains = (process.env.SENTINEL_EGRESS_DOMAINS ?? "").split(",").filter(Boolean);
			cleanupInterceptor = installFetchInterceptor({
				executorUrl: pluginConfig.executorUrl,
				authToken: pluginConfig.authToken,
				egressDomains,
				agentId: "openclaw-gateway",
				logger: (msg) => api.logger.info(`[sentinel] ${msg}`),
			});
			const telegramCleanup = installTelegramInterceptor({
				executorUrl: pluginConfig.executorUrl,
				authToken: pluginConfig.authToken,
				logger: (msg) => api.logger.info(`[sentinel] ${msg}`),
			});
			const originalCleanup = cleanupInterceptor;
			cleanupInterceptor = () => {
				telegramCleanup();
				originalCleanup();
			};
		} else {
			// Host mode: only intercept Telegram getUpdates for confirmation forwarding
			cleanupInterceptor = installTelegramInterceptor({
				executorUrl: pluginConfig.executorUrl,
				authToken: pluginConfig.authToken,
				logger: (msg) => api.logger.info(`[sentinel] ${msg}`),
			});
		}
	}

	api.on(
		"before_tool_call",
		async (
			event: PluginHookBeforeToolCallEvent,
			ctx: PluginHookToolContext,
		): Promise<PluginHookBeforeToolCallResult> => {
			return plugin.beforeToolCall({
				toolName: event.toolName,
				params: event.params,
				runId: ctx.runId ?? event.runId ?? "unknown",
				session: {
					sessionId: ctx.sessionId ?? "unknown",
					agentId: ctx.agentId,
				},
			});
		},
	);

	api.on(
		"tool_result_persist",
		(
			event: PluginHookToolResultPersistEvent,
			_ctx: PluginHookToolResultPersistContext,
		): PluginHookToolResultPersistResult => {
			const msg = event.message as Record<string, unknown> | undefined;
			if (msg && typeof msg.content === "string") {
				return { message: { ...msg, content: plugin.sanitizeOutput(msg.content) } };
			}
			if (msg && Array.isArray(msg.content)) {
				const sanitized = (msg.content as Array<Record<string, unknown>>).map((block) => {
					if (block.type === "text" && typeof block.text === "string") {
						return { ...block, text: plugin.sanitizeOutput(block.text) };
					}
					return block;
				});
				return { message: { ...msg, content: sanitized } };
			}
			return {};
		},
	);

	api.on(
		"message_sending",
		(
			event: PluginHookMessageSendingEvent,
			_ctx: PluginHookMessageContext,
		): PluginHookMessageSendingResult => {
			return { content: plugin.sanitizeOutput(event.content) };
		},
	);

	api.on(
		"gateway_stop",
		(_event: PluginHookGatewayStopEvent, _ctx: PluginHookGatewayContext): void => {
			cleanupInterceptor?.();
			plugin.stop();
		},
	);
}
