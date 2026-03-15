import type { PluginConfig } from "./config.js";
import { createSentinelPlugin } from "./index.js";

// ---------------------------------------------------------------------------
// OpenClaw Plugin API types (locally defined — OpenClaw SDK is not a dependency)
// ---------------------------------------------------------------------------

export interface OpenClawBeforeToolCallEvent {
	tool: string;
	params: Record<string, unknown>;
	runId: string;
	session: { sessionId: string; agentId?: string };
}

export interface OpenClawBeforeToolCallResult {
	block: boolean;
	blockReason?: string;
}

export interface OpenClawToolResultPersistEvent {
	tool: string;
	result: string;
}

export interface OpenClawToolResultPersistResult {
	result: string;
}

export interface OpenClawMessageSendingEvent {
	content: string;
}

export interface OpenClawMessageSendingResult {
	content: string;
}

type HookHandler<TEvent, TResult> = (event: TEvent) => TResult | Promise<TResult>;

export interface OpenClawPluginApi {
	on(
		hook: "before_tool_call",
		handler: HookHandler<OpenClawBeforeToolCallEvent, OpenClawBeforeToolCallResult>,
	): void;
	on(
		hook: "tool_result_persist",
		handler: HookHandler<OpenClawToolResultPersistEvent, OpenClawToolResultPersistResult>,
	): void;
	on(
		hook: "message_sending",
		handler: HookHandler<OpenClawMessageSendingEvent, OpenClawMessageSendingResult>,
	): void;
	on(hook: "gateway_stop", handler: () => void): void;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * Registers Sentinel security hooks with OpenClaw's plugin API.
 *
 * Bridges `createSentinelPlugin()` methods to OpenClaw's `api.on()` hooks:
 * - `before_tool_call` → `plugin.beforeToolCall()`
 * - `tool_result_persist` → `plugin.sanitizeOutput()`
 * - `message_sending` → `plugin.sanitizeOutput()`
 * - `gateway_stop` → `plugin.stop()`
 */
export function registerSentinelPlugin(
	api: OpenClawPluginApi,
	config?: Partial<PluginConfig>,
): void {
	const plugin = createSentinelPlugin(config);

	api.on("before_tool_call", async (event) => {
		return plugin.beforeToolCall({
			toolName: event.tool,
			params: event.params,
			runId: event.runId,
			session: {
				sessionId: event.session.sessionId,
				agentId: event.session.agentId,
			},
		});
	});

	api.on("tool_result_persist", (event) => {
		return { result: plugin.sanitizeOutput(event.result) };
	});

	api.on("message_sending", (event) => {
		return { content: plugin.sanitizeOutput(event.content) };
	});

	api.on("gateway_stop", () => {
		plugin.stop();
	});
}
