import { describe, expect, it, vi } from "vitest";
import type { OpenClawPluginApi } from "../register.js";
import { registerSentinelPlugin } from "../register.js";

function captureHandlers(config?: { executorUrl?: string; connectionTimeoutMs?: number }) {
	const handlers = new Map<string, Function>();
	const api: OpenClawPluginApi = {
		id: "sentinel",
		name: "@sentinel/openclaw-plugin",
		config: {},
		pluginConfig: {
			executorUrl: config?.executorUrl ?? "http://127.0.0.1:1",
			connectionTimeoutMs: config?.connectionTimeoutMs ?? 500,
		},
		runtime: {},
		logger: {
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
		},
		on: vi.fn((hook: string, handler: Function) => {
			handlers.set(hook, handler);
		}),
	} as unknown as OpenClawPluginApi;
	registerSentinelPlugin(api, {
		executorUrl: config?.executorUrl ?? "http://127.0.0.1:1",
		connectionTimeoutMs: config?.connectionTimeoutMs ?? 500,
	});
	return { api, handlers };
}

// Minimal context objects matching OpenClaw's hook context types
const toolCtx = { agentId: "a1", sessionId: "s1", runId: "run-1", toolName: "bash" };
const persistCtx = { agentId: "a1", sessionKey: "sk1" };
const msgCtx = { channelId: "telegram" };
const gwCtx = { port: 8080 };

describe("registerSentinelPlugin", () => {
	it("registers all 4 hooks", () => {
		const { api } = captureHandlers();
		expect(api.on).toHaveBeenCalledTimes(4);
		const hookNames = (api.on as ReturnType<typeof vi.fn>).mock.calls.map(
			(call: unknown[]) => call[0],
		);
		expect(hookNames).toContain("before_tool_call");
		expect(hookNames).toContain("tool_result_persist");
		expect(hookNames).toContain("message_sending");
		expect(hookNames).toContain("gateway_stop");
	});

	it("before_tool_call blocks when executor unreachable in fail-closed mode", async () => {
		const { handlers } = captureHandlers({
			executorUrl: "http://127.0.0.1:1",
			connectionTimeoutMs: 500,
		});
		const beforeToolCall = handlers.get("before_tool_call")!;
		expect(beforeToolCall).toBeDefined();

		const result = await beforeToolCall(
			{ toolName: "bash", params: { command: "ls" }, runId: "run-1" },
			toolCtx,
		);
		expect(result.block).toBe(true);
	});

	it("tool_result_persist sanitizes credentials from message content", () => {
		const { handlers } = captureHandlers();
		const handler = handlers.get("tool_result_persist")!;
		expect(handler).toBeDefined();

		const key = ["sk", "ant", "api03", "abc123def456"].join("-");
		const result = handler({ message: { role: "tool", content: `key: ${key}` } }, persistCtx);
		const msg = result.message as Record<string, unknown>;
		expect(msg.content).not.toContain("sk-ant");
		expect(msg.content).toContain("[REDACTED]");
	});

	it("message_sending sanitizes PII from content", () => {
		const { handlers } = captureHandlers();
		const handler = handlers.get("message_sending")!;
		expect(handler).toBeDefined();

		const result = handler({ to: "user", content: "SSN: 123-45-6789" }, msgCtx);
		expect(result.content).not.toContain("123-45-6789");
	});

	it("gateway_stop calls stop without error", () => {
		const { handlers } = captureHandlers();
		const handler = handlers.get("gateway_stop")!;
		expect(handler).toBeDefined();

		expect(() => handler({ reason: "shutdown" }, gwCtx)).not.toThrow();
	});
});
