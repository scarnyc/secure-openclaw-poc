import { describe, expect, it, vi } from "vitest";
import type { OpenClawPluginApi } from "../register.js";
import { registerSentinelPlugin } from "../register.js";

function captureHandlers(config?: { executorUrl?: string; connectionTimeoutMs?: number }) {
	const handlers = new Map<string, Function>();
	const api: OpenClawPluginApi = {
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

		const result = await beforeToolCall({
			tool: "bash",
			params: { command: "ls" },
			runId: "run-1",
			session: { sessionId: "s1", agentId: "a1" },
		});
		expect(result.block).toBe(true);
	});

	it("tool_result_persist sanitizes credentials from output", () => {
		const { handlers } = captureHandlers();
		const handler = handlers.get("tool_result_persist")!;
		expect(handler).toBeDefined();

		const key = ["sk", "ant", "api03", "abc123def456"].join("-");
		const result = handler({ tool: "test", result: `key: ${key}` });
		expect(result.result).not.toContain("sk-ant");
		expect(result.result).toContain("[REDACTED]");
	});

	it("message_sending sanitizes PII from content", () => {
		const { handlers } = captureHandlers();
		const handler = handlers.get("message_sending")!;
		expect(handler).toBeDefined();

		const result = handler({ content: "SSN: 123-45-6789" });
		expect(result.content).not.toContain("123-45-6789");
	});

	it("gateway_stop calls stop without error", () => {
		const { handlers } = captureHandlers();
		const handler = handlers.get("gateway_stop")!;
		expect(handler).toBeDefined();

		// Should not throw
		expect(() => handler()).not.toThrow();
	});
});
