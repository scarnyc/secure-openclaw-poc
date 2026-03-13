import { redactAll, redactPII } from "@sentinel/types";
import { type PluginConfig, PluginConfigSchema, loadConfigFromEnv } from "./config.js";
import { ExecutorClient } from "./executor-client.js";
import { HealthMonitor } from "./health-monitor.js";
import { buildManifest, type SessionContext } from "./manifest-bridge.js";

export { type PluginConfig, PluginConfigSchema, loadConfigFromEnv } from "./config.js";
export { ExecutorClient } from "./executor-client.js";
export { HealthMonitor } from "./health-monitor.js";
export { buildManifest, type SessionContext } from "./manifest-bridge.js";

export interface BeforeToolCallResult {
	block: boolean;
	blockReason?: string;
}

export interface ToolCallContext {
	toolName: string;
	params: Record<string, unknown>;
	runId: string;
	session: SessionContext;
}

export interface SentinelPlugin {
	beforeToolCall: (ctx: ToolCallContext) => Promise<BeforeToolCallResult>;
	afterToolCall: (ctx: ToolCallContext, result: unknown) => Promise<void>;
	sanitizeOutput: (output: string) => string;
	stop: () => void;
}

/**
 * Creates a Sentinel plugin for OpenClaw.
 *
 * Registers three hooks:
 * 1. beforeToolCall — classifies via executor, blocks/confirms as needed
 * 2. afterToolCall — posts audit data (informational)
 * 3. sanitizeOutput — redacts credentials and PII before transcript write
 */
export function createSentinelPlugin(
	config?: Partial<PluginConfig>,
): SentinelPlugin {
	const resolved = PluginConfigSchema.parse({
		...loadConfigFromEnv(),
		...config,
	});

	const client = ExecutorClient.fromConfig(resolved);
	const monitor = new HealthMonitor({
		client,
		intervalMs: resolved.healthCheckIntervalMs,
		unhealthyThreshold: 3,
	});
	monitor.start();

	return {
		async beforeToolCall(ctx: ToolCallContext): Promise<BeforeToolCallResult> {
			// Fail-closed: if executor unreachable, block
			if (!monitor.isHealthy()) {
				if (resolved.failMode === "closed") {
					return {
						block: true,
						blockReason: "Sentinel executor unreachable — fail-closed mode",
					};
				}
				// fail-open: allow through (not recommended for production)
				return { block: false };
			}

			try {
				const manifest = buildManifest(
					ctx.toolName,
					ctx.params,
					ctx.runId,
					ctx.session,
				);

				const response = await client.classify(
					manifest.tool,
					manifest.parameters,
					manifest.agentId,
					manifest.sessionId,
				);

				if (response.decision === "block") {
					return { block: true, blockReason: response.reason };
				}

				if (response.decision === "confirm") {
					// Route through executor's confirmation flow
					const result = await client.execute({
						...manifest,
						source: "openclaw",
					});
					if (!result.success) {
						return {
							block: true,
							blockReason: (result.error as string) ?? "Execution denied",
						};
					}
				}

				// auto_approve — allow through
				return { block: false };
			} catch (error) {
				const errMsg = error instanceof Error ? error.message : "Unknown";
				// SENTINEL: Always log classification errors, even in fail-open (HIGH-2 security fix)
				console.error(`[sentinel-plugin] Classification error: ${errMsg}`);
				if (resolved.failMode === "closed") {
					return {
						block: true,
						blockReason: `Sentinel error: ${errMsg}`,
					};
				}
				// Fail-open: allow through but with logged warning
				console.warn(
					`[sentinel-plugin] WARN: fail-open allowing unclassified tool call for ${ctx.toolName}`,
				);
				return { block: false };
			}
		},

		async afterToolCall(_ctx: ToolCallContext, _result: unknown): Promise<void> {
			// No-op: audit is already recorded by the /classify call in beforeToolCall.
			// Previously this called client.classify() again, which double-counted
			// rate limiter and loop guard state. Kept as a hook point for future
			// post-execution audit endpoint.
		},

		sanitizeOutput(output: string): string {
			// Pure functions — no HTTP needed. Used in tool_result_persist hook.
			const afterCreds = redactAll(output);
			return redactPII(afterCreds);
		},

		stop(): void {
			monitor.stop();
		},
	};
}
