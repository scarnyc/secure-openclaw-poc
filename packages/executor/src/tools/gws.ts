import type { CredentialVault } from "@sentinel/crypto";
import { GWS_READ_PATTERNS, type GwsAgentScopes, type ToolResult } from "@sentinel/types";
import { execa } from "execa";
import { moderateEmail } from "../moderation/email-scanner.js";
import { truncateBashOutput } from "../output-truncation.js";
import { getGwsAccessToken } from "./gws-auth.js";

const STRIPPED_ENV_PREFIXES = ["SENTINEL_", "ANTHROPIC_", "OPENAI_", "GEMINI_"];
const STRIPPED_ENV_KEYS = new Set([
	"MOLTBOT_GATEWAY_TOKEN",
	"CF_ACCESS_AUD",
	"R2_ACCESS_KEY_ID",
	"R2_SECRET_ACCESS_KEY",
	"CF_ACCOUNT_ID",
]);

function stripSensitiveEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
	const cleaned: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(env)) {
		if (STRIPPED_ENV_KEYS.has(key)) continue;
		if (STRIPPED_ENV_PREFIXES.some((p) => key.startsWith(p))) continue;
		cleaned[key] = value;
	}
	return cleaned;
}

export interface GwsParams {
	service: string;
	method: string;
	args?: Record<string, unknown>;
	sanitize?: boolean;
}

export type { GwsAgentScopes } from "@sentinel/types";

export interface ExecuteGwsContext {
	agentId?: string;
	scopes?: GwsAgentScopes;
	vault?: CredentialVault;
}

export async function executeGws(
	params: GwsParams,
	manifestId: string,
	ctx?: ExecuteGwsContext,
): Promise<ToolResult> {
	const start = Date.now();

	// SENTINEL: Per-agent scope restriction (G4)
	if (ctx?.agentId && ctx?.scopes?.[ctx.agentId]) {
		const agentScope = ctx.scopes[ctx.agentId];
		if (agentScope.denyServices?.includes(params.service)) {
			return {
				manifestId,
				success: false,
				error: `Agent not authorized for service: ${params.service}`,
				duration_ms: Date.now() - start,
			};
		}
		if (agentScope.allowedServices && !agentScope.allowedServices.includes(params.service)) {
			return {
				manifestId,
				success: false,
				error: `Agent not authorized for service: ${params.service}`,
				duration_ms: Date.now() - start,
			};
		}
	}

	const cliArgs = [params.service, params.method];

	if (params.args && Object.keys(params.args).length > 0) {
		cliArgs.push("--json", JSON.stringify(params.args));
	}

	if (params.sanitize) {
		cliArgs.push("--sanitize");
	}

	try {
		const env = stripSensitiveEnv(process.env);
		if (ctx?.vault) {
			try {
				const token = await getGwsAccessToken(ctx.vault);
				env.GOOGLE_WORKSPACE_CLI_TOKEN = token;
			} catch (error) {
				const msg = error instanceof Error ? error.message : "Unknown";
				console.error(`[gws] Vault token injection failed: ${msg}`);
				if (process.env.SENTINEL_DOCKER === "true") {
					return {
						manifestId,
						success: false,
						error: "GWS authentication failed — vault token refresh error",
						duration_ms: Date.now() - start,
					};
				}
				console.warn("[gws] Falling back to keyring auth (local dev only)");
			}
		}

		const result = await execa("gws", cliArgs, {
			timeout: 30_000,
			killSignal: "SIGKILL",
			env,
			extendEnv: false,
			reject: false,
		});
		delete env.GOOGLE_WORKSPACE_CLI_TOKEN;

		if (result.exitCode !== 0) {
			// Never include raw stderr — may contain credentials
			return {
				manifestId,
				success: false,
				error: `gws exited with code ${result.exitCode}`,
				duration_ms: Date.now() - start,
			};
		}

		let output = result.stdout;

		// Email scanning: scan FULL output before truncation (inbound email is untrusted).
		// Scanning after truncation would let payloads at the boundary bypass detection.
		if (output && params.service === "gmail" && GWS_READ_PATTERNS.test(params.method)) {
			const emailModeration = moderateEmail(output);
			if (emailModeration.blocked && emailModeration.sanitizedOutput) {
				output = emailModeration.sanitizedOutput;
			}
		}

		// Truncate after scanning to bound output size for the agent
		const truncatedOutput = output ? truncateBashOutput(output) : undefined;

		return {
			manifestId,
			success: true,
			output: truncatedOutput,
			duration_ms: Date.now() - start,
		};
	} catch (error) {
		// Handle missing binary gracefully
		if (
			error instanceof Error &&
			"code" in error &&
			(error as NodeJS.ErrnoException).code === "ENOENT"
		) {
			return {
				manifestId,
				success: false,
				error: "gws CLI not found — install @googleworkspace/cli",
				duration_ms: Date.now() - start,
			};
		}

		// Never include raw error.message — may contain credentials or tokens
		return {
			manifestId,
			success: false,
			error: "gws execution failed",
			duration_ms: Date.now() - start,
		};
	}
}
