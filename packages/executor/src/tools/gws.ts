import type { CredentialVault } from "@sentinel/crypto";
import {
	containsCredential,
	GMAIL_SEND_PATTERNS,
	GWS_READ_PATTERNS,
	type GwsAgentScopes,
	type ToolResult,
} from "@sentinel/types";
import { execa } from "execa";
import { moderateEmail, scanOutboundEmail } from "../moderation/email-scanner.js";
import { getModerationMode } from "../moderation/scanner.js";
import { truncateBashOutput } from "../output-truncation.js";
import { getGwsAccessToken } from "./gws-auth.js";
import { validateGwsSendArgs } from "./gws-validation.js";

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

	if (params.args) {
		const validation = validateGwsSendArgs(params.service, params.method, params.args);
		if (!validation.valid) {
			return {
				manifestId,
				success: false,
				error: `GWS parameter validation failed: ${validation.errors.join("; ")}`,
				duration_ms: Date.now() - start,
			};
		}
	}

	// SENTINEL: Credential leakage check — block emails containing API keys/tokens/[REDACTED] markers
	if (params.args && params.service === "gmail" && GMAIL_SEND_PATTERNS.test(params.method)) {
		GMAIL_SEND_PATTERNS.lastIndex = 0;
		const mode = getModerationMode();
		if (mode !== "off") {
			const subject = typeof params.args.subject === "string" ? params.args.subject : "";
			const body = typeof params.args.body === "string" ? params.args.body : "";
			const emailText = `${subject}\n${body}`;
			const hasRedacted = /\[REDACTED\]|\[PII_REDACTED\]/.test(emailText);

			if (containsCredential(emailText) || hasRedacted) {
				if (mode === "enforce") {
					return {
						manifestId,
						success: false,
						error: "Outbound email blocked: credential pattern detected in email content",
						duration_ms: Date.now() - start,
					};
				}
				console.warn("[gws:outbound-cred] Credential pattern detected in outbound email");
			}
		}
	}

	// Outbound email scanning: check subject/body for injection patterns before send
	if (params.args && params.service === "gmail" && GMAIL_SEND_PATTERNS.test(params.method)) {
		GMAIL_SEND_PATTERNS.lastIndex = 0;
		const mode = getModerationMode();
		if (mode !== "off") {
			const scanResult = scanOutboundEmail(params.args);
			if (scanResult.flagged) {
				if (mode === "enforce") {
					return {
						manifestId,
						success: false,
						error: `Outbound email blocked: ${scanResult.reason}`,
						duration_ms: Date.now() - start,
					};
				}
				// warn mode: log but proceed
				console.warn(`[gws:outbound-scan] ${scanResult.reason}`);
			}
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
			} catch (_error) {
				// Never log error.message — may contain OAuth tokens or account identifiers
				console.error("[gws] Vault token injection failed");
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

		let exitCode: number | undefined;
		let stdout: string;
		try {
			const result = await execa("gws", cliArgs, {
				timeout: 30_000,
				killSignal: "SIGKILL",
				env,
				extendEnv: false,
				reject: false,
			});
			exitCode = result.exitCode;
			stdout = result.stdout as string;
		} finally {
			// SENTINEL: Always clean token from env, even on error (LOW-15)
			delete env.GOOGLE_WORKSPACE_CLI_TOKEN;
		}

		if (exitCode !== 0) {
			// Never include raw stderr — may contain credentials
			return {
				manifestId,
				success: false,
				error: `gws exited with code ${exitCode}`,
				duration_ms: Date.now() - start,
			};
		}

		let output = stdout;

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
