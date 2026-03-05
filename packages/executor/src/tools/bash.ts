import type { ToolResult } from "@sentinel/types";
import { execaCommand } from "execa";

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 300_000;

// File-reading commands that could exfiltrate sensitive data
const FILE_READ_CMDS = String.raw`\b(cat|head|tail|less|more|tac|nl|od|xxd|hexdump|base64|strings)\b`;
const SENSITIVE_FILE = String.raw`\.(env|pem|key)\b`;
const DENIED_FILE_PATTERNS = [
	new RegExp(`${FILE_READ_CMDS}.*${SENSITIVE_FILE}`),
	new RegExp(`${FILE_READ_CMDS}.*\\.dev\\.vars\\b`),
	new RegExp(`${FILE_READ_CMDS}.*\\.git/(config|credentials)\\b`),
	new RegExp(`${FILE_READ_CMDS}.*secret`, "i"),
	new RegExp(`${FILE_READ_CMDS}.*credential`, "i"),
	new RegExp(`${FILE_READ_CMDS}.*vault\\.enc\\b`),
	// Block cp/mv of sensitive files
	/\b(cp|mv)\b.*\.(env|pem|key)\b/,
	/\b(cp|mv)\b.*\.dev\.vars\b/,
	/\b(cp|mv)\b.*vault\.enc\b/,
	// Block curl/wget file exfiltration of sensitive files
	/\bcurl\b.*@.*\.(env|pem|key)\b/,
	/\bcurl\b.*-d\b.*\.(env|pem|key)\b/,
];

function isDeniedBashCommand(command: string): string | null {
	for (const pattern of DENIED_FILE_PATTERNS) {
		if (pattern.test(command)) {
			return "Command attempts to read a denied file";
		}
	}
	return null;
}

const STRIPPED_ENV_PREFIXES = ["SENTINEL_", "ANTHROPIC_", "OPENAI_"];
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

interface BashParams {
	command: string;
	cwd?: string;
	timeout?: number;
}

export async function executeBash(params: BashParams, manifestId: string): Promise<ToolResult> {
	const start = Date.now();

	const denyReason = isDeniedBashCommand(params.command);
	if (denyReason) {
		return {
			manifestId,
			success: false,
			error: denyReason,
			duration_ms: Date.now() - start,
		};
	}

	const timeout = Math.min(Math.max(params.timeout ?? DEFAULT_TIMEOUT_MS, 1), MAX_TIMEOUT_MS);

	try {
		const result = await execaCommand(params.command, {
			cwd: params.cwd ?? process.cwd(),
			timeout,
			killSignal: "SIGKILL",
			env: stripSensitiveEnv(process.env),
			reject: false,
			shell: true,
		});

		const output = [result.stdout, result.stderr].filter(Boolean).join("\n");

		return {
			manifestId,
			success: result.exitCode === 0,
			output: output || undefined,
			error: result.exitCode !== 0 ? `Exit code: ${result.exitCode}` : undefined,
			duration_ms: Date.now() - start,
		};
	} catch (error) {
		return {
			manifestId,
			success: false,
			error: error instanceof Error ? error.message : "Unknown error",
			duration_ms: Date.now() - start,
		};
	}
}
