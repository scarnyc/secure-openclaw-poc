import type { ToolResult } from "@sentinel/types";
import { execaCommand } from "execa";

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 300_000;

const DENIED_FILE_PATTERNS = [
	/\bcat\b.*\.(env|pem|key)\b/,
	/\bcat\b.*\.dev\.vars\b/,
	/\bcat\b.*\.git\/(config|credentials)\b/,
	/\bcat\b.*secret/i,
	/\bcat\b.*credential/i,
];

function isDeniedBashCommand(command: string): string | null {
	for (const pattern of DENIED_FILE_PATTERNS) {
		if (pattern.test(command)) {
			return "Command attempts to read a denied file";
		}
	}
	return null;
}

function stripSentinelEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
	const cleaned: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(env)) {
		if (!key.startsWith("SENTINEL_")) {
			cleaned[key] = value;
		}
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
			env: stripSentinelEnv(process.env),
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
