import type { ToolResult } from "@sentinel/types";

const CREDENTIAL_PATTERNS: RegExp[] = [
	// Anthropic API keys
	/sk-ant-[A-Za-z0-9_-]+/g,
	// OpenAI-style keys
	/sk-[A-Za-z0-9_-]{20,}/g,
	// GitHub personal access tokens
	/ghp_[A-Za-z0-9]{36,}/g,
	// GitHub OAuth/app tokens
	/gh[ous]_[A-Za-z0-9]{36,}/g,
	// Slack tokens
	/xox[bpar]-[A-Za-z0-9-]+/g,
	// AWS access keys
	/AKIA[A-Z0-9]{16}/g,
	// Bearer tokens
	/Bearer\s+[A-Za-z0-9_\-.~+/]+=*/g,
	// Generic long base64-like strings (40+ chars)
	/[A-Za-z0-9+/=]{40,}/g,
];

const REDACTED = "[REDACTED]";

function redactString(text: string): string {
	let result = text;
	for (const pattern of CREDENTIAL_PATTERNS) {
		pattern.lastIndex = 0;
		result = result.replace(pattern, REDACTED);
	}
	return result;
}

export function filterCredentials(result: ToolResult): ToolResult {
	return {
		...result,
		output: result.output ? redactString(result.output) : result.output,
		error: result.error ? redactString(result.error) : result.error,
	};
}
