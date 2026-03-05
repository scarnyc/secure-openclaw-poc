const CREDENTIAL_PATTERNS: RegExp[] = [
	// Anthropic API keys
	/sk-ant-[A-Za-z0-9_-]+/g,
	// OpenAI-style keys
	/sk-[A-Za-z0-9_-]{20,}/g,
	// GitHub personal access tokens
	/ghp_[A-Za-z0-9]{36,}/g,
	// GitHub OAuth tokens
	/gho_[A-Za-z0-9]{36,}/g,
	// GitHub app tokens
	/ghu_[A-Za-z0-9]{36,}/g,
	/ghs_[A-Za-z0-9]{36,}/g,
	// Slack tokens
	/xoxb-[A-Za-z0-9-]+/g,
	/xoxp-[A-Za-z0-9-]+/g,
	/xoxa-[A-Za-z0-9-]+/g,
	/xoxr-[A-Za-z0-9-]+/g,
	// AWS access keys
	/AKIA[A-Z0-9]{16}/g,
	// Bearer tokens
	/Bearer\s+[A-Za-z0-9_\-.~+/]+=*/g,
	// Generic long base64-like strings (40+ chars)
	/[A-Za-z0-9+/=]{40,}/g,
];

const MAX_LENGTH = 500;
const REDACTED = "[REDACTED]";
const TRUNCATED_SUFFIX = "... [truncated]";

export function redactCredentials(text: string): string {
	let result = text;

	for (const pattern of CREDENTIAL_PATTERNS) {
		// Reset lastIndex for global regexes
		pattern.lastIndex = 0;
		result = result.replace(pattern, REDACTED);
	}

	if (result.length > MAX_LENGTH) {
		result = result.slice(0, MAX_LENGTH - TRUNCATED_SUFFIX.length) + TRUNCATED_SUFFIX;
	}

	return result;
}
