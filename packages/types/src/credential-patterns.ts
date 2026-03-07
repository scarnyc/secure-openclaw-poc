/**
 * Single source of truth for credential detection patterns.
 * Used by both executor credential-filter and audit redaction.
 */

export const CREDENTIAL_PATTERNS: readonly RegExp[] = [
	// Anthropic API keys
	/sk-ant-[A-Za-z0-9_-]+/g,
	// OpenAI-style keys
	/sk-[A-Za-z0-9_-]{20,}/g,
	// Gemini / Google API keys
	/AIza[A-Za-z0-9_-]{35}/g,
	// GitHub personal access tokens
	/ghp_[A-Za-z0-9]{36,}/g,
	// GitHub OAuth tokens
	/gho_[A-Za-z0-9]{36,}/g,
	// GitHub user tokens
	/ghu_[A-Za-z0-9]{36,}/g,
	// GitHub app tokens
	/ghs_[A-Za-z0-9]{36,}/g,
	// Slack tokens (all variants)
	/xoxb-[A-Za-z0-9-]+/g,
	/xoxp-[A-Za-z0-9-]+/g,
	/xoxa-[A-Za-z0-9-]+/g,
	/xoxr-[A-Za-z0-9-]+/g,
	// AWS access keys
	/AKIA[A-Z0-9]{16}/g,
	// Bearer tokens
	/Bearer\s+[A-Za-z0-9_\-.~+/]+=*/g,
	// Database connection strings
	/(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^\s]+/g,
	// Generic long base64-like strings (40+ chars)
	/[A-Za-z0-9+/=]{40,}/g,
];

const REDACTED = "[REDACTED]";

/**
 * Redact all credential patterns from a string.
 * Resets lastIndex on each global regex before use.
 */
export function redactAllCredentials(text: string): string {
	let result = text;
	for (const pattern of CREDENTIAL_PATTERNS) {
		pattern.lastIndex = 0;
		result = result.replace(pattern, REDACTED);
	}
	return result;
}
