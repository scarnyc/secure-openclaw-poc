/**
 * Single source of truth for credential detection patterns.
 * Used by both executor credential-filter and audit redaction.
 */

const CREDENTIAL_PATTERNS: readonly RegExp[] = [
	// Anthropic API keys
	/sk-ant-[A-Za-z0-9_-]+/g,
	// OpenAI-style keys
	/sk-[A-Za-z0-9_-]{20,}/g,
	// Gemini / Google API keys
	/AIza[A-Za-z0-9_-]{35}/g,
	// Google OAuth2 access tokens
	/ya29\.[A-Za-z0-9_\-.]+/g,
	// Google OAuth2 refresh tokens
	/1\/\/[A-Za-z0-9_\-.]{60,}/g,
	// Google OAuth2 authorization codes
	/4\/[A-Za-z0-9_\-.]{40,}/g,
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
	// PEM private keys (PKCS#8, RSA, EC, OpenSSH, DSA)
	// Bounded to 16KB to prevent unbounded backtracking on malformed input (ReDoS hardening).
	/-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----[\s\S]{1,16384}?-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----/g,
];

const REDACTED = "[REDACTED]";
const REDACTED_ENCODED = "[REDACTED_ENCODED]";

/**
 * Check if text contains any credential pattern.
 * Returns true on first match, does not mutate.
 */
export function containsCredential(text: string): boolean {
	for (const pattern of CREDENTIAL_PATTERNS) {
		pattern.lastIndex = 0;
		if (pattern.test(text)) {
			pattern.lastIndex = 0;
			return true;
		}
	}
	return false;
}

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

/** Regex matching base64 chunks of 20+ characters */
const BASE64_CHUNK_RE = /[A-Za-z0-9+/=]{20,}/g;

/** Regex detecting percent-encoded hex sequences */
const PERCENT_ENCODED_RE = /%[0-9A-Fa-f]{2}/;

/** Matches runs of URL-encoded content including surrounding non-encoded chars.
 * Captures: leading alphanumeric + sequences of %XX with interleaved alphanumeric.
 * E.g., "sk%2Dant%2Dabc123" matches as one segment so credentials spanning boundaries are caught. */
const URL_ENCODED_RUN_RE = /[A-Za-z0-9_\-.~+/=]*(?:%[0-9A-Fa-f]{2}[A-Za-z0-9_\-.~+/=]*)+/g;

/**
 * Encoding-aware credential redaction.
 *
 * Three-pass approach:
 *   1. Plaintext redaction via `redactAllCredentials()`
 *   2. Base64 — find chunks ≥20 chars, decode, check for credentials
 *   3. URL-encoding — if `%XX` sequences present, decode and check
 */
export function redactAllCredentialsWithEncoding(text: string): string {
	// Pass 1: plaintext
	let result = redactAllCredentials(text);

	// Pass 2: base64 chunks
	BASE64_CHUNK_RE.lastIndex = 0;
	result = result.replace(BASE64_CHUNK_RE, (chunk) => {
		try {
			const decoded = Buffer.from(chunk, "base64").toString("utf-8");
			if (containsCredential(decoded)) {
				return REDACTED_ENCODED;
			}
		} catch {
			// Invalid base64 — leave as-is
		}
		return chunk;
	});

	// Pass 3: URL-encoded segments — decode individual encoded runs, not the whole string.
	// This preserves non-credential content in its original encoding while still catching
	// credentials that are percent-encoded (e.g., sk%2Dant%2Dabc123).
	if (PERCENT_ENCODED_RE.test(result)) {
		result = result.replace(URL_ENCODED_RUN_RE, (segment) => {
			try {
				const decoded = decodeURIComponent(segment);
				if (containsCredential(decoded)) {
					return REDACTED_ENCODED;
				}
			} catch {
				// Invalid percent-encoding — leave as-is
			}
			return segment;
		});
	}

	return result;
}

/**
 * Regex-feasible PII categories. Names, cities, titles deferred to NER
 * (see Phase 2 backlog in CLAUDE.md).
 */
const PII_PATTERNS: readonly RegExp[] = [
	// US Social Security Numbers: XXX-XX-XXXX
	/\b\d{3}-\d{2}-\d{4}\b/g,
	// US phone: (XXX) XXX-XXXX
	/\(\d{3}\)\s?\d{3}[-. ]\d{4}/g,
	// US phone: XXX-XXX-XXXX, XXX.XXX.XXXX, XXX XXX XXXX
	/(?<!\d)\d{3}[-. ]\d{3}[-. ]\d{4}(?!\d)/g,
	// US/Canada phone with country code: +1XXXXXXXXXX
	/\+1\d{10}\b/g,
	// Email addresses
	/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
	// Salary: $XX,XXX or $XXX,XXX.XX (requires comma-separated thousands)
	/\$\d{1,3},\d{3}(,\d{3})*(\.\d{2})?\b/g,
	// Salary shorthand: $XXK or $XXXk
	/\$\d+[Kk]\b/g,
	// LinkedIn profile URLs
	/https?:\/\/(www\.)?linkedin\.com\/in\/[A-Za-z0-9_-]+\/?/g,
	// GitHub profile URLs (not repo URLs — requires end of string or whitespace after username)
	/https?:\/\/(www\.)?github\.com\/[A-Za-z0-9_-]+\/?(?=\s|$)/g,
];

const PII_REDACTED = "[PII_REDACTED]";

/**
 * Redact PII patterns from text.
 * Resets lastIndex on each global regex before use.
 */
export function redactPII(text: string): string {
	let result = text;
	for (const pattern of PII_PATTERNS) {
		pattern.lastIndex = 0;
		result = result.replace(pattern, PII_REDACTED);
	}
	return result;
}

/**
 * Redact credentials first (more specific), then PII.
 * Credentials first so tokens matching both get [REDACTED] rather than [PII_REDACTED].
 */
export function redactAll(text: string): string {
	return redactPII(redactAllCredentialsWithEncoding(text));
}
