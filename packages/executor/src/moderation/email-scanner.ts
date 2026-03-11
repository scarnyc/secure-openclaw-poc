import { getModerationMode } from "./scanner.js";

export interface EmailScanResult {
	flagged: boolean;
	patterns: string[];
	severity: "low" | "medium" | "high";
	reason?: string;
}

export interface EmailModerationResult {
	blocked: boolean;
	scanResult: EmailScanResult;
	sanitizedOutput?: string;
}

const SUSPICIOUS_REPLACEMENT = "[SUSPICIOUS_CONTENT_REMOVED]";

// ── Detection patterns organized by category ─────────────────────────

interface DetectionPattern {
	pattern: RegExp;
	name: string;
	severity: "low" | "medium" | "high";
}

const DETECTION_PATTERNS: DetectionPattern[] = [
	// Hidden text (high severity)
	{
		pattern: /\u200B|\u200C|\u200D|\uFEFF/,
		name: "zero_width_characters",
		severity: "high",
	},
	{
		pattern: /<!--\s*(ignore|system|instruction|override|forget|disregard)/i,
		name: "html_comment_injection",
		severity: "high",
	},
	{
		pattern: /font-size:\s*0/i,
		name: "hidden_text_font_zero",
		severity: "high",
	},
	{
		pattern: /color:\s*#fff[^;]*;[^}]*background[^:]*:\s*#fff/i,
		name: "white_on_white_text",
		severity: "high",
	},
	{
		pattern: /color:\s*white[^;]*;[^}]*background[^:]*:\s*white/i,
		name: "white_on_white_text",
		severity: "high",
	},

	// Encoding tricks (high severity)
	{
		pattern: /atob\s*\(/i,
		name: "base64_decode_call",
		severity: "high",
	},
	{
		pattern: /(&#x[0-9a-f]{2};){5,}/i,
		name: "html_entity_obfuscation",
		severity: "high",
	},
	{
		pattern: /(&#\d{2,3};){5,}/,
		name: "html_entity_obfuscation",
		severity: "high",
	},

	// Instruction override (high severity)
	{
		pattern: /ignore\s+(all\s+)?previous\s+instructions/i,
		name: "instruction_override",
		severity: "high",
	},
	{
		pattern: /(?:^|[\n>])\s*system\s*:/im,
		name: "role_injection_system",
		severity: "high",
	},
	{
		pattern: /(?:^|[\n>])\s*assistant\s*:/im,
		name: "role_injection_assistant",
		severity: "high",
	},
	{
		pattern: /you\s+are\s+now\s+(a|an)\s+/i,
		name: "persona_override",
		severity: "high",
	},
	{
		pattern: /new\s+instructions?\s*:/i,
		name: "new_instructions",
		severity: "high",
	},
	{
		pattern: /updated?\s+instructions?\s*:/i,
		name: "updated_instructions",
		severity: "high",
	},
	{
		pattern: /\bIMPORTANT\s*:\s*.{0,20}(ignore|override|forget|disregard)/i,
		name: "urgency_manipulation",
		severity: "high",
	},
	{
		pattern: /\bURGENT\s*:\s*.{0,20}(ignore|override|forget|disregard)/i,
		name: "urgency_manipulation",
		severity: "high",
	},

	// SMTP header injection — only detects CRLF injection (outbound construction).
	// Bare LF patterns removed: they false-positive on inbound email bodies where
	// forwarded/quoted headers (From:, To:, Subject:) are legitimate content.
	{
		pattern: /\r\n(To|CC|BCC|Subject|From)\s*:/i,
		name: "smtp_header_injection_crlf",
		severity: "high",
	},
];

/**
 * Scan email content for prompt injection patterns.
 */
export function scanEmailContent(text: string): EmailScanResult {
	const matchedPatterns: string[] = [];
	let maxSeverity: "low" | "medium" | "high" = "low";

	const severityOrder = { low: 0, medium: 1, high: 2 };

	for (const detection of DETECTION_PATTERNS) {
		detection.pattern.lastIndex = 0;
		if (detection.pattern.test(text)) {
			if (!matchedPatterns.includes(detection.name)) {
				matchedPatterns.push(detection.name);
			}
			if (severityOrder[detection.severity] > severityOrder[maxSeverity]) {
				maxSeverity = detection.severity;
			}
		}
	}

	return {
		flagged: matchedPatterns.length > 0,
		patterns: matchedPatterns,
		severity: maxSeverity,
		reason:
			matchedPatterns.length > 0
				? `Email injection detected: ${matchedPatterns.join(", ")}`
				: undefined,
	};
}

/**
 * Moderate email content using SENTINEL_MODERATION_MODE.
 * - enforce: replace flagged content with [SUSPICIOUS_CONTENT_REMOVED]
 * - warn: log but pass through
 * - off: skip scanning
 */
export function moderateEmail(text: string): EmailModerationResult {
	const mode = getModerationMode();

	if (mode === "off") {
		return {
			blocked: false,
			scanResult: { flagged: false, patterns: [], severity: "low" },
		};
	}

	const scanResult = scanEmailContent(text);

	if (!scanResult.flagged) {
		return { blocked: false, scanResult };
	}

	if (mode === "warn") {
		console.warn(
			`[email-scanner:warn] Injection patterns detected: ${scanResult.patterns.join(", ")}`,
		);
		return { blocked: false, scanResult };
	}

	// enforce mode: replace the content
	return {
		blocked: true,
		scanResult,
		sanitizedOutput: SUSPICIOUS_REPLACEMENT,
	};
}
