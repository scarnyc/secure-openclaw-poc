/**
 * Content moderation scanner for executor pipeline.
 * Scans inbound (agent requests) and outbound (tool results) for harmful content.
 *
 * Mode controlled by SENTINEL_MODERATION_MODE env var:
 * - "enforce": flagged content is blocked (fail-closed)
 * - "warn": flagged content is logged but not blocked (async, non-blocking)
 * - "off": scanning disabled entirely (default for local dev)
 */

export type ModerationMode = "enforce" | "warn" | "off";

export interface ScanResult {
	flagged: boolean;
	categories: string[];
	reason?: string;
}

const HARMFUL_PATTERNS: Array<{ pattern: RegExp; category: string }> = [
	// Prompt injection attempts
	{ pattern: /ignore\s+(all\s+)?previous\s+instructions/i, category: "prompt_injection" },
	{ pattern: /you\s+are\s+now\s+(a|an)\s+/i, category: "prompt_injection" },
	{ pattern: /system\s*:\s*you\s+are/i, category: "prompt_injection" },
	{ pattern: /\bDAN\s+mode\b/i, category: "prompt_injection" },
	// Data exfiltration attempts
	{ pattern: /base64\s+encode.*secret/i, category: "exfiltration" },
	{ pattern: /curl.*-d.*password/i, category: "exfiltration" },
	{ pattern: /wget.*--post-data.*token/i, category: "exfiltration" },
];

export function scanContent(text: string): ScanResult {
	const matchedCategories: string[] = [];
	const reasons: string[] = [];

	for (const { pattern, category } of HARMFUL_PATTERNS) {
		pattern.lastIndex = 0;
		if (pattern.test(text)) {
			if (!matchedCategories.includes(category)) {
				matchedCategories.push(category);
			}
			reasons.push(`Matched ${category} pattern`);
		}
	}

	return {
		flagged: matchedCategories.length > 0,
		categories: matchedCategories,
		reason: reasons.length > 0 ? reasons.join("; ") : undefined,
	};
}

export function getModerationMode(): ModerationMode {
	const mode = process.env.SENTINEL_MODERATION_MODE;
	if (mode === "enforce" || mode === "off") return mode;
	return "warn";
}

export interface ModerationResult {
	blocked: boolean;
	scanResult: ScanResult;
}

/**
 * Run moderation check. Returns whether the content should be blocked.
 * In "warn" mode, logs but does not block.
 * In "off" mode, skips scanning entirely.
 */
export function moderate(text: string): ModerationResult {
	const mode = getModerationMode();

	if (mode === "off") {
		return { blocked: false, scanResult: { flagged: false, categories: [] } };
	}

	const scanResult = scanContent(text);

	if (!scanResult.flagged) {
		return { blocked: false, scanResult };
	}

	if (mode === "warn") {
		console.warn(`[moderation:warn] Content flagged: ${scanResult.categories.join(", ")}`);
		return { blocked: false, scanResult };
	}

	// enforce mode
	return { blocked: true, scanResult };
}
