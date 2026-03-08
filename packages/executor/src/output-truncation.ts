const BASH_OUTPUT_LIMIT = 50 * 1024; // 50 KB
const HTTP_OUTPUT_LIMIT = 10 * 1024 * 1024; // 10 MB
const TRUNCATION_NOTICE = "\n\n[OUTPUT TRUNCATED — exceeded maximum size]";

/**
 * Truncate output to the given byte limit.
 * Returns the original string if within limit, otherwise truncates with a notice.
 */
export function truncateOutput(output: string, limit: number): string {
	if (Buffer.byteLength(output, "utf-8") <= limit) {
		return output;
	}
	// Find a safe cut point within the byte limit, respecting UTF-8 boundaries.
	// Walk backward from the limit to avoid splitting multi-byte characters.
	const buf = Buffer.from(output, "utf-8");
	let end = limit;
	// If we're in the middle of a multi-byte sequence, back up
	while (end > 0 && (buf[end] & 0xc0) === 0x80) {
		end--;
	}
	const truncated = buf.subarray(0, end).toString("utf-8");
	return truncated + TRUNCATION_NOTICE;
}

/**
 * Truncate bash command output to 50KB.
 */
export function truncateBashOutput(output: string): string {
	return truncateOutput(output, BASH_OUTPUT_LIMIT);
}

export { BASH_OUTPUT_LIMIT, HTTP_OUTPUT_LIMIT };
