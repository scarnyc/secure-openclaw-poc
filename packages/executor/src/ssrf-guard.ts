import dns from "node:dns/promises";

export class SsrfError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SsrfError";
	}
}

/**
 * Parse an IPv4 address into a 32-bit number.
 * Returns null if the string is not a valid IPv4 address.
 */
function parseIPv4(ip: string): number | null {
	const parts = ip.split(".");
	if (parts.length !== 4) return null;
	let result = 0;
	for (const part of parts) {
		const n = Number(part);
		if (!Number.isInteger(n) || n < 0 || n > 255) return null;
		result = (result << 8) | n;
	}
	return result >>> 0; // unsigned
}

/** Check if an unsigned 32-bit IPv4 number falls within a CIDR block. */
function inCidr(ip: number, base: number, prefix: number): boolean {
	const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
	return (ip & mask) === (base & mask);
}

const IPV4_BLOCKED: Array<[number, number]> = [
	[0x7f000000, 8], // 127.0.0.0/8
	[0x0a000000, 8], // 10.0.0.0/8
	[0xac100000, 12], // 172.16.0.0/12
	[0xc0a80000, 16], // 192.168.0.0/16
	[0xa9fe0000, 16], // 169.254.0.0/16
	[0x00000000, 8], // 0.0.0.0/8
];

/** Returns true if the given IP address is in a blocked (private/reserved) range. */
export function isPrivateIp(ip: string): boolean {
	// Handle IPv4-mapped IPv6 in dotted form (::ffff:x.x.x.x)
	const mappedMatch = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
	if (mappedMatch) {
		return isPrivateIp(mappedMatch[1]);
	}

	// Handle IPv4-mapped IPv6 in hex form (::ffff:7f00:1) — URL parser normalizes to this
	const hexMappedMatch = ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
	if (hexMappedMatch) {
		const hi = Number.parseInt(hexMappedMatch[1], 16);
		const lo = Number.parseInt(hexMappedMatch[2], 16);
		const a = (hi >> 8) & 0xff;
		const b = hi & 0xff;
		const c = (lo >> 8) & 0xff;
		const d = lo & 0xff;
		return isPrivateIp(`${a}.${b}.${c}.${d}`);
	}

	// Try IPv4
	const ipv4 = parseIPv4(ip);
	if (ipv4 !== null) {
		return IPV4_BLOCKED.some(([base, prefix]) => inCidr(ipv4, base, prefix));
	}

	// IPv6 checks
	const normalized = ip.toLowerCase();
	if (normalized === "::1") return true;

	// Expand IPv6 to check prefixes
	// fc00::/7 — unique local (fc00:: and fd00::)
	if (normalized.startsWith("fc") || normalized.startsWith("fd")) {
		return true;
	}

	// fe80::/10 — link-local (covers fe80:: through febf::)
	const prefix = parseInt(normalized.slice(0, 4), 16);
	if (!Number.isNaN(prefix) && prefix >= 0xfe80 && prefix <= 0xfebf) {
		return true;
	}

	return false;
}

/**
 * Check a URL for SSRF: block requests to private IPs, localhost,
 * and cloud metadata endpoints. Resolves DNS to prevent rebinding.
 */
export async function checkSsrf(url: string): Promise<void> {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch (parseError) {
		throw new SsrfError(
			`Invalid URL: ${url} (${parseError instanceof Error ? parseError.message : "parse error"})`,
		);
	}

	const hostname = parsed.hostname;
	if (!hostname) {
		throw new SsrfError(`URL has no hostname: ${url}`);
	}

	// Strip brackets from IPv6 literals (URL parser includes them in hostname)
	const bare =
		hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;

	// If the hostname is an IP literal, check directly — no DNS needed
	if (parseIPv4(bare) !== null || bare.includes(":")) {
		if (isPrivateIp(bare)) {
			throw new SsrfError(`Blocked SSRF: ${bare} is a private/reserved IP`);
		}
		return;
	}

	// Resolve DNS and check all returned IPs
	const allIps: string[] = [];

	const [v4Result, v6Result] = await Promise.allSettled([dns.resolve4(bare), dns.resolve6(bare)]);

	if (v4Result.status === "fulfilled") {
		allIps.push(...v4Result.value);
	}
	if (v6Result.status === "fulfilled") {
		allIps.push(...v6Result.value);
	}

	if (allIps.length === 0) {
		throw new SsrfError(`DNS resolution failed for hostname: ${bare}`);
	}

	for (const ip of allIps) {
		if (isPrivateIp(ip)) {
			throw new SsrfError(`Blocked SSRF: ${bare} resolved to private IP ${ip}`);
		}
	}
}
