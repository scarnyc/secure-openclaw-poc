import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { GwsIntegrityConfig } from "@sentinel/types";
import { execa } from "execa";
import { stripSensitiveEnv } from "../env-utils.js";

const cleanEnv = stripSensitiveEnv(process.env);

// --- Binary resolution ---

export async function resolveGwsBinary(): Promise<string> {
	const result = await execa("which", ["gws"], {
		reject: false,
		env: cleanEnv,
		extendEnv: false,
	});
	if (result.exitCode !== 0) {
		throw new Error("gws binary not found on PATH");
	}
	return result.stdout.trim();
}

// --- SHA-256 hash ---

export async function computeBinaryHash(binaryPath: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const hash = createHash("sha256");
		const stream = createReadStream(binaryPath);
		stream.on("data", (chunk: Buffer) => hash.update(chunk));
		stream.on("end", () => resolve(hash.digest("hex")));
		stream.on("error", reject);
	});
}

// --- Version check ---

export async function getGwsVersion(binaryPath: string): Promise<string> {
	const result = await execa(binaryPath, ["--version"], {
		timeout: 5_000,
		reject: false,
		env: cleanEnv,
		extendEnv: false,
	});
	if (result.exitCode !== 0) {
		throw new Error("gws --version failed");
	}
	const match = result.stdout.match(/(\d+\.\d+\.\d+)/);
	if (!match) {
		throw new Error(`Cannot parse version from: ${result.stdout}`);
	}
	return match[1];
}

// --- Version comparison (no semver dependency) ---

function parseVersion(v: string): [number, number, number] {
	const parts = v.split(".").map(Number);
	return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

function compareVersions(a: string, b: string): number {
	const [aMaj, aMin, aPat] = parseVersion(a);
	const [bMaj, bMin, bPat] = parseVersion(b);
	if (aMaj !== bMaj) return aMaj - bMaj;
	if (aMin !== bMin) return aMin - bMin;
	return aPat - bPat;
}

export interface VersionCheckResult {
	ok: boolean;
	reason?: string;
}

export function validateVersion(
	version: string,
	pinnedVersion: string,
	policy: "exact" | "minimum",
): VersionCheckResult {
	if (policy === "exact") {
		if (version !== pinnedVersion) {
			return {
				ok: false,
				reason: `Version ${version} does not match exact pin ${pinnedVersion}`,
			};
		}
		return { ok: true };
	}

	// minimum: version >= pinnedVersion
	if (compareVersions(version, pinnedVersion) < 0) {
		return {
			ok: false,
			reason: `Version ${version} below minimum pin ${pinnedVersion}`,
		};
	}
	return { ok: true };
}

// --- CVE blocklist ---

export function isVulnerableVersion(version: string, vulnerableVersions: string[]): boolean {
	return vulnerableVersions.includes(version);
}

// --- OAuth scope cap ---

const GWS_SERVICE_SCOPE_MAP: Record<string, string> = {
	gmail: "https://www.googleapis.com/auth/gmail.modify",
	calendar: "https://www.googleapis.com/auth/calendar",
	drive: "https://www.googleapis.com/auth/drive",
	sheets: "https://www.googleapis.com/auth/spreadsheets",
	docs: "https://www.googleapis.com/auth/documents",
	slides: "https://www.googleapis.com/auth/presentations",
	admin: "https://www.googleapis.com/auth/admin.directory.user",
	people: "https://www.googleapis.com/auth/contacts",
	tasks: "https://www.googleapis.com/auth/tasks",
};

export function isServiceAllowed(service: string, allowedScopes?: string[]): boolean {
	// No system cap configured — allow all (backward compat)
	if (!allowedScopes) return true;
	const scope = GWS_SERVICE_SCOPE_MAP[service];
	// Unknown service = blocked (fail-closed)
	if (!scope) return false;
	return allowedScopes.includes(scope);
}

// --- Integrated integrity gate ---

export interface IntegrityResult {
	ok: boolean;
	binaryPath: string;
	version: string;
	warnings: string[];
	error?: string;
}

// Cache keyed by stable JSON of config — prevents cross-agent contamination
// when different agents have different integrity configs
const integrityCache = new Map<string, Promise<IntegrityResult>>();

function configCacheKey(config?: GwsIntegrityConfig): string {
	if (!config) return "__no_config__";
	return JSON.stringify(config);
}

export function resetIntegrityCache(): void {
	integrityCache.clear();
}

async function performIntegrityCheck(config?: GwsIntegrityConfig): Promise<IntegrityResult> {
	const warnings: string[] = [];

	// Step 1: Resolve binary
	let binaryPath: string;
	try {
		binaryPath = await resolveGwsBinary();
	} catch {
		return {
			ok: false,
			binaryPath: "",
			version: "",
			warnings,
			error: "gws binary not found on PATH",
		};
	}

	// Step 2: Binary hash verification BEFORE executing the binary (TOCTOU mitigation)
	// Hash must be verified before any execution (--version) to prevent a compromised
	// binary from running arbitrary code during the version check.
	if (config?.verifyBinary) {
		if (!config.expectedSha256) {
			// Fail-closed: verifyBinary=true without expectedSha256 is a config error
			return {
				ok: false,
				binaryPath,
				version: "",
				warnings,
				error:
					"verifyBinary is true but expectedSha256 is not set — cannot verify binary integrity",
			};
		}
		try {
			const actualHash = await computeBinaryHash(binaryPath);
			if (actualHash !== config.expectedSha256) {
				return {
					ok: false,
					binaryPath,
					version: "",
					warnings,
					error: "Binary hash mismatch — gws binary may have been tampered with or updated",
				};
			}
		} catch (err) {
			return {
				ok: false,
				binaryPath,
				version: "",
				warnings,
				error: `Failed to compute binary hash: ${err instanceof Error ? err.message : "unknown error"}`,
			};
		}
	} else if (config?.verifyBinary === false) {
		// Intentional opt-out — no warning (user explicitly chose not to verify)
	} else {
		warnings.push(
			"Binary hash verification not configured — set verifyBinary and expectedSha256 to enable",
		);
	}

	// Step 3: Get version (only after binary is verified)
	let version: string;
	try {
		version = await getGwsVersion(binaryPath);
	} catch (err) {
		return {
			ok: false,
			binaryPath,
			version: "",
			warnings,
			error: `Failed to determine gws version: ${err instanceof Error ? err.message : "unknown error"}`,
		};
	}

	// Step 4: Version pinning
	if (config?.pinnedVersion) {
		const versionCheck = validateVersion(
			version,
			config.pinnedVersion,
			config.pinnedVersionPolicy ?? "minimum",
		);
		if (!versionCheck.ok) {
			return {
				ok: false,
				binaryPath,
				version,
				warnings,
				error: `Version check failed: ${versionCheck.reason}`,
			};
		}
	}

	// Step 5: CVE blocklist
	if (config?.vulnerableVersions && isVulnerableVersion(version, config.vulnerableVersions)) {
		return {
			ok: false,
			binaryPath,
			version,
			warnings,
			error: `Running vulnerable gws version ${version} — update the binary before use`,
		};
	}

	return { ok: true, binaryPath, version, warnings };
}

export async function ensureGwsIntegrity(config?: GwsIntegrityConfig): Promise<IntegrityResult> {
	const key = configCacheKey(config);
	const cached = integrityCache.get(key);
	if (cached) return cached;

	const check = performIntegrityCheck(config);

	// Only cache successful results — failed checks can be retried
	integrityCache.set(key, check);
	check
		.then((result) => {
			if (!result.ok) {
				integrityCache.delete(key);
			}
		})
		.catch(() => {
			// S2 fix: clean up cache on rejection (e.g., unhandled throws in performIntegrityCheck)
			integrityCache.delete(key);
		});

	return check;
}
