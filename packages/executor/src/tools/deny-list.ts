import { basename } from "node:path";

const EXTENSION_DENY = [".pem", ".key"];

const SUBSTRING_DENY = ["secret", "credential"];

export function isDeniedPath(filePath: string): boolean {
	const normalized = filePath.replace(/\\/g, "/");
	const base = basename(normalized).toLowerCase();

	// Check exact file names (also handles nested .env variants like .env.local)
	if (base.startsWith(".env")) return true;
	if (base === ".dev.vars") return true;

	// Check path segments for .git/config and .git/credentials
	if (normalized.includes(".git/config")) return true;
	if (normalized.includes(".git/credentials")) return true;

	// Check extensions
	for (const ext of EXTENSION_DENY) {
		if (base.endsWith(ext)) return true;
	}

	// Check substrings (case-insensitive)
	const lower = normalized.toLowerCase();
	for (const sub of SUBSTRING_DENY) {
		if (lower.includes(sub)) return true;
	}

	return false;
}
