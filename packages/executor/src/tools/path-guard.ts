import { realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

type PathAllowed = { allowed: true; resolved: string };
type PathDenied = { allowed: false; resolved: string; reason: string };
export type PathGuardResult = PathAllowed | PathDenied;

/**
 * Check if a file path is within one of the allowed root directories.
 * Uses realpath to resolve symlinks (defense against symlink-based traversal).
 *
 * Root resolution priority:
 * 1. Explicit `allowedRoots` parameter (Docker mode passes config directly)
 * 2. `SENTINEL_ALLOWED_ROOTS` env var (comma-separated paths)
 * 3. `process.cwd()` default (local dev fail-closed)
 * 4. All paths allowed only when `SENTINEL_DOCKER=true` with no explicit roots
 *
 * Only falls back to lexical resolve on ENOENT (new files); all other
 * realpath errors deny access (fail-closed).
 */
export async function isPathAllowed(
	filePath: string,
	allowedRoots: readonly string[] | undefined,
): Promise<PathGuardResult> {
	// Determine effective roots: explicit > env var > cwd default
	let effectiveRoots: readonly string[] | undefined = allowedRoots;
	if (!effectiveRoots || effectiveRoots.length === 0) {
		const envRoots = process.env.SENTINEL_ALLOWED_ROOTS;
		if (envRoots) {
			effectiveRoots = envRoots
				.split(",")
				.map((r) => r.trim())
				.filter((r) => r.length > 0);
		} else if (process.env.SENTINEL_DOCKER !== "true") {
			effectiveRoots = [process.cwd()];
		}
	}

	if (!effectiveRoots || effectiveRoots.length === 0) {
		return { allowed: true, resolved: resolve(filePath) };
	}

	// Resolve symlinks; only fall back to lexical resolve for ENOENT (new files)
	let resolved: string;
	try {
		resolved = await realpath(resolve(filePath));
	} catch (err: unknown) {
		const code = (err as NodeJS.ErrnoException).code;
		if (code === "ENOENT") {
			// New file: resolve parent dir (which should exist) to handle macOS
			// /var → /private/var symlink, then join the filename
			const absPath = resolve(filePath);
			try {
				resolved = join(await realpath(dirname(absPath)), basename(absPath));
			} catch (parentErr: unknown) {
				const parentCode = (parentErr as NodeJS.ErrnoException).code;
				console.warn(`[path-guard] Cannot resolve parent dir for ${filePath}: ${parentCode}`);
				resolved = absPath;
			}
		} else {
			console.warn(`[path-guard] Cannot resolve real path for ${filePath}: ${code}`);
			return {
				allowed: false,
				resolved: resolve(filePath),
				reason: `Cannot resolve real path (${code}) — possible symlink attack`,
			};
		}
	}

	for (const root of effectiveRoots) {
		let resolvedRoot: string;
		try {
			resolvedRoot = await realpath(resolve(root));
		} catch (err: unknown) {
			const code = (err as NodeJS.ErrnoException).code;
			if (code === "ENOENT") {
				resolvedRoot = resolve(root);
			} else {
				console.warn(`[path-guard] Cannot resolve root ${root}: ${code}`);
				continue; // Skip unresolvable roots
			}
		}
		if (resolved === resolvedRoot || resolved.startsWith(`${resolvedRoot}/`)) {
			return { allowed: true, resolved };
		}
	}

	console.warn(`[path-guard] Denied: ${filePath} outside allowed roots`);
	return {
		allowed: false,
		resolved,
		reason: "Path outside allowed roots",
	};
}
