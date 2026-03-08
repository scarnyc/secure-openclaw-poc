import { realpath } from "node:fs/promises";
import { resolve } from "node:path";

type PathAllowed = { allowed: true; resolved: string };
type PathDenied = { allowed: false; resolved: string; reason: string };
export type PathGuardResult = PathAllowed | PathDenied;

/**
 * Check if a file path is within one of the allowed root directories.
 * Uses realpath to resolve symlinks (defense against symlink-based traversal).
 * If allowedRoots is undefined or empty, all paths are allowed.
 * Only falls back to lexical resolve on ENOENT (new files); all other
 * realpath errors deny access (fail-closed).
 */
export async function isPathAllowed(
	filePath: string,
	allowedRoots: readonly string[] | undefined,
): Promise<PathGuardResult> {
	if (!allowedRoots || allowedRoots.length === 0) {
		return { allowed: true, resolved: resolve(filePath) };
	}

	// Resolve symlinks; only fall back to lexical resolve for ENOENT (new files)
	let resolved: string;
	try {
		resolved = await realpath(resolve(filePath));
	} catch (err: unknown) {
		const code = (err as NodeJS.ErrnoException).code;
		if (code === "ENOENT") {
			resolved = resolve(filePath);
		} else {
			console.warn(`[path-guard] Cannot resolve real path for ${filePath}: ${code}`);
			return {
				allowed: false,
				resolved: resolve(filePath),
				reason: `Cannot resolve real path (${code}) — possible symlink attack`,
			};
		}
	}

	for (const root of allowedRoots) {
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
