import { constants } from "node:fs";
import { mkdir, open } from "node:fs/promises";
import { dirname } from "node:path";
import type { ToolResult } from "@sentinel/types";
import { isDeniedPath } from "./deny-list.js";
import { isPathAllowed } from "./path-guard.js";

interface WriteFileParams {
	path: string;
	content: string;
}

export async function executeWriteFile(
	params: WriteFileParams,
	manifestId: string,
	allowedRoots?: readonly string[],
): Promise<ToolResult> {
	const start = Date.now();

	if (isDeniedPath(params.path)) {
		return {
			manifestId,
			success: false,
			error: "Access denied: file path is restricted",
			duration_ms: Date.now() - start,
		};
	}

	// Path whitelist check (runs before Docker-specific prefix check below)
	const guard = await isPathAllowed(params.path, allowedRoots);
	if (!guard.allowed) {
		return {
			manifestId,
			success: false,
			error: `Access denied: ${guard.reason}`,
			duration_ms: Date.now() - start,
		};
	}

	// Defense-in-depth: restrict writes to allowed prefix in Docker
	if (process.env.SENTINEL_DOCKER === "true") {
		const ALLOWED_WRITE_PREFIX = "/app/data/";
		if (!guard.resolved.startsWith(ALLOWED_WRITE_PREFIX)) {
			return {
				manifestId,
				success: false,
				error: "Access denied: writes restricted to /app/data/ in container mode",
				duration_ms: Date.now() - start,
			};
		}
	}

	// SENTINEL: TOCTOU mitigation — O_NOFOLLOW rejects symlinks atomically at open()
	// Uses params.path (user-supplied) not guard.resolved, because realpath() already
	// resolved the symlink — opening guard.resolved would bypass the symlink check.
	try {
		await mkdir(dirname(guard.resolved), { recursive: true });
		const fd = await open(
			params.path,
			constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW,
			0o644,
		);
		try {
			await fd.writeFile(params.content, "utf-8");
		} finally {
			await fd.close();
		}
		return {
			manifestId,
			success: true,
			output: `Written ${params.content.length} bytes to ${params.path}`,
			duration_ms: Date.now() - start,
		};
	} catch (err: unknown) {
		const code = (err as NodeJS.ErrnoException).code;
		if (code === "ELOOP" || code === "EMLINK") {
			return {
				manifestId,
				success: false,
				error: "Access denied: cannot write through symlink (TOCTOU mitigation)",
				duration_ms: Date.now() - start,
			};
		}
		return {
			manifestId,
			success: false,
			error: err instanceof Error ? err.message : "Unknown error",
			duration_ms: Date.now() - start,
		};
	}
}
