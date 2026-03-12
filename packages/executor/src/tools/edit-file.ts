import { constants } from "node:fs";
import { open } from "node:fs/promises";
import type { ToolResult } from "@sentinel/types";
import { isDeniedPath } from "./deny-list.js";
import { isPathAllowed } from "./path-guard.js";

interface EditFileParams {
	path: string;
	old_string: string;
	new_string: string;
}

export async function executeEditFile(
	params: EditFileParams,
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
		// SENTINEL: TOCTOU mitigation — O_NOFOLLOW rejects symlinks; fstat verifies same inode
		const readFd = await open(params.path, constants.O_RDONLY | constants.O_NOFOLLOW);
		let content: string;
		let readIno: bigint;
		try {
			const readStat = await readFd.stat({ bigint: true });
			readIno = readStat.ino;
			content = await readFd.readFile("utf-8");
		} finally {
			await readFd.close();
		}

		const occurrences = content.split(params.old_string).length - 1;
		if (occurrences === 0) {
			return {
				manifestId,
				success: false,
				error: "old_string not found in file",
				duration_ms: Date.now() - start,
			};
		}
		if (occurrences > 1) {
			return {
				manifestId,
				success: false,
				error: `old_string found ${occurrences} times, expected exactly 1`,
				duration_ms: Date.now() - start,
			};
		}

		const updated = content.replace(params.old_string, params.new_string);

		// Write with O_NOFOLLOW + verify inode matches read (TOCTOU defense)
		const writeFd = await open(
			params.path,
			constants.O_WRONLY | constants.O_TRUNC | constants.O_NOFOLLOW,
		);
		try {
			const writeStat = await writeFd.stat({ bigint: true });
			if (writeStat.ino !== readIno) {
				return {
					manifestId,
					success: false,
					error: "Access denied: file changed between read and write (TOCTOU detected)",
					duration_ms: Date.now() - start,
				};
			}
			await writeFd.writeFile(updated, "utf-8");
		} finally {
			await writeFd.close();
		}

		return {
			manifestId,
			success: true,
			output: `Edited ${params.path}`,
			duration_ms: Date.now() - start,
		};
	} catch (err: unknown) {
		const code = (err as NodeJS.ErrnoException).code;
		if (code === "ELOOP" || code === "EMLINK") {
			return {
				manifestId,
				success: false,
				error: "Access denied: cannot edit through symlink (TOCTOU mitigation)",
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
