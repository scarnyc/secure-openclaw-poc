import { mkdir, writeFile } from "node:fs/promises";
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
		try {
			await mkdir(dirname(guard.resolved), { recursive: true });
			await writeFile(guard.resolved, params.content, "utf-8");
			return {
				manifestId,
				success: true,
				output: `Written ${params.content.length} bytes to ${params.path}`,
				duration_ms: Date.now() - start,
			};
		} catch (error) {
			return {
				manifestId,
				success: false,
				error: error instanceof Error ? error.message : "Unknown error",
				duration_ms: Date.now() - start,
			};
		}
	}

	try {
		await mkdir(dirname(guard.resolved), { recursive: true });
		await writeFile(guard.resolved, params.content, "utf-8");

		return {
			manifestId,
			success: true,
			output: `Written ${params.content.length} bytes to ${params.path}`,
			duration_ms: Date.now() - start,
		};
	} catch (error) {
		return {
			manifestId,
			success: false,
			error: error instanceof Error ? error.message : "Unknown error",
			duration_ms: Date.now() - start,
		};
	}
}
