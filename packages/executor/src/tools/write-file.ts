import { mkdir, realpath, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { ToolResult } from "@sentinel/types";
import { isDeniedPath } from "./deny-list.js";

interface WriteFileParams {
	path: string;
	content: string;
}

export async function executeWriteFile(
	params: WriteFileParams,
	manifestId: string,
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

	// Defense-in-depth: restrict writes to allowed prefix in Docker
	if (process.env.SENTINEL_DOCKER === "true") {
		const ALLOWED_WRITE_PREFIX = "/app/data/";
		// Use realpath to resolve symlinks; fall back to lexical resolve for new paths
		const resolved = await realpath(resolve(params.path)).catch(() => resolve(params.path));
		if (!resolved.startsWith(ALLOWED_WRITE_PREFIX)) {
			return {
				manifestId,
				success: false,
				error: "Access denied: writes restricted to /app/data/ in container mode",
				duration_ms: Date.now() - start,
			};
		}
		// Use resolved path for actual write to prevent symlink-based bypasses
		try {
			await mkdir(dirname(resolved), { recursive: true });
			await writeFile(resolved, params.content, "utf-8");
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
		await mkdir(dirname(params.path), { recursive: true });
		await writeFile(params.path, params.content, "utf-8");

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
