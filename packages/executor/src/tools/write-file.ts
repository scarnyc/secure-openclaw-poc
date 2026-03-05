import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
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
