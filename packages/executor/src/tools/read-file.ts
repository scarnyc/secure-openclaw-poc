import { readFile } from "node:fs/promises";
import type { ToolResult } from "@sentinel/types";
import { isDeniedPath } from "./deny-list.js";

interface ReadFileParams {
	path: string;
	maxBytes?: number;
}

export async function executeReadFile(
	params: ReadFileParams,
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
		const buffer = await readFile(params.path);
		const maxBytes = params.maxBytes ?? buffer.length;
		const content = buffer.subarray(0, maxBytes).toString("utf-8");

		return {
			manifestId,
			success: true,
			output: content,
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
