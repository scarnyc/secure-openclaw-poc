import { readFile, writeFile } from "node:fs/promises";
import type { ToolResult } from "@sentinel/types";
import { isDeniedPath } from "./deny-list.js";

interface EditFileParams {
	path: string;
	old_string: string;
	new_string: string;
}

export async function executeEditFile(
	params: EditFileParams,
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
		const content = await readFile(params.path, "utf-8");

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
		await writeFile(params.path, updated, "utf-8");

		return {
			manifestId,
			success: true,
			output: `Edited ${params.path}`,
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
