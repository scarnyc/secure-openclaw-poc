import type { ToolResult } from "@sentinel/types";
import { redactAllCredentials } from "@sentinel/types";

export function filterCredentials(result: ToolResult): ToolResult {
	return {
		...result,
		output: result.output ? redactAllCredentials(result.output) : result.output,
		error: result.error ? redactAllCredentials(result.error) : result.error,
	};
}
