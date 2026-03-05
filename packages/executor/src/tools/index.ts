import { z } from "zod";
import { executeBash } from "./bash.js";
import { executeEditFile } from "./edit-file.js";
import { executeReadFile } from "./read-file.js";
import { ToolRegistry } from "./registry.js";
import { executeWriteFile } from "./write-file.js";

const BashParamsSchema = z.object({
	command: z.string().min(1),
	cwd: z.string().optional(),
	timeout: z.number().positive().optional(),
});

const ReadFileParamsSchema = z.object({
	path: z.string().min(1),
	maxBytes: z.number().positive().optional(),
});

const WriteFileParamsSchema = z.object({
	path: z.string().min(1),
	content: z.string(),
});

const EditFileParamsSchema = z.object({
	path: z.string().min(1),
	old_string: z.string(),
	new_string: z.string(),
});

export function createToolRegistry(): ToolRegistry {
	const registry = new ToolRegistry();

	registry.registerBuiltin("bash", (params, manifestId) => {
		const parsed = BashParamsSchema.parse(params);
		return executeBash(parsed, manifestId);
	});

	registry.registerBuiltin("read_file", (params, manifestId) => {
		const parsed = ReadFileParamsSchema.parse(params);
		return executeReadFile(parsed, manifestId);
	});

	registry.registerBuiltin("write_file", (params, manifestId) => {
		const parsed = WriteFileParamsSchema.parse(params);
		return executeWriteFile(parsed, manifestId);
	});

	registry.registerBuiltin("edit_file", (params, manifestId) => {
		const parsed = EditFileParamsSchema.parse(params);
		return executeEditFile(parsed, manifestId);
	});

	return registry;
}

export type { ToolHandler } from "./registry.js";
export { ToolRegistry } from "./registry.js";
