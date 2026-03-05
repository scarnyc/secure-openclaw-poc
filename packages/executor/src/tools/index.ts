import { executeBash } from "./bash.js";
import { executeEditFile } from "./edit-file.js";
import { executeReadFile } from "./read-file.js";
import { ToolRegistry } from "./registry.js";
import { executeWriteFile } from "./write-file.js";

export function createToolRegistry(): ToolRegistry {
	const registry = new ToolRegistry();

	registry.registerBuiltin("bash", (params, manifestId) =>
		executeBash(
			{
				command: params.command as string,
				cwd: params.cwd as string | undefined,
				timeout: params.timeout as number | undefined,
			},
			manifestId,
		),
	);

	registry.registerBuiltin("read_file", (params, manifestId) =>
		executeReadFile(
			{
				path: params.path as string,
				maxBytes: params.maxBytes as number | undefined,
			},
			manifestId,
		),
	);

	registry.registerBuiltin("write_file", (params, manifestId) =>
		executeWriteFile(
			{
				path: params.path as string,
				content: params.content as string,
			},
			manifestId,
		),
	);

	registry.registerBuiltin("edit_file", (params, manifestId) =>
		executeEditFile(
			{
				path: params.path as string,
				old_string: params.old_string as string,
				new_string: params.new_string as string,
			},
			manifestId,
		),
	);

	return registry;
}

export type { ToolHandler } from "./registry.js";
export { ToolRegistry } from "./registry.js";
