import type { GwsAgentScopes } from "@sentinel/types";
import { z } from "zod";
import { executeBash } from "./bash.js";
import { executeEditFile } from "./edit-file.js";
import { executeGws } from "./gws.js";
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

const GwsParamsSchema = z.object({
	service: z
		.string()
		.min(1)
		.max(64)
		.regex(/^[a-z][a-zA-Z0-9_-]*$/, "Invalid service name"),
	method: z
		.string()
		.min(1)
		.max(256)
		.regex(/^[a-zA-Z][a-zA-Z0-9_.]*$/, "Invalid method name"),
	args: z.record(z.unknown()).optional(),
	sanitize: z.boolean().optional(),
});

export function createToolRegistry(
	allowedRoots?: readonly string[],
	gwsScopes?: GwsAgentScopes,
): ToolRegistry {
	const registry = new ToolRegistry();

	registry.registerBuiltin("bash", (params, manifestId) => {
		const parsed = BashParamsSchema.parse(params);
		return executeBash(parsed, manifestId);
	});

	registry.registerBuiltin("read_file", (params, manifestId) => {
		const parsed = ReadFileParamsSchema.parse(params);
		return executeReadFile(parsed, manifestId, allowedRoots);
	});

	registry.registerBuiltin("write_file", (params, manifestId) => {
		const parsed = WriteFileParamsSchema.parse(params);
		return executeWriteFile(parsed, manifestId, allowedRoots);
	});

	registry.registerBuiltin("edit_file", (params, manifestId) => {
		const parsed = EditFileParamsSchema.parse(params);
		return executeEditFile(parsed, manifestId, allowedRoots);
	});

	// SENTINEL: G4 — per-agent GWS scope restriction via closure-captured scopes
	registry.registerBuiltin("gws", (params, manifestId, agentId) => {
		const parsed = GwsParamsSchema.parse(params);
		return executeGws(parsed, manifestId, agentId, gwsScopes);
	});

	return registry;
}

export type { ToolHandler } from "./registry.js";
export { ToolRegistry } from "./registry.js";
