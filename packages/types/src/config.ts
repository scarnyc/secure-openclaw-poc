import { z } from "zod";
import { ActionCategorySchema } from "./manifest.js";

export const ClassificationOverrideSchema = z.object({
	condition: z.string().min(1),
	category: ActionCategorySchema,
	reason: z.string().min(1),
});
export type ClassificationOverride = z.infer<typeof ClassificationOverrideSchema>;

export const ToolClassificationSchema = z.object({
	tool: z.string().min(1),
	defaultCategory: ActionCategorySchema,
	overrides: z.array(ClassificationOverrideSchema).optional(),
});
export type ToolClassification = z.infer<typeof ToolClassificationSchema>;

export const McpServerConfigSchema = z.object({
	name: z.string().min(1),
	transport: z.enum(["stdio", "sse"]),
	url: z.string().url().optional(),
	command: z.string().optional(),
	args: z.array(z.string()).optional(),
});
export type McpServerConfig = z.infer<typeof McpServerConfigSchema>;

export const ToolRegistryEntrySchema = z.object({
	name: z.string().min(1),
	source: z.enum(["builtin", "mcp"]),
	serverName: z.string().optional(),
	schema: z.record(z.unknown()).optional(),
});
export type ToolRegistryEntry = z.infer<typeof ToolRegistryEntrySchema>;

export const GwsAgentScopeSchema = z.object({
	allowedServices: z.array(z.string().min(1)).optional(),
	denyServices: z.array(z.string().min(1)).optional(),
});
export type GwsAgentScope = z.infer<typeof GwsAgentScopeSchema>;

export const GwsAgentScopesSchema = z.record(z.string(), GwsAgentScopeSchema);
export type GwsAgentScopes = z.infer<typeof GwsAgentScopesSchema>;

export const GwsIntegrityConfigSchema = z.object({
	/** Enable SHA-256 binary hash verification before first invocation */
	verifyBinary: z.boolean().default(false),
	/** Expected SHA-256 hex digest of the gws binary */
	expectedSha256: z
		.string()
		.regex(/^[a-f0-9]{64}$/)
		.optional(),
	/** Pinned version string (e.g., "1.2.3") */
	pinnedVersion: z.string().min(1).optional(),
	/** Version comparison policy: "exact" requires ==, "minimum" requires >= */
	pinnedVersionPolicy: z.enum(["exact", "minimum"]).default("minimum"),
	/** Known-vulnerable versions to block (exact match) */
	vulnerableVersions: z.array(z.string().min(1)).default([]),
	/** System-wide OAuth scope cap (Google API scope URIs). Unknown services blocked when set. */
	allowedOAuthScopes: z.array(z.string().min(1)).optional(),
});
export type GwsIntegrityConfig = z.infer<typeof GwsIntegrityConfigSchema>;

export const SentinelConfigSchema = z.object({
	executor: z.object({
		port: z.number().int().positive(),
		host: z.string().min(1),
	}),
	classifications: z.array(ToolClassificationSchema),
	autoApproveReadOps: z.boolean(),
	auditLogPath: z.string().min(1),
	vaultPath: z.string().min(1),
	mcpServers: z.array(McpServerConfigSchema).optional(),
	allowedRoots: z.array(z.string().min(1)).optional(),
	authToken: z.string().min(1).optional(),
	gwsAgentScopes: GwsAgentScopesSchema.optional(),
	gwsIntegrity: GwsIntegrityConfigSchema.optional(),
	llm: z.object({
		provider: z.literal("anthropic"),
		model: z.string().min(1),
		maxTokens: z.number().int().positive(),
	}),
});
export type SentinelConfig = z.infer<typeof SentinelConfigSchema>;
