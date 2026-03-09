import { z } from "zod";

export const ObservationTypeSchema = z.enum([
	"tool_call",
	"learning",
	"error",
	"decision",
	"context",
]);
export type ObservationType = z.infer<typeof ObservationTypeSchema>;

export const SourceSchema = z.enum(["developer", "agent"]);
export type Source = z.infer<typeof SourceSchema>;

export const ScopeSchema = z.enum(["session", "daily", "weekly"]);
export type Scope = z.infer<typeof ScopeSchema>;

export const CreateObservationSchema = z.object({
	project: z.string().min(1).max(500),
	sessionId: z.string().min(1).max(200),
	agentId: z.string().min(1).max(200).default("claude-code"),
	source: SourceSchema,
	type: ObservationTypeSchema,
	title: z.string().min(1).max(200),
	content: z.string().min(1).max(10240),
	concepts: z.array(z.string().max(100)).max(50).default([]),
	filesInvolved: z.array(z.string().max(500)).max(100).default([]),
});
export type CreateObservation = z.infer<typeof CreateObservationSchema>;

export const ObservationSchema = CreateObservationSchema.extend({
	id: z.string().uuid(),
	contentHash: z.string().length(64),
	createdAt: z.string(),
});
export type Observation = z.infer<typeof ObservationSchema>;

export const SearchQuerySchema = z.object({
	query: z.string().max(1000).optional(),
	project: z.string().max(500).optional(),
	agentId: z.string().max(200).optional(),
	type: ObservationTypeSchema.optional(),
	source: SourceSchema.optional(),
	fromDate: z.string().optional(),
	toDate: z.string().optional(),
	limit: z.number().int().min(1).max(100).default(20),
	offset: z.number().int().min(0).default(0),
});
export type SearchQuery = z.infer<typeof SearchQuerySchema>;
export type SearchInput = z.input<typeof SearchQuerySchema>;

export const CreateSummarySchema = z.object({
	project: z.string().min(1).max(500),
	source: SourceSchema,
	scope: ScopeSchema,
	periodStart: z.string(),
	periodEnd: z.string(),
	title: z.string().min(1).max(200),
	investigated: z.array(z.string().max(5120)).max(20).default([]),
	learned: z.array(z.string().max(5120)).max(20).default([]),
	completed: z.array(z.string().max(5120)).max(20).default([]),
	nextSteps: z.array(z.string().max(5120)).max(20).default([]),
	observationIds: z.array(z.string().uuid()).default([]),
});
export type CreateSummary = z.infer<typeof CreateSummarySchema>;
export type CreateSummaryInput = z.input<typeof CreateSummarySchema>;

export const SummarySchema = CreateSummarySchema.extend({
	id: z.string().uuid(),
	createdAt: z.string(),
});
export type Summary = z.infer<typeof SummarySchema>;
