import { z } from "zod";

export const AgentCapabilitySchema = z.object({
	name: z.string().min(1),
	description: z.string().min(1),
	inputSchema: z.record(z.unknown()).optional(),
});
export type AgentCapability = z.infer<typeof AgentCapabilitySchema>;

export const AgentCardSchema = z.object({
	name: z.string().min(1),
	description: z.string().min(1),
	url: z.string().url(),
	capabilities: z.array(AgentCapabilitySchema),
	version: z.string().min(1),
});
export type AgentCard = z.infer<typeof AgentCardSchema>;

export const A2AArtifactSchema = z.object({
	name: z.string().min(1),
	mimeType: z.string().min(1),
	data: z.string(),
});
export type A2AArtifact = z.infer<typeof A2AArtifactSchema>;

export const A2ATaskSchema = z.object({
	id: z.string().uuid(),
	status: z.enum(["submitted", "working", "completed", "failed"]),
	capability: z.string().min(1),
	input: z.record(z.unknown()),
	output: z.record(z.unknown()).optional(),
	artifacts: z.array(A2AArtifactSchema).optional(),
});
export type A2ATask = z.infer<typeof A2ATaskSchema>;
