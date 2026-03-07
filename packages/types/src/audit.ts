import { z } from "zod";
import { ActionCategorySchema } from "./manifest.js";
import { PolicyDecisionSchema } from "./policy.js";

export const AuditEntrySchema = z.object({
	id: z.string().uuid(),
	timestamp: z.string().datetime(),
	manifestId: z.string().uuid(),
	tool: z.string().min(1),
	category: ActionCategorySchema,
	decision: PolicyDecisionSchema.shape.action,
	parameters_summary: z.string(),
	result: z.enum(["success", "failure", "denied_by_user", "blocked_by_policy"]),
	duration_ms: z.number().nonnegative().optional(),
	sessionId: z.string().min(1),
	agentId: z.string().min(1),
});
export type AuditEntry = z.infer<typeof AuditEntrySchema>;
