import { z } from "zod";
import { ActionCategorySchema } from "./manifest.js";

export const PolicyDecisionSchema = z.object({
	action: z.enum(["auto_approve", "confirm", "block"]),
	category: ActionCategorySchema,
	reason: z.string().min(1),
});
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;
