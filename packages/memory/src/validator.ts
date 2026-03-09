import { redactAll } from "@sentinel/types";
import { type CreateObservation, CreateObservationSchema } from "./schema.js";

export type ValidationResult =
	| { valid: true; sanitized: CreateObservation }
	| { valid: false; reason: string; code: string };

export function validateObservation(input: unknown): ValidationResult {
	const parsed = CreateObservationSchema.safeParse(input);
	if (!parsed.success) {
		return {
			valid: false,
			reason: parsed.error.issues.map((i) => i.message).join("; "),
			code: "SCHEMA_INVALID",
		};
	}

	const sanitizedContent = redactAll(parsed.data.content);
	const sanitizedTitle = redactAll(parsed.data.title);

	const contentStripped = sanitizedContent.trim();
	if (
		contentStripped === "[REDACTED]" ||
		contentStripped === "[PII_REDACTED]"
	) {
		return {
			valid: false,
			reason: "Observation contains only sensitive data",
			code: "CONTENT_ONLY_SENSITIVE",
		};
	}

	return {
		valid: true,
		sanitized: {
			...parsed.data,
			content: sanitizedContent,
			title: sanitizedTitle,
		},
	};
}
