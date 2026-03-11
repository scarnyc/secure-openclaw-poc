import { GMAIL_SEND_PATTERNS } from "@sentinel/types";

const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const MAX_RECIPIENTS_PER_FIELD = 50;
const MAX_TOTAL_RECIPIENTS = 100;
const MAX_SUBJECT_LENGTH = 998;

interface ValidationResult {
	valid: boolean;
	errors: string[];
}

function validateEmailArray(value: unknown, fieldName: string, errors: string[]): string[] {
	if (value === undefined || value === null) return [];
	if (!Array.isArray(value)) {
		errors.push(`${fieldName} must be an array`);
		return [];
	}
	if (value.length > MAX_RECIPIENTS_PER_FIELD) {
		errors.push(`${fieldName} exceeds maximum of ${MAX_RECIPIENTS_PER_FIELD} recipients`);
	}
	for (const email of value) {
		if (typeof email !== "string" || !EMAIL_REGEX.test(email)) {
			errors.push(`${fieldName} contains invalid email: ${String(email)}`);
		}
	}
	return value as string[];
}

export function validateGwsSendArgs(
	service: string,
	method: string,
	args: Record<string, unknown>,
): ValidationResult {
	// Non-gmail or non-send methods: passthrough
	if (service !== "gmail" || !GMAIL_SEND_PATTERNS.test(method)) {
		return { valid: true, errors: [] };
	}

	const errors: string[] = [];

	// to: required, array of emails
	if (!args.to) {
		errors.push("to is required for gmail send");
	}
	const toList = validateEmailArray(args.to, "to", errors);
	const ccList = validateEmailArray(args.cc, "cc", errors);
	const bccList = validateEmailArray(args.bcc, "bcc", errors);

	// Total recipient cap
	const totalRecipients = toList.length + ccList.length + bccList.length;
	if (totalRecipients > MAX_TOTAL_RECIPIENTS) {
		errors.push(`Total recipients (${totalRecipients}) exceeds maximum of ${MAX_TOTAL_RECIPIENTS}`);
	}

	// subject: required, max 998 chars, no CRLF
	if (!args.subject || typeof args.subject !== "string") {
		errors.push("subject is required and must be a string");
	} else {
		if (args.subject.length > MAX_SUBJECT_LENGTH) {
			errors.push(`subject exceeds maximum length of ${MAX_SUBJECT_LENGTH} characters`);
		}
		if (/[\r\n]/.test(args.subject)) {
			errors.push("subject must not contain CR or LF characters");
		}
	}

	return { valid: errors.length === 0, errors };
}
