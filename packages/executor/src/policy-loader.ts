import * as fs from "node:fs";
import type { PolicyDocument } from "@sentinel/types";
import { PolicyDocumentSchema } from "@sentinel/types";
import { expandGroups, validateGroups } from "@sentinel/policy";

export function loadPolicy(policyPath: string): Readonly<PolicyDocument> {
	let raw: string;
	try {
		raw = fs.readFileSync(policyPath, "utf-8");
	} catch {
		throw new Error(`Policy file not found: ${policyPath}. Executor cannot start without a policy.`);
	}

	let json: unknown;
	try {
		json = JSON.parse(raw);
	} catch {
		throw new Error(`Policy file is not valid JSON: ${policyPath}`);
	}

	const parsed = PolicyDocumentSchema.safeParse(json);
	if (!parsed.success) {
		throw new Error(`Invalid policy schema: ${parsed.error.message}`);
	}

	const policy = parsed.data;

	// Validate tool groups
	validateGroups(policy.toolGroups);

	// Validate all group references in defaults and agents
	validateGroupReferences(policy);

	return Object.freeze(policy);
}

function validateGroupReferences(policy: PolicyDocument): void {
	const allToolLists = [policy.defaults.tools.allow, policy.defaults.tools.deny];

	for (const agent of Object.values(policy.agents)) {
		if (agent.tools.allow) allToolLists.push(agent.tools.allow);
		if (agent.tools.deny) allToolLists.push(agent.tools.deny);
	}

	for (const list of allToolLists) {
		// expandGroups throws on unknown group references
		expandGroups(list, policy.toolGroups);
	}
}
