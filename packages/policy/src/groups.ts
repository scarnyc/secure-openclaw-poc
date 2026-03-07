export function expandGroups(
	tools: string[],
	toolGroups: Record<string, string[]>,
): string[] {
	const result: string[] = [];
	const seen = new Set<string>();

	for (const tool of tools) {
		if (tool.startsWith("group:")) {
			const groupName = tool.slice(6);
			const members = toolGroups[groupName];
			if (!members) {
				throw new Error(`Unknown tool group: ${groupName}`);
			}
			for (const member of members) {
				if (!seen.has(member)) {
					seen.add(member);
					result.push(member);
				}
			}
		} else {
			if (!seen.has(tool)) {
				seen.add(tool);
				result.push(tool);
			}
		}
	}

	return result;
}

export function validateGroups(toolGroups: Record<string, string[]>): void {
	for (const name of Object.keys(toolGroups)) {
		if (name.length === 0) {
			throw new Error("Tool group name cannot be empty");
		}
	}
}
