export interface AuditFilters {
	tool?: string;
	category?: string;
	decision?: string;
	from?: string;
	to?: string;
}

interface QueryResult {
	sql: string;
	params: unknown[];
}

export function buildFilterQuery(filters: AuditFilters): QueryResult {
	const conditions: string[] = [];
	const params: unknown[] = [];

	if (filters.tool) {
		conditions.push("tool = ?");
		params.push(filters.tool);
	}
	if (filters.category) {
		conditions.push("category = ?");
		params.push(filters.category);
	}
	if (filters.decision) {
		conditions.push("decision = ?");
		params.push(filters.decision);
	}
	if (filters.from) {
		conditions.push("timestamp >= ?");
		params.push(filters.from);
	}
	if (filters.to) {
		conditions.push("timestamp <= ?");
		params.push(filters.to);
	}

	const where = conditions.length > 0 ? ` WHERE ${conditions.join(" AND ")}` : "";
	const sql = `SELECT * FROM audit_log${where} ORDER BY timestamp DESC`;

	return { sql, params };
}

export function buildSessionQuery(): QueryResult {
	return {
		sql: "SELECT * FROM audit_log WHERE session_id = ? ORDER BY timestamp ASC",
		params: [],
	};
}

export function buildRecentQuery(): QueryResult {
	return {
		sql: "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
		params: [],
	};
}
