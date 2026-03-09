export class MemoryQuotaError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "MemoryQuotaError";
	}
}

export class ContentOnlySensitiveError extends Error {
	constructor() {
		super("Observation contains only sensitive data");
		this.name = "ContentOnlySensitiveError";
	}
}
