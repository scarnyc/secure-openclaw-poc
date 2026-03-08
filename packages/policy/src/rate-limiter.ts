export interface RateLimiterConfig {
	rate: number; // max requests allowed
	period: number; // time window in milliseconds
}

export interface RateLimitResult {
	allowed: boolean;
	retryAfter?: number; // milliseconds until next allowed request
}

export class RateLimiter {
	private readonly emissionInterval: number;
	private readonly period: number;
	private readonly tats: Map<string, number> = new Map();

	constructor(config: RateLimiterConfig) {
		if (config.rate <= 0 || config.period <= 0) {
			throw new Error("rate and period must be positive");
		}
		this.emissionInterval = config.period / config.rate;
		this.period = config.period;
	}

	check(agentId: string): RateLimitResult {
		const now = Date.now();
		const previousTat = this.tats.get(agentId) ?? now;
		const newTat = Math.max(now, previousTat) + this.emissionInterval;

		if (newTat - now > this.period) {
			return { allowed: false, retryAfter: newTat - now - this.period };
		}

		this.tats.set(agentId, newTat);
		return { allowed: true };
	}

	reset(agentId?: string): void {
		if (agentId !== undefined) {
			this.tats.delete(agentId);
		} else {
			this.tats.clear();
		}
	}
}
