import type { ClassifyResponse, FilterOutputResponse } from "@sentinel/types";
import type { PluginConfig } from "./config.js";

/** Response from /confirm-only — extends ClassifyResponse with TUI confirmation outcomes. */
export interface ConfirmOnlyResponse {
	decision: "auto_approve" | "confirm" | "block" | "approved" | "denied";
	category?: string;
	reason?: string;
	manifestId: string;
}

export interface ExecutorClientOptions {
	executorUrl: string;
	authToken?: string;
	timeoutMs: number;
	confirmationTimeoutMs?: number;
}

export class ExecutorClient {
	private readonly baseUrl: string;
	private readonly authToken?: string;
	private readonly timeoutMs: number;
	private readonly confirmationTimeoutMs: number;

	constructor(options: ExecutorClientOptions) {
		// Strip trailing slash
		this.baseUrl = options.executorUrl.replace(/\/+$/, "");
		this.authToken = options.authToken;
		this.timeoutMs = options.timeoutMs;
		this.confirmationTimeoutMs = options.confirmationTimeoutMs ?? options.timeoutMs;
	}

	static fromConfig(config: PluginConfig): ExecutorClient {
		return new ExecutorClient({
			executorUrl: config.executorUrl,
			authToken: config.authToken,
			timeoutMs: config.connectionTimeoutMs,
			confirmationTimeoutMs: config.confirmationTimeoutMs,
		});
	}

	async classify(
		tool: string,
		params: Record<string, unknown>,
		agentId: string,
		sessionId: string,
	): Promise<ClassifyResponse> {
		const body = { tool, params, agentId, sessionId, source: "openclaw" as const };
		const res = await this.post("/classify", body);
		return (await res.json()) as ClassifyResponse;
	}

	async filterOutput(
		output: string,
		agentId: string,
		tool?: string,
	): Promise<FilterOutputResponse> {
		const body = { output, agentId, tool };
		const res = await this.post("/filter-output", body);
		return (await res.json()) as FilterOutputResponse;
	}

	async execute(manifest: Record<string, unknown>): Promise<Record<string, unknown>> {
		const res = await this.post("/execute", manifest);
		return (await res.json()) as Record<string, unknown>;
	}

	async confirmOnly(
		tool: string,
		params: Record<string, unknown>,
		agentId: string,
		sessionId: string,
	): Promise<ConfirmOnlyResponse> {
		const body = { tool, params, agentId, sessionId, source: "openclaw" as const };
		const res = await this.post("/confirm-only", body, this.confirmationTimeoutMs);
		return (await res.json()) as ConfirmOnlyResponse;
	}

	async health(): Promise<boolean> {
		try {
			const res = await this.get("/health");
			if (!res.ok) return false;
			const body = (await res.json()) as { status?: string };
			return body.status === "ok";
		} catch {
			return false;
		}
	}

	private async post(path: string, body: unknown, timeoutOverrideMs?: number): Promise<Response> {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutOverrideMs ?? this.timeoutMs);
		try {
			const res = await fetch(`${this.baseUrl}${path}`, {
				method: "POST",
				headers: this.headers(),
				body: JSON.stringify(body),
				signal: controller.signal,
			});
			return res;
		} finally {
			clearTimeout(timer);
		}
	}

	private async get(path: string): Promise<Response> {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeoutMs);
		try {
			const res = await fetch(`${this.baseUrl}${path}`, {
				method: "GET",
				headers: this.headers(),
				signal: controller.signal,
			});
			return res;
		} finally {
			clearTimeout(timer);
		}
	}

	private headers(): Record<string, string> {
		const h: Record<string, string> = { "Content-Type": "application/json" };
		if (this.authToken) {
			h.Authorization = `Bearer ${this.authToken}`;
		}
		return h;
	}
}
