import type { ActionManifest, ToolResult } from "@sentinel/types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ExecutorClient } from "./executor-client.js";

const mockFetch = vi.fn();

beforeEach(() => {
	vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
	vi.restoreAllMocks();
});

function makeManifest(overrides?: Partial<ActionManifest>): ActionManifest {
	return {
		id: "00000000-0000-4000-8000-000000000001",
		timestamp: new Date().toISOString(),
		tool: "bash",
		parameters: { command: "ls" },
		sessionId: "test-session",
		agentId: "test-agent",
		...overrides,
	};
}

function makeResult(overrides?: Partial<ToolResult>): ToolResult {
	return {
		manifestId: "00000000-0000-4000-8000-000000000001",
		success: true,
		output: "file1.ts\nfile2.ts",
		duration_ms: 42,
		...overrides,
	};
}

describe("ExecutorClient", () => {
	describe("execute", () => {
		it("sends POST with correct body and returns parsed result", async () => {
			const result = makeResult();
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve(result),
			});

			const client = new ExecutorClient("http://127.0.0.1:3141");
			const manifest = makeManifest();
			const response = await client.execute(manifest);

			expect(mockFetch).toHaveBeenCalledOnce();
			const [url, init] = mockFetch.mock.calls[0];
			expect(url).toBe("http://127.0.0.1:3141/execute");
			expect(init.method).toBe("POST");
			expect(init.headers["Content-Type"]).toBe("application/json");
			expect(JSON.parse(init.body)).toEqual(manifest);
			expect(response).toEqual(result);
		});

		it("throws on non-ok response", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: false,
				status: 403,
				text: () => Promise.resolve("Forbidden"),
			});

			const client = new ExecutorClient();
			await expect(client.execute(makeManifest())).rejects.toThrow(
				"Executor returned 403: Forbidden",
			);
		});

		it("does not retry on failure", async () => {
			mockFetch.mockResolvedValueOnce({
				ok: false,
				status: 403,
				text: () => Promise.resolve("Denied"),
			});

			const client = new ExecutorClient();
			await expect(client.execute(makeManifest())).rejects.toThrow();
			expect(mockFetch).toHaveBeenCalledOnce();
		});
	});

	describe("health", () => {
		it("returns true on 200", async () => {
			mockFetch.mockResolvedValueOnce({ ok: true });

			const client = new ExecutorClient();
			expect(await client.health()).toBe(true);
		});

		it("returns false on error", async () => {
			mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

			const client = new ExecutorClient();
			expect(await client.health()).toBe(false);
		});

		it("returns false on non-ok response", async () => {
			mockFetch.mockResolvedValueOnce({ ok: false, status: 503 });

			const client = new ExecutorClient();
			expect(await client.health()).toBe(false);
		});
	});

	describe("getTools", () => {
		it("returns parsed tool array", async () => {
			const tools = [
				{ name: "bash", source: "builtin" },
				{ name: "read_file", source: "builtin" },
			];
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve(tools),
			});

			const client = new ExecutorClient();
			const result = await client.getTools();

			expect(result).toEqual(tools);
			const [url] = mockFetch.mock.calls[0];
			expect(url).toBe("http://127.0.0.1:3141/tools");
		});

		it("throws on failure", async () => {
			mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });

			const client = new ExecutorClient();
			await expect(client.getTools()).rejects.toThrow("Failed to fetch tools: 500");
		});
	});
});
