import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SentinelGuard, SentinelGuardError } from "./index.js";

const EXECUTOR_URL = "http://localhost:3141";
const AUTH_TOKEN = "test-token-abc";

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function textResponse(text: string, status: number): Response {
	return new Response(text, { status });
}

const mockFetch = vi.fn<typeof fetch>();

beforeEach(() => {
	vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("SentinelGuard", () => {
	describe("constructor validation", () => {
		it("throws when executorUrl is empty", () => {
			expect(() => new SentinelGuard({ executorUrl: "" })).toThrow(SentinelGuardError);
			expect(() => new SentinelGuard({ executorUrl: "" })).toThrow("executorUrl is required");
		});

		it("throws when timeoutMs is zero", () => {
			expect(() => new SentinelGuard({ executorUrl: EXECUTOR_URL, timeoutMs: 0 })).toThrow(
				"timeoutMs must be positive",
			);
		});

		it("throws when timeoutMs is negative", () => {
			expect(() => new SentinelGuard({ executorUrl: EXECUTOR_URL, timeoutMs: -100 })).toThrow(
				SentinelGuardError,
			);
		});
	});

	describe("classify", () => {
		it("sends correct POST body and returns parsed response", async () => {
			const expected = {
				decision: "auto_approve",
				category: "read",
				manifestId: "m-001",
				reason: "whitelisted",
			};
			mockFetch.mockResolvedValueOnce(jsonResponse(expected));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			const result = await guard.classify(
				"file_read",
				{ path: "/tmp/test" },
				"agent-1",
				"session-42",
			);

			expect(result).toEqual(expected);
			expect(mockFetch).toHaveBeenCalledOnce();

			const [url, init] = mockFetch.mock.calls[0];
			expect(url).toBe(`${EXECUTOR_URL}/classify`);
			expect(init?.method).toBe("POST");

			const body = JSON.parse(init?.body as string);
			expect(body).toEqual({
				tool: "file_read",
				params: { path: "/tmp/test" },
				agentId: "agent-1",
				sessionId: "session-42",
				source: "guard-client",
			});
		});

		it("defaults sessionId to 'default' when not provided", async () => {
			mockFetch.mockResolvedValueOnce(
				jsonResponse({ decision: "confirm", category: "write", manifestId: "m-002" }),
			);

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			await guard.classify("file_write", { path: "/tmp/x" }, "agent-1");

			const body = JSON.parse(mockFetch.mock.calls[0][1]?.body as string);
			expect(body.sessionId).toBe("default");
		});

		it("includes auth header when token configured", async () => {
			mockFetch.mockResolvedValueOnce(
				jsonResponse({ decision: "block", category: "dangerous", manifestId: "m-003" }),
			);

			const guard = new SentinelGuard({
				executorUrl: EXECUTOR_URL,
				authToken: AUTH_TOKEN,
			});
			await guard.classify("rm_rf", {}, "agent-1");

			const headers = mockFetch.mock.calls[0][1]?.headers as Record<string, string>;
			expect(headers.Authorization).toBe(`Bearer ${AUTH_TOKEN}`);
		});
	});

	describe("filterOutput", () => {
		it("sends correct body with all parameters", async () => {
			const expected = { filtered: "output [REDACTED]", redactedCount: 1 };
			mockFetch.mockResolvedValueOnce(jsonResponse(expected));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			const result = await guard.filterOutput("output sk-abc123", "agent-1", "shell_exec");

			expect(result).toEqual(expected);

			const body = JSON.parse(mockFetch.mock.calls[0][1]?.body as string);
			expect(body).toEqual({
				output: "output sk-abc123",
				agentId: "agent-1",
				tool: "shell_exec",
			});
		});

		it("sends body with optional fields omitted", async () => {
			mockFetch.mockResolvedValueOnce(jsonResponse({ filtered: "clean", redactedCount: 0 }));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			await guard.filterOutput("clean output");

			const body = JSON.parse(mockFetch.mock.calls[0][1]?.body as string);
			expect(body).toEqual({
				output: "clean output",
				agentId: undefined,
				tool: undefined,
			});
		});
	});

	describe("confirmOnly", () => {
		it("sends correct body and uses confirmation timeout", async () => {
			const expected = {
				decision: "approved",
				manifestId: "m-123",
				category: "write",
			};
			mockFetch.mockResolvedValueOnce(jsonResponse(expected));

			const guard = new SentinelGuard({
				executorUrl: EXECUTOR_URL,
				confirmationTimeoutMs: 60_000,
			});
			const result = await guard.confirmOnly(
				"send_email",
				{ to: "test@example.com" },
				"agent-1",
				"session-7",
			);

			expect(result).toEqual(expected);

			const [url, init] = mockFetch.mock.calls[0];
			expect(url).toBe(`${EXECUTOR_URL}/confirm-only`);

			const body = JSON.parse(init?.body as string);
			expect(body).toEqual({
				tool: "send_email",
				params: { to: "test@example.com" },
				agentId: "agent-1",
				sessionId: "session-7",
				source: "guard-client",
			});
		});

		it("defaults sessionId to 'default'", async () => {
			mockFetch.mockResolvedValueOnce(jsonResponse({ decision: "denied", manifestId: "m-456" }));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			await guard.confirmOnly("delete_file", { path: "/" }, "agent-2");

			const body = JSON.parse(mockFetch.mock.calls[0][1]?.body as string);
			expect(body.sessionId).toBe("default");
		});
	});

	describe("pendingConfirmations", () => {
		it("sends GET and returns parsed array", async () => {
			const pending = [
				{
					manifestId: "m-1",
					tool: "send_email",
					parameters: { to: "a@b.com" },
					category: "write",
				},
				{
					manifestId: "m-2",
					tool: "delete_repo",
					parameters: {},
					category: "dangerous",
					reason: "destructive",
				},
			];
			mockFetch.mockResolvedValueOnce(jsonResponse(pending));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			const result = await guard.pendingConfirmations();

			expect(result).toEqual(pending);

			const [url, init] = mockFetch.mock.calls[0];
			expect(url).toBe(`${EXECUTOR_URL}/pending-confirmations`);
			expect(init?.method).toBe("GET");
		});
	});

	describe("awaitConfirmation", () => {
		it("returns true when manifestId disappears from pending list", async () => {
			vi.useFakeTimers();

			// First poll: manifest still pending
			mockFetch.mockResolvedValueOnce(
				jsonResponse([
					{
						manifestId: "m-target",
						tool: "t",
						parameters: {},
						category: "write",
					},
				]),
			);
			// Second poll: manifest resolved (empty list)
			mockFetch.mockResolvedValueOnce(jsonResponse([]));

			const guard = new SentinelGuard({
				executorUrl: EXECUTOR_URL,
				confirmationTimeoutMs: 10_000,
			});
			const promise = guard.awaitConfirmation("m-target");

			// Advance past first poll interval
			await vi.advanceTimersByTimeAsync(2_000);
			// Advance past second poll
			await vi.advanceTimersByTimeAsync(2_000);

			const result = await promise;
			expect(result).toBe(true);
			expect(mockFetch).toHaveBeenCalledTimes(2);

			vi.useRealTimers();
		});

		it("returns false when timeout expires", async () => {
			vi.useFakeTimers();

			// Always return the manifest as pending
			mockFetch.mockImplementation(() =>
				Promise.resolve(
					jsonResponse([
						{
							manifestId: "m-stuck",
							tool: "t",
							parameters: {},
							category: "write",
						},
					]),
				),
			);

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			const promise = guard.awaitConfirmation("m-stuck", 5_000);

			// Advance past the 5s timeout
			await vi.advanceTimersByTimeAsync(6_000);

			const result = await promise;
			expect(result).toBe(false);

			vi.useRealTimers();
		});

		it("throws after 3 consecutive polling errors", async () => {
			vi.useFakeTimers();

			mockFetch.mockRejectedValue(new Error("network failure"));

			const guard = new SentinelGuard({
				executorUrl: EXECUTOR_URL,
				confirmationTimeoutMs: 30_000,
			});
			const promise = guard.awaitConfirmation("m-err");
			// Prevent unhandled rejection warning — we'll inspect the result below
			const settled = promise.catch((err: unknown) => err);

			// Advance through poll cycles — error is thrown on 3rd failed fetch
			await vi.advanceTimersByTimeAsync(2_000);
			await vi.advanceTimersByTimeAsync(2_000);
			await vi.advanceTimersByTimeAsync(100);

			const err = await settled;
			expect(err).toBeInstanceOf(SentinelGuardError);
			expect((err as SentinelGuardError).status).toBe(500);
			expect((err as Error).message).toMatch(/consecutive errors/);

			vi.useRealTimers();
		});

		it("resets error count on successful poll", async () => {
			vi.useFakeTimers();

			// First poll: error
			mockFetch.mockRejectedValueOnce(new Error("transient"));
			// Second poll: success (still pending)
			mockFetch.mockResolvedValueOnce(
				jsonResponse([{ manifestId: "m-x", tool: "t", parameters: {}, category: "write" }]),
			);
			// Third poll: error
			mockFetch.mockRejectedValueOnce(new Error("transient"));
			// Fourth poll: resolved
			mockFetch.mockResolvedValueOnce(jsonResponse([]));

			const guard = new SentinelGuard({
				executorUrl: EXECUTOR_URL,
				confirmationTimeoutMs: 30_000,
			});
			const promise = guard.awaitConfirmation("m-x");

			await vi.advanceTimersByTimeAsync(2_000);
			await vi.advanceTimersByTimeAsync(2_000);
			await vi.advanceTimersByTimeAsync(2_000);
			await vi.advanceTimersByTimeAsync(2_000);

			const result = await promise;
			expect(result).toBe(true);

			vi.useRealTimers();
		});

		it("throws when AbortSignal is already aborted", async () => {
			const controller = new AbortController();
			controller.abort();

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			await expect(
				guard.awaitConfirmation("m-aborted", undefined, controller.signal),
			).rejects.toThrow("Confirmation polling aborted");
		});

		it("throws when AbortSignal is triggered during polling", async () => {
			vi.useFakeTimers();

			mockFetch.mockImplementation(() =>
				Promise.resolve(
					jsonResponse([{ manifestId: "m-cancel", tool: "t", parameters: {}, category: "write" }]),
				),
			);

			const controller = new AbortController();
			const guard = new SentinelGuard({
				executorUrl: EXECUTOR_URL,
				confirmationTimeoutMs: 30_000,
			});
			const promise = guard.awaitConfirmation("m-cancel", undefined, controller.signal);
			// Prevent unhandled rejection warning
			const settled = promise.catch((err: unknown) => err);

			// First poll succeeds (still pending), then abort before next poll
			await vi.advanceTimersByTimeAsync(2_000);
			controller.abort();
			await vi.advanceTimersByTimeAsync(2_100);

			const err = await settled;
			expect(err).toBeInstanceOf(SentinelGuardError);
			expect((err as Error).message).toBe("Confirmation polling aborted");

			vi.useRealTimers();
		});
	});

	describe("proxyLlm", () => {
		it("constructs correct URL path and returns raw Response", async () => {
			const llmResponse = new Response(JSON.stringify({ choices: [{ text: "hello" }] }), {
				status: 200,
			});
			mockFetch.mockResolvedValueOnce(llmResponse);

			const guard = new SentinelGuard({
				executorUrl: EXECUTOR_URL,
				authToken: AUTH_TOKEN,
			});
			const result = await guard.proxyLlm("openai", "v1/chat/completions", {
				model: "gpt-4",
				messages: [],
			});

			expect(result).toBe(llmResponse);

			const [url, init] = mockFetch.mock.calls[0];
			expect(url).toBe(`${EXECUTOR_URL}/proxy/llm/openai/v1/chat/completions`);
			expect(init?.method).toBe("POST");
		});

		it("throws SentinelGuardError on non-ok response", async () => {
			mockFetch.mockResolvedValueOnce(textResponse("rate limited", 429));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });

			await expect(guard.proxyLlm("anthropic", "v1/messages", {})).rejects.toThrow(
				SentinelGuardError,
			);
		});

		it("wraps AbortError as SentinelGuardError with status 408", async () => {
			const abortError = new Error("The operation was aborted");
			abortError.name = "AbortError";
			mockFetch.mockRejectedValueOnce(abortError);

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });

			try {
				await guard.proxyLlm("openai", "v1/chat/completions", {});
				expect.fail("should have thrown");
			} catch (err) {
				expect(err).toBeInstanceOf(SentinelGuardError);
				const guardErr = err as SentinelGuardError;
				expect(guardErr.status).toBe(408);
				expect(guardErr.message).toBe("Request timed out");
			}
		});
	});

	describe("health", () => {
		it("returns parsed response on success", async () => {
			mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok", version: "0.1.0" }));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			const result = await guard.health();

			expect(result).toEqual({ status: "ok", version: "0.1.0" });
		});

		it("returns {status: 'unreachable'} on network error", async () => {
			mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			const result = await guard.health();

			expect(result).toEqual({ status: "unreachable" });
		});

		it("returns {status: 'unreachable'} on non-ok HTTP response", async () => {
			mockFetch.mockResolvedValueOnce(textResponse("down", 503));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			const result = await guard.health();

			expect(result).toEqual({ status: "unreachable" });
		});
	});

	describe("error handling", () => {
		it("throws SentinelGuardError with status on non-ok response", async () => {
			mockFetch.mockResolvedValueOnce(textResponse("forbidden: invalid token", 403));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });

			try {
				await guard.classify("test", {}, "agent-1");
				expect.fail("should have thrown");
			} catch (err) {
				expect(err).toBeInstanceOf(SentinelGuardError);
				const guardErr = err as SentinelGuardError;
				expect(guardErr.status).toBe(403);
				expect(guardErr.message).toContain("403");
				expect(guardErr.message).toContain("forbidden: invalid token");
			}
		});

		it("throws SentinelGuardError on 500 from filter-output", async () => {
			mockFetch.mockResolvedValueOnce(textResponse("internal error", 500));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });

			await expect(guard.filterOutput("test")).rejects.toThrow(SentinelGuardError);
		});

		it("wraps AbortError in post() as SentinelGuardError with status 408", async () => {
			const abortError = new Error("The operation was aborted");
			abortError.name = "AbortError";
			mockFetch.mockRejectedValueOnce(abortError);

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });

			try {
				await guard.classify("test", {}, "agent-1");
				expect.fail("should have thrown");
			} catch (err) {
				expect(err).toBeInstanceOf(SentinelGuardError);
				const guardErr = err as SentinelGuardError;
				expect(guardErr.status).toBe(408);
				expect(guardErr.message).toBe("Request timed out");
			}
		});

		it("wraps AbortError in get() as SentinelGuardError with status 408", async () => {
			const abortError = new Error("The operation was aborted");
			abortError.name = "AbortError";
			mockFetch.mockRejectedValueOnce(abortError);

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });

			try {
				await guard.pendingConfirmations();
				expect.fail("should have thrown");
			} catch (err) {
				expect(err).toBeInstanceOf(SentinelGuardError);
				const guardErr = err as SentinelGuardError;
				expect(guardErr.status).toBe(408);
				expect(guardErr.message).toBe("Request timed out");
			}
		});

		it("rejects non-object response from post()", async () => {
			mockFetch.mockResolvedValueOnce(
				new Response(JSON.stringify("just a string"), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				}),
			);

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });

			await expect(guard.classify("test", {}, "agent-1")).rejects.toThrow(
				/Invalid response shape.*expected object/,
			);
		});

		it("rejects non-array response from pendingConfirmations()", async () => {
			mockFetch.mockResolvedValueOnce(jsonResponse({ not: "an array" }));

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });

			await expect(guard.pendingConfirmations()).rejects.toThrow(
				/Invalid response shape.*expected array/,
			);
		});
	});

	describe("auth header", () => {
		it("omits Authorization header when no token set", async () => {
			mockFetch.mockResolvedValueOnce(
				jsonResponse({ decision: "auto_approve", category: "read", manifestId: "m-010" }),
			);

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			await guard.classify("test", {}, "agent-1");

			const headers = mockFetch.mock.calls[0][1]?.headers as Record<string, string>;
			expect(headers.Authorization).toBeUndefined();
			expect(headers["Content-Type"]).toBe("application/json");
		});

		it("includes Bearer token when authToken is set", async () => {
			mockFetch.mockResolvedValueOnce(
				jsonResponse({ decision: "confirm", category: "write", manifestId: "m-011" }),
			);

			const guard = new SentinelGuard({
				executorUrl: EXECUTOR_URL,
				authToken: "my-secret",
			});
			await guard.classify("test", {}, "agent-1");

			const headers = mockFetch.mock.calls[0][1]?.headers as Record<string, string>;
			expect(headers.Authorization).toBe("Bearer my-secret");
		});
	});

	describe("URL normalization", () => {
		it("strips trailing slashes from executorUrl", async () => {
			mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));

			const guard = new SentinelGuard({
				executorUrl: "http://localhost:3141///",
			});
			await guard.health();

			const url = mockFetch.mock.calls[0][0];
			expect(url).toBe("http://localhost:3141/health");
		});

		it("works with URL that has no trailing slash", async () => {
			mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));

			const guard = new SentinelGuard({
				executorUrl: "http://executor:3141",
			});
			await guard.health();

			const url = mockFetch.mock.calls[0][0];
			expect(url).toBe("http://executor:3141/health");
		});
	});

	describe("timeout defaults", () => {
		it("uses 30s default timeout for regular requests", async () => {
			mockFetch.mockResolvedValueOnce(
				jsonResponse({ decision: "auto_approve", category: "read", manifestId: "m-020" }),
			);

			const guard = new SentinelGuard({ executorUrl: EXECUTOR_URL });
			await guard.classify("test", {}, "agent-1");

			// Verify AbortSignal was passed (indicates timeout was set)
			const init = mockFetch.mock.calls[0][1];
			expect(init?.signal).toBeDefined();
		});

		it("uses custom timeoutMs when provided", async () => {
			mockFetch.mockResolvedValueOnce(
				jsonResponse({ decision: "auto_approve", category: "read", manifestId: "m-021" }),
			);

			const guard = new SentinelGuard({
				executorUrl: EXECUTOR_URL,
				timeoutMs: 5_000,
			});
			await guard.classify("test", {}, "agent-1");

			const init = mockFetch.mock.calls[0][1];
			expect(init?.signal).toBeDefined();
		});
	});
});
