import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PendingConfirmation } from "./confirmation-tui.js";

// Mock @clack/prompts before importing the module under test
vi.mock("@clack/prompts", () => ({
	confirm: vi.fn().mockResolvedValue(true),
	isCancel: vi.fn().mockReturnValue(false),
}));

const { startConfirmationPoller } = await import("./confirmation-tui.js");

const SAMPLE: PendingConfirmation = {
	manifestId: "poller-test-001",
	tool: "bash",
	parameters: { command: "ls" },
	category: "safe",
	reason: "Read-only",
};

let server: Server;
let serverPort: number;
let executorUrl: string;
let handler: (req: IncomingMessage, res: ServerResponse) => void;

beforeEach(async () => {
	handler = (_req, res) => {
		res.writeHead(200, { "Content-Type": "application/json" });
		res.end("[]");
	};

	server = createServer((req, res) => handler(req, res));
	await new Promise<void>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const addr = server.address();
			if (addr && typeof addr === "object") {
				serverPort = addr.port;
				executorUrl = `http://127.0.0.1:${serverPort}`;
			}
			resolve();
		});
	});
});

afterEach(async () => {
	await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("startConfirmationPoller", () => {
	it("aborts cleanly when signal is already aborted", async () => {
		const ctrl = new AbortController();
		ctrl.abort();
		await expect(startConfirmationPoller(executorUrl, ctrl.signal)).resolves.toBeUndefined();
	});

	it("deduplicates confirmations by manifestId", async () => {
		const confirmCalls: string[] = [];

		handler = (req, res) => {
			if (req.url === "/pending-confirmations") {
				res.writeHead(200, { "Content-Type": "application/json" });
				// Return same ID twice in one response
				res.end(JSON.stringify([SAMPLE, SAMPLE]));
			} else if (req.url?.startsWith("/confirm/")) {
				const id = req.url.split("/confirm/")[1];
				confirmCalls.push(id);
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ status: "approved" }));
			} else {
				res.writeHead(404);
				res.end();
			}
		};

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		await new Promise((r) => setTimeout(r, 300));
		ctrl.abort();
		await promise;

		expect(confirmCalls.filter((id) => id === "poller-test-001")).toHaveLength(1);
	});

	it("handles non-ok poll response without crashing", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		handler = (_req, res) => {
			res.writeHead(503);
			res.end();
		};

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		await new Promise((r) => setTimeout(r, 300));
		ctrl.abort();
		await promise;

		expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("503"));
		consoleSpy.mockRestore();
	});

	it("handles invalid poll response format gracefully", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		handler = (_req, res) => {
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ notAnArray: true }));
		};

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		await new Promise((r) => setTimeout(r, 300));
		ctrl.abort();
		await promise;

		expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("Invalid poll response"));
		consoleSpy.mockRestore();
	});

	it("retries confirmation POST on failure by removing from seenIds", async () => {
		const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		let postAttempts = 0;

		handler = (req, res) => {
			if (req.url === "/pending-confirmations") {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify([SAMPLE]));
			} else if (req.url?.startsWith("/confirm/")) {
				postAttempts++;
				if (postAttempts === 1) {
					// Destroy the connection to simulate network error
					res.destroy();
					return;
				}
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ status: "approved" }));
			} else {
				res.writeHead(404);
				res.end();
			}
		};

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		// Give enough time for two poll cycles
		await new Promise((r) => setTimeout(r, 1500));
		ctrl.abort();
		await promise;

		expect(postAttempts).toBeGreaterThanOrEqual(2);
		consoleSpy.mockRestore();
	});

	it("posts correct approval decision to executor", async () => {
		let receivedBody: string | undefined;

		handler = (req, res) => {
			if (req.url === "/pending-confirmations") {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify([SAMPLE]));
			} else if (req.url?.startsWith("/confirm/")) {
				let body = "";
				req.on("data", (chunk: Buffer) => {
					body += chunk.toString();
				});
				req.on("end", () => {
					receivedBody = body;
					res.writeHead(200, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ status: "approved" }));
				});
			} else {
				res.writeHead(404);
				res.end();
			}
		};

		const ctrl = new AbortController();
		const promise = startConfirmationPoller(executorUrl, ctrl.signal);

		await new Promise((r) => setTimeout(r, 300));
		ctrl.abort();
		await promise;

		expect(receivedBody).toBeDefined();
		const parsed = JSON.parse(receivedBody as string);
		expect(parsed).toEqual({ approved: true });
	});
});
