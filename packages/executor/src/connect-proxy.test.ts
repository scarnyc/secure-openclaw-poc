import { EventEmitter } from "node:events";
import type { IncomingMessage } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { initConnectProxy } from "./connect-proxy.js";

// ---------------------------------------------------------------------------
// Mock AuditLogger
// ---------------------------------------------------------------------------

function createMockAuditLogger() {
	return {
		log: vi.fn(),
		getSigningPublicKey: vi.fn(),
		verifyChain: vi.fn(),
		close: vi.fn(),
	};
}

// ---------------------------------------------------------------------------
// Mock socket that captures writes and pipe calls
// ---------------------------------------------------------------------------

class MockSocket extends EventEmitter {
	written: string[] = [];
	destroyed = false;
	pipedTo: MockSocket | null = null;

	write(data: string | Buffer): boolean {
		this.written.push(typeof data === "string" ? data : data.toString());
		return true;
	}

	destroy(): void {
		this.destroyed = true;
		this.emit("close");
	}

	pipe(dest: MockSocket): MockSocket {
		this.pipedTo = dest;
		return dest;
	}

	setTimeout(_ms: number): void {
		// no-op for tests
	}
}

// ---------------------------------------------------------------------------
// Helper to capture the "connect" listener from initConnectProxy
// ---------------------------------------------------------------------------

type ConnectListener = (req: IncomingMessage, clientSocket: MockSocket, head: Buffer) => void;

function setupProxy(
	allowedDomains: string[],
	auditLogger: ReturnType<typeof createMockAuditLogger>,
): ConnectListener {
	let connectListener: ConnectListener | undefined;

	const mockServer = {
		on(_event: string, listener: ConnectListener) {
			connectListener = listener;
		},
	};

	// Cast through unknown — MockSocket has the methods we need for testing
	initConnectProxy(
		mockServer as unknown as Parameters<typeof initConnectProxy>[0],
		allowedDomains,
		auditLogger as never,
	);

	if (!connectListener) {
		throw new Error("initConnectProxy did not register a connect listener");
	}

	return connectListener;
}

function makeRequest(url: string): IncomingMessage {
	return { url } as IncomingMessage;
}

// ---------------------------------------------------------------------------
// Mock net.connect to avoid real TCP connections
// ---------------------------------------------------------------------------

vi.mock("node:net", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:net")>();
	return {
		...actual,
		connect: vi.fn((...args: unknown[]) => {
			const callback = args.find((a) => typeof a === "function") as (() => void) | undefined;
			const socket = new MockSocket();
			if (callback) {
				setTimeout(callback, 0);
			}
			return socket;
		}),
	};
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("connect-proxy", () => {
	let auditLogger: ReturnType<typeof createMockAuditLogger>;
	let handler: ConnectListener;

	beforeEach(() => {
		auditLogger = createMockAuditLogger();
		vi.clearAllMocks();
	});

	describe("domain filtering", () => {
		beforeEach(() => {
			handler = setupProxy(["api.telegram.org", "api.openai.com"], auditLogger);
		});

		it("rejects CONNECT to non-allowed domain with 403", () => {
			const clientSocket = new MockSocket();
			handler(makeRequest("evil.example.com:443"), clientSocket, Buffer.alloc(0));

			expect(clientSocket.written).toContain("HTTP/1.1 403 Forbidden\r\n\r\n");
			expect(clientSocket.destroyed).toBe(true);
			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					tool: "connect_proxy",
					decision: "block",
					result: "blocked_by_policy",
					parameters_summary: "CONNECT evil.example.com:443",
				}),
			);
		});

		it("rejects CONNECT to non-443 port with 403", () => {
			const clientSocket = new MockSocket();
			handler(makeRequest("api.telegram.org:80"), clientSocket, Buffer.alloc(0));

			expect(clientSocket.written).toContain("HTTP/1.1 403 Forbidden\r\n\r\n");
			expect(clientSocket.destroyed).toBe(true);
			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					decision: "block",
				}),
			);
		});

		it("rejects CONNECT with empty target", () => {
			const clientSocket = new MockSocket();
			handler(makeRequest(""), clientSocket, Buffer.alloc(0));

			expect(clientSocket.written).toContain("HTTP/1.1 403 Forbidden\r\n\r\n");
			expect(clientSocket.destroyed).toBe(true);
		});

		it("domain matching is case-insensitive", async () => {
			const clientSocket = new MockSocket();
			handler(makeRequest("API.TELEGRAM.ORG:443"), clientSocket, Buffer.alloc(0));

			// Should NOT be rejected — wait for async connect callback
			await vi.waitFor(() => {
				expect(clientSocket.written).not.toContain("HTTP/1.1 403 Forbidden\r\n\r\n");
			});
		});

		it("allows CONNECT to permitted domain on port 443", async () => {
			const clientSocket = new MockSocket();
			handler(makeRequest("api.telegram.org:443"), clientSocket, Buffer.alloc(0));

			// Wait for the async net.connect callback
			await vi.waitFor(() => {
				expect(clientSocket.written).toContain("HTTP/1.1 200 Connection Established\r\n\r\n");
			});
		});

		it("allows CONNECT to second permitted domain", async () => {
			const clientSocket = new MockSocket();
			handler(makeRequest("api.openai.com:443"), clientSocket, Buffer.alloc(0));

			await vi.waitFor(() => {
				expect(clientSocket.written).toContain("HTTP/1.1 200 Connection Established\r\n\r\n");
			});
		});
	});

	describe("tunnel establishment", () => {
		beforeEach(() => {
			handler = setupProxy(["api.telegram.org"], auditLogger);
		});

		it("pipes client and upstream sockets bidirectionally", async () => {
			const clientSocket = new MockSocket();
			handler(makeRequest("api.telegram.org:443"), clientSocket, Buffer.alloc(0));

			await vi.waitFor(() => {
				expect(clientSocket.written).toContain("HTTP/1.1 200 Connection Established\r\n\r\n");
			});

			// Verify bidirectional piping was set up
			expect(clientSocket.pipedTo).toBeTruthy();
		});

		it("sends buffered head data to upstream after connect", async () => {
			const { connect: mockConnect } = await import("node:net");
			let upstreamSocket: MockSocket | undefined;
			vi.mocked(mockConnect).mockImplementation((...args: unknown[]) => {
				const cb = args.find((a) => typeof a === "function") as (() => void) | undefined;
				upstreamSocket = new MockSocket();
				if (cb) setTimeout(cb, 0);
				return upstreamSocket as never;
			});

			const clientSocket = new MockSocket();
			const headData = Buffer.from("TLS-CLIENT-HELLO");
			handler(makeRequest("api.telegram.org:443"), clientSocket, headData);

			await vi.waitFor(() => {
				expect(clientSocket.written).toContain("HTTP/1.1 200 Connection Established\r\n\r\n");
			});

			// Head data should have been forwarded to upstream
			expect(upstreamSocket).toBeTruthy();
			expect(upstreamSocket!.written).toContain("TLS-CLIENT-HELLO");
		});

		it("does not send empty head buffer", async () => {
			const { connect: mockConnect } = await import("node:net");
			let upstreamSocket: MockSocket | undefined;
			vi.mocked(mockConnect).mockImplementation((...args: unknown[]) => {
				const cb = args.find((a) => typeof a === "function") as (() => void) | undefined;
				upstreamSocket = new MockSocket();
				if (cb) setTimeout(cb, 0);
				return upstreamSocket as never;
			});

			const clientSocket = new MockSocket();
			handler(makeRequest("api.telegram.org:443"), clientSocket, Buffer.alloc(0));

			await vi.waitFor(() => {
				expect(clientSocket.written).toContain("HTTP/1.1 200 Connection Established\r\n\r\n");
			});

			expect(upstreamSocket!.written).toHaveLength(0);
		});

		it("audit logs allow decisions for established tunnels", async () => {
			const clientSocket = new MockSocket();
			handler(makeRequest("api.telegram.org:443"), clientSocket, Buffer.alloc(0));

			await vi.waitFor(() => {
				expect(auditLogger.log).toHaveBeenCalledWith(
					expect.objectContaining({
						tool: "connect_proxy",
						decision: "auto_approve",
						result: "success",
						parameters_summary: "CONNECT api.telegram.org:443",
					}),
				);
			});
		});
	});

	describe("error handling", () => {
		beforeEach(() => {
			handler = setupProxy(["api.telegram.org"], auditLogger);
		});

		it("returns 502 and destroys client when upstream errors", async () => {
			const { connect: mockConnect } = await import("node:net");
			let upstreamSocket: MockSocket | undefined;
			vi.mocked(mockConnect).mockImplementation((..._args: unknown[]) => {
				upstreamSocket = new MockSocket();
				setTimeout(() => {
					upstreamSocket!.emit("error", new Error("Connection refused"));
				}, 0);
				return upstreamSocket as never;
			});

			const clientSocket = new MockSocket();
			handler(makeRequest("api.telegram.org:443"), clientSocket, Buffer.alloc(0));

			await vi.waitFor(() => {
				expect(clientSocket.written).toContain("HTTP/1.1 502 Bad Gateway\r\n\r\n");
				expect(clientSocket.destroyed).toBe(true);
			});
		});

		it("destroys upstream when client errors", async () => {
			const { connect: mockConnect } = await import("node:net");
			let upstreamSocket: MockSocket | undefined;
			vi.mocked(mockConnect).mockImplementation((...args: unknown[]) => {
				const cb = args.find((a) => typeof a === "function") as (() => void) | undefined;
				upstreamSocket = new MockSocket();
				if (cb) setTimeout(cb, 0);
				return upstreamSocket as never;
			});

			const clientSocket = new MockSocket();
			handler(makeRequest("api.telegram.org:443"), clientSocket, Buffer.alloc(0));

			// Wait for tunnel to establish
			await vi.waitFor(() => {
				expect(clientSocket.written).toContain("HTTP/1.1 200 Connection Established\r\n\r\n");
			});

			// Simulate client error
			clientSocket.emit("error", new Error("Client disconnected"));

			expect(upstreamSocket!.destroyed).toBe(true);
		});

		it("does not write 502 if client already destroyed", async () => {
			const { connect: mockConnect } = await import("node:net");
			vi.mocked(mockConnect).mockImplementation((..._args: unknown[]) => {
				const upstream = new MockSocket();
				setTimeout(() => {
					upstream.emit("error", new Error("Connection refused"));
				}, 0);
				return upstream as never;
			});

			const clientSocket = new MockSocket();
			// Pre-destroy the client
			clientSocket.destroyed = true;
			handler(makeRequest("api.telegram.org:443"), clientSocket, Buffer.alloc(0));

			// Should not crash — the 502 write is guarded by !clientSocket.destroyed
			await new Promise((r) => setTimeout(r, 10));
			// No 502 written because client was already destroyed
			expect(clientSocket.written).not.toContain("HTTP/1.1 502 Bad Gateway\r\n\r\n");
		});
	});
});
