import { EventEmitter } from "node:events";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock dependencies before importing module under test
const mockCheckSsrf =
	vi.fn<(url: string) => Promise<{ resolvedIps: string[]; hostname: string }>>();

vi.mock("./ssrf-guard.js", () => {
	class SsrfError extends Error {
		constructor(msg: string) {
			super(msg);
			this.name = "SsrfError";
		}
	}
	return {
		checkSsrf: (...args: unknown[]) => mockCheckSsrf(args[0] as string),
		SsrfError,
	};
});

const mockNetConnect = vi.fn();
vi.mock("node:net", () => ({
	default: { connect: (...args: unknown[]) => mockNetConnect(...args) },
}));

// Import SsrfError from the mocked module for use in tests
const { SsrfError: MockSsrfError } = await import("./ssrf-guard.js");

import { type ConnectProxyOptions, createConnectHandler } from "./connect-proxy.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface MockSocket extends EventEmitter {
	write: ReturnType<typeof vi.fn>;
	end: ReturnType<typeof vi.fn>;
	destroy: ReturnType<typeof vi.fn>;
	pipe: ReturnType<typeof vi.fn>;
	setTimeout: ReturnType<typeof vi.fn>;
	writtenData: string[];
	destroyed: boolean;
}

function createMockSocket(): MockSocket {
	const emitter = new EventEmitter();
	const mock = Object.assign(emitter, {
		write: vi.fn((data: string) => {
			mock.writtenData.push(data);
			return true;
		}),
		end: vi.fn(),
		destroy: vi.fn(() => {
			mock.destroyed = true;
		}),
		pipe: vi.fn(),
		setTimeout: vi.fn(),
		writtenData: [] as string[],
		destroyed: false,
	});
	return mock;
}

function createMockReq(url: string, headers: Record<string, string> = {}): IncomingMessage {
	return { url, headers } as unknown as IncomingMessage;
}

function createMockAuditLogger() {
	return {
		log: vi.fn(),
		query: vi.fn(),
		close: vi.fn(),
		verifyChain: vi.fn(),
		getSigningPublicKey: vi.fn(),
	};
}

const DEFAULT_BINDINGS = [
	{
		serviceId: "telegram",
		allowedDomains: ["api.telegram.org"],
		credentialFields: ["bot_token"],
	},
	{
		serviceId: "github",
		allowedDomains: ["api.github.com"],
		credentialFields: ["token"],
	},
];

function createHandler(overrides?: Partial<ConnectProxyOptions>) {
	const auditLogger = createMockAuditLogger();
	const opts: ConnectProxyOptions = {
		authToken: "test-secret-token",
		egressBindings: DEFAULT_BINDINGS,
		auditLogger: auditLogger as unknown as import("@sentinel/audit").AuditLogger,
		...overrides,
	};
	const handler = createConnectHandler(opts);
	return { handler, auditLogger };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("connect-proxy", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mockCheckSsrf.mockResolvedValue({ resolvedIps: ["1.2.3.4"], hostname: "api.telegram.org" });
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	describe("target parsing", () => {
		it("rejects missing port in CONNECT target", async () => {
			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("400");
			expect(clientSocket.writtenData[0]).toContain("Bad Request");
			expect(clientSocket.end).toHaveBeenCalled();
			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					tool: "connect_proxy",
					decision: "block",
					result: "blocked_by_policy",
				}),
			);
		});

		it("rejects invalid port number", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:0", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("400");
		});

		it("rejects port > 65535", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:70000", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("400");
		});

		it("rejects empty URL", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = { url: undefined, headers: {} } as unknown as IncomingMessage;

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("400");
		});

		it("rejects NaN port", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:abc", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("400");
		});
	});

	describe("authentication", () => {
		it("rejects when auth configured but no Proxy-Authorization header", async () => {
			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443");

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("407");
			expect(clientSocket.writtenData[0]).toContain("Proxy Authentication Required");
			expect(auditLogger.log).toHaveBeenCalledWith(expect.objectContaining({ decision: "block" }));
		});

		it("rejects invalid scheme (not Bearer)", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Basic dXNlcjpwYXNz",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("407");
			expect(clientSocket.writtenData[0]).toContain("Invalid Proxy-Authorization scheme");
		});

		it("rejects wrong token (timing-safe)", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer wrong-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("407");
			expect(clientSocket.writtenData[0]).toContain("Invalid proxy credentials");
		});

		it("passes without auth when authToken is undefined", async () => {
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation((_port: number, _ip: string, cb: () => void) => {
				// Don't call cb yet — just return the mock socket
				return targetSocket;
			});

			const { handler } = createHandler({ authToken: undefined });
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443");

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			// Should reach net.connect (not rejected)
			expect(mockNetConnect).toHaveBeenCalled();
			// No 407 response
			expect(clientSocket.writtenData).toHaveLength(0);
		});
	});

	describe("domain allowlist", () => {
		it("rejects domain not in allowlist with generic Forbidden", async () => {
			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("evil.example.com:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("403");
			expect(clientSocket.writtenData[0]).toContain("Forbidden");
			// Must NOT leak hostname in response
			expect(clientSocket.writtenData[0]).not.toContain("evil.example.com");
			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					decision: "block",
					result: "blocked_by_policy",
				}),
			);
		});

		it("allows domain in allowlist (case-insensitive)", async () => {
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation(() => targetSocket);

			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("API.TELEGRAM.ORG:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(mockNetConnect).toHaveBeenCalled();
		});
	});

	describe("SSRF protection", () => {
		it("blocks when SSRF check detects private IP", async () => {
			mockCheckSsrf.mockRejectedValue(
				new MockSsrfError("Blocked SSRF: resolved to private IP 127.0.0.1"),
			);

			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("403");
			expect(clientSocket.writtenData[0]).toContain("SSRF protection");
			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					decision: "block",
					result: "blocked_by_policy",
				}),
			);
		});

		it("returns 502 on DNS resolution failure (non-SSRF error)", async () => {
			mockCheckSsrf.mockRejectedValue(new Error("ENOTFOUND"));

			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("502");
			expect(clientSocket.writtenData[0]).toContain("Bad Gateway");
			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					decision: "block",
					result: "failure",
				}),
			);
		});
	});

	describe("successful tunnel", () => {
		it("establishes tunnel with 200 response, pipes, and clears timeouts", async () => {
			let connectCallback: (() => void) | undefined;
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation((_port: number, _ip: string, cb: () => void) => {
				connectCallback = cb;
				return targetSocket;
			});

			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const head = Buffer.from("initial-tls-data");
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, head);

			// Simulate target connect
			expect(connectCallback).toBeDefined();
			connectCallback!();

			// Should write 200 Connection Established
			expect(clientSocket.writtenData[0]).toContain("200 Connection Established");
			expect(clientSocket.writtenData[0]).toContain("X-Sentinel-Request-Id:");

			// Should clear timeouts (setTimeout(0))
			expect(targetSocket.setTimeout).toHaveBeenCalledWith(0);
			expect(clientSocket.setTimeout).toHaveBeenCalledWith(0);

			// Should forward head data
			expect(targetSocket.write).toHaveBeenCalledWith(head);

			// Should set up bidirectional pipes
			expect(targetSocket.pipe).toHaveBeenCalledWith(clientSocket);
			expect(clientSocket.pipe).toHaveBeenCalledWith(targetSocket);

			// Should audit success
			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					tool: "connect_proxy",
					decision: "auto_approve",
					result: "success",
					parameters_summary: expect.stringContaining("CONNECT api.telegram.org:443"),
				}),
			);
		});

		it("does not forward head when buffer is empty", async () => {
			let connectCallback: (() => void) | undefined;
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation((_port: number, _ip: string, cb: () => void) => {
				connectCallback = cb;
				return targetSocket;
			});

			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));
			connectCallback!();

			// Only the 200 response should be written to targetSocket, no head data
			expect(targetSocket.write).not.toHaveBeenCalled();
		});
	});

	describe("connection timeout", () => {
		it("sends 504 when connect phase times out", async () => {
			let timeoutCallback: (() => void) | undefined;
			const targetSocket = createMockSocket();
			targetSocket.setTimeout.mockImplementation((ms: number, cb?: () => void) => {
				if (ms > 0 && cb) {
					timeoutCallback = cb;
				}
			});
			mockNetConnect.mockImplementation(() => targetSocket);

			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			// Trigger timeout
			expect(timeoutCallback).toBeDefined();

			// Track call order to verify write-before-destroy
			const callOrder: string[] = [];
			clientSocket.write.mockImplementation((data: string) => {
				callOrder.push("write");
				clientSocket.writtenData.push(data);
				return true;
			});
			targetSocket.destroy.mockImplementation(() => {
				callOrder.push("destroy");
				targetSocket.destroyed = true;
			});

			timeoutCallback!();

			expect(clientSocket.writtenData[0]).toContain("504");
			expect(clientSocket.writtenData[0]).toContain("Gateway Timeout");
			expect(targetSocket.destroy).toHaveBeenCalled();
			// Write must happen before destroy to avoid race
			expect(callOrder.indexOf("write")).toBeLessThan(callOrder.indexOf("destroy"));
			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					decision: "auto_approve",
					result: "failure",
				}),
			);
		});
	});

	describe("error handling", () => {
		it("sends 502 on target socket error", async () => {
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation(() => targetSocket);

			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			// Simulate target error
			targetSocket.emit("error", new Error("ECONNREFUSED"));

			expect(clientSocket.writtenData[0]).toContain("502");
			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					decision: "auto_approve",
					result: "failure",
				}),
			);
		});

		it("destroys target on client socket error", async () => {
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation(() => targetSocket);

			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			// Simulate client error
			clientSocket.emit("error", new Error("ECONNRESET"));

			expect(targetSocket.destroy).toHaveBeenCalled();
		});

		it("destroys peer on close", async () => {
			let connectCallback: (() => void) | undefined;
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation((_port: number, _ip: string, cb: () => void) => {
				connectCallback = cb;
				return targetSocket;
			});

			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));
			connectCallback!();

			// Client closes
			clientSocket.emit("close");
			expect(targetSocket.destroy).toHaveBeenCalled();

			// Target closes
			targetSocket.emit("close");
			expect(clientSocket.destroy).toHaveBeenCalled();
		});
	});

	describe("audit logging", () => {
		it("logs all required fields for successful tunnel", async () => {
			let connectCallback: (() => void) | undefined;
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation((_port: number, _ip: string, cb: () => void) => {
				connectCallback = cb;
				return targetSocket;
			});

			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.github.com:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));
			connectCallback!();

			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					id: expect.any(String),
					timestamp: expect.any(String),
					manifestId: expect.any(String),
					sessionId: "connect-proxy",
					agentId: "unknown",
					tool: "connect_proxy",
					category: "write",
					decision: "auto_approve",
					result: "success",
					parameters_summary: "CONNECT api.github.com:443",
					duration_ms: expect.any(Number),
				}),
			);
		});

		it("does not throw when audit logger fails", async () => {
			const auditLogger = createMockAuditLogger();
			auditLogger.log.mockImplementation(() => {
				throw new Error("DB write failed");
			});

			const { handler } = createHandler({
				auditLogger: auditLogger as unknown as import("@sentinel/audit").AuditLogger,
			});
			const clientSocket = createMockSocket();
			const req = createMockReq("no-port");

			// Should not throw even when audit logging fails
			await expect(
				handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0)),
			).resolves.toBeUndefined();
		});
	});

	describe("connect timeout value", () => {
		it("sets 10s connect-phase timeout on target socket", async () => {
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation(() => targetSocket);

			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			// First setTimeout call should be the 10s connect-phase timeout
			expect(targetSocket.setTimeout).toHaveBeenCalledWith(10_000, expect.any(Function));
		});
	});

	describe("writeReject on destroyed socket", () => {
		it("does not throw when socket is already destroyed", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			clientSocket.destroyed = true;
			const req = createMockReq("no-port");

			// Should not throw even when socket is already destroyed
			await expect(
				handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0)),
			).resolves.toBeUndefined();
			// write should NOT have been called on a destroyed socket
			expect(clientSocket.write).not.toHaveBeenCalled();
		});

		it("does not throw when socket.write throws", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			clientSocket.write.mockImplementation(() => {
				throw new Error("Socket closed");
			});
			const req = createMockReq("no-port");

			await expect(
				handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0)),
			).resolves.toBeUndefined();
		});
	});

	describe("malformed Bearer header", () => {
		it("rejects empty token after Bearer prefix", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer ",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("407");
		});

		it("rejects double space in Bearer header", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer  token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("407");
		});
	});

	describe("IPv6 CONNECT target", () => {
		it("rejects [::1]:443 — brackets in hostname fail allowlist", async () => {
			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("[::1]:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("403");
		});
	});

	describe("empty egress bindings", () => {
		it("rejects all requests with 403 (fail-closed)", async () => {
			const { handler } = createHandler({ egressBindings: [] });
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(clientSocket.writtenData[0]).toContain("403");
			expect(mockNetConnect).not.toHaveBeenCalled();
		});
	});

	describe("agentId from X-Sentinel-Agent-Id header", () => {
		it("uses header value in audit log", async () => {
			let connectCallback: (() => void) | undefined;
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation((_port: number, _ip: string, cb: () => void) => {
				connectCallback = cb;
				return targetSocket;
			});

			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
				"x-sentinel-agent-id": "agent-007",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));
			connectCallback!();

			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					agentId: "agent-007",
					decision: "auto_approve",
					result: "success",
				}),
			);
		});

		it("falls back to 'unknown' when header is absent", async () => {
			const { handler, auditLogger } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("evil.example.com:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			expect(auditLogger.log).toHaveBeenCalledWith(
				expect.objectContaining({
					agentId: "unknown",
				}),
			);
		});
	});

	describe("DNS-pinned connection", () => {
		it("calls net.connect with resolved IP, not hostname", async () => {
			mockCheckSsrf.mockResolvedValue({
				resolvedIps: ["93.184.216.34"],
				hostname: "api.telegram.org",
			});
			const targetSocket = createMockSocket();
			mockNetConnect.mockImplementation(() => targetSocket);

			const { handler } = createHandler();
			const clientSocket = createMockSocket();
			const req = createMockReq("api.telegram.org:443", {
				"proxy-authorization": "Bearer test-secret-token",
			});

			await handler(req, clientSocket as unknown as Duplex, Buffer.alloc(0));

			// Must connect to the resolved IP, not the hostname
			expect(mockNetConnect).toHaveBeenCalledWith(443, "93.184.216.34", expect.any(Function));
		});
	});
});
