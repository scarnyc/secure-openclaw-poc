import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import net from "node:net";
import type { Duplex } from "node:stream";
import type { AuditLogger } from "@sentinel/audit";
import type { EgressBinding } from "@sentinel/types";
import { checkSsrf, SsrfError } from "./ssrf-guard.js";

/** Build domain allowlist from egress bindings. */
function buildAllowedDomains(bindings: EgressBinding[]): Set<string> {
	const domains = new Set<string>();
	for (const binding of bindings) {
		for (const domain of binding.allowedDomains) {
			domains.add(domain.toLowerCase());
		}
	}
	return domains;
}

export interface ConnectProxyOptions {
	authToken?: string;
	egressBindings: EgressBinding[];
	auditLogger: AuditLogger;
}

/** Connect-phase timeout: 10 seconds. */
const CONNECT_TIMEOUT_MS = 10_000;

/**
 * Create a handler for HTTP CONNECT requests.
 * Attach to the Node.js http.Server 'connect' event.
 *
 * Flow:
 * 1. Authenticate (Bearer token from Proxy-Authorization header)
 * 2. Parse target hostname:port from CONNECT request
 * 3. Check domain against allowlist (from egress bindings)
 * 4. SSRF guard check on resolved IPs
 * 5. Create TCP connection to target
 * 6. Pipe bidirectional tunnel
 * 7. Audit log the request
 */
export function createConnectHandler(options: ConnectProxyOptions) {
	const allowedDomains = buildAllowedDomains(options.egressBindings);
	const { authToken, auditLogger } = options;

	return async (req: IncomingMessage, clientSocket: Duplex, head: Buffer) => {
		const reqId = crypto.randomUUID().slice(0, 8);
		const startTime = Date.now();

		// Extract agent ID from header (if present)
		const agentId = (req.headers["x-sentinel-agent-id"] as string | undefined) ?? "unknown";

		// Parse CONNECT target — format: "hostname:port"
		const target = req.url ?? "";
		const colonIndex = target.lastIndexOf(":");
		if (colonIndex <= 0) {
			writeReject(clientSocket, 400, "Bad Request: invalid CONNECT target");
			auditConnect(auditLogger, reqId, target, "block", "blocked_by_policy", startTime, agentId);
			return;
		}
		const hostname = target.slice(0, colonIndex).toLowerCase();
		const port = Number.parseInt(target.slice(colonIndex + 1), 10);
		if (!hostname || Number.isNaN(port) || port <= 0 || port > 65535) {
			writeReject(clientSocket, 400, "Bad Request: invalid hostname or port");
			auditConnect(auditLogger, reqId, target, "block", "blocked_by_policy", startTime, agentId);
			return;
		}

		console.log(`[connect-proxy][${reqId}] CONNECT ${hostname}:${port}`);

		// Auth check — Proxy-Authorization: Bearer <token>
		if (authToken) {
			const proxyAuth = req.headers["proxy-authorization"];
			if (!proxyAuth) {
				writeReject(clientSocket, 407, "Proxy Authentication Required");
				auditConnect(auditLogger, reqId, target, "block", "blocked_by_policy", startTime, agentId);
				return;
			}
			const parts = proxyAuth.split(" ");
			if (parts.length !== 2 || parts[0] !== "Bearer") {
				writeReject(clientSocket, 407, "Invalid Proxy-Authorization scheme");
				auditConnect(auditLogger, reqId, target, "block", "blocked_by_policy", startTime, agentId);
				return;
			}
			const tokenBuf = Buffer.from(parts[1]);
			const expectedBuf = Buffer.from(authToken);
			if (tokenBuf.length !== expectedBuf.length || !timingSafeEqual(tokenBuf, expectedBuf)) {
				writeReject(clientSocket, 407, "Invalid proxy credentials");
				auditConnect(auditLogger, reqId, target, "block", "blocked_by_policy", startTime, agentId);
				return;
			}
		}

		// Domain allowlist check
		if (!allowedDomains.has(hostname)) {
			console.warn(`[connect-proxy][${reqId}] Blocked: ${hostname} not in allowlist`);
			writeReject(clientSocket, 403, "Forbidden");
			auditConnect(auditLogger, reqId, target, "block", "blocked_by_policy", startTime, agentId);
			return;
		}

		// SSRF guard — prevent connections to private IPs; pin to resolved IP
		let targetIp: string;
		try {
			const ssrfResult = await checkSsrf(`https://${hostname}:${port}/`);
			targetIp = ssrfResult.resolvedIps[0];
		} catch (error) {
			if (error instanceof SsrfError) {
				console.warn(`[connect-proxy][${reqId}] SSRF blocked: ${error.message}`);
				writeReject(clientSocket, 403, "Forbidden: SSRF protection");
				auditConnect(auditLogger, reqId, target, "block", "blocked_by_policy", startTime, agentId);
				return;
			}
			console.error(
				`[connect-proxy][${reqId}] SSRF check failed: ${error instanceof Error ? error.message : "Unknown"}`,
			);
			writeReject(clientSocket, 502, "Bad Gateway: DNS resolution failed");
			auditConnect(auditLogger, reqId, target, "block", "failure", startTime, agentId);
			return;
		}

		// Establish TCP connection to resolved IP (DNS-pinned to prevent rebinding)
		const targetSocket = net.connect(port, targetIp, () => {
			// Connection established — send 200 to client
			clientSocket.write(
				`HTTP/1.1 200 Connection Established\r\nX-Sentinel-Request-Id: ${reqId}\r\n\r\n`,
			);

			// Disable connect-phase timeout after tunnel established — long-lived connections
			// (e.g., Telegram long-polling, SSE streams) would otherwise be killed
			targetSocket.setTimeout(0);
			// clientSocket is a net.Socket at runtime (Node 'connect' event) but typed as Duplex
			if ("setTimeout" in clientSocket) {
				(clientSocket as net.Socket).setTimeout(0);
			}

			// Forward any initial data from the CONNECT request
			if (head.length > 0) {
				targetSocket.write(head);
			}

			// Bidirectional pipe
			targetSocket.pipe(clientSocket);
			clientSocket.pipe(targetSocket);

			console.log(
				`[connect-proxy][${reqId}] Tunnel established: ${hostname}:${port} (${Date.now() - startTime}ms)`,
			);
			auditConnect(auditLogger, reqId, target, "auto_approve", "success", startTime, agentId);
		});

		// Connection timeout for the connect phase (10s)
		targetSocket.setTimeout(CONNECT_TIMEOUT_MS, () => {
			console.error(`[connect-proxy][${reqId}] Connection to ${hostname}:${port} timed out`);
			writeReject(clientSocket, 504, "Gateway Timeout");
			targetSocket.destroy();
			auditConnect(auditLogger, reqId, target, "auto_approve", "failure", startTime, agentId);
		});

		targetSocket.on("error", (err) => {
			try {
				console.error(`[connect-proxy][${reqId}] Target socket error: ${err.message}`);
				if (!clientSocket.destroyed) {
					writeReject(clientSocket, 502, "Bad Gateway");
				}
				auditConnect(auditLogger, reqId, target, "auto_approve", "failure", startTime, agentId);
			} catch {
				// Socket already torn down — nothing to do
			}
		});

		clientSocket.on("error", (err) => {
			console.error(`[connect-proxy][${reqId}] Client socket error: ${err.message}`);
			targetSocket.destroy();
		});

		// Clean up on close
		clientSocket.on("close", () => {
			targetSocket.destroy();
		});
		targetSocket.on("close", () => {
			clientSocket.destroy();
		});
	};
}

function writeReject(socket: Duplex, statusCode: number, reason: string): void {
	try {
		if (!socket.destroyed) {
			socket.write(`HTTP/1.1 ${statusCode} ${reason}\r\n\r\n`);
			socket.end();
		}
	} catch {
		// Socket already closed — rejection cannot be delivered
	}
}

type AuditDecision = "auto_approve" | "block";
type AuditResult = "success" | "failure" | "blocked_by_policy";

function auditConnect(
	logger: AuditLogger,
	reqId: string,
	target: string,
	decision: AuditDecision,
	result: AuditResult,
	startTime: number,
	agentId = "unknown",
): void {
	try {
		logger.log({
			id: crypto.randomUUID(),
			timestamp: new Date().toISOString(),
			manifestId: crypto.randomUUID(),
			sessionId: "connect-proxy",
			agentId,
			tool: "connect_proxy",
			category: "write",
			decision,
			parameters_summary: `CONNECT ${target}`,
			result,
			duration_ms: Date.now() - startTime,
		});
	} catch (err) {
		console.error(
			`[connect-proxy] Audit logging failed: ${err instanceof Error ? err.message : "Unknown"}`,
		);
	}
}
