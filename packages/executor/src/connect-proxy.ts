/**
 * HTTP CONNECT proxy handler for the Sentinel executor.
 *
 * Attaches to a node:http.Server's "connect" event to handle CONNECT
 * tunneling requests from the gateway container. This enables the gateway
 * (on sentinel-internal, no internet) to reach external HTTPS services
 * through the executor (which has external network access).
 *
 * The tunnel is opaque — the executor sees only the target domain:port,
 * not the encrypted request/response content. Domain-level access control
 * and audit logging are applied before establishing the tunnel.
 */

import type { IncomingMessage } from "node:http";
import { connect as netConnect, type Socket } from "node:net";
import type { AuditLogger } from "@sentinel/audit";

/** Max time to wait for upstream TCP connection. */
const UPSTREAM_CONNECT_TIMEOUT_MS = 10_000;

/**
 * Attach a CONNECT proxy handler to the given HTTP server.
 *
 * Only domains in `allowedDomains` (case-insensitive) are permitted.
 * All other CONNECT requests are rejected with 403.
 */
export function initConnectProxy(
	server: { on(event: "connect", listener: ConnectListener): void },
	allowedDomains: string[],
	auditLogger: AuditLogger,
): void {
	const allowedSet = new Set(allowedDomains.map((d) => d.toLowerCase()));

	server.on("connect", (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
		const target = req.url ?? "";
		const [hostname, portStr] = target.split(":");
		const port = Number.parseInt(portStr ?? "443", 10);
		const normalizedHost = (hostname ?? "").toLowerCase();
		const reqId = Math.random().toString(36).slice(2, 10);

		// Domain access control
		if (!normalizedHost || !allowedSet.has(normalizedHost)) {
			console.warn(`[connect-proxy][${reqId}] BLOCKED: ${target} (not in allowed domains)`);
			auditLog(auditLogger, reqId, normalizedHost, port, "block");
			clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
			clientSocket.destroy();
			return;
		}

		// Validate port (only 443 for HTTPS)
		if (port !== 443) {
			console.warn(`[connect-proxy][${reqId}] BLOCKED: ${target} (only port 443 allowed)`);
			auditLog(auditLogger, reqId, normalizedHost, port, "block");
			clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
			clientSocket.destroy();
			return;
		}

		console.log(`[connect-proxy][${reqId}] CONNECT ${target}`);

		// Open TCP connection to upstream
		const upstreamSocket = netConnect(port, hostname, () => {
			// Connection established — tell client
			clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

			// Send any buffered data from the CONNECT request
			if (head.length > 0) {
				upstreamSocket.write(head);
			}

			// Bidirectional pipe
			upstreamSocket.pipe(clientSocket);
			clientSocket.pipe(upstreamSocket);

			auditLog(auditLogger, reqId, normalizedHost, port, "allow");
		});

		upstreamSocket.setTimeout(UPSTREAM_CONNECT_TIMEOUT_MS);

		upstreamSocket.on("timeout", () => {
			console.error(`[connect-proxy][${reqId}] Upstream connection timed out: ${target}`);
			upstreamSocket.destroy();
			clientSocket.destroy();
		});

		upstreamSocket.on("error", (err) => {
			console.error(`[connect-proxy][${reqId}] Upstream error: ${err.message}`);
			if (!clientSocket.destroyed) {
				clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
				clientSocket.destroy();
			}
		});

		clientSocket.on("error", (err) => {
			console.error(`[connect-proxy][${reqId}] Client socket error: ${err.message}`);
			if (!upstreamSocket.destroyed) {
				upstreamSocket.destroy();
			}
		});
	});

	console.log(
		`[connect-proxy] CONNECT proxy enabled for ${allowedDomains.length} domain(s): ${allowedDomains.join(", ")}`,
	);
}

type ConnectListener = (req: IncomingMessage, socket: Socket, head: Buffer) => void;

/** Best-effort audit logging for CONNECT proxy events. */
function auditLog(
	logger: AuditLogger,
	reqId: string,
	hostname: string,
	port: number,
	decision: "allow" | "block",
): void {
	try {
		logger.log({
			id: crypto.randomUUID(),
			timestamp: new Date().toISOString(),
			manifestId: crypto.randomUUID(),
			sessionId: "connect-proxy",
			agentId: "openclaw-gateway",
			tool: "connect_proxy",
			category: "write",
			decision: decision === "allow" ? "auto_approve" : "block",
			parameters_summary: `CONNECT ${hostname}:${port}`,
			result: decision === "allow" ? "success" : "blocked_by_policy",
			duration_ms: 0,
		});
	} catch (err) {
		console.error(
			`[connect-proxy] Audit logging failed: ${err instanceof Error ? err.message : "Unknown"}`,
		);
	}
}
