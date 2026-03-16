import type { Context } from "hono";

// SENTINEL: ag-ui Custom event types for confirmation lifecycle
export interface ConfirmationRequestedEvent {
	type: "custom";
	name: "confirmation_requested";
	value: {
		manifestId: string;
		tool: string;
		category: string;
		reason: string;
		parameters: Record<string, unknown>;
		expiresAt: string;
		confirmUrl: string;
	};
}

export interface ConfirmationResolvedEvent {
	type: "custom";
	name: "confirmation_resolved";
	value: {
		manifestId: string;
		decision: "approved" | "denied" | "timeout";
		resolvedBy: "web" | "api" | "telegram" | "timeout";
	};
}

export type ConfirmationEvent = ConfirmationRequestedEvent | ConfirmationResolvedEvent;

interface SseClient {
	controller: ReadableStreamDefaultController<Uint8Array>;
	encoder: TextEncoder;
}

const HEARTBEAT_INTERVAL_MS = 30_000;

export function createConfirmationStream(): {
	handler: (c: Context) => Response;
	emit: (event: ConfirmationEvent) => void;
} {
	const clients = new Set<SseClient>();

	function emit(event: ConfirmationEvent): void {
		const data = `data: ${JSON.stringify(event)}\n\n`;
		for (const client of clients) {
			try {
				client.controller.enqueue(client.encoder.encode(data));
			} catch {
				// Client disconnected — will be cleaned up by cancel()
				clients.delete(client);
			}
		}
	}

	function handler(_c: Context): Response {
		const encoder = new TextEncoder();
		let client: SseClient; // declared here so cancel() can access via closure
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				client = { controller, encoder };
				clients.add(client);

				// Send initial connection event
				controller.enqueue(encoder.encode('data: {"type":"connected"}\n\n'));

				// Heartbeat to keep connection alive
				const heartbeat = setInterval(() => {
					try {
						controller.enqueue(encoder.encode(": heartbeat\n\n"));
					} catch {
						clearInterval(heartbeat);
						clients.delete(client);
					}
				}, HEARTBEAT_INTERVAL_MS);

				// Cleanup on disconnect — stored on client for testability
				(client as unknown as Record<string, unknown>)._heartbeat = heartbeat;
			},
			cancel() {
				// Only clean up THIS client's heartbeat (not all clients)
				const hb = (client as unknown as Record<string, unknown>)._heartbeat as
					| ReturnType<typeof setInterval>
					| undefined;
				if (hb) clearInterval(hb);
				clients.delete(client);
			},
		});

		return new Response(stream, {
			headers: {
				"Content-Type": "text/event-stream",
				"Cache-Control": "no-cache",
				Connection: "keep-alive",
			},
		});
	}

	return { handler, emit };
}

// Exported for testing
export { HEARTBEAT_INTERVAL_MS };
