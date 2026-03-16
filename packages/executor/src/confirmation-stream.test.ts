import type { Context } from "hono";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type ConfirmationRequestedEvent,
	type ConfirmationResolvedEvent,
	createConfirmationStream,
	HEARTBEAT_INTERVAL_MS,
} from "./confirmation-stream.js";

const decoder = new TextDecoder();

function makeRequestedEvent(id = "m-1"): ConfirmationRequestedEvent {
	return {
		type: "custom",
		name: "confirmation_requested",
		value: {
			manifestId: id,
			tool: "send_email",
			category: "write-irreversible",
			reason: "Sends email to external recipient",
			parameters: { to: "user@example.com" },
			expiresAt: "2026-03-16T12:00:00Z",
			confirmUrl: "/confirm/m-1",
		},
	};
}

function makeResolvedEvent(id = "m-1"): ConfirmationResolvedEvent {
	return {
		type: "custom",
		name: "confirmation_resolved",
		value: {
			manifestId: id,
			decision: "approved",
			resolvedBy: "web",
		},
	};
}

async function readNextChunk(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<string> {
	const { value } = await reader.read();
	return decoder.decode(value);
}

describe("confirmation-stream", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("SSE client receives confirmation_requested event", async () => {
		const { handler, emit } = createConfirmationStream();
		const res = handler({} as Context);
		const reader = res.body!.getReader();

		// First chunk is the connected event
		const connected = await readNextChunk(reader);
		expect(connected).toContain('"type":"connected"');

		// Emit a confirmation_requested event
		const event = makeRequestedEvent();
		emit(event);

		const chunk = await readNextChunk(reader);
		expect(chunk).toBe(`data: ${JSON.stringify(event)}\n\n`);

		reader.cancel();
	});

	it("SSE client receives confirmation_resolved event", async () => {
		const { handler, emit } = createConfirmationStream();
		const res = handler({} as Context);
		const reader = res.body!.getReader();

		await readNextChunk(reader); // skip connected

		const event = makeResolvedEvent();
		emit(event);

		const chunk = await readNextChunk(reader);
		expect(chunk).toBe(`data: ${JSON.stringify(event)}\n\n`);

		reader.cancel();
	});

	it("multiple SSE clients all receive events", async () => {
		const { handler, emit } = createConfirmationStream();

		const res1 = handler({} as Context);
		const res2 = handler({} as Context);
		const reader1 = res1.body!.getReader();
		const reader2 = res2.body!.getReader();

		// Drain connected events
		await readNextChunk(reader1);
		await readNextChunk(reader2);

		const event = makeRequestedEvent("m-broadcast");
		emit(event);

		const expected = `data: ${JSON.stringify(event)}\n\n`;
		const [chunk1, chunk2] = await Promise.all([readNextChunk(reader1), readNextChunk(reader2)]);

		expect(chunk1).toBe(expected);
		expect(chunk2).toBe(expected);

		reader1.cancel();
		reader2.cancel();
	});

	it("heartbeat sent every 30s", async () => {
		vi.useFakeTimers();

		const { handler } = createConfirmationStream();
		const res = handler({} as Context);
		const reader = res.body!.getReader();

		// Read connected event
		await vi.advanceTimersByTimeAsync(0);
		await readNextChunk(reader);

		// Advance past heartbeat interval
		await vi.advanceTimersByTimeAsync(HEARTBEAT_INTERVAL_MS);

		const heartbeat = await readNextChunk(reader);
		expect(heartbeat).toBe(": heartbeat\n\n");

		expect(HEARTBEAT_INTERVAL_MS).toBe(30_000);

		reader.cancel();
	});

	it("client disconnect cleans up without throwing", async () => {
		const { handler, emit } = createConfirmationStream();
		const res = handler({} as Context);
		const reader = res.body!.getReader();

		await readNextChunk(reader); // connected

		// Cancel simulates client disconnect
		await reader.cancel();

		// Emitting after disconnect should not throw
		expect(() => emit(makeRequestedEvent())).not.toThrow();
	});
});
