import { describe, expect, it } from "vitest";
import { createSseCredentialFilter } from "./sse-credential-filter.js";

/**
 * Helper: pipe input through the SSE credential filter and return the output as a string.
 * Uses ReadableStream -> pipeThrough -> Response to avoid backpressure deadlocks.
 */
async function filterSse(input: string): Promise<string> {
	const encoder = new TextEncoder();
	const source = new ReadableStream<Uint8Array>({
		start(controller) {
			controller.enqueue(encoder.encode(input));
			controller.close();
		},
	});
	const filtered = source.pipeThrough(createSseCredentialFilter());
	return new Response(filtered).text();
}

describe("SSE Credential Filter", () => {
	it("redacts ya29 Google OAuth token in data line", async () => {
		const input = 'data: {"token":"ya29.a0test_token_1234567890"}\n\n';
		const output = await filterSse(input);

		expect(output).not.toContain("ya29.");
		expect(output).toContain("[REDACTED]");
		// SSE structure preserved
		expect(output).toMatch(/^data: /);
		expect(output.endsWith("\n\n")).toBe(true);
	});

	it("redacts sk-ant Anthropic key in data line", async () => {
		const input = 'data: {"error":"Invalid key: sk-ant-abc123-leaked-key"}\n\n';
		const output = await filterSse(input);

		expect(output).not.toContain("sk-ant-abc123");
		expect(output).toContain("[REDACTED]");
	});

	it("passes clean SSE content through unchanged", async () => {
		const input =
			'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}\n\n';
		const output = await filterSse(input);

		expect(output).toBe(input);
	});

	it("does not modify non-data lines (event, id, retry, comments)", async () => {
		const input = [
			"event: message_start",
			"id: 123",
			"retry: 5000",
			": this is a comment",
			'data: {"type":"message_start"}',
			"",
			"",
		].join("\n");
		const output = await filterSse(input);

		expect(output).toContain("event: message_start\n");
		expect(output).toContain("id: 123\n");
		expect(output).toContain("retry: 5000\n");
		expect(output).toContain(": this is a comment\n");
	});

	it("filters credentials in multi-event stream independently", async () => {
		const event1 = 'data: {"type":"content_block_delta","delta":{"text":"Hello"}}\n\n';
		const event2 = 'data: {"error":"key sk-ant-secret123-key-value leaked"}\n\n';
		const event3 = 'data: {"type":"message_stop"}\n\n';
		const input = event1 + event2 + event3;

		const output = await filterSse(input);

		// Event 1 unchanged
		expect(output).toContain('data: {"type":"content_block_delta","delta":{"text":"Hello"}}\n\n');
		// Event 2 redacted
		expect(output).not.toContain("sk-ant-secret123");
		expect(output).toContain("[REDACTED]");
		// Event 3 unchanged
		expect(output).toContain('data: {"type":"message_stop"}\n\n');
	});

	it("processes 1000 events in under 100ms", async () => {
		const events: string[] = [];
		for (let i = 0; i < 1000; i++) {
			events.push(
				`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"token ${i}"}}\n\n`,
			);
		}
		const input = events.join("");

		const start = performance.now();
		const output = await filterSse(input);
		const elapsed = performance.now() - start;

		expect(elapsed).toBeLessThan(100);
		// Verify all events came through
		expect(output).toContain("token 0");
		expect(output).toContain("token 999");
	});
});
