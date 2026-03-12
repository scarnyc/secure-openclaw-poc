import { redactAllCredentialsWithEncoding } from "@sentinel/types";

const MAX_SSE_BUFFER_SIZE = 1024 * 1024; // 1MB max buffer before forced flush

/**
 * Creates a TransformStream that filters credentials from SSE (Server-Sent Events) streams.
 *
 * Buffers incoming chunks until SSE event boundaries (\n\n) are found,
 * applies credential redaction to each `data:` line, then flushes the filtered event.
 * Non-data lines (event:, id:, retry:, comments) pass through untouched.
 */
export function createSseCredentialFilter(): TransformStream<Uint8Array, Uint8Array> {
	const decoder = new TextDecoder();
	const encoder = new TextEncoder();
	let buffer = "";

	return new TransformStream({
		transform(chunk, controller) {
			buffer += decoder.decode(chunk, { stream: true });

			// Safety: flush oversized buffer to prevent memory exhaustion from malformed streams
			if (buffer.length > MAX_SSE_BUFFER_SIZE) {
				const filteredLines = buffer.split("\n").map((line) => {
					if (line.startsWith("data:") || line.startsWith("data: ")) {
						const prefix = line.startsWith("data: ") ? "data: " : "data:";
						const content = line.slice(prefix.length);
						return `${prefix}${redactAllCredentialsWithEncoding(content)}`;
					}
					return line;
				});
				// Append \n\n to maintain valid SSE framing even on overflow flush
				controller.enqueue(encoder.encode(`${filteredLines.join("\n")}\n\n`));
				buffer = "";
				return;
			}

			// Process complete events (delimited by \n\n)
			let eventEnd: number = buffer.indexOf("\n\n");
			while (eventEnd !== -1) {
				const event = buffer.slice(0, eventEnd);
				buffer = buffer.slice(eventEnd + 2);

				// Filter each line of the event
				const filteredLines = event.split("\n").map((line) => {
					// Only filter data: lines — event:, id:, retry:, comments are metadata
					if (line.startsWith("data:") || line.startsWith("data: ")) {
						const prefix = line.startsWith("data: ") ? "data: " : "data:";
						const content = line.slice(prefix.length);
						return `${prefix}${redactAllCredentialsWithEncoding(content)}`;
					}
					return line;
				});

				controller.enqueue(encoder.encode(`${filteredLines.join("\n")}\n\n`));
				eventEnd = buffer.indexOf("\n\n");
			}
		},
		flush(controller) {
			// Handle any remaining partial event in the buffer
			if (buffer.length > 0) {
				const filteredLines = buffer.split("\n").map((line) => {
					if (line.startsWith("data:") || line.startsWith("data: ")) {
						const prefix = line.startsWith("data: ") ? "data: " : "data:";
						const content = line.slice(prefix.length);
						return `${prefix}${redactAllCredentialsWithEncoding(content)}`;
					}
					return line;
				});
				controller.enqueue(encoder.encode(filteredLines.join("\n")));
			}
		},
	});
}
