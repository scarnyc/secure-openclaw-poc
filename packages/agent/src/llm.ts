import Anthropic from "@anthropic-ai/sdk";
import type { ToolRegistryEntry } from "@sentinel/types";

export type StreamEvent =
	| { type: "text"; text: string }
	| { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
	| { type: "end" };

const DEFAULT_MODEL = "claude-sonnet-4-5-20250514";
const DEFAULT_MAX_TOKENS = 8192;

export function toAnthropicTools(entries: ToolRegistryEntry[]): Anthropic.Tool[] {
	return entries.map((entry) => ({
		name: entry.name,
		description: `Tool: ${entry.name} (source: ${entry.source})`,
		input_schema: (entry.schema as Anthropic.Tool.InputSchema) ?? {
			type: "object" as const,
			properties: {},
		},
	}));
}

export class LLMClient {
	private client: Anthropic;
	private model: string;

	constructor(apiKey: string, model?: string) {
		this.client = new Anthropic({ apiKey });
		this.model = model ?? DEFAULT_MODEL;
	}

	async *chat(
		systemPrompt: string,
		messages: Anthropic.MessageParam[],
		tools: Anthropic.Tool[],
	): AsyncGenerator<StreamEvent> {
		const stream = this.client.messages.stream({
			model: this.model,
			max_tokens: DEFAULT_MAX_TOKENS,
			system: systemPrompt,
			messages,
			tools,
		});

		for await (const event of stream) {
			if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
				yield { type: "text", text: event.delta.text };
			} else if (event.type === "content_block_stop" && stream.currentMessage) {
				const block = stream.currentMessage.content[event.index];
				if (block?.type === "tool_use") {
					yield {
						type: "tool_use",
						id: block.id,
						name: block.name,
						input: block.input as Record<string, unknown>,
					};
				}
			}
		}

		yield { type: "end" };
	}
}
