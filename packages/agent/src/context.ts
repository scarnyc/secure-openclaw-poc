import type Anthropic from "@anthropic-ai/sdk";
import type { ToolResult } from "@sentinel/types";

export class ConversationContext {
	private messages: Anthropic.MessageParam[] = [];

	addUserMessage(content: string): void {
		this.messages.push({ role: "user", content });
	}

	addAssistantMessage(content: string): void {
		this.messages.push({ role: "assistant", content });
	}

	addToolResult(toolUseId: string, result: ToolResult): void {
		const content: Anthropic.ToolResultBlockParam = {
			type: "tool_result",
			tool_use_id: toolUseId,
			content: result.success ? (result.output ?? "") : `Error: ${result.error ?? "unknown error"}`,
			is_error: !result.success,
		};
		this.messages.push({ role: "user", content: [content] });
	}

	addAssistantToolUse(blocks: Array<Anthropic.TextBlockParam | Anthropic.ToolUseBlockParam>): void {
		this.messages.push({ role: "assistant", content: blocks });
	}

	getMessages(): Anthropic.MessageParam[] {
		return [...this.messages];
	}

	trimToFit(maxTokens: number): void {
		const estimateTokens = (): number => {
			let chars = 0;
			for (const msg of this.messages) {
				if (typeof msg.content === "string") {
					chars += msg.content.length;
				} else if (Array.isArray(msg.content)) {
					for (const block of msg.content) {
						if ("text" in block && typeof block.text === "string") {
							chars += block.text.length;
						} else if ("content" in block && typeof block.content === "string") {
							chars += block.content.length;
						}
					}
				}
			}
			return Math.ceil(chars / 4);
		};

		while (this.messages.length > 1 && estimateTokens() > maxTokens) {
			this.messages.shift();
		}
	}
}
