import { createInterface } from "node:readline";
import type Anthropic from "@anthropic-ai/sdk";
import { ConversationContext } from "./context.js";
import { ExecutorClient } from "./executor-client.js";
import { LLMClient, toAnthropicTools } from "./llm.js";
import { buildManifest } from "./manifest-builder.js";
import { buildSystemPrompt } from "./system-prompt.js";

export interface AgentLoopConfig {
	executorUrl: string;
	apiKey: string;
	model?: string;
	llmBaseUrl?: string;
	sessionId: string;
	agentId: string;
}

export async function agentLoop(config: AgentLoopConfig): Promise<void> {
	const executor = new ExecutorClient(config.executorUrl);

	const healthy = await executor.health();
	if (!healthy) {
		throw new Error(`Executor at ${config.executorUrl} is not reachable`);
	}

	const toolEntries = await executor.getTools();
	const systemPrompt = buildSystemPrompt(toolEntries);
	const anthropicTools = toAnthropicTools(toolEntries);

	const llm = new LLMClient(config.apiKey, config.model, config.llmBaseUrl);
	const context = new ConversationContext();

	const rl = createInterface({ input: process.stdin, output: process.stdout });

	const shutdown = () => {
		rl.close();
		process.exit(0);
	};
	process.on("SIGTERM", shutdown);
	process.on("SIGINT", shutdown);

	const prompt = (): Promise<string> =>
		new Promise((resolve, reject) => {
			rl.question("> ", (answer) => {
				if (answer === undefined) {
					reject(new Error("stdin closed"));
				} else {
					resolve(answer);
				}
			});
		});

	try {
		while (true) {
			const input = await prompt();
			if (!input.trim()) continue;

			context.addUserMessage(input);
			context.trimToFit(100_000);

			let continueLoop = true;
			while (continueLoop) {
				continueLoop = false;

				const assistantBlocks: Array<Anthropic.TextBlockParam | Anthropic.ToolUseBlockParam> = [];
				const pendingToolUses: Array<{
					id: string;
					name: string;
					input: Record<string, unknown>;
				}> = [];

				for await (const event of llm.chat(systemPrompt, context.getMessages(), anthropicTools)) {
					if (event.type === "text") {
						process.stdout.write(event.text);
						const last = assistantBlocks[assistantBlocks.length - 1];
						if (last?.type === "text") {
							last.text += event.text;
						} else {
							assistantBlocks.push({ type: "text", text: event.text });
						}
					} else if (event.type === "tool_use") {
						assistantBlocks.push({
							type: "tool_use",
							id: event.id,
							name: event.name,
							input: event.input,
						});
						pendingToolUses.push(event);
					}
				}

				if (assistantBlocks.length > 0) {
					context.addAssistantToolUse(assistantBlocks);
				}

				if (pendingToolUses.length > 0) {
					process.stdout.write("\n");
					for (const tu of pendingToolUses) {
						const manifest = buildManifest(tu.name, tu.input, config.sessionId, config.agentId);
						const result = await executor.execute(manifest);
						context.addToolResult(tu.id, result);
					}
					continueLoop = true;
				} else {
					process.stdout.write("\n");
				}
			}
		}
	} finally {
		rl.close();
	}
}
