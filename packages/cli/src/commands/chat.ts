import * as p from "@clack/prompts";
import { serve } from "@hono/node-server";
import { agentLoop } from "@sentinel/agent";
import { AuditLogger } from "@sentinel/audit";
import { CredentialVault } from "@sentinel/crypto";
import { createApp, createToolRegistry } from "@sentinel/executor";
import type { SentinelConfig } from "@sentinel/types";
import chalk from "chalk";

export async function chatCommand(config: SentinelConfig, _dataDir: string): Promise<void> {
	// Prompt for master password
	const password = await p.password({
		message: "Master password:",
	});
	if (p.isCancel(password)) {
		p.cancel("Cancelled.");
		return;
	}

	// Open vault
	let vault: CredentialVault;
	try {
		vault = await CredentialVault.open(config.vaultPath, password);
	} catch {
		p.cancel("Failed to unlock vault. Wrong password?");
		return;
	}

	// Get API key from vault
	let apiKey: string;
	try {
		const creds = await vault.retrieve("anthropic");
		apiKey = creds.key;
		if (!apiKey) throw new Error("No API key found");
	} catch {
		vault.destroy();
		p.cancel("No Anthropic API key in vault. Run `sentinel init` first.");
		return;
	}

	// Start executor (in-process for local dev)
	const auditLogger = new AuditLogger(config.auditLogPath);
	const registry = createToolRegistry();
	const app = createApp(config, auditLogger, registry);

	const server = serve({
		fetch: app.fetch,
		port: config.executor.port,
		hostname: config.executor.host,
	});

	const executorUrl = `http://${config.executor.host}:${config.executor.port}`;
	console.log(chalk.dim(`Executor running at ${executorUrl}`));

	const sessionId = crypto.randomUUID();
	console.log(chalk.dim(`Session: ${sessionId}`));
	console.log(chalk.dim("Type your message. Press Ctrl+C to exit.\n"));

	// Graceful shutdown
	const shutdown = () => {
		console.log(chalk.dim("\nShutting down..."));
		vault.destroy();
		auditLogger.close();
		server.close();
		process.exit(0);
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);

	const agentId = `cli-${sessionId.slice(0, 8)}`;
	try {
		await agentLoop({
			executorUrl,
			apiKey,
			model: config.llm.model,
			sessionId,
			agentId,
		});
	} catch (error) {
		if (error instanceof Error && error.message.includes("stdin closed")) {
			// Normal exit
		} else {
			console.error(chalk.red(`Error: ${error}`));
		}
	} finally {
		vault.destroy();
		auditLogger.close();
		server.close();
	}
}
