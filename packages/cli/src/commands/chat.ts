import * as p from "@clack/prompts";
import { serve } from "@hono/node-server";
import { agentLoop } from "@sentinel/agent";
import { AuditLogger } from "@sentinel/audit";
import { CredentialVault } from "@sentinel/crypto";
import { createApp, createToolRegistry } from "@sentinel/executor";
import { validateConfig } from "@sentinel/policy";
import type { SentinelConfig } from "@sentinel/types";
import chalk from "chalk";
import { startConfirmationPoller } from "../confirmation-tui.js";

export async function chatCommand(config: SentinelConfig, _dataDir: string): Promise<void> {
	// Validate config (same gate as entrypoint)
	validateConfig(config);

	// Prompt for master password
	const password = await p.password({
		message: "Master password:",
	});
	if (p.isCancel(password)) {
		p.cancel("Cancelled.");
		return;
	}

	// Open vault — distinguish file-not-found / permission errors from wrong password
	let vault: CredentialVault;
	try {
		vault = await CredentialVault.open(config.vaultPath, password);
	} catch (err: unknown) {
		const code = (err as NodeJS.ErrnoException).code;
		if (code === "ENOENT") {
			p.cancel("Vault file not found. Run `sentinel init` first.");
		} else if (code === "EACCES") {
			p.cancel(`Vault file permission denied: ${config.vaultPath}`);
		} else {
			p.cancel("Failed to unlock vault. Wrong password?");
		}
		return;
	}

	// Get API key from vault — distinguish missing key from corruption/decryption errors
	let apiKey: string;
	try {
		const creds = await vault.retrieve("anthropic");
		apiKey = creds.key;
		if (!apiKey) throw new Error("No API key found");
	} catch (err: unknown) {
		vault.destroy();
		const msg = err instanceof Error ? err.message : "Unknown error";
		if (msg.includes("No credential found") || msg.includes("No API key found")) {
			p.cancel("No Anthropic API key in vault. Run `sentinel init` first.");
		} else {
			p.cancel(`Failed to retrieve API key: ${msg}`);
		}
		return;
	}

	// Start executor (in-process for local dev)
	const auditLogger = new AuditLogger(config.auditLogPath);
	const registry = createToolRegistry(config.allowedRoots);
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

	const agentId = `cli-${sessionId.slice(0, 8)}`;
	const pollerCtrl = new AbortController();

	// Graceful shutdown
	const shutdown = () => {
		console.log(chalk.dim("\nShutting down..."));
		pollerCtrl.abort();
		vault.destroy();
		auditLogger.close();
		server.close();
		process.exit(0);
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);

	// Start confirmation poller concurrently
	const pollerPromise = startConfirmationPoller(executorUrl, pollerCtrl.signal);

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
		pollerCtrl.abort();
		await pollerPromise;
		vault.destroy();
		auditLogger.close();
		server.close();
	}
}
