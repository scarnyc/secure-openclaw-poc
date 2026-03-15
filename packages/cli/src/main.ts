#!/usr/bin/env node

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type SentinelConfig, SentinelConfigSchema } from "@sentinel/types";
import { auditCommand } from "./commands/audit.js";
import { chatCommand } from "./commands/chat.js";
import { initCommand } from "./commands/init.js";
import { setupOpenclawCommand } from "./commands/setup-openclaw.js";
import { startCommand, stopCommand } from "./commands/start.js";
import { vaultCommand } from "./commands/vault.js";

// Resolve project root (3 levels up from packages/cli/src/ or packages/cli/dist/)
const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DATA_DIR = resolve(PROJECT_ROOT, "data");
const CONFIG_PATH = resolve(DATA_DIR, "sentinel.json");

async function loadConfig(): Promise<SentinelConfig> {
	const raw = await readFile(CONFIG_PATH, "utf-8");
	return SentinelConfigSchema.parse(JSON.parse(raw));
}

async function main(): Promise<void> {
	const [command, ...args] = process.argv.slice(2);

	if (command === "init") {
		await initCommand(DATA_DIR);
		return;
	}

	if (command === "setup" && args[0] === "openclaw") {
		await setupOpenclawCommand(DATA_DIR);
		return;
	}

	if (command === "start") {
		await startCommand(PROJECT_ROOT, args);
		return;
	}

	if (command === "stop") {
		await stopCommand(PROJECT_ROOT);
		return;
	}

	// All other commands need config
	if (!existsSync(CONFIG_PATH)) {
		console.error("Sentinel is not initialized. Run `sentinel init` first.");
		process.exit(1);
	}

	const config = await loadConfig();

	switch (command) {
		case "chat":
			await chatCommand(config, DATA_DIR);
			break;
		case "vault":
			await vaultCommand(config, args[0]);
			break;
		case "audit":
			await auditCommand(config, args[0]);
			break;
		case "config":
			console.log(JSON.stringify(config, null, "\t"));
			break;
		default:
			console.log(`Sentinel — Secure Agent Runtime

Usage:
  sentinel init              First-time setup (master password, API key)
  sentinel start [services]  Build, start Docker, wait for healthy (default: executor + openclaw-gateway)
  sentinel stop              Stop all Docker services
  sentinel chat              Start interactive agent session
  sentinel vault <cmd>       Manage credentials (list, add, remove)
  sentinel audit [N]         View recent audit log entries (default: 20)
  sentinel config            Show current configuration
  sentinel setup openclaw    Configure OpenClaw integration`);
			break;
	}
}

main().catch((error) => {
	console.error(error instanceof Error ? error.message : String(error));
	process.exit(1);
});
