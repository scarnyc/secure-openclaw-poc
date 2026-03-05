#!/usr/bin/env node

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { SentinelConfig } from "@sentinel/types";
import { auditCommand } from "./commands/audit.js";
import { chatCommand } from "./commands/chat.js";
import { initCommand } from "./commands/init.js";
import { vaultCommand } from "./commands/vault.js";

const DATA_DIR = resolve(process.cwd(), "data");
const CONFIG_PATH = resolve(DATA_DIR, "sentinel.json");

async function loadConfig(): Promise<SentinelConfig> {
	const raw = await readFile(CONFIG_PATH, "utf-8");
	return JSON.parse(raw) as SentinelConfig;
}

async function main(): Promise<void> {
	const [command, ...args] = process.argv.slice(2);

	if (command === "init") {
		await initCommand(DATA_DIR);
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
  sentinel init          First-time setup (master password, API key)
  sentinel chat          Start interactive agent session
  sentinel vault <cmd>   Manage credentials (list, add, remove)
  sentinel audit [N]     View recent audit log entries (default: 20)
  sentinel config        Show current configuration`);
			break;
	}
}

main().catch((error) => {
	console.error(error instanceof Error ? error.message : String(error));
	process.exit(1);
});
