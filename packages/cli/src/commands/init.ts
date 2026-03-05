import { existsSync, mkdirSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import * as p from "@clack/prompts";
import { CredentialVault } from "@sentinel/crypto";
import { getDefaultConfig } from "@sentinel/policy";
import chalk from "chalk";

export async function initCommand(dataDir: string): Promise<void> {
	p.intro(`${chalk.bold("Sentinel")} — Secure Agent Runtime`);

	const configPath = resolve(dataDir, "sentinel.json");
	if (existsSync(configPath)) {
		const overwrite = await p.confirm({
			message: "Configuration already exists. Overwrite?",
			initialValue: false,
		});
		if (p.isCancel(overwrite) || !overwrite) {
			p.cancel("Setup cancelled.");
			return;
		}
	}

	// Step 1: Master password
	const password = await p.password({
		message: "Create a master password for your credential vault:",
		validate: (v) => {
			if (v.length < 8) return "Password must be at least 8 characters";
		},
	});
	if (p.isCancel(password)) {
		p.cancel("Setup cancelled.");
		return;
	}

	const confirmPassword = await p.password({
		message: "Confirm master password:",
	});
	if (p.isCancel(confirmPassword)) {
		p.cancel("Setup cancelled.");
		return;
	}
	if (password !== confirmPassword) {
		p.cancel("Passwords do not match.");
		return;
	}

	// Create data directory
	mkdirSync(dataDir, { recursive: true });

	// Create vault
	const vaultPath = resolve(dataDir, "vault.enc");
	const vault = await CredentialVault.create(vaultPath, password);

	// Step 2: API key
	const apiKey = await p.password({
		message: "Anthropic API key (stored in encrypted vault, not env vars):",
		validate: (v) => {
			if (!v.startsWith("sk-")) return "API key should start with sk-";
		},
	});
	if (p.isCancel(apiKey)) {
		vault.destroy();
		p.cancel("Setup cancelled.");
		return;
	}

	await vault.store("anthropic", "api_key", { key: apiKey });

	// Step 3: Security level
	const securityLevel = await p.select({
		message: "Default security level:",
		options: [
			{
				value: "standard",
				label: "Standard",
				hint: "reads auto-approve, writes confirm (recommended)",
			},
			{
				value: "strict",
				label: "Strict",
				hint: "everything confirms",
			},
			{
				value: "relaxed",
				label: "Relaxed",
				hint: "only dangerous actions confirm",
			},
		],
	});
	if (p.isCancel(securityLevel)) {
		vault.destroy();
		p.cancel("Setup cancelled.");
		return;
	}

	// Build config
	const config = getDefaultConfig();
	config.auditLogPath = resolve(dataDir, "audit.db");
	config.vaultPath = vaultPath;

	if (securityLevel === "strict") {
		config.autoApproveReadOps = false;
	}

	await writeFile(configPath, JSON.stringify(config, null, "\t"), "utf-8");
	vault.destroy();

	p.outro(`Setup complete! Run ${chalk.cyan("sentinel chat")} to start.`);
}
