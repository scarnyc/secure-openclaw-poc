import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as p from "@clack/prompts";
import chalk from "chalk";

const OPENCLAW_CONFIG_DIR = join(homedir(), ".openclaw");
const OPENCLAW_CONFIG_PATH = join(OPENCLAW_CONFIG_DIR, "openclaw.json");
const PLUGIN_DIR = join(OPENCLAW_CONFIG_DIR, "extensions", "sentinel");

const TIER_CONSTRAINTS: Record<string, string> = {
	Normal: [
		"Standard operating constraints apply.",
		"- Read operations auto-approved when configured",
		"- Write operations require confirmation",
		"- Rate limit: 60 requests/minute",
	].join("\n"),
	High: [
		"Elevated security constraints apply.",
		"- ALL operations require confirmation (no auto-approve)",
		"- Rate limit: 30 requests/minute",
		"- Output scanning in enforce mode",
		"- No delegate.code unless explicitly authorized",
	].join("\n"),
	Critical: [
		"Maximum security constraints apply.",
		"- ALL operations require confirmation with mandatory wait",
		"- Rate limit: 10 requests/minute",
		"- Output scanning in enforce mode with strict PII blocking",
		"- delegate.code disabled",
		"- Network egress blocked",
	].join("\n"),
};

export async function setupOpenclawCommand(dataDir: string): Promise<void> {
	p.intro(`${chalk.bold("Sentinel")} — OpenClaw Integration Setup`);

	// Step 1: Check OpenClaw installation
	const spin = p.spinner();

	spin.start("Checking OpenClaw installation...");
	const configExists = existsSync(OPENCLAW_CONFIG_PATH);
	spin.stop(configExists ? "OpenClaw config found" : "OpenClaw config not found");

	if (!configExists) {
		p.note(
			[
				"OpenClaw configuration not found at:",
				`  ${OPENCLAW_CONFIG_PATH}`,
				"",
				"Install OpenClaw first:",
				"  npm install -g openclaw",
				"  openclaw init",
			].join("\n"),
			"Missing OpenClaw",
		);
		p.cancel("Setup requires OpenClaw to be installed.");
		return;
	}

	// Step 2: Read existing OpenClaw config
	let openclawConfig: Record<string, unknown>;
	try {
		const raw = readFileSync(OPENCLAW_CONFIG_PATH, "utf-8");
		openclawConfig = JSON.parse(raw) as Record<string, unknown>;
	} catch (error) {
		p.cancel(
			`Failed to read OpenClaw config: ${error instanceof Error ? error.message : "Unknown error"}`,
		);
		return;
	}

	// Step 3: Prompt for executor URL
	const executorUrl = await p.text({
		message: "Sentinel executor URL:",
		placeholder: "http://localhost:3141",
		initialValue: "http://localhost:3141",
		validate: (v) => {
			try {
				new URL(v);
			} catch {
				return "Must be a valid URL";
			}
		},
	});
	if (p.isCancel(executorUrl)) {
		p.cancel("Setup cancelled.");
		return;
	}

	// Step 4: Prompt for sensitivity tier
	const tier = await p.select({
		message: "Select sensitivity tier for this workspace:",
		options: [
			{ value: "Normal", label: "Normal — standard confirmation model" },
			{ value: "High", label: "High — all ops require confirmation, lower rate limits" },
			{
				value: "Critical",
				label: "Critical — maximum restrictions, no delegation",
			},
		],
	});
	if (p.isCancel(tier)) {
		p.cancel("Setup cancelled.");
		return;
	}

	// Step 5: Patch OpenClaw config — add LLM proxy baseUrls, disable ask mode
	spin.start("Patching OpenClaw configuration...");

	const patchedConfig = {
		...openclawConfig,
		llm: {
			...(openclawConfig.llm as Record<string, unknown> | undefined),
			baseUrls: {
				anthropic: `${executorUrl}/proxy/llm/anthropic`,
				openai: `${executorUrl}/proxy/llm/openai`,
				gemini: `${executorUrl}/proxy/llm/gemini`,
			},
		},
		confirmation: {
			mode: "sentinel",
			executorUrl,
		},
	};

	await writeFile(OPENCLAW_CONFIG_PATH, JSON.stringify(patchedConfig, null, "\t"), "utf-8");
	spin.stop("OpenClaw configuration patched");

	// Step 6: Install plugin
	spin.start("Installing Sentinel plugin...");
	mkdirSync(PLUGIN_DIR, { recursive: true });

	// Write plugin config
	const pluginConfig = {
		name: "@sentinel/openclaw-plugin",
		executorUrl,
		failMode: "closed",
		tier,
	};
	writeFileSync(join(PLUGIN_DIR, "config.json"), JSON.stringify(pluginConfig, null, "\t"));

	spin.stop("Sentinel plugin installed");

	// Step 7: Generate SOUL.md from template
	spin.start("Generating SOUL.md...");

	const __filename = fileURLToPath(import.meta.url);
	const __dirname = dirname(__filename);
	const templatePath = resolve(__dirname, "../../packages/openclaw-plugin/templates/SOUL.md");
	const fallbackTemplatePath = resolve(
		__dirname,
		"../../../openclaw-plugin/templates/SOUL.md",
	);

	let template: string;
	try {
		template = existsSync(templatePath)
			? readFileSync(templatePath, "utf-8")
			: readFileSync(fallbackTemplatePath, "utf-8");
	} catch {
		// Inline minimal template if file not found
		template = [
			"# Identity",
			"You are a Sentinel-managed agent. Sensitivity tier: {{TIER}}.",
			"",
			"{{TIER_CONSTRAINTS}}",
		].join("\n");
	}

	const soulContent = template
		.replace("{{TIER}}", tier as string)
		.replace("{{TIER_CONSTRAINTS}}", TIER_CONSTRAINTS[tier as string] ?? "");

	const soulPath = join(OPENCLAW_CONFIG_DIR, "SOUL.md");
	writeFileSync(soulPath, soulContent);

	spin.stop("SOUL.md generated");

	// Step 8: Update Sentinel config
	spin.start("Updating Sentinel configuration...");
	const sentinelConfigPath = resolve(dataDir, "sentinel.json");
	if (existsSync(sentinelConfigPath)) {
		const sentinelRaw = readFileSync(sentinelConfigPath, "utf-8");
		const sentinelConfig = JSON.parse(sentinelRaw) as Record<string, unknown>;
		sentinelConfig.openclawPlugin = {
			enabled: true,
			executorUrl,
			tier,
		};
		await writeFile(sentinelConfigPath, JSON.stringify(sentinelConfig, null, "\t"), "utf-8");
	}
	spin.stop("Sentinel configuration updated");

	// Summary
	p.note(
		[
			`Executor URL: ${executorUrl}`,
			`Sensitivity Tier: ${tier}`,
			`Plugin Dir: ${PLUGIN_DIR}`,
			`SOUL.md: ${join(OPENCLAW_CONFIG_DIR, "SOUL.md")}`,
			"",
			"Next steps:",
			"  1. Start the executor: docker compose up executor -d",
			"  2. Start OpenClaw: openclaw gateway",
			"  3. Verify: curl http://localhost:3141/health",
		].join("\n"),
		"Setup Complete",
	);

	p.outro("OpenClaw integration configured successfully!");
}
