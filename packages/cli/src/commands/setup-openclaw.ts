import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

	// Step 5: Patch OpenClaw config — add plugin config only (no unknown top-level keys)
	spin.start("Patching OpenClaw configuration...");

	const patchedConfig = {
		...openclawConfig,
		plugins: {
			...(openclawConfig.plugins as Record<string, unknown> | undefined),
			entries: {
				...((openclawConfig.plugins as Record<string, unknown> | undefined)?.entries as
					| Record<string, unknown>
					| undefined),
				sentinel: {
					enabled: true,
					config: {
						executorUrl,
						failMode: "closed",
						tier,
					},
				},
			},
		},
	};

	await writeFile(OPENCLAW_CONFIG_PATH, JSON.stringify(patchedConfig, null, "\t"), "utf-8");
	spin.stop("OpenClaw configuration patched");

	// Resolve __dirname for file lookups
	const __filename = fileURLToPath(import.meta.url);
	const __dirname = dirname(__filename);

	// Step 6: Install plugin — copy dist files from package
	spin.start("Installing Sentinel plugin...");
	mkdirSync(PLUGIN_DIR, { recursive: true });

	// Copy plugin files from package
	const pluginPkgDir = resolve(__dirname, "../../packages/openclaw-plugin");
	// Fallback path for when running from dist/
	const fallbackPkgDir = resolve(__dirname, "../../../openclaw-plugin");
	const sourcePkgDir = existsSync(pluginPkgDir) ? pluginPkgDir : fallbackPkgDir;

	// Copy dist/, openclaw.plugin.json, and package.json
	const filesToCopy = ["openclaw.plugin.json", "package.json"];
	for (const file of filesToCopy) {
		const src = join(sourcePkgDir, file);
		if (existsSync(src)) {
			copyFileSync(src, join(PLUGIN_DIR, file));
		}
	}

	// Copy dist directory
	const distSrc = join(sourcePkgDir, "dist");
	if (existsSync(distSrc)) {
		cpSync(distSrc, join(PLUGIN_DIR, "dist"), { recursive: true });
	}

	spin.stop("Sentinel plugin installed");

	// Step 7: Generate SOUL.md from template
	spin.start("Generating SOUL.md...");

	const templatePath = resolve(__dirname, "../../packages/openclaw-plugin/templates/SOUL.md");
	const fallbackTemplatePath = resolve(__dirname, "../../../openclaw-plugin/templates/SOUL.md");

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

	const workspaceDir = join(OPENCLAW_CONFIG_DIR, "workspace");
	mkdirSync(workspaceDir, { recursive: true });
	const soulPath = join(workspaceDir, "SOUL.md");
	// SENTINEL: Back up existing SOUL.md before overwriting — user may have customized it
	if (existsSync(soulPath)) {
		const backupPath = join(workspaceDir, `SOUL.md.backup.${Date.now()}`);
		copyFileSync(soulPath, backupPath);
		console.log(`  Backed up existing SOUL.md → ${backupPath}`);
	}
	writeFileSync(soulPath, soulContent);

	spin.stop("SOUL.md generated");

	// Step 7b: Write placeholder credentials info
	spin.start("Writing credential placeholders...");
	const placeholderNote = [
		"# Sentinel Credential Placeholders",
		"",
		"OpenClaw uses SENTINEL_PLACEHOLDER_* tokens instead of real credentials.",
		"The egress proxy on the executor replaces these with vault values at runtime.",
		"",
		"## Format",
		"",
		"SENTINEL_PLACEHOLDER_{SERVICE_ID}__{FIELD_NAME}",
		"",
		"Double-underscore (__) separates service ID from field name.",
		"Service ID is alphanumeric only (no underscores); field may contain underscores.",
		"",
		"## Configured Placeholders",
		"",
		"### Telegram",
		"- Bot token: SENTINEL_PLACEHOLDER_TELEGRAM__BOT_TOKEN",
		'  Store real value: sentinel vault set telegram \'{"BOT_TOKEN": "your-token"}\'',
		"",
		"Add domain binding in vault metadata for each service.",
	].join("\n");
	writeFileSync(join(workspaceDir, "CREDENTIALS.md"), placeholderNote);
	spin.stop("Credential placeholders documented");

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
			`SOUL.md: ${join(workspaceDir, "SOUL.md")}`,
			`Credentials: ${join(workspaceDir, "CREDENTIALS.md")}`,
			"",
			"Next steps:",
			"  1. Start the executor: sentinel start",
			"  2. Start OpenClaw: openclaw gateway",
			"  3. Verify: curl http://localhost:3141/health",
		].join("\n"),
		"Setup Complete",
	);

	p.outro("OpenClaw integration configured successfully!");
}
