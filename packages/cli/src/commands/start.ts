import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { CredentialVault } from "@sentinel/crypto";

function run(
	projectRoot: string,
	cmd: string,
	args: string[],
	env?: Record<string, string>,
): string {
	return execFileSync(cmd, args, {
		cwd: projectRoot,
		encoding: "utf-8",
		timeout: 120_000,
		env: { ...process.env, ...env },
	}).trim();
}

function waitForHealthy(
	projectRoot: string,
	composeFile: string,
	service: string,
	maxWaitMs: number,
): { healthy: boolean; elapsed: number } {
	const start = Date.now();

	while (Date.now() - start < maxWaitMs) {
		try {
			const output = run(projectRoot, "docker", [
				"compose",
				"-f",
				composeFile,
				"ps",
				"--format",
				"{{.Health}}",
				service,
			]);
			if (output === "healthy") {
				return { healthy: true, elapsed: Date.now() - start };
			}
		} catch {
			// container not ready yet
		}
		execFileSync("sleep", ["2"]);
	}

	return { healthy: false, elapsed: Date.now() - start };
}

async function promptPassword(): Promise<string> {
	// Check env first
	if (process.env.SENTINEL_VAULT_PASSWORD) {
		return process.env.SENTINEL_VAULT_PASSWORD;
	}

	const rl = createInterface({
		input: process.stdin,
		output: process.stdout,
	});

	return new Promise((resolve) => {
		// Disable echo for password input
		process.stdout.write("Vault password: ");
		if (process.stdin.isTTY) {
			process.stdin.setRawMode(true);
		}

		let password = "";
		process.stdin.resume();
		process.stdin.setEncoding("utf-8");

		const onData = (ch: string) => {
			const c = ch.toString();
			if (c === "\n" || c === "\r" || c === "\u0004") {
				if (process.stdin.isTTY) {
					process.stdin.setRawMode(false);
				}
				process.stdout.write("\n");
				process.stdin.removeListener("data", onData);
				rl.close();
				resolve(password);
			} else if (c === "\u007F" || c === "\b") {
				// Backspace
				if (password.length > 0) {
					password = password.slice(0, -1);
				}
			} else if (c === "\u0003") {
				// Ctrl+C
				process.stdout.write("\n");
				process.exit(130);
			} else {
				password += c;
			}
		};

		process.stdin.on("data", onData);
	});
}

export async function startCommand(projectRoot: string, services: string[]): Promise<void> {
	const composeFile = resolve(projectRoot, "docker-compose.yml");
	const targets = services.length > 0 ? services : ["executor", "openclaw-gateway"];

	// Prompt for vault password if executor is being started
	let vaultPassword: string | undefined;
	if (targets.includes("executor")) {
		vaultPassword = await promptPassword();
		if (!vaultPassword) {
			console.error("Vault password is required to start the executor.");
			process.exit(1);
		}
	}

	// SENTINEL: Generate a shared auth token for executor ↔ gateway communication.
	// Both services read SENTINEL_AUTH_TOKEN from env; if empty, executor auto-generates
	// one internally but the gateway can't match it. Generate here so both share the same value.
	const authToken = process.env.SENTINEL_AUTH_TOKEN || randomBytes(32).toString("hex");

	// SENTINEL: Default egress bindings for Telegram confirmation interception (Docker mode)
	const defaultEgressBindings = JSON.stringify([
		{ serviceId: "telegram_bot", allowedDomains: ["api.telegram.org"] },
	]);

	// SENTINEL: Dual-poller mode — both executor and gateway poll Telegram.
	// The CONNECT tunnel (HTTPS_PROXY) is opaque, so the executor can't intercept
	// confirmation callbacks from getUpdates responses. The executor must poll
	// separately to handle confirmations. 409 conflicts are expected and handled
	// by both sides with retry logic.
	const openclawConfigPath = join(homedir(), ".openclaw", "openclaw.json");
	const gatewayTargeted = targets.includes("openclaw-gateway");

	const composeEnv: Record<string, string> = {
		SENTINEL_AUTH_TOKEN: authToken,
		// Egress bindings: use host env override if set, otherwise default with Telegram
		SENTINEL_EGRESS_BINDINGS: process.env.SENTINEL_EGRESS_BINDINGS || defaultEgressBindings,
		// Executor polls for confirmations; gateway polls for messages (dual-poller)
		SENTINEL_TELEGRAM_POLLER: "executor",
	};
	if (gatewayTargeted) {
		const gatewayToken = randomBytes(16).toString("hex");
		composeEnv.OPENCLAW_GATEWAY_TOKEN = gatewayToken;
	}

	// SENTINEL: Extract real bot token from vault for gateway injection.
	// The CONNECT proxy tunnel is opaque — the executor can't substitute placeholders.
	// Always try extraction when vault is available and gateway is targeted.
	if (vaultPassword && gatewayTargeted) {
		try {
			const vaultPath = resolve(projectRoot, "data", "vault.enc");
			const vault = await CredentialVault.open(vaultPath, vaultPassword);
			const { useCredential } = await import("@sentinel/crypto");
			const botToken = await useCredential(
				vault,
				"telegram_bot",
				["key"] as const,
				(cred) => cred.key,
			);
			composeEnv.SENTINEL_TELEGRAM_BOT_TOKEN = botToken;
			console.log("Telegram bot token extracted from vault for gateway injection.");
		} catch (err) {
			console.warn(
				`[sentinel] Could not extract bot token from vault: ${err instanceof Error ? err.message : "Unknown"}`,
			);
			console.warn("[sentinel] Gateway will use placeholder token (egress proxy will substitute).");
		}
	}
	if (vaultPassword) {
		composeEnv.SENTINEL_VAULT_PASSWORD = vaultPassword;
	}

	console.log(`Starting Sentinel (${targets.join(", ")})...`);
	console.log(
		`Auth token: ${authToken.slice(0, 8)}...${authToken.slice(-4)} (${authToken.length} chars)`,
	);

	// SENTINEL: Stop host gateway before Docker startup to prevent triple-poller conflicts.
	// Docker executor + Docker gateway already dual-poll; a host gateway adds a third.
	if (gatewayTargeted) {
		try {
			run(projectRoot, "openclaw", ["gateway", "stop"]);
			console.log("Host-mode OpenClaw gateway stopped (preventing triple-poller conflicts).");
		} catch {
			// openclaw CLI not installed or gateway not running — skip silently
		}
	}

	// Build images
	console.log("Building Docker images...");
	try {
		const buildOutput = run(
			projectRoot,
			"docker",
			["compose", "-f", composeFile, "build", ...targets],
			composeEnv,
		);
		if (buildOutput) console.log(buildOutput);
	} catch (err) {
		console.error("Build failed:", err instanceof Error ? err.message : String(err));
		process.exit(1);
	}

	// Start containers
	console.log("Starting containers...");
	try {
		// SENTINEL: --force-recreate ensures containers pick up new env vars (auth token, vault password)
		// Without this, docker compose may reuse existing containers with stale env values.
		run(
			projectRoot,
			"docker",
			["compose", "-f", composeFile, "up", "-d", "--force-recreate", ...targets],
			composeEnv,
		);
	} catch (err) {
		console.error("Failed to start:", err instanceof Error ? err.message : String(err));
		process.exit(1);
	}

	// Clear password from memory
	vaultPassword = undefined;

	// SENTINEL: Sync auth token into host OpenClaw config so LLM proxy calls authenticate.
	// OpenClaw stores the executor token in models.providers.sentinel-openai.apiKey.
	if (existsSync(openclawConfigPath)) {
		try {
			const raw = readFileSync(openclawConfigPath, "utf-8");
			const ocConfig = JSON.parse(raw) as Record<string, unknown>;
			const models = ocConfig.models as Record<string, unknown> | undefined;
			const providers = models?.providers as Record<string, Record<string, unknown>> | undefined;
			if (providers) {
				let updated = false;
				for (const [name, provider] of Object.entries(providers)) {
					const baseUrl = provider.baseUrl as string | undefined;
					if (baseUrl?.includes("localhost:3141")) {
						provider.apiKey = authToken;
						updated = true;
						console.log(`Updated ${name} provider apiKey in openclaw.json`);
					}
				}
				// Also update plugin config if present
				const plugins = ocConfig.plugins as Record<string, unknown> | undefined;
				const entries = plugins?.entries as Record<string, Record<string, unknown>> | undefined;
				const sentinel = entries?.sentinel as Record<string, Record<string, unknown>> | undefined;
				if (sentinel?.config) {
					sentinel.config.authToken = authToken;
					updated = true;
				}
				if (updated) {
					writeFileSync(openclawConfigPath, JSON.stringify(ocConfig, null, "\t"), "utf-8");
				}
			}
		} catch (err) {
			console.warn(
				`[sentinel] Could not update openclaw.json: ${err instanceof Error ? err.message : "Unknown"}`,
			);
		}
	}

	// Wait for each service to be healthy
	let allHealthy = true;
	for (const service of targets) {
		process.stdout.write(`Waiting for ${service} to be healthy...`);
		const result = waitForHealthy(projectRoot, composeFile, service, 60_000);
		if (result.healthy) {
			console.log(` ✅ (${(result.elapsed / 1000).toFixed(1)}s)`);
		} else {
			console.log(` ❌ (timed out after ${(result.elapsed / 1000).toFixed(0)}s)`);
			allHealthy = false;
		}
	}

	if (!allHealthy) {
		console.error("\nSome services failed to start. Check logs:");
		console.error(`  docker compose -f ${composeFile} logs --tail 20`);
		process.exit(1);
	}

	// Show final status
	console.log(`\n${run(projectRoot, "docker", ["compose", "-f", composeFile, "ps"])}`);

	// SENTINEL: Post-healthy gateway handling.
	// Docker gateway + executor dual-poll — do NOT restart host gateway (would triple-poll).
	if (gatewayTargeted) {
		console.log("Docker gateway + executor dual-polling Telegram (host gateway not restarted).");
	} else {
		// Non-gateway mode: still restart gateway if installed (backward compat)
		try {
			run(projectRoot, "openclaw", ["gateway", "restart"]);
			console.log("Host-mode OpenClaw gateway restarted.");
		} catch {
			// openclaw CLI not installed or gateway not running — skip silently
		}
	}

	console.log("\nSentinel is running.");
}

export async function stopCommand(projectRoot: string): Promise<void> {
	const composeFile = resolve(projectRoot, "docker-compose.yml");
	console.log("Stopping Sentinel...");
	try {
		run(projectRoot, "docker", ["compose", "-f", composeFile, "down"]);
		console.log("Sentinel stopped.");
	} catch (err) {
		console.error("Stop failed:", err instanceof Error ? err.message : String(err));
		process.exit(1);
	}
}
