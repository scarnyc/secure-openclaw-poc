import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";

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
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			if (
				msg.includes("Cannot connect to the Docker daemon") ||
				msg.includes("permission denied")
			) {
				console.error(`[health] Docker error: ${msg}`);
				return { healthy: false, elapsed: Date.now() - start };
			}
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

/**
 * Start a Cloudflare quick tunnel to expose the executor publicly.
 * Returns the public URL and the child process (for cleanup).
 * Falls back gracefully if cloudflared is not installed.
 */
async function startTunnel(
	projectRoot: string,
	port: number,
): Promise<{ url: string; process: ChildProcess } | null> {
	// Skip if user explicitly set a confirm base URL
	if (process.env.SENTINEL_CONFIRM_BASE_URL) {
		console.log(
			`[tunnel] Using explicit SENTINEL_CONFIRM_BASE_URL: ${process.env.SENTINEL_CONFIRM_BASE_URL}`,
		);
		return null;
	}

	// Check if cloudflared is installed
	try {
		execFileSync("which", ["cloudflared"], { encoding: "utf-8" });
	} catch {
		console.log("[tunnel] cloudflared not installed — confirmation links will use localhost.");
		console.log("[tunnel] Install with: brew install cloudflared");
		return null;
	}

	console.log("[tunnel] Starting Cloudflare tunnel...");

	const child = spawn("cloudflared", ["tunnel", "--url", `http://localhost:${port}`], {
		stdio: ["ignore", "pipe", "pipe"],
		detached: true,
	});

	// Save PID for cleanup on stop
	const pidPath = join(projectRoot, "data", "cloudflared.pid");
	writeFileSync(pidPath, String(child.pid), "utf-8");

	// Parse the tunnel URL from cloudflared stderr output
	// cloudflared prints: INF +--- https://random.trycloudflare.com ---+
	const url = await new Promise<string | null>((resolvePromise) => {
		const timeout = setTimeout(() => {
			console.warn("[tunnel] Timed out waiting for tunnel URL (15s)");
			resolvePromise(null);
		}, 15_000);

		let stderrBuffer = "";

		child.stderr?.on("data", (chunk: Buffer) => {
			stderrBuffer += chunk.toString();
			const match = stderrBuffer.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
			if (match) {
				clearTimeout(timeout);
				resolvePromise(match[0]);
			}
		});

		child.on("error", (err) => {
			clearTimeout(timeout);
			console.error(`[tunnel] Failed to start: ${err.message}`);
			resolvePromise(null);
		});

		child.on("exit", (code) => {
			if (code !== null && code !== 0) {
				clearTimeout(timeout);
				console.error(`[tunnel] Exited with code ${code}`);
				resolvePromise(null);
			}
		});
	});

	if (!url) {
		child.kill();
		try {
			unlinkSync(pidPath);
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
				console.warn(
					`[tunnel] Failed to clean up PID file: ${err instanceof Error ? err.message : "Unknown"}`,
				);
			}
		}
		return null;
	}

	// Unref so tunnel doesn't prevent CLI from exiting
	child.unref();

	console.log(`[tunnel] Public URL: ${url}`);
	return { url, process: child };
}

export function stopTunnel(projectRoot: string): void {
	const pidPath = join(projectRoot, "data", "cloudflared.pid");
	if (!existsSync(pidPath)) return;

	try {
		const pid = Number.parseInt(readFileSync(pidPath, "utf-8").trim(), 10);
		if (!Number.isNaN(pid)) {
			process.kill(pid, "SIGTERM");
			console.log(`[tunnel] Stopped cloudflared (PID ${pid})`);
		}
	} catch (err) {
		// Process may already be gone
		if ((err as NodeJS.ErrnoException).code !== "ESRCH") {
			console.warn(
				`[tunnel] Failed to stop cloudflared: ${err instanceof Error ? err.message : "Unknown"}`,
			);
		}
	}

	try {
		unlinkSync(pidPath);
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
			console.warn(
				`[tunnel] Failed to clean up PID file: ${err instanceof Error ? err.message : "Unknown"}`,
			);
		}
	}
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

	// SENTINEL: Start Cloudflare tunnel for public confirmation URLs
	const tunnel = targets.includes("executor") ? await startTunnel(projectRoot, 3141) : null;

	const confirmBaseUrl =
		process.env.SENTINEL_CONFIRM_BASE_URL ?? tunnel?.url ?? "http://localhost:3141";

	const composeEnv: Record<string, string> = {
		SENTINEL_AUTH_TOKEN: authToken,
		SENTINEL_CONFIRM_BASE_URL: confirmBaseUrl,
		// Egress bindings: use host env override if set, otherwise default with Telegram
		SENTINEL_EGRESS_BINDINGS: process.env.SENTINEL_EGRESS_BINDINGS || defaultEgressBindings,
	};
	if (vaultPassword) {
		composeEnv.SENTINEL_VAULT_PASSWORD = vaultPassword;
	}

	console.log(`Starting Sentinel (${targets.join(", ")})...`);
	console.log(
		`Auth token: ${authToken.slice(0, 8)}...${authToken.slice(-4)} (${authToken.length} chars)`,
	);

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
	const openclawConfigPath = join(homedir(), ".openclaw", "openclaw.json");
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
					if (baseUrl && baseUrl.includes("localhost:3141")) {
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
	console.log("\n" + run(projectRoot, "docker", ["compose", "-f", composeFile, "ps"]));

	// Restart host-mode OpenClaw gateway if installed (fallback for non-Docker OpenClaw)
	try {
		run(projectRoot, "openclaw", ["gateway", "restart"]);
		console.log("Host-mode OpenClaw gateway restarted.");
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		if (msg.includes("ENOENT") || msg.includes("not found")) {
			// openclaw CLI not installed — expected in Docker-only setups
		} else {
			console.warn(`[sentinel] OpenClaw gateway restart failed: ${msg}`);
		}
	}

	console.log("\nSentinel is running.");
	console.log(`Confirmation UI: ${confirmBaseUrl}/confirm-ui/<manifestId>`);
	if (tunnel) {
		console.log("Cloudflare tunnel active — confirmations accessible from any device.");
	}
}

export async function stopCommand(projectRoot: string): Promise<void> {
	const composeFile = resolve(projectRoot, "docker-compose.yml");
	console.log("Stopping Sentinel...");

	// Stop tunnel first
	stopTunnel(projectRoot);

	try {
		run(projectRoot, "docker", ["compose", "-f", composeFile, "down"]);
		console.log("Sentinel stopped.");
	} catch (err) {
		console.error("Stop failed:", err instanceof Error ? err.message : String(err));
		process.exit(1);
	}
}
