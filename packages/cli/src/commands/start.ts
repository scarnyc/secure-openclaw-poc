import { execFileSync, execSync } from "node:child_process";
import { resolve } from "node:path";
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

	const composeEnv: Record<string, string> = {};
	if (vaultPassword) {
		composeEnv.SENTINEL_VAULT_PASSWORD = vaultPassword;
	}

	console.log(`Starting Sentinel (${targets.join(", ")})...`);

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
		run(projectRoot, "docker", ["compose", "-f", composeFile, "up", "-d", ...targets], composeEnv);
	} catch (err) {
		console.error("Failed to start:", err instanceof Error ? err.message : String(err));
		process.exit(1);
	}

	// Clear password from memory
	vaultPassword = undefined;

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
	} catch {
		// openclaw CLI not installed or gateway not running — skip silently
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
