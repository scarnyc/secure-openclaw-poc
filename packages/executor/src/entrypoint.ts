import { serve } from "@hono/node-server";
import { AuditLogger } from "@sentinel/audit";
import { CredentialVault } from "@sentinel/crypto";
import { getDefaultConfig, validateConfig } from "@sentinel/policy";
import { ensureDockerAuth } from "./docker-auth.js";
import { applyDockerDefaults } from "./docker-defaults.js";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";

const mutableConfig = getDefaultConfig();
mutableConfig.auditLogPath = process.env.SENTINEL_AUDIT_PATH ?? "/app/data/audit.db";
mutableConfig.vaultPath = process.env.SENTINEL_VAULT_PATH ?? "/app/data/vault.enc";
if (process.env.SENTINEL_AUTH_TOKEN) {
	mutableConfig.authToken = process.env.SENTINEL_AUTH_TOKEN;
}

let validated: import("@sentinel/types").SentinelConfig;
try {
	validated = validateConfig(mutableConfig);
} catch (err) {
	console.error("FATAL: Invalid Sentinel configuration. Fix and restart.");
	console.error(err instanceof Error ? err.message : String(err));
	process.exit(1);
}
validated = ensureDockerAuth(validated);

// SENTINEL: G2, G4, G5 — Docker GWS security defaults
const dockerResult = applyDockerDefaults(validated, process.env);
if (dockerResult.fatal) {
	console.error(dockerResult.fatal);
	process.exit(1);
}
for (const warning of dockerResult.warnings) {
	console.warn(warning);
}
validated = dockerResult.config;

const config = Object.freeze(structuredClone(validated));

const auditLogger = new AuditLogger(config.auditLogPath);

// SENTINEL: Open vault for Buffer-based credential injection (G1 fix).
// Falls back gracefully — LLM proxy and GWS tool use process.env when vault is unavailable.
let vault: CredentialVault | undefined;
const vaultPassword = process.env.SENTINEL_VAULT_PASSWORD;
if (vaultPassword && config.vaultPath) {
	try {
		vault = await CredentialVault.open(config.vaultPath, vaultPassword);
		delete process.env.SENTINEL_VAULT_PASSWORD;
		console.log("[sentinel] Vault opened — LLM proxy will use vault-based credentials");
	} catch (err) {
		delete process.env.SENTINEL_VAULT_PASSWORD;
		console.warn(
			`[sentinel] Vault open failed — falling back to env vars: ${err instanceof Error ? err.message : "Unknown"}`,
		);
		// SENTINEL: G7 — Vault failure in Docker is fatal (fail-closed)
		if (process.env.SENTINEL_DOCKER === "true") {
			console.error(
				"[sentinel] FATAL: Vault open failed in Docker — cannot start without credential vault",
			);
			process.exit(1);
		}
	}
}

const registry = createToolRegistry({
	allowedRoots: config.allowedRoots,
	gwsScopes: config.gwsAgentScopes,
	vault,
	gwsIntegrity: config.gwsIntegrity,
	gwsDefaultDeny: config.gwsDefaultDeny,
});
// SENTINEL: Generate HMAC secret for response signing (B4 pen test finding)
const { randomBytes: generateHmacBytes } = await import("node:crypto");
const hmacSecret = generateHmacBytes(32);

const app = createApp(config, auditLogger, registry, vault, hmacSecret);

const port = config.executor.port;
const host = "0.0.0.0";

serve({ fetch: app.fetch, port, hostname: host }, () => {
	console.log(`Sentinel Executor listening on http://${host}:${port}`);
});
