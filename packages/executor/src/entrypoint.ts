import { serve } from "@hono/node-server";
import { AuditLogger } from "@sentinel/audit";
import { CredentialVault } from "@sentinel/crypto";
import { getDefaultConfig, validateConfig } from "@sentinel/policy";
import type { EgressBinding } from "@sentinel/types";
import { ensureDockerAuth } from "./docker-auth.js";
import { applyDockerDefaults } from "./docker-defaults.js";
import { createApp } from "./server.js";
import { TelegramConfirmAdapter } from "./telegram-confirm.js";
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

// SENTINEL: Wave 2.4 — Egress proxy domain-scoped credential bindings
let egressBindings: EgressBinding[] = [];
const egressBindingsRaw = process.env.SENTINEL_EGRESS_BINDINGS;
if (egressBindingsRaw) {
	try {
		egressBindings = JSON.parse(egressBindingsRaw) as EgressBinding[];
		console.log(
			`[sentinel] Egress proxy configured with ${egressBindings.length} domain binding(s)`,
		);
	} catch (err) {
		console.error(
			`[sentinel] Failed to parse SENTINEL_EGRESS_BINDINGS: ${err instanceof Error ? err.message : "Unknown"}`,
		);
		// Fail-closed: invalid config means no egress proxy
	}
}

// SENTINEL: Telegram confirmation adapter — sends confirmation prompts via Telegram bot
// Vault entries: "telegram_bot" (bot token as {"key": "<token>"}), "TELEGRAM_CHAT" (chat ID as {"key": "<id>"})
// Both stored via `sentinel vault add`. Falls back to SENTINEL_TELEGRAM_CHAT_ID env var for chat ID.
let telegramAdapter: TelegramConfirmAdapter | undefined;
if (vault) {
	try {
		const { useCredential } = await import("@sentinel/crypto");
		// Read chat ID from vault — stored as separate entry via `sentinel vault add`
		const chatId = await useCredential(
			vault,
			"TELEGRAM_CHAT",
			["key"] as const,
			(cred) => cred.key,
		);
		telegramAdapter = new TelegramConfirmAdapter(vault, chatId);
		console.log("[sentinel] Telegram adapter created from vault credentials");
	} catch (vaultErr) {
		console.warn(
			`[sentinel] TELEGRAM_CHAT vault lookup failed (falling back to env var): ${vaultErr instanceof Error ? vaultErr.message : "Unknown"}`,
		);
		const telegramChatId = process.env.SENTINEL_TELEGRAM_CHAT_ID;
		if (telegramChatId) {
			try {
				telegramAdapter = new TelegramConfirmAdapter(vault, telegramChatId);
				console.log("[sentinel] Telegram adapter created with env var chat ID");
			} catch (err) {
				console.error(
					`[sentinel] Failed to create Telegram adapter — confirmations will only be available via HTTP /confirm endpoint. ` +
						`Error: ${err instanceof Error ? err.message : "Unknown"}`,
				);
			}
		}
	}
} else if (process.env.SENTINEL_TELEGRAM_CHAT_ID) {
	console.warn(
		"[sentinel] SENTINEL_TELEGRAM_CHAT_ID is set but vault is unavailable — Telegram confirmations disabled",
	);
}

const { app, resolveConfirmation } = createApp(
	config,
	auditLogger,
	registry,
	vault,
	hmacSecret,
	undefined,
	egressBindings,
	telegramAdapter,
);

const port = config.executor.port;
const host = "0.0.0.0";

serve({ fetch: app.fetch, port, hostname: host }, () => {
	console.log(`Sentinel Executor listening on http://${host}:${port}`);
	if (telegramAdapter) {
		const hasTelegramBinding = egressBindings.some((b) =>
			b.allowedDomains.some((d) => d === "api.telegram.org"),
		);
		if (hasTelegramBinding) {
			console.log("[sentinel] Telegram egress proxy interception active (Docker mode)");
		}
		// SENTINEL_TELEGRAM_POLLER controls who polls Telegram:
		// - "executor" (default): executor runs fallback polling (standalone Sentinel mode)
		// - "gateway": OpenClaw gateway is the sole poller; plugin forwards callbacks via interceptor
		const telegramPoller = process.env.SENTINEL_TELEGRAM_POLLER ?? "executor";
		if (telegramPoller === "executor") {
			telegramAdapter.startFallbackPolling(resolveConfirmation);
			console.log(
				"[entrypoint] Telegram fallback polling started (SENTINEL_TELEGRAM_POLLER=executor)",
			);
		} else {
			console.log(
				`[entrypoint] Telegram fallback polling disabled (SENTINEL_TELEGRAM_POLLER=${telegramPoller})`,
			);
			console.log("[entrypoint] Confirmations will be forwarded by OpenClaw plugin interceptor");
		}
	}
});
