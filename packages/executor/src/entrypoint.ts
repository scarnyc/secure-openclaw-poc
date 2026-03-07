import { serve } from "@hono/node-server";
import { AuditLogger } from "@sentinel/audit";
import { getDefaultConfig } from "@sentinel/policy";
import { createApp } from "./server.js";
import { createToolRegistry } from "./tools/index.js";

const mutableConfig = getDefaultConfig();
mutableConfig.auditLogPath = process.env.SENTINEL_AUDIT_PATH ?? "/app/data/audit.db";
mutableConfig.vaultPath = process.env.SENTINEL_VAULT_PATH ?? "/app/data/vault.enc";
const config = Object.freeze(structuredClone(mutableConfig));

const auditLogger = new AuditLogger(config.auditLogPath);
const registry = createToolRegistry();
const app = createApp(config, auditLogger, registry);

const port = config.executor.port;
const host = "0.0.0.0";

serve({ fetch: app.fetch, port, hostname: host }, () => {
	console.log(`Sentinel Executor listening on http://${host}:${port}`);
});
