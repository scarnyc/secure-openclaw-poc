import { GwsAgentScopesSchema, type SentinelConfig } from "@sentinel/types";

export interface DockerDefaultsEnv {
	SENTINEL_DOCKER?: string;
	SENTINEL_GWS_SHA256?: string;
	SENTINEL_GWS_AGENT_SCOPES?: string;
	SENTINEL_GWS_ACCOUNT_EMAIL?: string;
}

export interface DockerDefaultsResult {
	config: SentinelConfig;
	/** Non-empty when SENTINEL_DOCKER=true and SENTINEL_GWS_SHA256 is missing */
	fatal?: string;
	warnings: string[];
}

/**
 * Apply Docker-mode GWS security defaults to a validated config.
 * Pure function — no process.exit, no console.log (caller handles those).
 */
export function applyDockerDefaults(
	validated: SentinelConfig,
	env: DockerDefaultsEnv,
): DockerDefaultsResult {
	let config = { ...validated };
	const warnings: string[] = [];

	// G2: Docker forces GWS binary verification with SHA-256 hash
	if (env.SENTINEL_DOCKER === "true") {
		const base = config.gwsIntegrity ?? {
			verifyBinary: false,
			pinnedVersionPolicy: "minimum" as const,
			vulnerableVersions: [],
		};
		const expectedSha256 = env.SENTINEL_GWS_SHA256 ?? base.expectedSha256;
		if (!expectedSha256) {
			return {
				config,
				fatal:
					"FATAL: SENTINEL_DOCKER=true requires SENTINEL_GWS_SHA256 for GWS binary verification",
				warnings,
			};
		}
		const gwsIntegrity = {
			...base,
			verifyBinary: true,
			expectedSha256,
		};
		// G5: Docker default-deny for unconfigured agents (top-level config field)
		config = { ...config, gwsIntegrity, gwsDefaultDeny: true };
	}

	// G5: Parse per-agent GWS scopes from env var
	if (env.SENTINEL_GWS_AGENT_SCOPES) {
		let rawJson: unknown;
		try {
			rawJson = JSON.parse(env.SENTINEL_GWS_AGENT_SCOPES);
		} catch {
			return {
				config,
				fatal:
					"FATAL: SENTINEL_GWS_AGENT_SCOPES contains invalid JSON — check Docker env var syntax",
				warnings,
			};
		}
		const parseResult = GwsAgentScopesSchema.safeParse(rawJson);
		if (!parseResult.success) {
			return {
				config,
				fatal: `FATAL: SENTINEL_GWS_AGENT_SCOPES schema validation failed: ${parseResult.error.message}`,
				warnings,
			};
		}
		config = { ...config, gwsAgentScopes: parseResult.data };
	}

	// G4: Warn when GWS account email not configured
	if (!env.SENTINEL_GWS_ACCOUNT_EMAIL) {
		warnings.push(
			"[sentinel] No SENTINEL_GWS_ACCOUNT_EMAIL configured — GWS account identity not validated",
		);
	}

	return { config, warnings };
}
