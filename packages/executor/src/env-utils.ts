import { STRIPPED_ENV_KEYS, STRIPPED_ENV_PREFIXES } from "@sentinel/types";

export { STRIPPED_ENV_KEYS, STRIPPED_ENV_PREFIXES };

export function stripSensitiveEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
	const cleaned: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(env)) {
		if (STRIPPED_ENV_KEYS.has(key)) continue;
		if (STRIPPED_ENV_PREFIXES.some((p) => key.startsWith(p))) continue;
		cleaned[key] = value;
	}
	return cleaned;
}
