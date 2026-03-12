/**
 * Bridge to @sentinel/crypto-native Rust addon.
 * Falls back to JS implementation with security warning when native addon is unavailable.
 */

import { warnOnce } from "./warn-once.js";

interface NativeModule {
	useCredentialNative(vaultPath: string, derivedKey: Buffer, serviceId: string): Buffer;
	getCredentialFieldNative(
		vaultPath: string,
		derivedKey: Buffer,
		serviceId: string,
		field: string,
	): string;
	spawnWithCredential(
		command: string,
		args: string[],
		env: Record<string, string>,
		envVarName: string,
		vaultPath: string,
		derivedKey: Buffer,
		serviceId: string,
		credentialField: string,
		timeoutMs?: number,
	): { stdout: string; stderr: string; exitCode: number };
	deriveKeyNative(password: string, saltB64: string): Buffer;
}

let nativeModule: NativeModule | undefined;
let loadAttempted = false;

function getNativeModule(): NativeModule | undefined {
	if (loadAttempted) return nativeModule;
	loadAttempted = true;

	try {
		// Dynamic require of native addon — ESM import would need top-level await
		// biome-ignore lint/suspicious/noExplicitAny: dynamic native addon loading
		const mod = require("@sentinel/crypto-native") as any;

		// Runtime shape check — verify native module exports match expected interface
		const requiredFunctions = ["useCredentialNative", "spawnWithCredential", "deriveKeyNative"];
		for (const fn of requiredFunctions) {
			if (typeof mod[fn] !== "function") {
				throw new Error(`Native module missing expected export: ${fn}`);
			}
		}
		nativeModule = mod;
	} catch (err: unknown) {
		const code = (err as NodeJS.ErrnoException).code;
		if (code === "MODULE_NOT_FOUND") {
			warnOnce(
				"crypto-native",
				"[sentinel/crypto] Native crypto addon not available — credential strings will use V8 heap (not zeroizable). Install @sentinel/crypto-native for deterministic zeroization.",
			);
		} else {
			console.error(
				`[sentinel/crypto] Native crypto addon found but failed to load: ${err instanceof Error ? err.message : String(err)}. Falling back to JS implementation.`,
			);
		}
	}

	return nativeModule;
}

/**
 * Check if the native crypto addon is available.
 */
export function isNativeAvailable(): boolean {
	return getNativeModule() !== undefined;
}

/**
 * Spawn a subprocess with a credential from the vault injected as an env var.
 * Credential NEVER enters JavaScript when native addon is available.
 *
 * @throws Error if native addon is not available (no JS fallback for this function)
 */
export function spawnWithCredentialNative(
	command: string,
	args: string[],
	env: Record<string, string>,
	envVarName: string,
	vaultPath: string,
	derivedKey: Buffer,
	serviceId: string,
	credentialField: string,
	timeoutMs?: number,
): { stdout: string; stderr: string; exitCode: number } {
	const mod = getNativeModule();
	if (!mod) {
		throw new Error(
			"Native crypto addon required for spawnWithCredential — install @sentinel/crypto-native",
		);
	}

	return mod.spawnWithCredential(
		command,
		args,
		env,
		envVarName,
		vaultPath,
		derivedKey,
		serviceId,
		credentialField,
		timeoutMs,
	);
}

/** Reset module loading state — test helper only. */
export function _resetNativeBridge(): void {
	nativeModule = undefined;
	loadAttempted = false;
}
