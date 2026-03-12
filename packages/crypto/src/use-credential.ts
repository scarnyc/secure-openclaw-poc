import type { CredentialVault } from "./vault.js";

/**
 * Callback-scoped credential accessor that minimizes V8 string lifetime.
 *
 * Retrieves a credential as a Buffer, parses it, passes the parsed object to `fn`,
 * then deterministically zeroes the Buffer in `finally`. The parsed credential strings
 * become unreachable after `fn` returns — eligible for GC.
 *
 * Callbacks MUST NOT store credential values outside their scope.
 */
export async function useCredential<T, K extends string>(
	vault: CredentialVault,
	serviceId: string,
	requiredKeys: readonly K[],
	fn: (cred: Readonly<Record<K, string>>) => T | Promise<T>,
): Promise<T>;
export async function useCredential<T>(
	vault: CredentialVault,
	serviceId: string,
	fn: (cred: Readonly<Record<string, string>>) => T | Promise<T>,
): Promise<T>;
export async function useCredential<T>(
	vault: CredentialVault,
	serviceId: string,
	fnOrKeys: readonly string[] | ((cred: Readonly<Record<string, string>>) => T | Promise<T>),
	maybeFn?: (cred: Readonly<Record<string, string>>) => T | Promise<T>,
): Promise<T> {
	const requiredKeys = typeof fnOrKeys === "function" ? undefined : fnOrKeys;
	// biome-ignore lint/style/noNonNullAssertion: overload guarantees maybeFn when fnOrKeys is array
	const fn = typeof fnOrKeys === "function" ? fnOrKeys : maybeFn!;

	const buf = vault.retrieveBuffer(serviceId);
	try {
		let parsed: Record<string, string>;
		try {
			parsed = JSON.parse(buf.toString("utf8"));
		} catch {
			throw new Error(
				`Failed to parse credential for service "${serviceId}": vault entry is malformed`,
			);
		}

		// Validate all values are strings (detect {"key": 123} corruption)
		for (const v of Object.values(parsed)) {
			if (typeof v !== "string") {
				throw new Error(`Credential entry for "${serviceId}" contains non-string values`);
			}
		}

		// Validate required keys if provided
		if (requiredKeys) {
			for (const key of requiredKeys) {
				if (!parsed[key]) {
					throw new Error(
						`Missing required field "${key}" in credential for service: ${serviceId}`,
					);
				}
			}
		}

		return await fn(Object.freeze(parsed) as Readonly<Record<string, string>>);
	} finally {
		buf.fill(0);
	}
}
