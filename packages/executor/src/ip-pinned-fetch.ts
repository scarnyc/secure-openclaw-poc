import { Agent, fetch as undiciFetch } from "undici";

/** Agent cache keyed by `${pinnedIp}:${hostname}` — reuses connection pools for identical targets. */
const agentCache = new Map<string, Agent>();

/** Creates a fetch function that pins TCP connections to a pre-resolved IP address.
 *  TLS SNI still uses the original hostname for certificate validation.
 *  Agents are cached by (pinnedIp, hostname) pair to avoid per-request connection pool leaks. */
export function createIpPinnedFetch(pinnedIp: string, hostname: string) {
	const key = `${pinnedIp}:${hostname}`;
	let agent = agentCache.get(key);
	if (!agent) {
		agent = new Agent({
			connect: {
				host: pinnedIp,
				servername: hostname,
			},
		});
		agentCache.set(key, agent);
	}
	return (url: string | URL, init?: RequestInit) =>
		undiciFetch(url, { ...init, dispatcher: agent } as Parameters<typeof undiciFetch>[1]);
}

/** Destroys all cached undici Agents and clears the cache. Call during graceful shutdown. */
export async function destroyAllPinnedAgents(): Promise<void> {
	for (const agent of agentCache.values()) {
		await agent.destroy();
	}
	agentCache.clear();
}
