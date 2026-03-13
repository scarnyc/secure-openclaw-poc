import { afterEach, describe, expect, it, vi } from "vitest";

// Mock undici — Agent constructor is tracked per-call; destroy is a vi.fn per instance
const mockAgentInstances: { connect: object; destroy: ReturnType<typeof vi.fn> }[] = [];

vi.mock("undici", () => {
	const AgentMock = vi.fn().mockImplementation((opts: { connect: object }) => {
		const instance = { connect: opts.connect, destroy: vi.fn().mockResolvedValue(undefined) };
		mockAgentInstances.push(instance);
		return instance;
	});
	return {
		Agent: AgentMock,
		fetch: vi.fn().mockResolvedValue(new Response("{}", { status: 200 })),
	};
});

import { Agent, fetch as undiciFetch } from "undici";
import { createIpPinnedFetch, destroyAllPinnedAgents } from "./ip-pinned-fetch.js";

// Clear agent cache between tests to keep tests isolated
afterEach(async () => {
	await destroyAllPinnedAgents();
	mockAgentInstances.length = 0;
	vi.mocked(Agent).mockClear();
	vi.mocked(undiciFetch).mockClear();
});

describe("createIpPinnedFetch", () => {
	it("returns a callable function", () => {
		const pinnedFetch = createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		expect(typeof pinnedFetch).toBe("function");
	});

	it("creates Agent with correct connect options", () => {
		createIpPinnedFetch("93.184.216.34", "api.openai.com");
		expect(Agent).toHaveBeenCalledWith({
			connect: {
				host: "93.184.216.34",
				servername: "api.openai.com",
			},
		});
	});

	it("calls undici fetch with dispatcher agent", async () => {
		const pinnedFetch = createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		await pinnedFetch("https://api.anthropic.com/v1/messages", {
			method: "POST",
			headers: new Headers({ "Content-Type": "application/json" }),
		});

		expect(undiciFetch).toHaveBeenCalledOnce();
		const [url, opts] = vi.mocked(undiciFetch).mock.calls[0];
		expect(url).toBe("https://api.anthropic.com/v1/messages");
		expect(opts?.method).toBe("POST");
		expect(opts?.dispatcher).toBeDefined();
	});

	it("returns the same fetch function (same Agent) for identical ip+host key", () => {
		// First call — creates an Agent
		createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		expect(Agent).toHaveBeenCalledTimes(1);

		// Second call with identical args — must reuse cached Agent, not create a new one
		createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		expect(Agent).toHaveBeenCalledTimes(1);
	});

	it("creates separate Agents for different ip+host combinations", () => {
		createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		createIpPinnedFetch("5.6.7.8", "api.anthropic.com"); // different IP
		createIpPinnedFetch("1.2.3.4", "api.openai.com"); // different host
		expect(Agent).toHaveBeenCalledTimes(3);
	});
});

describe("destroyAllPinnedAgents", () => {
	it("calls destroy() on every cached Agent and clears the cache", async () => {
		// Populate the cache with two distinct entries
		createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		createIpPinnedFetch("5.6.7.8", "api.openai.com");
		expect(mockAgentInstances).toHaveLength(2);

		await destroyAllPinnedAgents();

		for (const instance of mockAgentInstances) {
			expect(instance.destroy).toHaveBeenCalledOnce();
		}
	});

	it("clears cache so subsequent calls create fresh Agents", async () => {
		createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		expect(Agent).toHaveBeenCalledTimes(1);

		await destroyAllPinnedAgents();

		// After clearing, same key must create a new Agent
		createIpPinnedFetch("1.2.3.4", "api.anthropic.com");
		expect(Agent).toHaveBeenCalledTimes(2);
	});

	it("is a no-op when cache is empty", async () => {
		await expect(destroyAllPinnedAgents()).resolves.toBeUndefined();
	});
});
