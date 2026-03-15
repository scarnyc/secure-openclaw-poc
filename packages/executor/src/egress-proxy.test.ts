import type { EgressBinding } from "@sentinel/types";
import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createEgressProxyHandler, EgressSecurityError } from "./egress-proxy.js";

// Mock dns to avoid real DNS resolution in SSRF guard
vi.mock("node:dns/promises", () => ({
	default: {
		resolve4: vi.fn().mockResolvedValue(["1.2.3.4"]),
		resolve6: vi.fn().mockRejectedValue(new Error("no AAAA")),
	},
}));

const DEFAULT_BINDINGS: EgressBinding[] = [
	{ serviceId: "TELEGRAM", allowedDomains: ["api.telegram.org"] },
];

function createMockVault(credentialData?: Record<string, string>) {
	const data = credentialData ?? { BOT_TOKEN: "test-token-123" };
	return {
		retrieveBuffer: vi.fn().mockReturnValue(Buffer.from(JSON.stringify(data))),
	};
}

function createTestApp(options?: {
	bindings?: EgressBinding[];
	vault?: ReturnType<typeof createMockVault> | undefined;
}) {
	const app = new Hono();
	const mockAuditLogger = { log: vi.fn() };
	const bindings = options?.bindings ?? DEFAULT_BINDINGS;
	const vault =
		options?.vault === undefined && !("vault" in (options ?? {}))
			? createMockVault()
			: options?.vault;

	const handler = createEgressProxyHandler(vault as any, mockAuditLogger as any, bindings);
	app.post("/proxy/egress", handler);

	return { app, mockAuditLogger, vault };
}

async function postEgress(app: Hono, body: Record<string, unknown>): Promise<Response> {
	return app.request("/proxy/egress", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

describe("egress proxy", () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	it("rejects non-HTTPS URLs", async () => {
		const { app } = createTestApp();
		const res = await postEgress(app, {
			url: "http://api.telegram.org/bot123/sendMessage",
		});
		expect(res.status).toBe(400);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.error).toContain("HTTPS");
	});

	it("blocks unbound domains", async () => {
		const { app } = createTestApp();
		const res = await postEgress(app, {
			url: "https://evil.com/steal",
		});
		expect(res.status).toBe(403);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.error).toContain("not a bound egress domain");
	});

	it("blocks private IPs via SSRF guard", async () => {
		// Use dynamic import to override the dns mock for this test
		const dns = await import("node:dns/promises");
		(dns.default.resolve4 as ReturnType<typeof vi.fn>).mockResolvedValue(["10.0.0.1"]);

		const { app } = createTestApp({
			bindings: [{ serviceId: "internal", allowedDomains: ["internal.example.com"] }],
		});
		const res = await postEgress(app, {
			url: "https://internal.example.com/secret",
		});
		expect(res.status).toBe(403);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.error).toContain("SSRF");

		// Restore dns mock
		(dns.default.resolve4 as ReturnType<typeof vi.fn>).mockResolvedValue(["1.2.3.4"]);
	});

	it("substitutes credential placeholders in URL, headers, and body", async () => {
		const mockResponse = new Response(JSON.stringify({ ok: true }), {
			status: 200,
			headers: { "content-type": "application/json" },
		});
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

		const { app } = createTestApp();
		const res = await postEgress(app, {
			url: "https://api.telegram.org/botSENTINEL_PLACEHOLDER_TELEGRAM__BOT_TOKEN/sendMessage",
			method: "POST",
			body: "chat_id=1&text=hello",
		});

		expect(res.status).toBe(200);

		// Verify fetch was called with the substituted URL (token replaced in URL path)
		const mockFetch = globalThis.fetch as ReturnType<typeof vi.fn>;
		expect(mockFetch).toHaveBeenCalled();
		const calledUrl = mockFetch.mock.calls[0][0] as string;
		expect(calledUrl).toBe("https://api.telegram.org/bottest-token-123/sendMessage");
		expect(calledUrl).not.toContain("SENTINEL_PLACEHOLDER");

		vi.stubGlobal("fetch", originalFetch);
	});

	it("blocks cross-service placeholder injection", async () => {
		vi.stubGlobal("fetch", vi.fn());

		const { app } = createTestApp();
		// URL targets telegram domain, but placeholder references a different service
		const res = await postEgress(app, {
			url: "https://api.telegram.org/sendMessage",
			method: "POST",
			headers: {
				Authorization: "Bearer SENTINEL_PLACEHOLDER_GITHUB__TOKEN",
			},
		});
		expect(res.status).toBe(403);
		const json = (await res.json()) as Record<string, unknown>;
		// Error message should be generic (no vault structure leak)
		expect(json.error).toBe("Credential substitution failed");

		vi.stubGlobal("fetch", originalFetch);
	});

	it("filters credentials from upstream response", async () => {
		const fakeKey = ["sk", "ant", "api03", "abc123def456ghi789jkl012"].join("-");
		const mockResponse = new Response(`secret: ${fakeKey}`, {
			status: 200,
			headers: { "content-type": "text/plain" },
		});
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(mockResponse));

		const { app } = createTestApp();
		const res = await postEgress(app, {
			url: "https://api.telegram.org/getMe",
		});
		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).not.toContain("sk-ant");
		expect(body).toContain("[REDACTED]");

		vi.stubGlobal("fetch", originalFetch);
	});

	it("returns 500 when vault is undefined", async () => {
		const { app } = createTestApp({ vault: undefined });
		const res = await postEgress(app, {
			url: "https://api.telegram.org/getMe",
		});
		expect(res.status).toBe(500);
		const json = (await res.json()) as Record<string, unknown>;
		expect(json.error).toContain("credential vault");
	});
});
