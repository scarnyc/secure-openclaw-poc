import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CredentialVault } from "@sentinel/crypto";
import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	type MockInstance,
	vi,
} from "vitest";
import { getGwsAccessToken } from "./gws-auth.js";

const MASTER_PASSWORD = "test-password-123";

const baseCreds = {
	clientId: "test-client-id",
	clientSecret: "test-client-secret",
	refreshToken: "test-refresh-token",
	accessToken: "valid-access-token",
};

describe("getGwsAccessToken", () => {
	let tmpDir: string;
	let vault: CredentialVault;
	let mockFetch: MockInstance;
	const originalFetch = globalThis.fetch;

	beforeAll(async () => {
		tmpDir = await mkdtemp(join(tmpdir(), "gws-auth-test-"));
	});

	afterAll(async () => {
		await rm(tmpDir, { recursive: true, force: true });
	});

	beforeEach(async () => {
		const vaultPath = join(tmpDir, `vault-${Date.now()}.enc`);
		vault = await CredentialVault.create(vaultPath, MASTER_PASSWORD);
		mockFetch = vi.fn();
		globalThis.fetch = mockFetch as unknown as typeof fetch;
	});

	afterEach(() => {
		vault.destroy();
		globalThis.fetch = originalFetch;
	});

	it("returns cached token when not expired", async () => {
		const futureExpiry = String(Date.now() + 300_000); // 5 min from now
		await vault.store("google/oauth", "oauth", {
			...baseCreds,
			expiresAt: futureExpiry,
		});

		const token = await getGwsAccessToken(vault);
		expect(token).toBe("valid-access-token");
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it("refreshes when token is expired", async () => {
		const pastExpiry = String(Date.now() - 60_000); // 1 min ago
		await vault.store("google/oauth", "oauth", {
			...baseCreds,
			expiresAt: pastExpiry,
		});

		mockFetch.mockResolvedValueOnce(
			new Response(JSON.stringify({ access_token: "new-token-123", expires_in: 3600 }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		const token = await getGwsAccessToken(vault);
		expect(token).toBe("new-token-123");
		expect(mockFetch).toHaveBeenCalledOnce();
		expect(mockFetch).toHaveBeenCalledWith(
			"https://oauth2.googleapis.com/token",
			expect.objectContaining({ method: "POST" }),
		);
	});

	it("refreshes when token expires within 60s", async () => {
		const soonExpiry = String(Date.now() + 30_000); // 30s from now (within 60s window)
		await vault.store("google/oauth", "oauth", {
			...baseCreds,
			expiresAt: soonExpiry,
		});

		mockFetch.mockResolvedValueOnce(
			new Response(JSON.stringify({ access_token: "refreshed-token", expires_in: 3600 }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		const token = await getGwsAccessToken(vault);
		expect(token).toBe("refreshed-token");
		expect(mockFetch).toHaveBeenCalledOnce();
	});

	it("throws meaningful error without credentials on refresh failure", async () => {
		const pastExpiry = String(Date.now() - 60_000);
		await vault.store("google/oauth", "oauth", {
			...baseCreds,
			expiresAt: pastExpiry,
		});

		mockFetch.mockResolvedValue(
			new Response(JSON.stringify({ error: "invalid_grant" }), {
				status: 400,
				headers: { "Content-Type": "application/json" },
			}),
		);

		await expect(getGwsAccessToken(vault)).rejects.toThrow("OAuth token refresh failed: HTTP 400");
		// Ensure error does not contain credentials
		try {
			await getGwsAccessToken(vault);
		} catch (err) {
			const msg = (err as Error).message;
			expect(msg).not.toContain("test-client-secret");
			expect(msg).not.toContain("test-refresh-token");
		}
	});

	it("throws when access_token missing from 200 response", async () => {
		const pastExpiry = String(Date.now() - 60_000);
		await vault.store("google/oauth", "oauth", {
			...baseCreds,
			expiresAt: pastExpiry,
		});

		mockFetch.mockResolvedValueOnce(
			new Response(JSON.stringify({}), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		await expect(getGwsAccessToken(vault)).rejects.toThrow();
	});

	it("stores refreshed token back to vault", async () => {
		// First call: expired token triggers refresh
		const pastExpiry = String(Date.now() - 60_000);
		await vault.store("google/oauth", "oauth", {
			...baseCreds,
			expiresAt: pastExpiry,
		});

		mockFetch.mockResolvedValueOnce(
			new Response(JSON.stringify({ access_token: "refreshed-token", expires_in: 3600 }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		const token1 = await getGwsAccessToken(vault);
		expect(token1).toBe("refreshed-token");
		expect(mockFetch).toHaveBeenCalledOnce();

		// Second call: stored token should still be valid (no second fetch)
		const token2 = await getGwsAccessToken(vault);
		expect(token2).toBe("refreshed-token");
		// fetch should NOT have been called again — the refreshed token was stored with future expiry
		expect(mockFetch).toHaveBeenCalledOnce();
	});

	it("throws on missing required credential field", async () => {
		const pastExpiry = String(Date.now() - 60_000);
		// Store creds without clientSecret
		await vault.store("google/oauth", "oauth", {
			clientId: "test-client-id",
			refreshToken: "test-refresh-token",
			accessToken: "valid-access-token",
			expiresAt: pastExpiry,
		});

		await expect(getGwsAccessToken(vault)).rejects.toThrow("clientSecret");
	});
});
