import type { CredentialVault } from "@sentinel/crypto";
import { useCredential } from "@sentinel/crypto";
import { z } from "zod";

const TOKEN_REFRESH_BUFFER_MS = 60_000;

const OAuthRefreshResponse = z.object({
	access_token: z.string().min(1),
	expires_in: z.number().positive(),
});

const REQUIRED_OAUTH_FIELDS = ["clientId", "clientSecret", "refreshToken", "accessToken"] as const;

/**
 * Retrieve a valid Google Workspace access token from the vault.
 * Refreshes via OAuth2 if the token is expired or expiring within 60s.
 */
export async function getGwsAccessToken(vault: CredentialVault): Promise<string> {
	// NOTE: Access token intentionally escapes useCredential scope — subprocess injection requires a string.
	// Token is short-lived (single GWS call).
	return useCredential(vault, "google/oauth", async (creds) => {
		// Validate required credential fields
		for (const field of REQUIRED_OAUTH_FIELDS) {
			if (!creds[field]) {
				throw new Error(`Missing required OAuth field "${field}" in google/oauth vault entry`);
			}
		}

		const expiresAt = creds.expiresAt ? Number(creds.expiresAt) : 0;
		if (!Number.isNaN(expiresAt) && Date.now() < expiresAt - TOKEN_REFRESH_BUFFER_MS) {
			return creds.accessToken;
		}

		// Token expired or expiring soon — refresh
		const body = new URLSearchParams({
			client_id: creds.clientId,
			client_secret: creds.clientSecret,
			refresh_token: creds.refreshToken,
			grant_type: "refresh_token",
		});

		const resp = await fetch("https://oauth2.googleapis.com/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: body.toString(),
		});

		if (!resp.ok) {
			// Never include response body — may contain credential hints
			throw new Error(`OAuth token refresh failed: HTTP ${resp.status}`);
		}

		const data = OAuthRefreshResponse.parse(await resp.json());

		// Store updated token back to vault
		await vault.store("google/oauth", "oauth", {
			...creds,
			accessToken: data.access_token,
			expiresAt: String(Date.now() + data.expires_in * 1000),
		});

		return data.access_token;
	});
}
