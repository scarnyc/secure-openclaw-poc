import * as p from "@clack/prompts";
import { CredentialVault } from "@sentinel/crypto";
import type { SentinelConfig } from "@sentinel/types";
import chalk from "chalk";

export async function vaultCommand(
	config: SentinelConfig,
	action: string | undefined,
): Promise<void> {
	const password = await p.password({
		message: "Master password:",
	});
	if (p.isCancel(password)) {
		p.cancel("Cancelled.");
		return;
	}

	let vault: CredentialVault;
	try {
		vault = await CredentialVault.open(config.vaultPath, password);
	} catch {
		p.cancel("Failed to unlock vault. Wrong password?");
		return;
	}

	try {
		switch (action) {
			case "list": {
				const entries = await vault.list();
				if (entries.length === 0) {
					console.log(chalk.dim("No credentials stored."));
				} else {
					for (const e of entries) {
						console.log(`  ${chalk.cyan(e.serviceId)} (${e.type}) — ${e.createdAt}`);
					}
				}
				break;
			}
			case "add": {
				const serviceId = await p.text({
					message: "Service ID (e.g., anthropic, github):",
				});
				if (p.isCancel(serviceId)) return;

				const credType = await p.text({
					message: "Credential type (api_key, oauth, token):",
					initialValue: "api_key",
				});
				if (p.isCancel(credType)) return;

				const value = await p.password({
					message: "Credential value:",
				});
				if (p.isCancel(value)) return;

				await vault.store(serviceId, credType, { key: value });
				console.log(chalk.green(`Stored credential for ${serviceId}.`));
				break;
			}
			case "remove": {
				const serviceId = await p.text({
					message: "Service ID to remove:",
				});
				if (p.isCancel(serviceId)) return;

				await vault.remove(serviceId);
				console.log(chalk.green(`Removed credential for ${serviceId}.`));
				break;
			}
			default: {
				console.log("Usage: sentinel vault <list|add|remove>");
			}
		}
	} finally {
		vault.destroy();
	}
}
