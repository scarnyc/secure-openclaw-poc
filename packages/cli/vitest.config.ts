import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		alias: {
			"@sentinel/types": resolve(__dirname, "../types/src/index.ts"),
			"@sentinel/policy": resolve(__dirname, "../policy/src/index.ts"),
			"@sentinel/audit": resolve(__dirname, "../audit/src/index.ts"),
			"@sentinel/crypto": resolve(__dirname, "../crypto/src/index.ts"),
			"@sentinel/executor": resolve(__dirname, "../executor/src/index.ts"),
			"@sentinel/agent": resolve(__dirname, "../agent/src/index.ts"),
		},
	},
	test: {
		globals: false,
	},
});
