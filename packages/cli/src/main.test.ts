import { describe, expect, it } from "vitest";

describe("CLI", () => {
	it("exports all command functions", async () => {
		const mod = await import("./index.js");
		expect(typeof mod.initCommand).toBe("function");
		expect(typeof mod.chatCommand).toBe("function");
		expect(typeof mod.vaultCommand).toBe("function");
		expect(typeof mod.auditCommand).toBe("function");
	});
});
