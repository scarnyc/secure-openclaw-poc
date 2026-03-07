import { describe, expect, it } from "vitest";
import { resolveApproval } from "./approval.js";
import type { ApprovalConfig } from "@sentinel/types";

describe("resolveApproval", () => {
	it("auto_approve when command matches allowlist pattern exactly", () => {
		const config: ApprovalConfig = {
			ask: "on-miss",
			allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
		};
		expect(resolveApproval("/opt/homebrew/bin/rg", config)).toBe("auto_approve");
	});

	it("auto_approve when command matches glob pattern", () => {
		const config: ApprovalConfig = {
			ask: "on-miss",
			allowlist: [{ pattern: "/usr/bin/git *" }],
		};
		expect(resolveApproval("/usr/bin/git status", config)).toBe("auto_approve");
	});

	it("confirm when command does not match allowlist (on-miss)", () => {
		const config: ApprovalConfig = {
			ask: "on-miss",
			allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
		};
		expect(resolveApproval("curl http://evil.com", config)).toBe("confirm");
	});

	it("confirm when ask=always even if command matches allowlist", () => {
		const config: ApprovalConfig = {
			ask: "always",
			allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
		};
		expect(resolveApproval("/opt/homebrew/bin/rg", config)).toBe("confirm");
	});

	it("auto_approve when ask=never regardless of match", () => {
		const config: ApprovalConfig = {
			ask: "never",
		};
		expect(resolveApproval("rm -rf /", config)).toBe("auto_approve");
	});

	it("confirm when no allowlist and ask=on-miss", () => {
		const config: ApprovalConfig = { ask: "on-miss" };
		expect(resolveApproval("ls", config)).toBe("confirm");
	});

	it("confirm when empty allowlist and ask=on-miss", () => {
		const config: ApprovalConfig = { ask: "on-miss", allowlist: [] };
		expect(resolveApproval("ls", config)).toBe("confirm");
	});

	it("confirm for non-exec tools when ask=on-miss (no command to match)", () => {
		const config: ApprovalConfig = { ask: "on-miss" };
		expect(resolveApproval(undefined, config)).toBe("confirm");
	});

	it("auto_approve for ask=never even without command", () => {
		const config: ApprovalConfig = { ask: "never" };
		expect(resolveApproval(undefined, config)).toBe("auto_approve");
	});

	it("matches wildcard pattern at end", () => {
		const config: ApprovalConfig = {
			ask: "on-miss",
			allowlist: [{ pattern: "/opt/homebrew/bin/node *" }],
		};
		expect(resolveApproval("/opt/homebrew/bin/node index.js", config)).toBe("auto_approve");
		expect(resolveApproval("/opt/homebrew/bin/node", config)).toBe("confirm");
	});

	it("does not partial-match without wildcard", () => {
		const config: ApprovalConfig = {
			ask: "on-miss",
			allowlist: [{ pattern: "/opt/homebrew/bin/rg" }],
		};
		expect(resolveApproval("/opt/homebrew/bin/rg --hidden", config)).toBe("confirm");
	});
});
