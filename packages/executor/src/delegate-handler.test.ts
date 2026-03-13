import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDelegateHandler, DelegationQueue } from "./delegate-handler.js";

let tempDir: string;
let queue: DelegationQueue;

beforeEach(() => {
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-delegate-test-")));
	queue = new DelegationQueue(join(tempDir, "delegations.db"));
});

afterEach(() => {
	queue.close();
	rmSync(tempDir, { recursive: true, force: true });
});

describe("DelegationQueue", () => {
	it("enqueues and retrieves pending delegations", () => {
		queue.enqueue({
			id: "test-1",
			task: "Fix the bug",
			allowedTools: ["Read", "Write"],
			maxBudgetUsd: 5,
			timeoutSeconds: 900,
			agentId: "agent-1",
			sessionId: "session-1",
			status: "pending",
		});

		const pending = queue.getPending();
		expect(pending).toHaveLength(1);
		expect(pending[0].task).toBe("Fix the bug");
		expect(pending[0].allowedTools).toEqual(["Read", "Write"]);
	});

	it("updates delegation status", () => {
		queue.enqueue({
			id: "test-2",
			task: "Add feature",
			allowedTools: ["Read"],
			maxBudgetUsd: 3,
			timeoutSeconds: 600,
			agentId: "agent-1",
			sessionId: "session-1",
			status: "pending",
		});

		queue.updateStatus("test-2", "completed", "https://github.com/org/repo/pull/42");
		const pending = queue.getPending();
		expect(pending).toHaveLength(0);
	});
});

describe("createDelegateHandler", () => {
	it("enqueues valid delegation and returns pending result", async () => {
		const handler = createDelegateHandler(queue);
		const result = await handler(
			{ task: "Implement feature X" },
			"manifest-1",
			"agent-1",
			"session-1",
		);

		expect(result.success).toBe(true);
		const output = JSON.parse(result.output!);
		expect(output.status).toBe("pending");
		expect(output.delegationId).toBeTruthy();

		const pending = queue.getPending();
		expect(pending).toHaveLength(1);
		expect(pending[0].sessionId).toBe("session-1");
	});

	it("rejects invalid params", async () => {
		const handler = createDelegateHandler(queue);
		const result = await handler(
			{ task: "" }, // empty task fails min(1)
			"manifest-1",
			"agent-1",
			"session-1",
		);
		expect(result.success).toBe(false);
		expect(result.error).toContain("Invalid delegate.code params");
	});
});
