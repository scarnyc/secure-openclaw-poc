import type { ToolResult } from "@sentinel/types";
import { describe, expect, it } from "vitest";
import { ConversationContext } from "./context.js";

describe("ConversationContext", () => {
	it("returns empty array for new context", () => {
		const ctx = new ConversationContext();
		expect(ctx.getMessages()).toEqual([]);
	});

	it("addUserMessage returns correct format", () => {
		const ctx = new ConversationContext();
		ctx.addUserMessage("Hello");

		const msgs = ctx.getMessages();
		expect(msgs).toHaveLength(1);
		expect(msgs[0]).toEqual({ role: "user", content: "Hello" });
	});

	it("addAssistantMessage returns correct format", () => {
		const ctx = new ConversationContext();
		ctx.addAssistantMessage("Hi there");

		const msgs = ctx.getMessages();
		expect(msgs).toHaveLength(1);
		expect(msgs[0]).toEqual({ role: "assistant", content: "Hi there" });
	});

	it("addToolResult formats tool_result correctly for success", () => {
		const ctx = new ConversationContext();
		const result: ToolResult = {
			manifestId: "00000000-0000-4000-8000-000000000001",
			success: true,
			output: "file contents here",
			duration_ms: 10,
		};

		ctx.addToolResult("tool-use-123", result);

		const msgs = ctx.getMessages();
		expect(msgs).toHaveLength(1);
		expect(msgs[0].role).toBe("user");

		const content = msgs[0].content;
		expect(Array.isArray(content)).toBe(true);
		const blocks = content as unknown[];
		expect(blocks).toHaveLength(1);
		expect(blocks[0]).toMatchObject({
			type: "tool_result",
			tool_use_id: "tool-use-123",
			content: "file contents here",
			is_error: false,
		});
	});

	it("addToolResult formats tool_result correctly for error", () => {
		const ctx = new ConversationContext();
		const result: ToolResult = {
			manifestId: "00000000-0000-4000-8000-000000000001",
			success: false,
			error: "Permission denied",
			duration_ms: 5,
		};

		ctx.addToolResult("tool-use-456", result);

		const msgs = ctx.getMessages();
		const blocks = msgs[0].content as unknown[];
		expect(blocks[0]).toMatchObject({
			type: "tool_result",
			tool_use_id: "tool-use-456",
			content: "Error: Permission denied",
			is_error: true,
		});
	});

	it("getMessages returns a copy", () => {
		const ctx = new ConversationContext();
		ctx.addUserMessage("test");

		const msgs1 = ctx.getMessages();
		const msgs2 = ctx.getMessages();
		expect(msgs1).not.toBe(msgs2);
		expect(msgs1).toEqual(msgs2);
	});

	describe("trimToFit", () => {
		it("removes oldest messages when over token limit", () => {
			const ctx = new ConversationContext();
			// Each message ~25 chars = ~6 tokens
			for (let i = 0; i < 20; i++) {
				ctx.addUserMessage(`Message number ${i} here!`);
			}

			expect(ctx.getMessages()).toHaveLength(20);

			// Trim to ~10 tokens — should keep only 1-2 messages
			ctx.trimToFit(10);

			const remaining = ctx.getMessages();
			expect(remaining.length).toBeLessThan(20);
			expect(remaining.length).toBeGreaterThan(0);
		});

		it("does not remove if within limit", () => {
			const ctx = new ConversationContext();
			ctx.addUserMessage("short");
			ctx.addAssistantMessage("reply");

			ctx.trimToFit(100_000);

			expect(ctx.getMessages()).toHaveLength(2);
		});

		it("keeps at least one message", () => {
			const ctx = new ConversationContext();
			ctx.addUserMessage("a".repeat(1000));

			ctx.trimToFit(1);

			expect(ctx.getMessages()).toHaveLength(1);
		});
	});
});
