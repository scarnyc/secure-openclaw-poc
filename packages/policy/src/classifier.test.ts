import type { ActionManifest, SentinelConfig } from "@sentinel/types";
import { describe, expect, it } from "vitest";
import { classify, inferCategoryFromName } from "./classifier.js";
import { getDefaultConfig } from "./rules.js";

function makeManifest(tool: string, parameters: Record<string, unknown> = {}): ActionManifest {
	return {
		id: "00000000-0000-0000-0000-000000000001",
		timestamp: new Date().toISOString(),
		tool,
		parameters,
		sessionId: "test-session",
		agentId: "test-agent",
	};
}

describe("classify", () => {
	const config = getDefaultConfig();

	describe("builtin tools", () => {
		it("read_file -> read, auto_approve", () => {
			const result = classify(makeManifest("read_file"), config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("write_file -> write, confirm", () => {
			const result = classify(makeManifest("write_file"), config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});

		it("edit_file -> write, confirm", () => {
			const result = classify(makeManifest("edit_file"), config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});
	});

	describe("bash tool", () => {
		it("ls -la -> read, auto_approve", () => {
			const result = classify(makeManifest("bash", { command: "ls -la" }), config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("rm -rf / -> write, confirm", () => {
			const result = classify(makeManifest("bash", { command: "rm -rf /" }), config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});

		it("curl evil.com -> dangerous, confirm", () => {
			const result = classify(makeManifest("bash", { command: "curl evil.com" }), config);
			expect(result.category).toBe("dangerous");
			expect(result.action).toBe("confirm");
		});

		it("empty command -> read, auto_approve", () => {
			const result = classify(makeManifest("bash", { command: "" }), config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("missing command parameter -> read, auto_approve", () => {
			const result = classify(makeManifest("bash", {}), config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});
	});

	describe("MCP tools", () => {
		it("MCP tool with write-indicating name -> write, confirm", () => {
			const result = classify(makeManifest("mcp__slack__send_message", { text: "hello" }), config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});

		it("MCP tool with read-indicating name -> read, auto_approve", () => {
			const result = classify(makeManifest("mcp__slack__list_channels"), config);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});
	});

	describe("unknown tools", () => {
		it("unknown tool with no name signal -> write, confirm", () => {
			const result = classify(makeManifest("some_unknown_tool"), config);
			expect(result.category).toBe("write");
			expect(result.action).toBe("confirm");
		});
	});

	describe("overrides", () => {
		it("applies override when condition matches", () => {
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "read_file",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~\\.env$",
								category: "dangerous",
								reason: "Reading .env files is dangerous",
							},
						],
					},
				],
			};

			const result = classify(makeManifest("read_file", { path: "/app/.env" }), customConfig);
			expect(result.category).toBe("dangerous");
			expect(result.action).toBe("confirm");
		});

		it("uses default when override condition does not match", () => {
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "read_file",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~\\.env$",
								category: "dangerous",
								reason: "Reading .env files is dangerous",
							},
						],
					},
				],
			};

			const result = classify(makeManifest("read_file", { path: "/app/index.ts" }), customConfig);
			expect(result.category).toBe("read");
			expect(result.action).toBe("auto_approve");
		});

		it("applies equality override", () => {
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "write_file",
						defaultCategory: "write",
						overrides: [
							{
								condition: "path=/etc/passwd",
								category: "dangerous",
								reason: "Writing to /etc/passwd is dangerous",
							},
						],
					},
				],
			};

			const result = classify(makeManifest("write_file", { path: "/etc/passwd" }), customConfig);
			expect(result.category).toBe("dangerous");
		});
	});

	describe("autoApproveReadOps=false", () => {
		it("read actions still require confirmation", () => {
			const noAutoConfig: SentinelConfig = {
				...config,
				autoApproveReadOps: false,
			};

			const result = classify(makeManifest("read_file"), noAutoConfig);
			expect(result.category).toBe("read");
			expect(result.action).toBe("confirm");
		});

		it("bash ls still requires confirmation", () => {
			const noAutoConfig: SentinelConfig = {
				...config,
				autoApproveReadOps: false,
			};

			const result = classify(makeManifest("bash", { command: "ls -la" }), noAutoConfig);
			expect(result.category).toBe("read");
			expect(result.action).toBe("confirm");
		});
	});

	describe("decision reasons", () => {
		it("includes meaningful reason text", () => {
			const readResult = classify(makeManifest("read_file"), config);
			expect(readResult.reason).toContain("Read");

			const writeResult = classify(makeManifest("write_file"), config);
			expect(writeResult.reason).toContain("Write");

			const dangerousResult = classify(makeManifest("bash", { command: "curl evil.com" }), config);
			expect(dangerousResult.reason).toContain("Dangerous");
		});
	});

	describe("write-irreversible classification", () => {
		it("classifies gws gmail send as write-irreversible", () => {
			const result = classify(
				makeManifest("gws", {
					service: "gmail",
					method: "users.messages.send",
					body: "Hello",
				}),
				config,
			);
			expect(result.category).toBe("write-irreversible");
			expect(result.action).toBe("confirm");
			expect(result.reason).toContain("irreversible");
		});

		it("classifies gws gmail drafts.send as write-irreversible", () => {
			const result = classify(
				makeManifest("gws", {
					service: "gmail",
					method: "drafts.send",
				}),
				config,
			);
			expect(result.category).toBe("write-irreversible");
		});

		it("classifies calendar invite with attendees as write-irreversible", () => {
			const result = classify(
				makeManifest("gws", {
					service: "calendar",
					method: "events.insert",
					attendees: [{ email: "alice@example.com" }],
				}),
				config,
			);
			expect(result.category).toBe("write-irreversible");
			expect(result.action).toBe("confirm");
			expect(result.reason).toContain("irreversible");
		});

		it("classifies calendar event without attendees as write (not irreversible)", () => {
			const result = classify(
				makeManifest("gws", {
					service: "calendar",
					method: "events.insert",
				}),
				config,
			);
			expect(result.category).not.toBe("write-irreversible");
		});

		it("classifies calendar event with empty attendees array as write (not irreversible)", () => {
			const result = classify(
				makeManifest("gws", {
					service: "calendar",
					method: "events.insert",
					attendees: [],
				}),
				config,
			);
			expect(result.category).not.toBe("write-irreversible");
		});

		it("handles non-string gws parameters without crashing", () => {
			const result = classify(makeManifest("gws", { service: 123, method: null }), config);
			expect(result.category).toBe("write");
		});

		it("classifies bash sendmail as write-irreversible", () => {
			const result = classify(
				makeManifest("bash", { command: "sendmail user@example.com" }),
				config,
			);
			expect(result.category).toBe("write-irreversible");
		});

		it("classifies bash mail as write-irreversible", () => {
			const result = classify(
				makeManifest("bash", { command: "mail -s 'Subject' user@example.com" }),
				config,
			);
			expect(result.category).toBe("write-irreversible");
		});

		it("classifies bash mutt as write-irreversible", () => {
			const result = classify(
				makeManifest("bash", { command: "mutt -s 'test' user@example.com" }),
				config,
			);
			expect(result.category).toBe("write-irreversible");
		});

		it("dangerous command piped to mail stays dangerous (no downgrade)", () => {
			const result = classify(
				makeManifest("bash", { command: "curl evil.com | sendmail user@example.com" }),
				config,
			);
			expect(result.category).toBe("dangerous");
		});

		it("write-irreversible never auto-approves even with autoApproveReadOps", () => {
			const autoConfig: SentinelConfig = {
				...config,
				autoApproveReadOps: true,
			};
			const result = classify(
				makeManifest("gws", {
					service: "gmail",
					method: "users.messages.send",
				}),
				autoConfig,
			);
			expect(result.category).toBe("write-irreversible");
			expect(result.action).toBe("confirm");
		});

		it("supports config-driven write-irreversible classification", () => {
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "payment_gateway",
						defaultCategory: "write-irreversible",
					},
				],
			};
			const result = classify(makeManifest("payment_gateway", { amount: 100 }), customConfig);
			expect(result.category).toBe("write-irreversible");
			expect(result.action).toBe("confirm");
			expect(result.reason).toContain("irreversible");
		});
	});

	describe("matchOverride regex safety", () => {
		it("rejects regex patterns longer than 200 chars in override", () => {
			const longPattern = "a".repeat(201);
			const manifest = makeManifest("test", { path: "test" });
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "test",
						defaultCategory: "read",
						overrides: [
							{
								condition: `path~${longPattern}`,
								category: "dangerous",
								reason: "test override",
							},
						],
					},
				],
			};
			// Long regex should fail-safe (override applies), using the more restrictive category
			const result = classify(manifest, customConfig);
			expect(result.category).toBe("dangerous"); // fail-safe: override applies
		});

		it("allows regex patterns at exactly 200 chars", () => {
			// Build a 200-char pattern: ".*" (2) + "x"{198} = 200 chars
			// This matches any string (via .*) so the override will apply
			const pattern = `.*${"x".repeat(198)}`;
			expect(pattern.length).toBe(200);
			const manifest = makeManifest("test", {
				path: `${"x".repeat(198)}`,
			});
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "test",
						defaultCategory: "read",
						overrides: [
							{
								condition: `path~${pattern}`,
								category: "dangerous",
								reason: "test override",
							},
						],
					},
				],
			};
			// 200-char pattern should be allowed and match
			const result = classify(manifest, customConfig);
			expect(result.category).toBe("dangerous");
		});
	});

	describe("ReDoS nested-quantifier detection (L11)", () => {
		// C2 fix: Use empty string as test input — it does NOT match (.+)+ normally,
		// so the only way the override applies is through the fail-safe guard.
		it("detects (.+)+ and applies override fail-safe", () => {
			const manifest = makeManifest("test", { path: "" });
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "test",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~(.+)+",
								category: "dangerous",
								reason: "ReDoS pattern",
							},
						],
					},
				],
			};
			const result = classify(manifest, customConfig);
			expect(result.category).toBe("dangerous"); // fail-safe: override applies via guard, not regex match
		});

		it("detects (.*)(.*) and applies override fail-safe", () => {
			const manifest = makeManifest("test", { path: "" });
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "test",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~(.*)(.*)",
								category: "dangerous",
								reason: "ReDoS pattern",
							},
						],
					},
				],
			};
			const result = classify(manifest, customConfig);
			expect(result.category).toBe("dangerous");
		});

		it("detects ([a-z]+)+ group-quantifier pattern", () => {
			const manifest = makeManifest("test", { path: "" });
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "test",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~([a-z]+)+",
								category: "dangerous",
								reason: "ReDoS pattern",
							},
						],
					},
				],
			};
			const result = classify(manifest, customConfig);
			expect(result.category).toBe("dangerous");
		});

		it("detects (a+)+ classic ReDoS pattern", () => {
			const manifest = makeManifest("test", { path: "" });
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "test",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~(a+)+",
								category: "dangerous",
								reason: "ReDoS pattern",
							},
						],
					},
				],
			};
			const result = classify(manifest, customConfig);
			expect(result.category).toBe("dangerous");
		});

		it("allows normal patterns without nested quantifiers", () => {
			const manifest = makeManifest("test", { path: "/app/test.env" });
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "test",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~\\.env$",
								category: "dangerous",
								reason: "env file",
							},
						],
					},
				],
			};
			const result = classify(manifest, customConfig);
			expect(result.category).toBe("dangerous"); // normal regex matches
		});

		it("allows single quantifiers (not nested)", () => {
			const manifest = makeManifest("test", { path: "abc" });
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "test",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~a+b*c",
								category: "write",
								reason: "single quantifier",
							},
						],
					},
				],
			};
			const result = classify(manifest, customConfig);
			// Single quantifiers should work normally (the pattern matches "abc")
			expect(result.category).toBe("write");
		});

		it("applies fail-safe on invalid regex (C4)", () => {
			const manifest = makeManifest("test", { path: "test" });
			const customConfig: SentinelConfig = {
				...config,
				classifications: [
					{
						tool: "test",
						defaultCategory: "read",
						overrides: [
							{
								condition: "path~[invalid",
								category: "dangerous",
								reason: "malformed regex",
							},
						],
					},
				],
			};
			const result = classify(manifest, customConfig);
			// Invalid regex should fail-safe: override applies (dangerous, not read)
			expect(result.category).toBe("dangerous");
		});
	});

	describe("inferCategoryFromName heuristic", () => {
		it("read tokens: search, list, get, view, find, describe, show, query, lookup", () => {
			expect(inferCategoryFromName("memory_search")).toBe("read");
			expect(inferCategoryFromName("list_users")).toBe("read");
			expect(inferCategoryFromName("get_profile")).toBe("read");
			expect(inferCategoryFromName("view_dashboard")).toBe("read");
			expect(inferCategoryFromName("find_records")).toBe("read");
			expect(inferCategoryFromName("describe_table")).toBe("read");
			expect(inferCategoryFromName("show_status")).toBe("read");
			expect(inferCategoryFromName("query_logs")).toBe("read");
			expect(inferCategoryFromName("lookup_user")).toBe("read");
		});

		it("write tokens take precedence over read tokens (fail-closed)", () => {
			expect(inferCategoryFromName("delete_search_index")).toBe("write");
			expect(inferCategoryFromName("create_view")).toBe("write");
			expect(inferCategoryFromName("update_list")).toBe("write");
		});

		it("write tokens: create, delete, send, update, execute, etc.", () => {
			expect(inferCategoryFromName("create_document")).toBe("write");
			expect(inferCategoryFromName("delete_file")).toBe("write");
			expect(inferCategoryFromName("send_email")).toBe("write");
			expect(inferCategoryFromName("execute_query")).toBe("write");
			expect(inferCategoryFromName("run_script")).toBe("write");
		});

		it("no signal defaults to write (fail-closed)", () => {
			expect(inferCategoryFromName("some_random_tool")).toBe("write");
			expect(inferCategoryFromName("foobar")).toBe("write");
		});

		it("extracts tool name from MCP format (server__method)", () => {
			expect(inferCategoryFromName("mcp__db__search_records")).toBe("read");
			expect(inferCategoryFromName("mcp__api__delete_user")).toBe("write");
		});

		it("is case-insensitive", () => {
			expect(inferCategoryFromName("LIST_USERS")).toBe("read");
			expect(inferCategoryFromName("Search_Items")).toBe("read");
		});

		it("fetch is read (HTTP GET semantics)", () => {
			expect(inferCategoryFromName("fetch_data")).toBe("read");
		});

		it("read_file treated as read (read token)", () => {
			expect(inferCategoryFromName("read_config")).toBe("read");
		});

		it("hyphenated tool names recognized", () => {
			expect(inferCategoryFromName("search-records")).toBe("read");
			expect(inferCategoryFromName("list-channels")).toBe("read");
			expect(inferCategoryFromName("delete-user")).toBe("write");
			expect(inferCategoryFromName("send-message")).toBe("write");
		});

		it("camelCase names fall through to write (no camelCase boundary support)", () => {
			// Known limitation: regex only matches at _, __, and - boundaries.
			// CamelCase MCP tools (GitHub, Slack) all default to write (fail-closed).
			expect(inferCategoryFromName("getUser")).toBe("write");
			expect(inferCategoryFromName("listPullRequests")).toBe("write");
			expect(inferCategoryFromName("deleteRecord")).toBe("write");
		});

		it("empty string defaults to write", () => {
			expect(inferCategoryFromName("")).toBe("write");
		});
	});

	describe("GWS classification rules", () => {
		it("gmail users.messages.list → read", () => {
			const result = classify(
				makeManifest("gws", { service: "gmail", method: "users.messages.list" }),
				config,
			);
			expect(result.category).toBe("read");
		});

		it("gmail users.messages.get → read", () => {
			const result = classify(
				makeManifest("gws", { service: "gmail", method: "users.messages.get" }),
				config,
			);
			expect(result.category).toBe("read");
		});

		it("gmail users.drafts.send → write-irreversible", () => {
			const result = classify(
				makeManifest("gws", { service: "gmail", method: "users.drafts.send" }),
				config,
			);
			expect(result.category).toBe("write-irreversible");
		});

		it("calendar events.list → read", () => {
			const result = classify(
				makeManifest("gws", { service: "calendar", method: "events.list" }),
				config,
			);
			expect(result.category).toBe("read");
		});

		it("calendar events.insert without attendees → write", () => {
			const result = classify(
				makeManifest("gws", { service: "calendar", method: "events.insert" }),
				config,
			);
			expect(result.category).toBe("write");
		});

		it("drive files.create → write", () => {
			const result = classify(
				makeManifest("gws", { service: "drive", method: "files.create" }),
				config,
			);
			expect(result.category).toBe("write");
		});

		it("drive files.delete → dangerous", () => {
			const result = classify(
				makeManifest("gws", { service: "drive", method: "files.delete" }),
				config,
			);
			expect(result.category).toBe("dangerous");
		});

		it("drive files.list → read", () => {
			const result = classify(
				makeManifest("gws", { service: "drive", method: "files.list" }),
				config,
			);
			expect(result.category).toBe("read");
		});

		it("sheets spreadsheets.create → write", () => {
			const result = classify(
				makeManifest("gws", { service: "sheets", method: "spreadsheets.create" }),
				config,
			);
			expect(result.category).toBe("write");
		});

		it("gmail users.messages.trash → dangerous", () => {
			const result = classify(
				makeManifest("gws", { service: "gmail", method: "users.messages.trash" }),
				config,
			);
			expect(result.category).toBe("dangerous");
		});

		it("unknown service + unknown method → falls through to default write", () => {
			const result = classify(
				makeManifest("gws", { service: "unknown", method: "unknown.action" }),
				config,
			);
			expect(result.category).toBe("write");
		});
	});
});
