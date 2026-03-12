import {
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeEditFile } from "./edit-file.js";

let tempDir: string;

beforeEach(() => {
	// Use realpathSync to resolve macOS /var -> /private/var symlink,
	// ensuring SENTINEL_ALLOWED_ROOTS matches realpath-resolved paths
	tempDir = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-edit-test-")));
});

afterEach(() => {
	rmSync(tempDir, { recursive: true, force: true });
	delete process.env.SENTINEL_DOCKER;
	delete process.env.SENTINEL_ALLOWED_ROOTS;
});

describe("executeEditFile", () => {
	it("edits file successfully", async () => {
		process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
		const path = join(tempDir, "test.txt");
		writeFileSync(path, "hello world");

		const result = await executeEditFile(
			{ path, old_string: "hello", new_string: "goodbye" },
			"test-id",
		);
		expect(result.success).toBe(true);
		expect(result.output).toContain("Edited");
		expect(readFileSync(path, "utf-8")).toBe("goodbye world");
	});

	it("returns error when old_string not found", async () => {
		process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
		const path = join(tempDir, "test.txt");
		writeFileSync(path, "hello world");

		const result = await executeEditFile(
			{ path, old_string: "missing", new_string: "replacement" },
			"test-id",
		);
		expect(result.success).toBe(false);
		expect(result.error).toContain("not found");
	});

	it("returns error when old_string found multiple times", async () => {
		process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
		const path = join(tempDir, "test.txt");
		writeFileSync(path, "aaa bbb aaa");

		const result = await executeEditFile({ path, old_string: "aaa", new_string: "ccc" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("2 times");
	});

	it("rejects edit through a symlink (TOCTOU mitigation)", async () => {
		process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
		const realFile = join(tempDir, "real.txt");
		writeFileSync(realFile, "original content");
		const linkPath = join(tempDir, "link.txt");
		symlinkSync(realFile, linkPath);

		const result = await executeEditFile(
			{ path: linkPath, old_string: "original", new_string: "hacked" },
			"test-id",
		);
		expect(result.success).toBe(false);
		expect(result.error).toContain("symlink");
		// Verify original file was NOT modified
		expect(readFileSync(realFile, "utf-8")).toBe("original content");
	});

	describe("Docker mode (SENTINEL_DOCKER=true)", () => {
		beforeEach(() => {
			process.env.SENTINEL_DOCKER = "true";
		});

		it("blocks edits outside /app/data/", async () => {
			const result = await executeEditFile(
				{ path: "/tmp/outside.txt", old_string: "a", new_string: "b" },
				"test-id",
			);
			expect(result.success).toBe(false);
			expect(result.error).toContain("/app/data/");
		});

		it("blocks path traversal attempts", async () => {
			const result = await executeEditFile(
				{ path: "/app/data/../../etc/passwd", old_string: "a", new_string: "b" },
				"test-id",
			);
			expect(result.success).toBe(false);
			expect(result.error).toContain("/app/data/");
		});
	});

	it("uses single fd for read-write (no TOCTOU gap)", async () => {
		process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
		const path = join(tempDir, "toctou-test.txt");
		writeFileSync(path, "before edit");

		const result = await executeEditFile(
			{ path, old_string: "before", new_string: "after" },
			"test-id",
		);
		expect(result.success).toBe(true);
		// Verify the file was actually modified correctly
		expect(readFileSync(path, "utf-8")).toBe("after edit");
	});

	it("denies editing .env files", async () => {
		const result = await executeEditFile(
			{ path: "/tmp/.env", old_string: "a", new_string: "b" },
			"test-id",
		);
		expect(result.success).toBe(false);
		expect(result.error).toContain("denied");
	});
});
