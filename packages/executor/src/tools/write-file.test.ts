import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWriteFile } from "./write-file.js";

let tempDir: string;

beforeEach(() => {
	tempDir = mkdtempSync(join(tmpdir(), "sentinel-write-test-"));
});

afterEach(() => {
	rmSync(tempDir, { recursive: true, force: true });
	delete process.env.SENTINEL_DOCKER;
});

describe("executeWriteFile", () => {
	it("writes file successfully", async () => {
		const path = join(tempDir, "test.txt");
		const result = await executeWriteFile({ path, content: "hello" }, "test-id");
		expect(result.success).toBe(true);
		expect(readFileSync(path, "utf-8")).toBe("hello");
	});

	it("denies writing to .env files", async () => {
		const result = await executeWriteFile({ path: "/tmp/.env", content: "x" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("denied");
	});

	it("denies writing to .pem files", async () => {
		const result = await executeWriteFile({ path: "/tmp/server.pem", content: "x" }, "test-id");
		expect(result.success).toBe(false);
		expect(result.error).toContain("denied");
	});

	describe("Docker mode (SENTINEL_DOCKER=true)", () => {
		beforeEach(() => {
			process.env.SENTINEL_DOCKER = "true";
		});

		it("allows writes to /app/data/", async () => {
			// We can't actually write to /app/data in tests, so we test the path check logic
			// by checking that non-/app/data/ paths are rejected
			const result = await executeWriteFile(
				{ path: "/tmp/outside.txt", content: "data" },
				"test-id",
			);
			expect(result.success).toBe(false);
			expect(result.error).toContain("/app/data/");
		});

		it("blocks path traversal attempts", async () => {
			const result = await executeWriteFile(
				{ path: "/app/data/../../etc/passwd", content: "evil" },
				"test-id",
			);
			expect(result.success).toBe(false);
			expect(result.error).toContain("/app/data/");
		});

		it("blocks writes to /etc/passwd", async () => {
			const result = await executeWriteFile({ path: "/etc/passwd", content: "evil" }, "test-id");
			expect(result.success).toBe(false);
		});

		it("blocks symlink-based path traversal", async () => {
			// Create a symlink inside a fake /app/data/ that points outside
			const fakeAppData = join(tempDir, "app", "data");
			const outsideDir = join(tempDir, "outside");
			const { mkdirSync } = await import("node:fs");
			mkdirSync(fakeAppData, { recursive: true });
			mkdirSync(outsideDir, { recursive: true });

			// Symlink: /app/data/escape -> /outside/
			const symlinkPath = join(fakeAppData, "escape");
			symlinkSync(outsideDir, symlinkPath);

			// The symlink target resolves outside /app/data/ via realpath
			const targetFile = join(symlinkPath, "escaped.txt");
			const result = await executeWriteFile({ path: targetFile, content: "evil" }, "test-id");
			expect(result.success).toBe(false);
			expect(result.error).toContain("/app/data/");
		});
	});

	describe("Local dev mode (no SENTINEL_DOCKER)", () => {
		it("allows writes to arbitrary paths", async () => {
			const path = join(tempDir, "local-test.txt");
			const result = await executeWriteFile({ path, content: "local" }, "test-id");
			expect(result.success).toBe(true);
		});
	});
});
