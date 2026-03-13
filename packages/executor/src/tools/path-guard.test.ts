import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isPathAllowed } from "./path-guard.js";

let tempDir: string;

beforeEach(() => {
	tempDir = mkdtempSync(join(tmpdir(), "sentinel-pathguard-"));
});

afterEach(() => {
	rmSync(tempDir, { recursive: true, force: true });
});

describe("isPathAllowed", () => {
	it("warns in Docker mode when no roots configured (L1)", async () => {
		process.env.SENTINEL_DOCKER = "true";
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const result = await isPathAllowed("/etc/passwd", undefined);
		// Tool-level restriction enforces /app/data — path-guard warns but allows
		expect(result.allowed).toBe(true);
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("Docker mode with no allowed roots"),
		);
		warnSpy.mockRestore();
		delete process.env.SENTINEL_DOCKER;
	});

	it("warns in Docker mode when empty roots provided (L1)", async () => {
		process.env.SENTINEL_DOCKER = "true";
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const result = await isPathAllowed("/etc/passwd", []);
		expect(result.allowed).toBe(true);
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("Docker mode with no allowed roots"),
		);
		warnSpy.mockRestore();
		delete process.env.SENTINEL_DOCKER;
	});

	it("allows path within an allowed root", async () => {
		const testFile = join(tempDir, "test.txt");
		writeFileSync(testFile, "hello");
		const result = await isPathAllowed(testFile, [tempDir]);
		expect(result.allowed).toBe(true);
	});

	it("denies path outside all allowed roots", async () => {
		const result = await isPathAllowed("/etc/passwd", [tempDir]);
		expect(result.allowed).toBe(false);
		if (!result.allowed) {
			expect(result.reason).toContain("outside allowed roots");
		}
	});

	it("allows path that is exactly the root", async () => {
		const result = await isPathAllowed(tempDir, [tempDir]);
		expect(result.allowed).toBe(true);
	});

	it("denies symlink pointing outside allowed root", async () => {
		const outsideDir = mkdtempSync(join(tmpdir(), "sentinel-outside-"));
		const outsideFile = join(outsideDir, "secret.txt");
		writeFileSync(outsideFile, "secret data");

		const symlinkPath = join(tempDir, "escape");
		symlinkSync(outsideFile, symlinkPath);

		const result = await isPathAllowed(symlinkPath, [tempDir]);
		expect(result.allowed).toBe(false);
		if (!result.allowed) {
			expect(result.reason).toContain("outside allowed roots");
		}

		rmSync(outsideDir, { recursive: true, force: true });
	});

	it("allows with multiple roots", async () => {
		const secondRoot = mkdtempSync(join(tmpdir(), "sentinel-root2-"));
		const testFile = join(secondRoot, "test.txt");
		writeFileSync(testFile, "hello");

		const result = await isPathAllowed(testFile, [tempDir, secondRoot]);
		expect(result.allowed).toBe(true);

		rmSync(secondRoot, { recursive: true, force: true });
	});

	it("denies path traversal via ..", async () => {
		const result = await isPathAllowed(join(tempDir, "..", "etc", "passwd"), [tempDir]);
		expect(result.allowed).toBe(false);
	});

	it("denies circular symlink (ELOOP) instead of falling back", async () => {
		const link1 = join(tempDir, "loop1");
		const link2 = join(tempDir, "loop2");
		symlinkSync(link2, link1);
		symlinkSync(link1, link2);
		const result = await isPathAllowed(link1, [tempDir]);
		expect(result.allowed).toBe(false);
		if (!result.allowed) {
			expect(result.reason).toContain("Cannot resolve real path");
		}
	});
});

// I8 fix: Duplicate Docker mode tests removed — already covered above in "isPathAllowed" describe block.
// Unique test retained below:
describe("Docker mode with configured roots (L1)", () => {
	afterEach(() => {
		delete process.env.SENTINEL_DOCKER;
	});

	it("allows paths in Docker mode when roots ARE configured", async () => {
		process.env.SENTINEL_DOCKER = "true";
		const testFile = join(tempDir, "test.txt");
		writeFileSync(testFile, "hello");
		const result = await isPathAllowed(testFile, [tempDir]);
		expect(result.allowed).toBe(true);
	});
});

describe("SENTINEL_ALLOWED_ROOTS env var", () => {
	afterEach(() => {
		delete process.env.SENTINEL_ALLOWED_ROOTS;
	});

	it("uses env var when allowedRoots is undefined", async () => {
		process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
		const testFile = join(tempDir, "test.txt");
		writeFileSync(testFile, "hello");
		const result = await isPathAllowed(testFile, undefined);
		expect(result.allowed).toBe(true);
	});

	it("uses env var to deny paths outside roots", async () => {
		process.env.SENTINEL_ALLOWED_ROOTS = tempDir;
		const result = await isPathAllowed("/etc/passwd", undefined);
		expect(result.allowed).toBe(false);
	});

	it("parses comma-separated roots from env var", async () => {
		const secondRoot = mkdtempSync(join(tmpdir(), "sentinel-root3-"));
		process.env.SENTINEL_ALLOWED_ROOTS = `${tempDir},${secondRoot}`;
		const testFile = join(secondRoot, "test.txt");
		writeFileSync(testFile, "hello");
		const result = await isPathAllowed(testFile, undefined);
		expect(result.allowed).toBe(true);
		rmSync(secondRoot, { recursive: true, force: true });
	});

	it("explicit allowedRoots override env var", async () => {
		process.env.SENTINEL_ALLOWED_ROOTS = "/some/other/path";
		const testFile = join(tempDir, "test.txt");
		writeFileSync(testFile, "hello");
		const result = await isPathAllowed(testFile, [tempDir]);
		expect(result.allowed).toBe(true);
	});
});

describe("cwd default in local mode", () => {
	afterEach(() => {
		delete process.env.SENTINEL_ALLOWED_ROOTS;
		delete process.env.SENTINEL_DOCKER;
	});

	it("defaults to cwd when no allowedRoots and no env var", async () => {
		const result = await isPathAllowed("/etc/passwd", undefined);
		expect(result.allowed).toBe(false);
	});

	it("allows files within cwd by default", async () => {
		const cwd = process.cwd();
		const testPath = join(cwd, "package.json");
		const result = await isPathAllowed(testPath, undefined);
		expect(result.allowed).toBe(true);
	});
});
