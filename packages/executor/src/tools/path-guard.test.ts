import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isPathAllowed } from "./path-guard.js";

let tempDir: string;

beforeEach(() => {
	tempDir = mkdtempSync(join(tmpdir(), "sentinel-pathguard-"));
});

afterEach(() => {
	rmSync(tempDir, { recursive: true, force: true });
});

describe("isPathAllowed", () => {
	it("allows any path when allowedRoots is undefined", async () => {
		const result = await isPathAllowed("/etc/passwd", undefined);
		expect(result.allowed).toBe(true);
	});

	it("allows any path when allowedRoots is empty", async () => {
		const result = await isPathAllowed("/etc/passwd", []);
		expect(result.allowed).toBe(true);
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
