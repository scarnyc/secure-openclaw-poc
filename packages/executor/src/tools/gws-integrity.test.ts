import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";

// Mock execa before importing the module
vi.mock("execa", () => ({
	execa: vi.fn(),
}));

// Mock node:fs for createReadStream
vi.mock("node:fs", () => ({
	createReadStream: vi.fn(),
}));

import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import { execa } from "execa";
import { GwsIntegrityConfigSchema } from "@sentinel/types";
import {
	computeBinaryHash,
	ensureGwsIntegrity,
	getGwsVersion,
	isServiceAllowed,
	isVulnerableVersion,
	resetIntegrityCache,
	resolveGwsBinary,
	validateVersion,
} from "./gws-integrity.js";

const mockExeca = execa as unknown as MockInstance;
const mockCreateReadStream = createReadStream as unknown as MockInstance;

// SHA-256 of the bytes "gws-binary-content"
const KNOWN_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function mockReadStream(content: string): Readable {
	const stream = new Readable({
		read() {
			this.push(Buffer.from(content));
			this.push(null);
		},
	});
	return stream;
}

describe("GwsIntegrityConfigSchema", () => {
	it("accepts valid config with all fields", () => {
		const result = GwsIntegrityConfigSchema.parse({
			verifyBinary: true,
			expectedSha256: "a".repeat(64),
			pinnedVersion: "1.2.3",
			pinnedVersionPolicy: "exact",
			vulnerableVersions: ["1.0.0"],
			allowedOAuthScopes: ["https://www.googleapis.com/auth/gmail.modify"],
		});
		expect(result.verifyBinary).toBe(true);
		expect(result.pinnedVersionPolicy).toBe("exact");
	});

	it("defaults verifyBinary to false", () => {
		const result = GwsIntegrityConfigSchema.parse({});
		expect(result.verifyBinary).toBe(false);
	});

	it("defaults pinnedVersionPolicy to minimum", () => {
		const result = GwsIntegrityConfigSchema.parse({});
		expect(result.pinnedVersionPolicy).toBe("minimum");
	});

	it("defaults vulnerableVersions to empty array", () => {
		const result = GwsIntegrityConfigSchema.parse({});
		expect(result.vulnerableVersions).toEqual([]);
	});

	it("rejects invalid SHA-256 hash format", () => {
		expect(() =>
			GwsIntegrityConfigSchema.parse({ expectedSha256: "not-a-hash" }),
		).toThrow();
	});

	it("rejects SHA-256 with uppercase letters", () => {
		expect(() =>
			GwsIntegrityConfigSchema.parse({ expectedSha256: "A".repeat(64) }),
		).toThrow();
	});

	it("accepts valid SHA-256 hash", () => {
		const result = GwsIntegrityConfigSchema.parse({
			expectedSha256: "abcdef0123456789".repeat(4),
		});
		expect(result.expectedSha256).toBe("abcdef0123456789".repeat(4));
	});
});

describe("resolveGwsBinary", () => {
	beforeEach(() => vi.resetAllMocks());

	it("returns absolute path when gws is on PATH", async () => {
		mockExeca.mockResolvedValue({
			exitCode: 0,
			stdout: "/usr/local/bin/gws\n",
		});
		const path = await resolveGwsBinary();
		expect(path).toBe("/usr/local/bin/gws");
	});

	it("throws when gws is not found", async () => {
		mockExeca.mockResolvedValue({ exitCode: 1, stdout: "" });
		await expect(resolveGwsBinary()).rejects.toThrow("gws binary not found");
	});
});

describe("computeBinaryHash", () => {
	beforeEach(() => vi.resetAllMocks());

	it("computes SHA-256 hash of file content", async () => {
		mockCreateReadStream.mockReturnValue(mockReadStream("test-content"));
		const hash = await computeBinaryHash("/usr/local/bin/gws");
		expect(hash).toMatch(/^[a-f0-9]{64}$/);
	});

	it("returns different hashes for different content", async () => {
		mockCreateReadStream.mockReturnValueOnce(mockReadStream("content-a"));
		const hash1 = await computeBinaryHash("/path/a");
		mockCreateReadStream.mockReturnValueOnce(mockReadStream("content-b"));
		const hash2 = await computeBinaryHash("/path/b");
		expect(hash1).not.toBe(hash2);
	});

	it("rejects when stream errors", async () => {
		const errorStream = new Readable({
			read() {
				this.destroy(new Error("read error"));
			},
		});
		mockCreateReadStream.mockReturnValue(errorStream);
		await expect(computeBinaryHash("/bad/path")).rejects.toThrow("read error");
	});
});

describe("getGwsVersion", () => {
	beforeEach(() => vi.resetAllMocks());

	it("parses version from 'gws version X.Y.Z' output", async () => {
		mockExeca.mockResolvedValue({ exitCode: 0, stdout: "gws version 2.1.0" });
		const version = await getGwsVersion("/usr/local/bin/gws");
		expect(version).toBe("2.1.0");
	});

	it("parses version from bare 'X.Y.Z' output", async () => {
		mockExeca.mockResolvedValue({ exitCode: 0, stdout: "1.0.5" });
		const version = await getGwsVersion("/usr/local/bin/gws");
		expect(version).toBe("1.0.5");
	});

	it("throws when gws --version fails", async () => {
		mockExeca.mockResolvedValue({ exitCode: 1, stdout: "" });
		await expect(getGwsVersion("/usr/local/bin/gws")).rejects.toThrow("--version failed");
	});

	it("throws when version cannot be parsed", async () => {
		mockExeca.mockResolvedValue({ exitCode: 0, stdout: "unknown output" });
		await expect(getGwsVersion("/usr/local/bin/gws")).rejects.toThrow("Cannot parse version");
	});
});

describe("validateVersion", () => {
	it("passes when version matches exact pin", () => {
		expect(validateVersion("1.2.3", "1.2.3", "exact")).toEqual({ ok: true });
	});

	it("fails when version does not match exact pin", () => {
		const result = validateVersion("1.2.4", "1.2.3", "exact");
		expect(result.ok).toBe(false);
		expect(result.reason).toContain("exact");
	});

	it("passes when version >= minimum pin", () => {
		expect(validateVersion("2.0.0", "1.2.3", "minimum")).toEqual({ ok: true });
	});

	it("passes when version equals minimum pin", () => {
		expect(validateVersion("1.2.3", "1.2.3", "minimum")).toEqual({ ok: true });
	});

	it("fails when version < minimum pin", () => {
		const result = validateVersion("1.2.2", "1.2.3", "minimum");
		expect(result.ok).toBe(false);
		expect(result.reason).toContain("minimum");
	});

	it("compares major version correctly", () => {
		expect(validateVersion("2.0.0", "1.9.9", "minimum")).toEqual({ ok: true });
		const result = validateVersion("0.9.9", "1.0.0", "minimum");
		expect(result.ok).toBe(false);
	});

	it("compares minor version correctly", () => {
		expect(validateVersion("1.3.0", "1.2.9", "minimum")).toEqual({ ok: true });
		const result = validateVersion("1.1.0", "1.2.0", "minimum");
		expect(result.ok).toBe(false);
	});
});

describe("isVulnerableVersion", () => {
	it("returns false when version not in vulnerable list", () => {
		expect(isVulnerableVersion("1.2.3", ["1.0.0", "1.1.0"])).toBe(false);
	});

	it("returns true when version matches", () => {
		expect(isVulnerableVersion("1.1.0", ["1.0.0", "1.1.0"])).toBe(true);
	});

	it("returns false when vulnerable list is empty", () => {
		expect(isVulnerableVersion("1.0.0", [])).toBe(false);
	});
});

describe("isServiceAllowed", () => {
	it("passes when service scope is in allowedOAuthScopes", () => {
		expect(
			isServiceAllowed("gmail", ["https://www.googleapis.com/auth/gmail.modify"]),
		).toBe(true);
	});

	it("blocks when service scope is NOT in allowedOAuthScopes", () => {
		expect(
			isServiceAllowed("gmail", ["https://www.googleapis.com/auth/calendar"]),
		).toBe(false);
	});

	it("passes when allowedOAuthScopes is undefined (no cap)", () => {
		expect(isServiceAllowed("gmail", undefined)).toBe(true);
	});

	it("blocks unknown services when scopes are configured", () => {
		expect(
			isServiceAllowed("unknown-service", [
				"https://www.googleapis.com/auth/gmail.modify",
			]),
		).toBe(false);
	});

	it("maps calendar service correctly", () => {
		expect(
			isServiceAllowed("calendar", ["https://www.googleapis.com/auth/calendar"]),
		).toBe(true);
	});

	it("maps drive service correctly", () => {
		expect(
			isServiceAllowed("drive", ["https://www.googleapis.com/auth/drive"]),
		).toBe(true);
	});
});

describe("ensureGwsIntegrity", () => {
	beforeEach(() => {
		vi.resetAllMocks();
		resetIntegrityCache();
		delete process.env.SENTINEL_DOCKER;
	});

	afterEach(() => {
		delete process.env.SENTINEL_DOCKER;
	});

	it("returns pass when no config provided (backward compat)", async () => {
		// gws --version still called for basic info
		mockExeca.mockImplementation((_cmd: string, args?: string[]) => {
			if (args?.[0] === "--version") {
				return Promise.resolve({ exitCode: 0, stdout: "1.0.0" });
			}
			// which gws
			return Promise.resolve({ exitCode: 0, stdout: "/usr/local/bin/gws" });
		});
		const result = await ensureGwsIntegrity();
		expect(result.ok).toBe(true);
	});

	it("caches result after first successful check", async () => {
		mockExeca.mockImplementation((_cmd: string, args?: string[]) => {
			if (args?.[0] === "--version") {
				return Promise.resolve({ exitCode: 0, stdout: "1.0.0" });
			}
			return Promise.resolve({ exitCode: 0, stdout: "/usr/local/bin/gws" });
		});
		const result1 = await ensureGwsIntegrity();
		const result2 = await ensureGwsIntegrity();
		expect(result1).toBe(result2);
		// execa called only for first check (which + version = 2 calls)
		expect(mockExeca).toHaveBeenCalledTimes(2);
	});

	it("re-checks if previous check failed", async () => {
		let callCount = 0;
		mockExeca.mockImplementation((_cmd: string, args?: string[]) => {
			callCount++;
			if (callCount === 1) {
				// First "which gws" fails
				return Promise.resolve({ exitCode: 1, stdout: "" });
			}
			// After cache clear, second attempt succeeds
			if (args?.[0] === "--version") {
				return Promise.resolve({ exitCode: 0, stdout: "1.0.0" });
			}
			return Promise.resolve({ exitCode: 0, stdout: "/usr/local/bin/gws" });
		});

		const result1 = await ensureGwsIntegrity();
		expect(result1.ok).toBe(false);

		// Wait for cache clear (async .then)
		await new Promise((r) => setTimeout(r, 10));

		const result2 = await ensureGwsIntegrity();
		expect(result2.ok).toBe(true);
	});

	it("returns fail when binary not found", async () => {
		mockExeca.mockResolvedValue({ exitCode: 1, stdout: "" });
		const result = await ensureGwsIntegrity();
		expect(result.ok).toBe(false);
		expect(result.error).toContain("not found");
	});

	it("returns fail when hash mismatch and verifyBinary=true", async () => {
		mockExeca.mockImplementation((_cmd: string, args?: string[]) => {
			if (args?.[0] === "--version") {
				return Promise.resolve({ exitCode: 0, stdout: "1.0.0" });
			}
			return Promise.resolve({ exitCode: 0, stdout: "/usr/local/bin/gws" });
		});
		mockCreateReadStream.mockReturnValue(mockReadStream("some-binary-content"));

		const config = GwsIntegrityConfigSchema.parse({
			verifyBinary: true,
			expectedSha256: "0".repeat(64),
		});

		const result = await ensureGwsIntegrity(config);
		expect(result.ok).toBe(false);
		expect(result.error).toContain("hash mismatch");
	});

	it("returns fail when version below minimum pin", async () => {
		mockExeca.mockImplementation((_cmd: string, args?: string[]) => {
			if (args?.[0] === "--version") {
				return Promise.resolve({ exitCode: 0, stdout: "0.9.0" });
			}
			return Promise.resolve({ exitCode: 0, stdout: "/usr/local/bin/gws" });
		});

		const config = GwsIntegrityConfigSchema.parse({
			pinnedVersion: "1.0.0",
			pinnedVersionPolicy: "minimum",
		});

		const result = await ensureGwsIntegrity(config);
		expect(result.ok).toBe(false);
		expect(result.error).toContain("Version");
	});

	it("returns fail when running a vulnerable version", async () => {
		mockExeca.mockImplementation((_cmd: string, args?: string[]) => {
			if (args?.[0] === "--version") {
				return Promise.resolve({ exitCode: 0, stdout: "1.1.0" });
			}
			return Promise.resolve({ exitCode: 0, stdout: "/usr/local/bin/gws" });
		});

		const config = GwsIntegrityConfigSchema.parse({
			vulnerableVersions: ["1.1.0"],
		});

		const result = await ensureGwsIntegrity(config);
		expect(result.ok).toBe(false);
		expect(result.error).toContain("vulnerable");
	});

	it("adds warning when verifyBinary=false and expectedSha256 not set", async () => {
		mockExeca.mockImplementation((_cmd: string, args?: string[]) => {
			if (args?.[0] === "--version") {
				return Promise.resolve({ exitCode: 0, stdout: "1.0.0" });
			}
			return Promise.resolve({ exitCode: 0, stdout: "/usr/local/bin/gws" });
		});

		const result = await ensureGwsIntegrity(GwsIntegrityConfigSchema.parse({}));
		expect(result.ok).toBe(true);
		expect(result.warnings.length).toBeGreaterThan(0);
		expect(result.warnings.some((w) => w.includes("hash verification disabled"))).toBe(true);
	});

	it("passes all checks when config matches actual binary", async () => {
		mockExeca.mockImplementation((_cmd: string, args?: string[]) => {
			if (args?.[0] === "--version") {
				return Promise.resolve({ exitCode: 0, stdout: "2.0.0" });
			}
			return Promise.resolve({ exitCode: 0, stdout: "/usr/local/bin/gws" });
		});

		const config = GwsIntegrityConfigSchema.parse({
			pinnedVersion: "1.0.0",
			pinnedVersionPolicy: "minimum",
			vulnerableVersions: ["0.5.0"],
		});

		const result = await ensureGwsIntegrity(config);
		expect(result.ok).toBe(true);
		expect(result.version).toBe("2.0.0");
		expect(result.binaryPath).toBe("/usr/local/bin/gws");
	});
});
