import dns from "node:dns/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkSsrf, isPrivateIp, SsrfError } from "./ssrf-guard.js";

vi.mock("node:dns/promises");

const mockedDns = vi.mocked(dns);

beforeEach(() => {
	mockedDns.resolve4.mockReset();
	mockedDns.resolve6.mockReset();
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("isPrivateIp", () => {
	it("returns false for public IPv4", () => {
		expect(isPrivateIp("8.8.8.8")).toBe(false);
	});

	it("blocks 127.0.0.1 (loopback)", () => {
		expect(isPrivateIp("127.0.0.1")).toBe(true);
	});

	it("blocks 127.255.255.255 (loopback range)", () => {
		expect(isPrivateIp("127.255.255.255")).toBe(true);
	});

	it("blocks 10.0.0.1 (private class A)", () => {
		expect(isPrivateIp("10.0.0.1")).toBe(true);
	});

	it("blocks 172.16.0.1 (private class B)", () => {
		expect(isPrivateIp("172.16.0.1")).toBe(true);
	});

	it("blocks 172.31.255.255 (end of 172.16/12)", () => {
		expect(isPrivateIp("172.31.255.255")).toBe(true);
	});

	it("allows 172.32.0.0 (outside 172.16/12)", () => {
		expect(isPrivateIp("172.32.0.0")).toBe(false);
	});

	it("blocks 192.168.1.1 (private class C)", () => {
		expect(isPrivateIp("192.168.1.1")).toBe(true);
	});

	it("blocks 169.254.169.254 (AWS metadata / link-local)", () => {
		expect(isPrivateIp("169.254.169.254")).toBe(true);
	});

	it("blocks 0.0.0.0 (current network)", () => {
		expect(isPrivateIp("0.0.0.0")).toBe(true);
	});

	it("blocks ::1 (IPv6 loopback)", () => {
		expect(isPrivateIp("::1")).toBe(true);
	});

	it("blocks fc00:: (IPv6 unique local)", () => {
		expect(isPrivateIp("fc00::1")).toBe(true);
	});

	it("blocks fd00:: (IPv6 unique local)", () => {
		expect(isPrivateIp("fd00::1")).toBe(true);
	});

	it("blocks fe80:: (IPv6 link-local)", () => {
		expect(isPrivateIp("fe80::1")).toBe(true);
	});

	it("blocks ::ffff:127.0.0.1 (IPv4-mapped IPv6)", () => {
		expect(isPrivateIp("::ffff:127.0.0.1")).toBe(true);
	});

	it("blocks ::ffff:10.0.0.1 (IPv4-mapped IPv6 private)", () => {
		expect(isPrivateIp("::ffff:10.0.0.1")).toBe(true);
	});

	it("allows ::ffff:8.8.8.8 (IPv4-mapped IPv6 public)", () => {
		expect(isPrivateIp("::ffff:8.8.8.8")).toBe(false);
	});

	it("blocks fe90::1 (IPv6 link-local fe80::/10 range)", () => {
		expect(isPrivateIp("fe90::1")).toBe(true);
	});

	it("blocks febf::1 (end of IPv6 link-local range)", () => {
		expect(isPrivateIp("febf::1")).toBe(true);
	});

	it("allows ff00::1 (IPv6 multicast, outside link-local)", () => {
		expect(isPrivateIp("ff00::1")).toBe(false);
	});
});

describe("checkSsrf", () => {
	it("allows URL with public DNS resolution", async () => {
		mockedDns.resolve4.mockResolvedValue(["1.2.3.4"]);
		mockedDns.resolve6.mockRejectedValue(new Error("no AAAA"));
		await expect(checkSsrf("https://example.com/api")).resolves.toBeUndefined();
	});

	it("blocks URL resolving to private IP (DNS rebinding)", async () => {
		mockedDns.resolve4.mockResolvedValue(["10.0.0.1"]);
		mockedDns.resolve6.mockRejectedValue(new Error("no AAAA"));
		await expect(checkSsrf("https://example.com/api")).rejects.toThrow(SsrfError);
	});

	it("blocks http://localhost:8080/path", async () => {
		mockedDns.resolve4.mockResolvedValue(["127.0.0.1"]);
		mockedDns.resolve6.mockRejectedValue(new Error("no AAAA"));
		await expect(checkSsrf("http://localhost:8080/path")).rejects.toThrow(SsrfError);
	});

	it("blocks IP literal 127.0.0.1 without DNS lookup", async () => {
		await expect(checkSsrf("http://127.0.0.1:8080/path")).rejects.toThrow(SsrfError);
		expect(mockedDns.resolve4).not.toHaveBeenCalled();
	});

	it("blocks IP literal 169.254.169.254 (AWS metadata)", async () => {
		await expect(checkSsrf("http://169.254.169.254/latest/meta-data/")).rejects.toThrow(SsrfError);
	});

	it("blocks http://[::ffff:127.0.0.1] (IPv4-mapped IPv6)", async () => {
		await expect(checkSsrf("http://[::ffff:127.0.0.1]/path")).rejects.toThrow(SsrfError);
	});

	it("blocks http://[::1] (IPv6 loopback)", async () => {
		await expect(checkSsrf("http://[::1]:8080/path")).rejects.toThrow(SsrfError);
	});

	it("blocks when any resolved IP is private (mixed results)", async () => {
		mockedDns.resolve4.mockResolvedValue(["1.2.3.4", "10.0.0.1"]);
		mockedDns.resolve6.mockRejectedValue(new Error("no AAAA"));
		await expect(checkSsrf("https://example.com")).rejects.toThrow(SsrfError);
	});

	it("blocks when IPv6 resolution returns private address", async () => {
		mockedDns.resolve4.mockRejectedValue(new Error("no A"));
		mockedDns.resolve6.mockResolvedValue(["::1"]);
		await expect(checkSsrf("https://example.com")).rejects.toThrow(SsrfError);
	});

	it("throws on invalid URL", async () => {
		await expect(checkSsrf("not-a-url")).rejects.toThrow(SsrfError);
	});

	it("throws on URL with no hostname", async () => {
		await expect(checkSsrf("file:///etc/passwd")).rejects.toThrow(SsrfError);
	});

	it("blocks 0.0.0.0 IP literal", async () => {
		await expect(checkSsrf("http://0.0.0.0/")).rejects.toThrow(SsrfError);
	});

	it("allows multiple public IPs", async () => {
		mockedDns.resolve4.mockResolvedValue(["1.2.3.4", "5.6.7.8"]);
		mockedDns.resolve6.mockResolvedValue(["2001:4860:4860::8888"]);
		await expect(checkSsrf("https://example.com")).resolves.toBeUndefined();
	});

	it("throws when DNS resolution fails entirely", async () => {
		mockedDns.resolve4.mockRejectedValue(new Error("ENOTFOUND"));
		mockedDns.resolve6.mockRejectedValue(new Error("ENOTFOUND"));
		await expect(checkSsrf("https://no-such-host.test")).rejects.toThrow(SsrfError);
	});

	it("blocks hex IP literal http://0x7f000001/", async () => {
		await expect(checkSsrf("http://0x7f000001/")).rejects.toThrow(SsrfError);
	});

	it("blocks decimal IP literal http://2130706433/", async () => {
		await expect(checkSsrf("http://2130706433/")).rejects.toThrow(SsrfError);
	});

	it("blocks http://[fe90::1]/ (IPv6 link-local in full range)", async () => {
		await expect(checkSsrf("http://[fe90::1]/")).rejects.toThrow(SsrfError);
	});
});
