import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfigFromEnv } from "../config.js";

describe("loadConfigFromEnv", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.restoreAllMocks();
	});

	it("defaults failMode to 'closed'", () => {
		const config = loadConfigFromEnv();
		expect(config.failMode).toBe("closed");
	});

	it("overrides failMode='open' to 'closed' when SENTINEL_DOCKER=true", () => {
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		vi.stubEnv("SENTINEL_DOCKER", "true");
		vi.stubEnv("SENTINEL_FAIL_MODE", "open");

		const config = loadConfigFromEnv();

		expect(config.failMode).toBe("closed");
		expect(errorSpy).toHaveBeenCalledWith(
			expect.stringContaining("failMode='open' is not permitted in Docker mode"),
		);
	});

	it("allows failMode='open' when not in Docker mode", () => {
		vi.stubEnv("SENTINEL_FAIL_MODE", "open");

		const config = loadConfigFromEnv();

		expect(config.failMode).toBe("open");
	});

	it("keeps failMode='closed' in Docker mode without override", () => {
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		vi.stubEnv("SENTINEL_DOCKER", "true");
		vi.stubEnv("SENTINEL_FAIL_MODE", "closed");

		const config = loadConfigFromEnv();

		expect(config.failMode).toBe("closed");
		expect(errorSpy).not.toHaveBeenCalled();
	});
});
