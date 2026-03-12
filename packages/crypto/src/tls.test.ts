import { randomBytes } from "node:crypto";
import { rm } from "node:fs/promises";
import {
	Agent,
	createServer as createHttpsServer,
	request as httpsRequest,
	type Server,
} from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { generateMtlsCerts, type MtlsCerts, readMtlsCerts, writeMtlsCerts } from "./tls.js";

let certs: MtlsCerts;
let testDir: string;

beforeAll(async () => {
	certs = await generateMtlsCerts();
}, 30_000);

afterEach(async () => {
	if (testDir) {
		await rm(testDir, { recursive: true, force: true }).catch(() => {});
	}
});

function makeTempDir(): string {
	testDir = join(tmpdir(), `sentinel-tls-test-${randomBytes(4).toString("hex")}`);
	return testDir;
}

describe("generateMtlsCerts", () => {
	it("produces valid PEM-formatted cert chain with all 3 certs and keys", () => {
		// CA
		expect(certs.ca.cert).toContain("-----BEGIN CERTIFICATE-----");
		expect(certs.ca.cert).toContain("-----END CERTIFICATE-----");
		expect(certs.ca.key).toContain("-----BEGIN PRIVATE KEY-----");
		expect(certs.ca.key).toContain("-----END PRIVATE KEY-----");

		// Executor
		expect(certs.executor.cert).toContain("-----BEGIN CERTIFICATE-----");
		expect(certs.executor.cert).toContain("-----END CERTIFICATE-----");
		expect(certs.executor.key).toContain("-----BEGIN PRIVATE KEY-----");
		expect(certs.executor.key).toContain("-----END PRIVATE KEY-----");

		// Agent
		expect(certs.agent.cert).toContain("-----BEGIN CERTIFICATE-----");
		expect(certs.agent.cert).toContain("-----END CERTIFICATE-----");
		expect(certs.agent.key).toContain("-----BEGIN PRIVATE KEY-----");
		expect(certs.agent.key).toContain("-----END PRIVATE KEY-----");

		// All certs should be distinct
		expect(certs.ca.cert).not.toBe(certs.executor.cert);
		expect(certs.ca.cert).not.toBe(certs.agent.cert);
		expect(certs.executor.cert).not.toBe(certs.agent.cert);
	});
});

describe("writeMtlsCerts + readMtlsCerts", () => {
	it("round-trips certs through disk", async () => {
		const dir = makeTempDir();
		await writeMtlsCerts(dir, certs);

		const read = await readMtlsCerts(dir);
		expect(read).toBeDefined();
		expect(read?.ca.cert).toBe(certs.ca.cert);
		expect(read?.executor.cert).toBe(certs.executor.cert);
		expect(read?.executor.key).toBe(certs.executor.key);
		expect(read?.agent.cert).toBe(certs.agent.cert);
		expect(read?.agent.key).toBe(certs.agent.key);
	});

	it("returns undefined when directory does not exist", async () => {
		const result = await readMtlsCerts("/nonexistent/path/tls");
		expect(result).toBeUndefined();
	});
});

describe("mTLS handshake", () => {
	function startServer(
		serverCert: string,
		serverKey: string,
		ca: string,
		rejectUnauthorized: boolean,
	): Promise<{ server: Server; port: number }> {
		return new Promise((resolve) => {
			const server = createHttpsServer(
				{
					cert: serverCert,
					key: serverKey,
					ca,
					requestCert: true,
					rejectUnauthorized,
				},
				(_req, res) => {
					res.writeHead(200, { "Content-Type": "text/plain" });
					res.end("ok");
				},
			);
			server.listen(0, "127.0.0.1", () => {
				const addr = server.address();
				const port = typeof addr === "object" && addr !== null ? addr.port : 0;
				resolve({ server, port });
			});
		});
	}

	function closeServer(server: Server): Promise<void> {
		return new Promise((resolve) => server.close(() => resolve()));
	}

	function makeRequest(url: string, agent: Agent): Promise<string> {
		return new Promise((resolve, reject) => {
			const req = httpsRequest(url, { agent }, (res) => {
				let data = "";
				res.on("data", (chunk: Buffer) => {
					data += chunk.toString();
				});
				res.on("end", () => resolve(data));
			});
			req.on("error", reject);
			req.end();
		});
	}

	it("executor accepts valid agent cert", async () => {
		const { server, port } = await startServer(
			certs.executor.cert,
			certs.executor.key,
			certs.ca.cert,
			true,
		);

		try {
			const agent = new Agent({
				cert: certs.agent.cert,
				key: certs.agent.key,
				ca: certs.ca.cert,
				rejectUnauthorized: true,
			});

			const result = await makeRequest(`https://127.0.0.1:${port}/health`, agent);
			expect(result).toBe("ok");
		} finally {
			await closeServer(server);
		}
	});

	it("executor rejects connections without client cert", async () => {
		const { server, port } = await startServer(
			certs.executor.cert,
			certs.executor.key,
			certs.ca.cert,
			true,
		);

		try {
			const agent = new Agent({
				ca: certs.ca.cert,
				rejectUnauthorized: true,
				// No client cert provided
			});

			await expect(makeRequest(`https://127.0.0.1:${port}/health`, agent)).rejects.toThrow();
		} finally {
			await closeServer(server);
		}
	});

	it("rejects cert signed by wrong CA", async () => {
		// Generate a completely separate CA + agent cert
		const wrongCerts = await generateMtlsCerts();

		const { server, port } = await startServer(
			certs.executor.cert,
			certs.executor.key,
			certs.ca.cert, // Server trusts only the original CA
			true,
		);

		try {
			const agent = new Agent({
				cert: wrongCerts.agent.cert, // Agent cert from wrong CA
				key: wrongCerts.agent.key,
				ca: certs.ca.cert,
				rejectUnauthorized: true,
			});

			await expect(makeRequest(`https://127.0.0.1:${port}/health`, agent)).rejects.toThrow();
		} finally {
			await closeServer(server);
		}
	}, 30_000);
});
