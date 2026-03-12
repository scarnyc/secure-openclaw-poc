import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface MtlsCerts {
	ca: { cert: string; key: string };
	executor: { cert: string; key: string };
	agent: { cert: string; key: string };
}

/**
 * Generate a complete mTLS certificate chain using openssl:
 * - Self-signed CA (10-year validity)
 * - Executor server cert signed by CA (SAN: DNS:executor, DNS:localhost, IP:127.0.0.1)
 * - Agent client cert signed by CA (CN: sentinel-agent)
 *
 * Uses openssl CLI (available in Alpine Docker images and macOS).
 * All intermediate files (CSRs, configs) are created in a temp directory and cleaned up.
 */
export async function generateMtlsCerts(): Promise<MtlsCerts> {
	const workDir = join(tmpdir(), `sentinel-tls-${randomBytes(8).toString("hex")}`);
	await mkdir(workDir, { recursive: true });

	try {
		// 1. Generate CA key + self-signed cert (10 years)
		execFileSync("openssl", [
			"req",
			"-new",
			"-x509",
			"-nodes",
			"-days",
			"3650",
			"-keyout",
			join(workDir, "ca.key"),
			"-out",
			join(workDir, "ca.crt"),
			"-subj",
			"/CN=Sentinel CA/O=Sentinel",
		]);

		// 2. Generate executor key + CSR
		execFileSync("openssl", [
			"req",
			"-new",
			"-nodes",
			"-keyout",
			join(workDir, "executor.key"),
			"-out",
			join(workDir, "executor.csr"),
			"-subj",
			"/CN=executor/O=Sentinel",
		]);

		// Write SAN config for executor cert
		const executorExtConf = [
			"[v3_ext]",
			"subjectAltName = DNS:executor, DNS:localhost, IP:127.0.0.1",
			"keyUsage = digitalSignature, keyEncipherment",
			"extendedKeyUsage = serverAuth",
		].join("\n");
		await writeFile(join(workDir, "executor-ext.cnf"), executorExtConf);

		// Sign executor cert with CA (1 year)
		execFileSync("openssl", [
			"x509",
			"-req",
			"-in",
			join(workDir, "executor.csr"),
			"-CA",
			join(workDir, "ca.crt"),
			"-CAkey",
			join(workDir, "ca.key"),
			"-CAcreateserial",
			"-out",
			join(workDir, "executor.crt"),
			"-days",
			"365",
			"-extfile",
			join(workDir, "executor-ext.cnf"),
			"-extensions",
			"v3_ext",
		]);

		// 3. Generate agent key + CSR
		execFileSync("openssl", [
			"req",
			"-new",
			"-nodes",
			"-keyout",
			join(workDir, "agent.key"),
			"-out",
			join(workDir, "agent.csr"),
			"-subj",
			"/CN=sentinel-agent/O=Sentinel",
		]);

		// Write ext config for agent client cert
		const agentExtConf = [
			"[v3_ext]",
			"keyUsage = digitalSignature",
			"extendedKeyUsage = clientAuth",
		].join("\n");
		await writeFile(join(workDir, "agent-ext.cnf"), agentExtConf);

		// Sign agent cert with CA (1 year)
		execFileSync("openssl", [
			"x509",
			"-req",
			"-in",
			join(workDir, "agent.csr"),
			"-CA",
			join(workDir, "ca.crt"),
			"-CAkey",
			join(workDir, "ca.key"),
			"-CAcreateserial",
			"-out",
			join(workDir, "agent.crt"),
			"-days",
			"365",
			"-extfile",
			join(workDir, "agent-ext.cnf"),
			"-extensions",
			"v3_ext",
		]);

		// Read all generated certs/keys
		const [caCert, caKey, executorCert, executorKey, agentCert, agentKey] = await Promise.all([
			readFile(join(workDir, "ca.crt"), "utf8"),
			readFile(join(workDir, "ca.key"), "utf8"),
			readFile(join(workDir, "executor.crt"), "utf8"),
			readFile(join(workDir, "executor.key"), "utf8"),
			readFile(join(workDir, "agent.crt"), "utf8"),
			readFile(join(workDir, "agent.key"), "utf8"),
		]);

		return {
			ca: { cert: caCert, key: caKey },
			executor: { cert: executorCert, key: executorKey },
			agent: { cert: agentCert, key: agentKey },
		};
	} finally {
		// Clean up temp directory — ignore errors
		const { rm } = await import("node:fs/promises");
		await rm(workDir, { recursive: true, force: true }).catch(() => {});
	}
}

/**
 * Write mTLS certs to disk in PEM format.
 * Output: tlsDir/{ca.crt, executor.crt, executor.key, agent.crt, agent.key}
 * Private keys are written with mode 0o600 (owner read/write only).
 */
export async function writeMtlsCerts(tlsDir: string, certs: MtlsCerts): Promise<void> {
	await mkdir(tlsDir, { recursive: true });
	await Promise.all([
		writeFile(join(tlsDir, "ca.crt"), certs.ca.cert),
		writeFile(join(tlsDir, "executor.crt"), certs.executor.cert),
		writeFile(join(tlsDir, "executor.key"), certs.executor.key, {
			mode: 0o600,
		}),
		writeFile(join(tlsDir, "agent.crt"), certs.agent.cert),
		writeFile(join(tlsDir, "agent.key"), certs.agent.key, { mode: 0o600 }),
	]);
}

/**
 * Read mTLS certs from a directory. Returns undefined if the directory
 * or any required cert file is missing.
 */
export async function readMtlsCerts(tlsDir: string): Promise<MtlsCerts | undefined> {
	const requiredFiles = ["ca.crt", "executor.crt", "executor.key", "agent.crt", "agent.key"];
	for (const f of requiredFiles) {
		if (!existsSync(join(tlsDir, f))) {
			return undefined;
		}
	}

	const [caCert, executorCert, executorKey, agentCert, agentKey] = await Promise.all([
		readFile(join(tlsDir, "ca.crt"), "utf8"),
		readFile(join(tlsDir, "executor.crt"), "utf8"),
		readFile(join(tlsDir, "executor.key"), "utf8"),
		readFile(join(tlsDir, "agent.crt"), "utf8"),
		readFile(join(tlsDir, "agent.key"), "utf8"),
	]);

	// CA key is only needed during generation, not at runtime.
	// Read it if present, otherwise leave empty.
	let caKey = "";
	if (existsSync(join(tlsDir, "ca.key"))) {
		caKey = await readFile(join(tlsDir, "ca.key"), "utf8");
	}

	return {
		ca: { cert: caCert, key: caKey },
		executor: { cert: executorCert, key: executorKey },
		agent: { cert: agentCert, key: agentKey },
	};
}
