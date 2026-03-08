import type { ToolResult } from "@sentinel/types";
import { execa, execaCommand } from "execa";

async function detectFirejail(): Promise<boolean> {
	try {
		const result = await execaCommand("which firejail", { reject: false });
		return result.exitCode === 0;
	} catch {
		return false;
	}
}

let firejailDetection: Promise<boolean> | null = null;

async function isFirejailAvailable(): Promise<boolean> {
	if (process.env.SENTINEL_BASH_SANDBOX !== "firejail") return false;
	if (!firejailDetection) {
		firejailDetection = detectFirejail();
		firejailDetection.then((available) => {
			if (!available) {
				console.warn(
					"SENTINEL_BASH_SANDBOX=firejail but firejail not found; falling back to unsandboxed execution",
				);
			}
		});
	}
	return firejailDetection;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 300_000;

// Deny-listed command patterns: sensitive file access, destructive ops, mail, DNS exfil
const FILE_READ_CMDS = String.raw`\b(cat|head|tail|less|more|tac|nl|od|xxd|hexdump|base64|strings)\b`;
const SENSITIVE_FILE = String.raw`\.(env|pem|key)\b`;
const DENIED_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
	// Sensitive file reads
	{
		pattern: new RegExp(`${FILE_READ_CMDS}.*${SENSITIVE_FILE}`),
		reason: "Command reads a sensitive file",
	},
	{
		pattern: new RegExp(`${FILE_READ_CMDS}.*\\.dev\\.vars\\b`),
		reason: "Command reads a sensitive file",
	},
	{
		pattern: new RegExp(`${FILE_READ_CMDS}.*\\.git/(config|credentials)\\b`),
		reason: "Command reads a sensitive file",
	},
	{
		pattern: new RegExp(`${FILE_READ_CMDS}.*secret`, "i"),
		reason: "Command reads a sensitive file",
	},
	{
		pattern: new RegExp(`${FILE_READ_CMDS}.*credential`, "i"),
		reason: "Command reads a sensitive file",
	},
	{
		pattern: new RegExp(`${FILE_READ_CMDS}.*vault\\.enc\\b`),
		reason: "Command reads a sensitive file",
	},
	// Block cp/mv of sensitive files
	{ pattern: /\b(cp|mv)\b.*\.(env|pem|key)\b/, reason: "Command copies/moves a sensitive file" },
	{ pattern: /\b(cp|mv)\b.*\.dev\.vars\b/, reason: "Command copies/moves a sensitive file" },
	{ pattern: /\b(cp|mv)\b.*vault\.enc\b/, reason: "Command copies/moves a sensitive file" },
	// Block curl/wget file exfiltration of sensitive files
	{ pattern: /\bcurl\b.*@.*\.(env|pem|key)\b/, reason: "Command exfiltrates a sensitive file" },
	{ pattern: /\bcurl\b.*-d\b.*\.(env|pem|key)\b/, reason: "Command exfiltrates a sensitive file" },
	// Destructive rm: recursive targeting root or home only
	{
		pattern: /\brm\b.*-[a-zA-Z]*r[a-zA-Z]*\s+\/(\s|$|\*)/,
		reason: "Destructive recursive deletion denied",
	},
	{ pattern: /\brm\b.*-[a-zA-Z]*r[a-zA-Z]*\s+~/, reason: "Destructive recursive deletion denied" },
	{
		pattern: /\brm\b.*-[a-zA-Z]*r[a-zA-Z]*\s+\$HOME/,
		reason: "Destructive recursive deletion denied",
	},
	{
		pattern: /\brm\b.*--recursive.*\s+\/(\s|$|\*)/,
		reason: "Destructive recursive deletion denied",
	},
	// Mail commands in command position (data exfiltration)
	{
		pattern: /(?:^|[|;&]\s*)(mail|mailx|sendmail|mutt|postfix)\b/,
		reason: "Mail commands denied (data exfiltration risk)",
	},
	// DNS exfiltration: nslookup/dig anywhere, host in command position only
	{ pattern: /\b(nslookup|dig)\b/, reason: "DNS lookup commands denied (exfiltration risk)" },
	{ pattern: /(?:^|[|;&]\s*)host\s/, reason: "DNS lookup commands denied (exfiltration risk)" },
];

function isDeniedBashCommand(command: string): string | null {
	for (const entry of DENIED_PATTERNS) {
		if (entry.pattern.test(command)) {
			console.warn(`[bash-deny] ${entry.reason}`);
			return entry.reason;
		}
	}
	return null;
}

const STRIPPED_ENV_PREFIXES = ["SENTINEL_", "ANTHROPIC_", "OPENAI_", "GEMINI_"];
const STRIPPED_ENV_KEYS = new Set([
	"MOLTBOT_GATEWAY_TOKEN",
	"CF_ACCESS_AUD",
	"R2_ACCESS_KEY_ID",
	"R2_SECRET_ACCESS_KEY",
	"CF_ACCOUNT_ID",
]);

function stripSensitiveEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
	const cleaned: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(env)) {
		if (STRIPPED_ENV_KEYS.has(key)) continue;
		if (STRIPPED_ENV_PREFIXES.some((p) => key.startsWith(p))) continue;
		cleaned[key] = value;
	}
	return cleaned;
}

interface BashParams {
	command: string;
	cwd?: string;
	timeout?: number;
}

export async function executeBash(params: BashParams, manifestId: string): Promise<ToolResult> {
	const start = Date.now();

	const denyReason = isDeniedBashCommand(params.command);
	if (denyReason) {
		return {
			manifestId,
			success: false,
			error: denyReason,
			duration_ms: Date.now() - start,
		};
	}

	const timeout = Math.min(Math.max(params.timeout ?? DEFAULT_TIMEOUT_MS, 1), MAX_TIMEOUT_MS);

	try {
		const useFirejail = await isFirejailAvailable();

		const execOptions = {
			cwd: params.cwd ?? process.cwd(),
			timeout,
			killSignal: "SIGKILL" as const,
			env: stripSensitiveEnv(process.env),
			extendEnv: false,
			reject: false,
		};

		const result = useFirejail
			? await execa(
					"firejail",
					["--net=none", "--private", "--", "sh", "-c", params.command],
					execOptions,
				)
			: await execaCommand(params.command, {
					...execOptions,
					shell: true,
				});

		const output = [result.stdout, result.stderr].filter(Boolean).join("\n");

		return {
			manifestId,
			success: result.exitCode === 0,
			output: output || undefined,
			error: result.exitCode !== 0 ? `Exit code: ${result.exitCode}` : undefined,
			duration_ms: Date.now() - start,
		};
	} catch (error) {
		return {
			manifestId,
			success: false,
			error: error instanceof Error ? error.message : "Unknown error",
			duration_ms: Date.now() - start,
		};
	}
}
