import type { ToolResult } from "@sentinel/types";
import { execa, execaCommand } from "execa";
import { stripSensitiveEnv } from "../env-utils.js";
import { truncateBashOutput } from "../output-truncation.js";
import { isPathAllowed } from "./path-guard.js";

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
				// SENTINEL: C3 fix — hard failure in Docker mode when firejail is missing
				if (process.env.SENTINEL_DOCKER === "true") {
					console.error(
						"FATAL: SENTINEL_BASH_SANDBOX=firejail but firejail not found in Docker mode — refusing to execute bash unsandboxed",
					);
					process.exit(1);
				}
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
	// Fork bomb
	{ pattern: /:\(\)\s*\{.*\|.*&\s*\}\s*;?\s*:/, reason: "Fork bomb denied" },
	// Disk destruction via dd targeting block devices
	{
		pattern: /\bdd\b.*\bof=\/dev\/[sh]d[a-z]/,
		reason: "Disk destruction command denied",
	},
	{
		pattern: /\bdd\b.*\bof=\/dev\/nvme/,
		reason: "Disk destruction command denied",
	},
	// Filesystem formatting
	{ pattern: /\bmkfs\b/, reason: "Filesystem format command denied" },
	// Process kill: init (PID 1) or all processes (PID -1)
	{
		pattern: /\bkill\b.*(-9|-KILL|-SIGKILL)\s+(-1|1)\b/,
		reason: "Process kill denied (init/all processes)",
	},
	// Recursive chmod 777 on root
	{
		pattern: /\bchmod\b.*(-R|--recursive).*777\s+\/(\s|$)/,
		reason: "Recursive permission change on root denied",
	},
	// SENTINEL: Full-path command variants — bypass word boundary (MEDIUM-3)
	{
		pattern: new RegExp(
			`(?:/usr)?/s?bin/(cat|head|tail|less|more|tac|nl|od|xxd|hexdump|base64|strings)\\b.*${SENSITIVE_FILE}`,
		),
		reason: "Command reads a sensitive file (full-path bypass)",
	},
	{
		pattern:
			/(?:\/usr)?\/s?bin\/(cat|head|tail|less|more|tac|nl|od|xxd|hexdump|base64|strings)\b.*\.dev\.vars\b/,
		reason: "Command reads a sensitive file (full-path bypass)",
	},
	{
		pattern:
			/(?:\/usr)?\/s?bin\/(cat|head|tail|less|more|tac|nl|od|xxd|hexdump|base64|strings)\b.*\.git\/(config|credentials)\b/,
		reason: "Command reads a sensitive file (full-path bypass)",
	},
	{
		pattern:
			/(?:\/usr)?\/s?bin\/(cat|head|tail|less|more|tac|nl|od|xxd|hexdump|base64|strings)\b.*secret/i,
		reason: "Command reads a sensitive file (full-path bypass)",
	},
	{
		pattern:
			/(?:\/usr)?\/s?bin\/(cat|head|tail|less|more|tac|nl|od|xxd|hexdump|base64|strings)\b.*credential/i,
		reason: "Command reads a sensitive file (full-path bypass)",
	},
	{
		pattern:
			/(?:\/usr)?\/s?bin\/(cat|head|tail|less|more|tac|nl|od|xxd|hexdump|base64|strings)\b.*vault\.enc\b/,
		reason: "Command reads a sensitive file (full-path bypass)",
	},
	// SENTINEL: M5 — sqlite3 direct database access denied
	{
		pattern: /(?:^|[|;&]\s*)sqlite3\b/,
		reason: "Direct database access denied",
	},
	{
		pattern: /(?:^|[|;&]\s*)sqlite3_analyzer\b/,
		reason: "Direct database access denied",
	},
	{
		pattern: /(?:\/usr)?\/s?bin\/sqlite3\b/,
		reason: "Direct database access denied (full-path bypass)",
	},
	// SENTINEL: I4 fix — sqlite3 bypass via env/command/./ prefixes and subshell execution
	{
		pattern: /(?:^|[|;&]\s*)(?:env\s+|command\s+|\.\/)sqlite3\b/,
		reason: "Direct database access denied (prefix bypass)",
	},
	{
		pattern: /\$\(\s*sqlite3\b/,
		reason: "Direct database access denied (subshell bypass)",
	},
	{
		pattern: /`[^`]*sqlite3\b/,
		reason: "Direct database access denied (backtick bypass)",
	},
	// SENTINEL: Pipe-to-shell — command output piped to shell interpreter (MEDIUM-3)
	{
		pattern: /\|\s*(sh|bash|zsh|dash|eval)\b/,
		reason: "Pipe-to-shell execution denied",
	},
	// SENTINEL: Base64 decode piped to shell (MEDIUM-3)
	{
		pattern: /base64\s+(-d|--decode).*\|\s*(sh|bash|zsh|dash)\b/,
		reason: "Base64-to-shell execution denied",
	},
	// SENTINEL: Full-path curl/wget exfiltration (MEDIUM-3)
	{
		pattern: /(?:\/usr)?\/s?bin\/curl\b.*@.*\.(env|pem|key)\b/,
		reason: "Command exfiltrates a sensitive file (full-path bypass)",
	},
	{
		pattern: /(?:\/usr)?\/s?bin\/curl\b.*-d\b.*\.(env|pem|key)\b/,
		reason: "Command exfiltrates a sensitive file (full-path bypass)",
	},
];

function isDeniedBashCommand(command: string): string | null {
	// SENTINEL: Normalize backslash-escaped characters to defeat bypass (MEDIUM-3)
	const normalized = command.replace(/\\(.)/g, "$1");

	for (const entry of DENIED_PATTERNS) {
		if (entry.pattern.test(normalized)) {
			console.warn(`[bash-deny] ${entry.reason}`);
			return entry.reason;
		}
	}
	return null;
}

interface BashParams {
	command: string;
	cwd?: string;
	timeout?: number;
}

export async function executeBash(
	params: BashParams,
	manifestId: string,
	allowedRoots?: readonly string[],
): Promise<ToolResult> {
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

	// SENTINEL: M1 — cwd must be within allowedRoots to prevent path whitelist bypass
	if (params.cwd && allowedRoots && allowedRoots.length > 0) {
		const cwdCheck = await isPathAllowed(params.cwd, allowedRoots);
		if (!cwdCheck.allowed) {
			return {
				manifestId,
				success: false,
				error: "Working directory outside allowed roots",
				duration_ms: Date.now() - start,
			};
		}
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

		const rawOutput = [result.stdout, result.stderr].filter(Boolean).join("\n");
		const output = rawOutput ? truncateBashOutput(rawOutput) : undefined;

		return {
			manifestId,
			success: result.exitCode === 0,
			output,
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
