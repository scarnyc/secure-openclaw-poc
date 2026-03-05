import type { ActionCategory } from "@sentinel/types";

const READ_COMMANDS = new Set([
	"ls",
	"cat",
	"head",
	"tail",
	"wc",
	"find",
	"grep",
	"which",
	"pwd",
	"echo",
	"date",
	"whoami",
	"tree",
	"file",
	"stat",
]);

const READ_MULTI_WORD = new Set([
	"node --version",
	"npm list",
	"pnpm list",
	"git status",
	"git log",
	"git diff",
	"git branch",
]);

const WRITE_COMMANDS = new Set([
	"cp",
	"mv",
	"rm",
	"mkdir",
	"rmdir",
	"touch",
	"chmod",
	"chown",
	"tee",
]);

const WRITE_MULTI_WORD = new Set([
	"sed -i",
	"git push",
	"git commit",
	"git checkout",
	"git reset",
	"npm install",
	"pip install",
	"pnpm add",
	"pnpm install",
	"yarn add",
]);

const DANGEROUS_COMMANDS = new Set([
	"curl",
	"wget",
	"ssh",
	"scp",
	"rsync",
	"nc",
	"netcat",
	"sudo",
	"su",
	"printenv",
	"env",
	"eval",
	"exec",
]);

const SENSITIVE_PATH_PATTERNS = [
	/~\/\.ssh\//,
	/~\/\.env/,
	/~\/\.aws\//,
	/\$HOME\/\.ssh\//,
	/\$HOME\/\.env/,
	/\$HOME\/\.aws\//,
];

function hasRedirect(command: string): boolean {
	return /(?:^|[^>])>{1,2}(?!>)/.test(command);
}

function hasPipeToShell(command: string): boolean {
	return /\|\s*(sh|bash|zsh)\b/.test(command);
}

function hasSensitivePath(command: string): boolean {
	return SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(command));
}

function hasSubshell(command: string): boolean {
	return /`[^`]+`/.test(command) || /\$\([^)]+\)/.test(command);
}

function classifySingleCommand(command: string): ActionCategory {
	const trimmed = command.trim();
	if (!trimmed) return "read";

	// Check dangerous signals first (these override everything)
	if (hasPipeToShell(trimmed)) return "dangerous";
	if (hasSensitivePath(trimmed)) return "dangerous";
	if (hasSubshell(trimmed)) return "dangerous";

	// Extract the first word(s) for command matching
	const words = trimmed.split(/\s+/);
	const firstWord = words[0];

	// Check multi-word dangerous patterns (eval, exec are single-word)
	if (DANGEROUS_COMMANDS.has(firstWord)) return "dangerous";

	// Check multi-word write commands
	const twoWords = words.slice(0, 2).join(" ");
	if (WRITE_MULTI_WORD.has(twoWords)) return "write";

	// Check multi-word read commands
	if (READ_MULTI_WORD.has(twoWords)) {
		// find with -exec or -delete is write
		if (firstWord === "find") {
			if (trimmed.includes("-exec") || trimmed.includes("-delete")) {
				return "write";
			}
		}
		return "read";
	}

	// Check single-word read commands
	if (READ_COMMANDS.has(firstWord)) {
		// find with -exec or -delete is write
		if (firstWord === "find") {
			if (trimmed.includes("-exec") || trimmed.includes("-delete")) {
				return "write";
			}
		}
		return "read";
	}

	// Check single-word write commands
	if (WRITE_COMMANDS.has(firstWord)) return "write";

	// Check for redirects (write)
	if (hasRedirect(trimmed)) return "write";

	// Unknown command defaults to write
	return "write";
}

const CATEGORY_ORDER: Record<ActionCategory, number> = {
	read: 0,
	write: 1,
	dangerous: 2,
};

function maxCategory(a: ActionCategory, b: ActionCategory): ActionCategory {
	return CATEGORY_ORDER[a] >= CATEGORY_ORDER[b] ? a : b;
}

/**
 * Split a command string by chaining operators (&&, ||, ;)
 * while respecting quoted strings and subshells.
 */
function splitChainedCommands(command: string): string[] {
	const parts: string[] = [];
	let current = "";
	let inSingle = false;
	let inDouble = false;
	let depth = 0;

	for (let i = 0; i < command.length; i++) {
		const ch = command[i];
		const next = command[i + 1];

		if (ch === "'" && !inDouble && depth === 0) {
			inSingle = !inSingle;
			current += ch;
		} else if (ch === '"' && !inSingle && depth === 0) {
			inDouble = !inDouble;
			current += ch;
		} else if (!inSingle && !inDouble) {
			if (ch === "(" || (ch === "$" && next === "(")) {
				depth++;
				current += ch;
			} else if (ch === ")" && depth > 0) {
				depth--;
				current += ch;
			} else if (depth === 0 && ch === ";" && !inSingle && !inDouble) {
				parts.push(current);
				current = "";
			} else if (depth === 0 && ch === "&" && next === "&" && !inSingle && !inDouble) {
				parts.push(current);
				current = "";
				i++; // skip next &
			} else if (depth === 0 && ch === "|" && next === "|" && !inSingle && !inDouble) {
				parts.push(current);
				current = "";
				i++; // skip next |
			} else {
				current += ch;
			}
		} else {
			current += ch;
		}
	}

	if (current.trim()) {
		parts.push(current);
	}

	return parts;
}

/**
 * Split a command by pipe operators while respecting || (logical OR).
 */
function splitPipeline(command: string): string[] {
	const parts: string[] = [];
	let current = "";
	let inSingle = false;
	let inDouble = false;

	for (let i = 0; i < command.length; i++) {
		const ch = command[i];
		const next = command[i + 1];

		if (ch === "'" && !inDouble) {
			inSingle = !inSingle;
			current += ch;
		} else if (ch === '"' && !inSingle) {
			inDouble = !inDouble;
			current += ch;
		} else if (!inSingle && !inDouble && ch === "|" && next !== "|") {
			// Check previous char isn't | (avoid splitting ||)
			if (i > 0 && command[i - 1] === "|") {
				current += ch;
			} else {
				parts.push(current);
				current = "";
			}
		} else {
			current += ch;
		}
	}

	if (current.trim()) {
		parts.push(current);
	}

	return parts;
}

/**
 * Classify a bash command string into an ActionCategory.
 * Handles pipes, chaining (&&, ||, ;), and classifies as the most dangerous sub-command.
 */
export function classifyBashCommand(command: string): ActionCategory {
	const trimmed = command.trim();
	if (!trimmed) return "read";

	// Top-level: check for pipe-to-shell and redirects on the whole string
	if (hasPipeToShell(trimmed)) return "dangerous";

	// Split by chaining operators
	const chained = splitChainedCommands(trimmed);

	let worst: ActionCategory = "read";

	for (const segment of chained) {
		// Split each chained segment by pipe
		const pipeStages = splitPipeline(segment);

		for (const stage of pipeStages) {
			const category = classifySingleCommand(stage);
			worst = maxCategory(worst, category);
		}
	}

	// Also check redirects on the whole command
	if (hasRedirect(trimmed) && CATEGORY_ORDER[worst] < CATEGORY_ORDER.write) {
		worst = "write";
	}

	return worst;
}
