import * as fs from "node:fs";
import * as path from "node:path";

export const PATH_PARAMS: Record<string, string> = {
	read: "path",
	read_file: "path",
	write: "path",
	write_file: "path",
	edit: "path",
	edit_file: "path",
	apply_patch: "path",
	exec: "cwd",
	bash: "cwd",
};

export function resolveAgentPath(targetPath: string, workspaceRoot: string): string {
	if (targetPath.startsWith("~/")) {
		return path.join(workspaceRoot, targetPath.slice(2));
	}
	if (targetPath === "~") {
		return workspaceRoot;
	}
	if (path.isAbsolute(targetPath)) {
		return targetPath;
	}
	return path.join(workspaceRoot, targetPath);
}

export function isWithinWorkspace(targetPath: string, workspaceRoot: string): boolean {
	const resolvedRoot = safeRealpath(workspaceRoot);
	if (!resolvedRoot) {
		// Workspace root doesn't exist on disk — fall back to normalized path comparison
		const normalRoot = path.resolve(workspaceRoot);
		const normalTarget = path.resolve(targetPath);
		return normalTarget === normalRoot || normalTarget.startsWith(normalRoot + path.sep);
	}

	const resolvedTarget = safeRealpath(targetPath);
	if (resolvedTarget) {
		return resolvedTarget === resolvedRoot || resolvedTarget.startsWith(resolvedRoot + path.sep);
	}

	// Path doesn't exist yet — check nearest existing ancestor
	let current = path.resolve(targetPath);
	while (current !== path.dirname(current)) {
		const parent = path.dirname(current);
		const resolvedParent = safeRealpath(parent);
		if (resolvedParent) {
			const remainder = path.relative(parent, path.resolve(targetPath));
			if (remainder.startsWith("..")) return false;
			const full = path.join(resolvedParent, remainder);
			return full === resolvedRoot || full.startsWith(resolvedRoot + path.sep);
		}
		current = parent;
	}

	return false;
}

export function checkWorkspaceAccess(
	targetPath: string,
	workspaceRoot: string,
	access: "ro" | "rw",
	operation: "read" | "write",
): { allowed: boolean; reason?: string } {
	if (!isWithinWorkspace(targetPath, workspaceRoot)) {
		return { allowed: false, reason: `Path outside workspace: ${targetPath}` };
	}

	if (access === "ro" && operation === "write") {
		return { allowed: false, reason: "Write denied: read-only workspace" };
	}

	return { allowed: true };
}

function safeRealpath(p: string): string | null {
	try {
		return fs.realpathSync(p);
	} catch {
		return null;
	}
}
