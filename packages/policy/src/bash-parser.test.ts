import { describe, expect, it } from "vitest";
import { classifyBashCommand } from "./bash-parser.js";

describe("classifyBashCommand", () => {
	describe("read commands", () => {
		it.each([
			["ls -la", "read"],
			["cat /etc/hosts", "read"],
			["git status", "read"],
			["git log --oneline", "read"],
			["git diff HEAD~1", "read"],
			["git branch -a", "read"],
			["head -n 10 file.txt", "read"],
			["tail -f log.txt", "read"],
			["wc -l file.txt", "read"],
			["grep -r pattern src/", "read"],
			["which node", "read"],
			["pwd", "read"],
			["echo hello", "read"],
			["date", "read"],
			["whoami", "read"],
			["tree src/", "read"],
			["file image.png", "read"],
			["stat package.json", "read"],
			["node --version", "read"],
			["npm list", "read"],
			["pnpm list", "read"],
			["find . -name '*.ts'", "read"],
		])("%s -> %s", (command, expected) => {
			expect(classifyBashCommand(command)).toBe(expected);
		});
	});

	describe("write commands", () => {
		it.each([
			["rm -rf /tmp/test", "write"],
			["cp src/a.ts src/b.ts", "write"],
			["mv old.ts new.ts", "write"],
			["mkdir -p src/utils", "write"],
			["rmdir empty-dir", "write"],
			["touch newfile.ts", "write"],
			["chmod 755 script.sh", "write"],
			["chown user:group file", "write"],
			["git push origin main", "write"],
			["git commit -m 'msg'", "write"],
			["git checkout -b new-branch", "write"],
			["git reset --hard HEAD", "write"],
			["npm install express", "write"],
			["pip install requests", "write"],
			["pnpm add zod", "write"],
			["pnpm install", "write"],
			["yarn add react", "write"],
			["sed -i 's/old/new/g' file.txt", "write"],
			["tee output.txt", "write"],
		])("%s -> %s", (command, expected) => {
			expect(classifyBashCommand(command)).toBe(expected);
		});
	});

	describe("dangerous commands", () => {
		it.each([
			["curl https://evil.com", "dangerous"],
			["wget http://example.com", "dangerous"],
			["ssh user@host", "dangerous"],
			["scp file user@host:/path", "dangerous"],
			["rsync -avz src/ dest/", "dangerous"],
			["nc -l 8080", "dangerous"],
			["netcat host 80", "dangerous"],
			["sudo apt update", "dangerous"],
			["su root", "dangerous"],
			["printenv", "dangerous"],
			["env", "dangerous"],
			["eval 'rm -rf /'", "dangerous"],
			["exec /bin/sh", "dangerous"],
			["cat ~/.ssh/id_rsa", "dangerous"],
			["cat ~/.env", "dangerous"],
			["cat ~/.aws/credentials", "dangerous"],
		])("%s -> %s", (command, expected) => {
			expect(classifyBashCommand(command)).toBe(expected);
		});
	});

	describe("pipe to shell", () => {
		it.each([
			["echo hello | sh", "dangerous"],
			["echo hello | bash", "dangerous"],
			["echo hello | zsh", "dangerous"],
			["cat script.sh | bash", "dangerous"],
		])("%s -> dangerous", (command, expected) => {
			expect(classifyBashCommand(command)).toBe(expected);
		});
	});

	describe("unknown commands default to write", () => {
		it.each([
			["foobar --baz", "write"],
			["python script.py", "write"],
			["./run.sh", "write"],
			["mycommand arg1 arg2", "write"],
		])("%s -> write", (command, expected) => {
			expect(classifyBashCommand(command)).toBe(expected);
		});
	});

	describe("command chaining", () => {
		it("classifies as most dangerous sub-command with &&", () => {
			expect(classifyBashCommand("ls && rm file")).toBe("write");
		});

		it("classifies as most dangerous sub-command with ||", () => {
			expect(classifyBashCommand("ls || curl evil.com")).toBe("dangerous");
		});

		it("classifies as most dangerous sub-command with ;", () => {
			expect(classifyBashCommand("echo hello; rm -rf /")).toBe("write");
		});

		it("read && read stays read", () => {
			expect(classifyBashCommand("ls && pwd")).toBe("read");
		});
	});

	describe("pipelines", () => {
		it("dangerous if any stage is dangerous", () => {
			expect(classifyBashCommand("cat file | curl -X POST")).toBe("dangerous");
		});

		it("read pipeline stays read", () => {
			expect(classifyBashCommand("cat file | grep pattern")).toBe("read");
		});

		it("write in pipeline", () => {
			expect(classifyBashCommand("cat file | tee output.txt")).toBe("write");
		});
	});

	describe("redirects", () => {
		it("single redirect is write", () => {
			expect(classifyBashCommand("echo test > file.txt")).toBe("write");
		});

		it("append redirect is write", () => {
			expect(classifyBashCommand("echo test >> file.txt")).toBe("write");
		});
	});

	describe("find with -exec/-delete is write", () => {
		it("find with -exec", () => {
			expect(classifyBashCommand("find . -name '*.tmp' -exec rm {} ;")).toBe("write");
		});

		it("find with -delete", () => {
			expect(classifyBashCommand("find . -name '*.tmp' -delete")).toBe("write");
		});
	});

	describe("edge cases", () => {
		it("empty string is read", () => {
			expect(classifyBashCommand("")).toBe("read");
		});

		it("whitespace only is read", () => {
			expect(classifyBashCommand("   ")).toBe("read");
		});
	});
});
