import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";
import { classifyShellCommand } from "../core/classifier.mjs";

export const handlers = {
  async git_run({ command: gitCmd }) {
    if (!gitCmd) return error("command is required (e.g., 'status', 'log --oneline -5')");

    const fullCmd = `git ${gitCmd}`;
    const toolName = classifyShellCommand(fullCmd);

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(fullCmd, {
        cwd: config.cwd, timeout: config.timeout, maxBuffer: 1024 * 1024,
        encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no output)", toolName);
    } catch (err) {
      return { content: [{ type: "text", text: `Git failed:\n${err.stderr || err.message}\n\n[✓ ${toolName}]` }], isError: true };
    }
  },
};

export const tools = [
  {
    name: "git_run",
    description: "Run a git command. Read operations (status, log, diff) require git.read.*. Write operations (commit, push) require git.write.*.",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string", description: "Git subcommand and arguments (e.g., 'status', 'log --oneline -5', 'push origin main')" } },
      required: ["command"],
    },
  },
];
