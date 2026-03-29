import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";
import { classifyShellCommand } from "../core/classifier.mjs";

export const handlers = {
  async shell_run({ command }) {
    if (!command) return error("command is required");
    const toolName = classifyShellCommand(command);
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(command, {
        cwd: config.cwd, timeout: config.timeout, maxBuffer: 1024 * 1024,
        encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no output)", toolName);
    } catch (err) {
      return { content: [{ type: "text", text: `Command failed (exit ${err.status}):\n${err.stderr || err.message}\n\n[✓ ${toolName}]` }], isError: true };
    }
  },
};

export const tools = [
  {
    name: "shell_run",
    description: "Run a shell command. Validated against AgentsID permissions. Read commands (ls, cat, grep) typically allowed. Destructive commands (rm, chmod) blocked unless permitted.",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string", description: "The shell command to run" } },
      required: ["command"],
    },
  },
];
