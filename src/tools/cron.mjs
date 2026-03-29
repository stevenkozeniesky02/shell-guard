import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";

export const handlers = {
  async cron_list() {
    const toolName = "cron.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync("crontab -l 2>/dev/null || echo '(no crontab)'", {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return success("(no crontab configured)", toolName);
    }
  },

  async cron_add({ schedule, command }) {
    if (!schedule) return error("schedule is required (e.g., '0 * * * *')");
    if (!command) return error("command is required");
    const toolName = "cron.write";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const existing = execSync("crontab -l 2>/dev/null || echo ''", {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      }).trim();
      const newEntry = `${schedule} ${command}`;
      const updated = existing ? `${existing}\n${newEntry}` : newEntry;
      execSync(`echo "${updated.replace(/"/g, '\\"')}" | crontab -`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(`Added cron job: ${newEntry}`, toolName);
    } catch (err) {
      return error(`Failed to add cron job: ${err.stderr || err.message}`);
    }
  },

  async cron_remove({ pattern }) {
    if (!pattern) return error("pattern is required (text to match in the cron entry)");
    const toolName = "cron.danger";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      execSync(`crontab -l 2>/dev/null | grep -v "${pattern.replace(/"/g, '\\"')}" | crontab -`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(`Removed cron entries matching: ${pattern}`, toolName);
    } catch (err) {
      return error(`Failed to remove cron job: ${err.stderr || err.message}`);
    }
  },
};

export const tools = [
  {
    name: "cron_list",
    description: "List current user's cron jobs. Requires cron.read permission.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "cron_add",
    description: "Add a cron job. Requires cron.write permission.",
    inputSchema: {
      type: "object",
      properties: {
        schedule: { type: "string", description: "Cron schedule (e.g., '0 * * * *' for hourly)" },
        command: { type: "string", description: "Command to run" },
      },
      required: ["schedule", "command"],
    },
  },
  {
    name: "cron_remove",
    description: "Remove cron jobs matching a pattern. Requires cron.danger permission.",
    inputSchema: {
      type: "object",
      properties: { pattern: { type: "string", description: "Text pattern to match in cron entries to remove" } },
      required: ["pattern"],
    },
  },
];
