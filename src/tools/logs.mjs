import { execSync } from "child_process";
import { resolve } from "path";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";

export const handlers = {
  async log_read({ path: logPath, lines }) {
    if (!logPath) return error("path is required");
    const resolved = resolve(logPath);
    const n = lines ? parseInt(lines, 10) : 100;
    const toolName = "log.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`tail -n ${n} "${resolved}"`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(empty log)", toolName);
    } catch (err) {
      return error(`Failed to read log ${logPath}: ${err.message}`);
    }
  },

  async log_search({ path: logPath, pattern, lines }) {
    if (!logPath) return error("path is required");
    if (!pattern) return error("pattern is required");
    const resolved = resolve(logPath);
    const n = lines ? parseInt(lines, 10) : 50;
    const toolName = "log.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`grep -i "${pattern.replace(/"/g, '\\"')}" "${resolved}" | tail -n ${n}`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no matches)", toolName);
    } catch (err) {
      if (err.status === 1) return success("(no matches)", toolName);
      return error(`Log search failed: ${err.message}`);
    }
  },
};

export const tools = [
  { name: "log_read", description: "Read last N lines of a log file. Requires log.read.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to log file" }, lines: { type: "string", description: "Number of lines (default: 100)" } }, required: ["path"] } },
  { name: "log_search", description: "Search a log file for a pattern. Requires log.read.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to log file" }, pattern: { type: "string", description: "Search pattern (case-insensitive)" }, lines: { type: "string", description: "Max results (default: 50)" } }, required: ["path", "pattern"] } },
];
