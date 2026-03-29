import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";

export const handlers = {
  async process_list() {
    const toolName = "process.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync("ps aux --sort=-%cpu | head -20", {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      // macOS ps doesn't support --sort
      try {
        const output = execSync("ps aux | head -20", {
          encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
        });
        return success(output, toolName);
      } catch (e) {
        return error(`Failed to list processes: ${e.message}`);
      }
    }
  },

  async process_info({ pid }) {
    if (!pid) return error("pid is required");
    const toolName = "process.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`ps -p ${parseInt(pid, 10)} -o pid,ppid,user,%cpu,%mem,stat,start,command`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`Process ${pid} not found or inaccessible`);
    }
  },

  async process_kill({ pid, signal }) {
    if (!pid) return error("pid is required");
    const sig = signal || "TERM";
    const toolName = "process.kill";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      execSync(`kill -${sig} ${parseInt(pid, 10)}`, {
        encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(`Sent ${sig} to PID ${pid}`, toolName);
    } catch (err) {
      return error(`Failed to kill PID ${pid}: ${err.stderr || err.message}`);
    }
  },
};

export const tools = [
  {
    name: "process_list",
    description: "List running processes sorted by CPU usage. Requires process.read permission.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "process_info",
    description: "Get detailed info about a specific process. Requires process.read permission.",
    inputSchema: {
      type: "object",
      properties: { pid: { type: "string", description: "Process ID" } },
      required: ["pid"],
    },
  },
  {
    name: "process_kill",
    description: "Send a signal to a process. Requires process.kill permission.",
    inputSchema: {
      type: "object",
      properties: {
        pid: { type: "string", description: "Process ID" },
        signal: { type: "string", description: "Signal name (default: TERM)", enum: ["TERM", "KILL", "HUP", "INT", "STOP", "CONT"] },
      },
      required: ["pid"],
    },
  },
];
