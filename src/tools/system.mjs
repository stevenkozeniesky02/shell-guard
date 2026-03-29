import { execSync } from "child_process";
import { validate, blocked, success, error } from "../core/validator.mjs";

export const handlers = {
  async system_info() {
    const toolName = "system.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const os = execSync("uname -a", { encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] }).trim();
      let cpu = "", mem = "", disk = "";
      try { cpu = execSync("sysctl -n machdep.cpu.brand_string 2>/dev/null || lscpu 2>/dev/null | grep 'Model name' || echo 'unknown'", { encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] }).trim(); } catch { cpu = "unknown"; }
      try { mem = execSync("free -h 2>/dev/null || vm_stat 2>/dev/null | head -5", { encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] }).trim(); } catch { mem = "unavailable"; }
      try { disk = execSync("df -h / | tail -1", { encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] }).trim(); } catch { disk = "unavailable"; }
      const uptime = execSync("uptime", { encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] }).trim();
      return success(`OS: ${os}\nCPU: ${cpu}\nMemory:\n${mem}\nDisk (/):\n${disk}\nUptime: ${uptime}`, toolName);
    } catch (err) {
      return error(`Failed to get system info: ${err.message}`);
    }
  },

  async disk_usage({ path: diskPath }) {
    const toolName = "system.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const target = diskPath || "/";
      const output = execSync(`df -h ${target}`, { encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] });
      return success(output, toolName);
    } catch (err) {
      return error(`Failed to get disk usage: ${err.message}`);
    }
  },

  async memory_usage() {
    const toolName = "system.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync("free -h 2>/dev/null || top -l 1 -s 0 | head -10 2>/dev/null || vm_stat", {
        encoding: "utf-8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`Failed to get memory usage: ${err.message}`);
    }
  },
};

export const tools = [
  { name: "system_info", description: "Get system overview: OS, CPU, memory, disk, uptime. Requires system.read.", inputSchema: { type: "object", properties: {} } },
  { name: "disk_usage", description: "Get disk usage for a path. Requires system.read.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Mount point or path (default: /)" } } } },
  { name: "memory_usage", description: "Get memory usage breakdown. Requires system.read.", inputSchema: { type: "object", properties: {} } },
];
