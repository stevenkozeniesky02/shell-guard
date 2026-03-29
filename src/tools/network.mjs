import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";

export const handlers = {
  async network_ping({ host, count }) {
    if (!host) return error("host is required");
    const toolName = "network.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const c = count ? parseInt(count, 10) : 4;
    try {
      const output = execSync(`ping -c ${c} ${host}`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`Ping failed: ${err.stderr || err.message}`);
    }
  },

  async network_ports() {
    const toolName = "network.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync("lsof -i -P -n | grep LISTEN 2>/dev/null || netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null", {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no listening ports found)", toolName);
    } catch (err) {
      return error(`Failed to list ports: ${err.message}`);
    }
  },

  async network_traceroute({ host }) {
    if (!host) return error("host is required");
    const toolName = "network.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`traceroute -m 15 ${host} 2>&1`, {
        encoding: "utf-8", timeout: 30000, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`Traceroute failed: ${err.stderr || err.message}`);
    }
  },

  async network_dns({ domain, type }) {
    if (!domain) return error("domain is required");
    const toolName = "network.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const recordType = type || "A";
    try {
      const output = execSync(`dig ${domain} ${recordType} +short`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no records)", toolName);
    } catch (err) {
      return error(`DNS lookup failed: ${err.message}`);
    }
  },
};

export const tools = [
  {
    name: "network_ping",
    description: "Ping a host. Requires network.read permission.",
    inputSchema: {
      type: "object",
      properties: {
        host: { type: "string", description: "Hostname or IP to ping" },
        count: { type: "string", description: "Number of pings (default: 4)" },
      },
      required: ["host"],
    },
  },
  {
    name: "network_ports",
    description: "List listening network ports. Requires network.read permission.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "network_traceroute",
    description: "Traceroute to a host. Requires network.read permission.",
    inputSchema: {
      type: "object",
      properties: { host: { type: "string", description: "Hostname or IP" } },
      required: ["host"],
    },
  },
  {
    name: "network_dns",
    description: "DNS lookup for a domain. Requires network.read permission.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Domain to look up" },
        type: { type: "string", description: "Record type (default: A)", enum: ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA"] },
      },
      required: ["domain"],
    },
  },
];
