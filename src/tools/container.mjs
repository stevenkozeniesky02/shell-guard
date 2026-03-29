import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";

export const handlers = {
  async container_list({ all }) {
    const toolName = "container.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const flag = all ? "-a" : "";
    try {
      const output = execSync(`docker ps ${flag} --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}"`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no containers)", toolName);
    } catch (err) {
      return error(`Docker not available or not running: ${err.message}`);
    }
  },

  async container_inspect({ id }) {
    if (!id) return error("id is required (container ID or name)");
    const toolName = "container.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`docker inspect ${id} --format '{{json .}}'`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`Container ${id} not found: ${err.message}`);
    }
  },

  async container_logs({ id, tail }) {
    if (!id) return error("id is required (container ID or name)");
    const toolName = "container.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const tailArg = tail ? `--tail ${parseInt(tail, 10)}` : "--tail 50";
    try {
      const output = execSync(`docker logs ${id} ${tailArg} 2>&1`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no logs)", toolName);
    } catch (err) {
      return error(`Failed to get logs for ${id}: ${err.message}`);
    }
  },

  async container_start({ id }) {
    if (!id) return error("id is required");
    const toolName = "container.write";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      execSync(`docker start ${id}`, { encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"] });
      return success(`Started container ${id}`, toolName);
    } catch (err) {
      return error(`Failed to start ${id}: ${err.message}`);
    }
  },

  async container_stop({ id }) {
    if (!id) return error("id is required");
    const toolName = "container.write";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      execSync(`docker stop ${id}`, { encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"] });
      return success(`Stopped container ${id}`, toolName);
    } catch (err) {
      return error(`Failed to stop ${id}: ${err.message}`);
    }
  },

  async container_remove({ id, force }) {
    if (!id) return error("id is required");
    const toolName = "container.danger";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const forceFlag = force ? " -f" : "";
    try {
      execSync(`docker rm${forceFlag} ${id}`, { encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"] });
      return success(`Removed container ${id}`, toolName);
    } catch (err) {
      return error(`Failed to remove ${id}: ${err.message}`);
    }
  },
};

export const tools = [
  {
    name: "container_list",
    description: "List Docker containers. Requires container.read permission.",
    inputSchema: {
      type: "object",
      properties: { all: { type: "boolean", description: "Include stopped containers (default: false)" } },
    },
  },
  {
    name: "container_inspect",
    description: "Get detailed info about a Docker container. Requires container.read permission.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string", description: "Container ID or name" } },
      required: ["id"],
    },
  },
  {
    name: "container_logs",
    description: "View Docker container logs. Requires container.read permission.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Container ID or name" },
        tail: { type: "string", description: "Number of lines from the end (default: 50)" },
      },
      required: ["id"],
    },
  },
  {
    name: "container_start",
    description: "Start a stopped Docker container. Requires container.write permission.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string", description: "Container ID or name" } },
      required: ["id"],
    },
  },
  {
    name: "container_stop",
    description: "Stop a running Docker container. Requires container.write permission.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string", description: "Container ID or name" } },
      required: ["id"],
    },
  },
  {
    name: "container_remove",
    description: "Remove a Docker container. Requires container.danger permission.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Container ID or name" },
        force: { type: "boolean", description: "Force removal of running container" },
      },
      required: ["id"],
    },
  },
];
