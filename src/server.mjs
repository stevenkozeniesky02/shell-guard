/**
 * AgentsID Guard — MCP server for safe shell, file, database, git, and HTTP access.
 *
 * Every operation is validated against AgentsID permission rules before execution.
 * One server. Every tool category protected.
 *
 * Usage:
 *   claude mcp add guard -- npx @agentsid/guard
 *
 * Environment:
 *   AGENTSID_PROJECT_KEY  — Your AgentsID project key (required)
 *   AGENTSID_AGENT_TOKEN  — Agent token for permission checks (required)
 *   AGENTSID_BASE_URL     — API base URL (default: https://agentsid.dev)
 *   GUARD_CWD             — Working directory (default: process.cwd())
 *   GUARD_TIMEOUT         — Command timeout in ms (default: 30000)
 *   GUARD_ALLOWED_DIRS    — Comma-separated allowed directories for file ops (default: cwd)
 *   GUARD_DB_URL          — Database connection string for db tools (optional)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { error } from "./core/validator.mjs";

// ─── Import All Tool Modules ───

import * as shell from "./tools/shell.mjs";
import * as files from "./tools/files.mjs";
import * as database from "./tools/database.mjs";
import * as git from "./tools/git.mjs";
import * as http from "./tools/http.mjs";
import * as env from "./tools/env.mjs";
import * as process_ from "./tools/process.mjs";
import * as cron from "./tools/cron.mjs";
import * as container from "./tools/container.mjs";
import * as network from "./tools/network.mjs";
import * as system from "./tools/system.mjs";
import * as logs from "./tools/logs.mjs";
import * as ssh from "./tools/ssh.mjs";
import * as packages from "./tools/packages.mjs";
import * as cloud from "./tools/cloud.mjs";
import * as secrets from "./tools/secrets.mjs";
import * as utility from "./tools/utility.mjs";

// ─── Merge All Modules ───

const modules = [
  shell, files, database, git, http, env, process_, cron,
  container, network, system, logs, ssh, packages, cloud,
  secrets, utility,
];

const handlers = Object.freeze(
  modules.reduce((acc, mod) => ({ ...acc, ...mod.handlers }), {})
);

const TOOLS = modules.flatMap((mod) => mod.tools);

// ─── MCP Server ───

const server = new Server(
  { name: "agentsid-guard", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const handler = handlers[name];
  if (!handler) {
    return error(`Unknown tool: ${name}`);
  }
  return handler(args || {});
});

// ─── Start ───

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("AgentsID Guard running — shell, file, db, git, http protected");
}

main().catch((err) => {
  console.error("Failed to start AgentsID Guard:", err);
  process.exit(1);
});
