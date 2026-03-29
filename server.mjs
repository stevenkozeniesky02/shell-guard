#!/usr/bin/env node

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

import { execSync } from "child_process";
import { readFileSync, writeFileSync, unlinkSync, readdirSync, statSync, existsSync, mkdirSync } from "fs";
import { resolve, relative, dirname } from "path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

// ─── Config ───

const PROJECT_KEY = process.env.AGENTSID_PROJECT_KEY || "";
const AGENT_TOKEN = process.env.AGENTSID_AGENT_TOKEN || "";
const BASE_URL = process.env.AGENTSID_BASE_URL || "https://agentsid.dev";
const CWD = process.env.GUARD_CWD || process.cwd();
const TIMEOUT = parseInt(process.env.GUARD_TIMEOUT || "30000", 10);
const ALLOWED_DIRS = (process.env.GUARD_ALLOWED_DIRS || CWD).split(",").map((d) => resolve(d.trim()));

// ─── AgentsID Validation ───

async function validate(toolName) {
  if (!PROJECT_KEY || !AGENT_TOKEN) {
    return {
      allowed: false,
      tool: toolName,
      reason: "AGENTSID_PROJECT_KEY and AGENTSID_AGENT_TOKEN required",
    };
  }

  try {
    const response = await fetch(`${BASE_URL}/api/v1/validate`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${PROJECT_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token: AGENT_TOKEN, tool: toolName }),
    });

    const result = await response.json();

    return {
      allowed: result.valid === true && result.permission?.allowed === true,
      tool: toolName,
      reason: result.permission?.reason || result.reason || "Unknown",
    };
  } catch (err) {
    return {
      allowed: false,
      tool: toolName,
      reason: `AgentsID validation failed: ${err.message}`,
    };
  }
}

function blocked(toolName, reason) {
  return {
    content: [
      {
        type: "text",
        text: `BLOCKED by AgentsID Guard\n\nTool: ${toolName}\nReason: ${reason}\n\nThis action was denied and logged to the audit trail.`,
      },
    ],
    isError: true,
  };
}

function success(text, toolName) {
  return {
    content: [{ type: "text", text: `${text}\n\n[✓ ${toolName}]` }],
  };
}

function error(text) {
  return {
    content: [{ type: "text", text }],
    isError: true,
  };
}

// ─── Path Safety ───

function isPathAllowed(targetPath) {
  const resolved = resolve(targetPath);
  return ALLOWED_DIRS.some((dir) => resolved.startsWith(dir));
}

// ─── Shell Command Classification ───

const SHELL_COMMANDS = {
  ls: "shell.read.ls", cat: "shell.read.cat", head: "shell.read.head",
  tail: "shell.read.tail", find: "shell.read.find", grep: "shell.read.grep",
  wc: "shell.read.wc", du: "shell.read.du", df: "shell.read.df",
  pwd: "shell.read.pwd", whoami: "shell.read.whoami", date: "shell.read.date",
  uname: "shell.read.uname", echo: "shell.read.echo", which: "shell.read.which",
  file: "shell.read.file", stat: "shell.read.stat", diff: "shell.read.diff",
  sort: "shell.read.sort", uniq: "shell.read.uniq", jq: "shell.read.jq",
  ps: "shell.read.ps", uptime: "shell.read.uptime", free: "shell.read.free",
  curl: "shell.read.curl", wget: "shell.read.wget", ping: "shell.read.ping",
  dig: "shell.read.dig",
  "git status": "git.read.status", "git log": "git.read.log",
  "git diff": "git.read.diff", "git branch": "git.read.branch",
  "git show": "git.read.show", "git blame": "git.read.blame",
  "git add": "git.write.add", "git commit": "git.write.commit",
  "git push": "git.write.push", "git pull": "git.write.pull",
  "git merge": "git.write.merge", "git checkout": "git.write.checkout",
  "git rebase": "git.write.rebase", "git reset": "git.danger.reset",
  "git stash": "git.write.stash",
  mkdir: "shell.write.mkdir", touch: "shell.write.touch",
  cp: "shell.write.cp", mv: "shell.write.mv", tee: "shell.write.tee",
  rm: "shell.danger.rm", rmdir: "shell.danger.rmdir",
  chmod: "shell.danger.chmod", chown: "shell.danger.chown",
  kill: "shell.danger.kill", killall: "shell.danger.killall",
  sudo: "shell.admin.sudo", su: "shell.admin.su",
  apt: "shell.admin.apt", brew: "shell.admin.brew",
  pip: "shell.admin.pip", npm: "shell.admin.npm",
  docker: "shell.admin.docker", systemctl: "shell.admin.systemctl",
  reboot: "shell.admin.reboot", shutdown: "shell.admin.shutdown",
};

function classifyShellCommand(command) {
  const trimmed = command.trim();
  const sortedKeys = Object.keys(SHELL_COMMANDS).sort((a, b) => b.length - a.length);
  for (const prefix of sortedKeys) {
    if (trimmed === prefix || trimmed.startsWith(prefix + " ")) {
      return SHELL_COMMANDS[prefix];
    }
  }
  return "shell.unknown." + trimmed.split(/\s+/)[0];
}

// ─── Tool Handlers ───

const handlers = {
  // ── Shell ──
  async shell_run({ command }) {
    if (!command) return error("command is required");
    const toolName = classifyShellCommand(command);
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(command, {
        cwd: CWD, timeout: TIMEOUT, maxBuffer: 1024 * 1024,
        encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no output)", toolName);
    } catch (err) {
      return { content: [{ type: "text", text: `Command failed (exit ${err.status}):\n${err.stderr || err.message}\n\n[✓ ${toolName}]` }], isError: true };
    }
  },

  // ── File Read ──
  async file_read({ path: filePath }) {
    if (!filePath) return error("path is required");
    const resolved = resolve(filePath);
    if (!isPathAllowed(resolved)) return blocked("file.read", "Path outside allowed directories");

    const toolName = "file.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const content = readFileSync(resolved, "utf-8");
      return success(content, toolName);
    } catch (err) {
      return error(`Failed to read ${filePath}: ${err.message}`);
    }
  },

  // ── File Write ──
  async file_write({ path: filePath, content }) {
    if (!filePath) return error("path is required");
    if (content === undefined) return error("content is required");
    const resolved = resolve(filePath);
    if (!isPathAllowed(resolved)) return blocked("file.write", "Path outside allowed directories");

    const toolName = "file.write";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const dir = dirname(resolved);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(resolved, content, "utf-8");
      return success(`Written ${content.length} bytes to ${filePath}`, toolName);
    } catch (err) {
      return error(`Failed to write ${filePath}: ${err.message}`);
    }
  },

  // ── File Delete ──
  async file_delete({ path: filePath }) {
    if (!filePath) return error("path is required");
    const resolved = resolve(filePath);
    if (!isPathAllowed(resolved)) return blocked("file.delete", "Path outside allowed directories");

    const toolName = "file.delete";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      unlinkSync(resolved);
      return success(`Deleted ${filePath}`, toolName);
    } catch (err) {
      return error(`Failed to delete ${filePath}: ${err.message}`);
    }
  },

  // ── File List ──
  async file_list({ path: dirPath }) {
    const resolved = resolve(dirPath || CWD);
    if (!isPathAllowed(resolved)) return blocked("file.list", "Path outside allowed directories");

    const toolName = "file.list";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const entries = readdirSync(resolved).map((name) => {
        try {
          const s = statSync(resolve(resolved, name));
          return `${s.isDirectory() ? "d" : "-"} ${String(s.size).padStart(8)} ${name}`;
        } catch {
          return `? ${name}`;
        }
      });
      return success(entries.join("\n") || "(empty directory)", toolName);
    } catch (err) {
      return error(`Failed to list ${dirPath}: ${err.message}`);
    }
  },

  // ── File Info ──
  async file_info({ path: filePath }) {
    if (!filePath) return error("path is required");
    const resolved = resolve(filePath);
    if (!isPathAllowed(resolved)) return blocked("file.info", "Path outside allowed directories");

    const toolName = "file.info";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const s = statSync(resolved);
      const info = [
        `Path: ${resolved}`,
        `Type: ${s.isDirectory() ? "directory" : "file"}`,
        `Size: ${s.size} bytes`,
        `Modified: ${s.mtime.toISOString()}`,
        `Created: ${s.birthtime.toISOString()}`,
        `Permissions: ${(s.mode & 0o777).toString(8)}`,
      ].join("\n");
      return success(info, toolName);
    } catch (err) {
      return error(`Failed to stat ${filePath}: ${err.message}`);
    }
  },

  // ── DB Query ──
  async db_query({ query, database }) {
    if (!query) return error("query is required");

    // Classify the query by SQL statement type
    const upper = query.trim().toUpperCase();
    let toolName;
    if (upper.startsWith("SELECT") || upper.startsWith("SHOW") || upper.startsWith("DESCRIBE") || upper.startsWith("EXPLAIN")) {
      toolName = "db.read";
    } else if (upper.startsWith("INSERT")) {
      toolName = "db.write.insert";
    } else if (upper.startsWith("UPDATE")) {
      toolName = "db.write.update";
    } else if (upper.startsWith("DELETE")) {
      toolName = "db.danger.delete";
    } else if (upper.startsWith("DROP") || upper.startsWith("TRUNCATE") || upper.startsWith("ALTER")) {
      toolName = "db.danger.ddl";
    } else if (upper.startsWith("CREATE")) {
      toolName = "db.write.create";
    } else {
      toolName = "db.unknown";
    }

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    // Execute via shell (psql, mysql, sqlite3)
    const dbUrl = database || process.env.GUARD_DB_URL;
    if (!dbUrl) return error("No database configured. Set GUARD_DB_URL or pass database parameter.");

    try {
      let cmd;
      if (dbUrl.startsWith("postgresql://") || dbUrl.startsWith("postgres://")) {
        cmd = `psql "${dbUrl}" -c "${query.replace(/"/g, '\\"')}" --no-psqlrc -P pager=off`;
      } else if (dbUrl.startsWith("mysql://")) {
        cmd = `mysql --defaults-extra-file=/dev/null -e "${query.replace(/"/g, '\\"')}" "${dbUrl}"`;
      } else if (dbUrl.endsWith(".db") || dbUrl.endsWith(".sqlite") || dbUrl.endsWith(".sqlite3")) {
        cmd = `sqlite3 "${dbUrl}" "${query.replace(/"/g, '\\"')}"`;
      } else {
        return error("Unsupported database type. Use postgresql://, mysql://, or a .db/.sqlite file path.");
      }

      const output = execSync(cmd, {
        cwd: CWD, timeout: TIMEOUT, maxBuffer: 1024 * 1024,
        encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no results)", toolName);
    } catch (err) {
      return { content: [{ type: "text", text: `Query failed:\n${err.stderr || err.message}\n\n[✓ ${toolName}]` }], isError: true };
    }
  },

  // ── Git Operations ──
  async git_run({ command: gitCmd }) {
    if (!gitCmd) return error("command is required (e.g., 'status', 'log --oneline -5')");

    const fullCmd = `git ${gitCmd}`;
    const toolName = classifyShellCommand(fullCmd);

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(fullCmd, {
        cwd: CWD, timeout: TIMEOUT, maxBuffer: 1024 * 1024,
        encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no output)", toolName);
    } catch (err) {
      return { content: [{ type: "text", text: `Git failed:\n${err.stderr || err.message}\n\n[✓ ${toolName}]` }], isError: true };
    }
  },

  // ── HTTP Request ──
  async http_request({ url, method, headers: reqHeaders, body }) {
    if (!url) return error("url is required");

    const httpMethod = (method || "GET").toUpperCase();
    const toolName = `http.${httpMethod.toLowerCase()}`;

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const fetchOptions = {
        method: httpMethod,
        headers: { "User-Agent": "AgentsID-Guard/0.1.0", ...(reqHeaders || {}) },
      };
      if (body && httpMethod !== "GET") {
        fetchOptions.body = typeof body === "string" ? body : JSON.stringify(body);
        if (!fetchOptions.headers["Content-Type"]) {
          fetchOptions.headers["Content-Type"] = "application/json";
        }
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), TIMEOUT);
      fetchOptions.signal = controller.signal;

      const response = await fetch(url, fetchOptions);
      clearTimeout(timeoutId);

      const responseText = await response.text();
      const result = [
        `HTTP ${response.status} ${response.statusText}`,
        `URL: ${url}`,
        "",
        responseText.slice(0, 10000),
      ].join("\n");

      return success(result, toolName);
    } catch (err) {
      return error(`HTTP request failed: ${err.message}`);
    }
  },

  // ── Check Permission ──
  async check_permission({ tool: toolToCheck }) {
    if (!toolToCheck) return error("tool is required (e.g., 'shell.read.ls', 'file.write', 'db.danger.delete')");
    const v = await validate(toolToCheck);
    const status = v.allowed ? "ALLOWED ✓" : "BLOCKED ✗";
    return {
      content: [{ type: "text", text: `Tool: ${toolToCheck}\nStatus: ${status}\nReason: ${v.reason}` }],
    };
  },

  // ── List Categories ──
  async list_categories() {
    const categories = {
      "shell.read.*": "ls, cat, grep, find, ps, df, curl, ping — read-only system commands",
      "shell.write.*": "mkdir, touch, cp, mv — file creation and modification",
      "shell.danger.*": "rm, chmod, chown, kill — destructive operations",
      "shell.admin.*": "sudo, docker, apt, npm, systemctl — admin operations",
      "file.read": "Read file contents",
      "file.write": "Write/create files",
      "file.delete": "Delete files",
      "file.list": "List directory contents",
      "file.info": "Get file metadata",
      "db.read": "SELECT, SHOW, DESCRIBE, EXPLAIN queries",
      "db.write.*": "INSERT, UPDATE, CREATE statements",
      "db.danger.*": "DELETE, DROP, TRUNCATE, ALTER statements",
      "git.read.*": "git status, log, diff, branch, show, blame",
      "git.write.*": "git add, commit, push, pull, merge, checkout, stash",
      "git.danger.*": "git reset, force-push",
      "http.get": "HTTP GET requests",
      "http.post": "HTTP POST requests",
      "http.put": "HTTP PUT requests",
      "http.delete": "HTTP DELETE requests",
    };

    let output = "AgentsID Guard — Permission Categories:\n\n";
    for (const [pattern, desc] of Object.entries(categories)) {
      output += `  ${pattern.padEnd(20)} ${desc}\n`;
    }
    output += "\nSet permissions at agentsid.dev/dashboard or via the SDK.\n";
    output += 'Example: allow "shell.read.*" + "file.read" + "git.read.*" for a read-only agent.\n';
    return { content: [{ type: "text", text: output }] };
  },
};

// ─── Tool Definitions ───

const TOOLS = [
  {
    name: "shell_run",
    description: "Run a shell command. Validated against AgentsID permissions. Read commands (ls, cat, grep) typically allowed. Destructive commands (rm, chmod) blocked unless permitted.",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string", description: "The shell command to run" } },
      required: ["command"],
    },
  },
  {
    name: "file_read",
    description: "Read a file's contents. Restricted to allowed directories. Requires file.read permission.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Path to the file" } },
      required: ["path"],
    },
  },
  {
    name: "file_write",
    description: "Write content to a file. Creates parent directories if needed. Requires file.write permission.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the file" },
        content: { type: "string", description: "Content to write" },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "file_delete",
    description: "Delete a file. Requires file.delete permission.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Path to the file" } },
      required: ["path"],
    },
  },
  {
    name: "file_list",
    description: "List files in a directory with size and type info. Requires file.list permission.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Directory path (default: working directory)" } },
    },
  },
  {
    name: "file_info",
    description: "Get file metadata (size, type, permissions, timestamps). Requires file.info permission.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Path to the file" } },
      required: ["path"],
    },
  },
  {
    name: "db_query",
    description: "Run a SQL query. SELECT/SHOW requires db.read. INSERT/UPDATE requires db.write.*. DELETE/DROP requires db.danger.*. Supports PostgreSQL, MySQL, SQLite.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "SQL query to execute" },
        database: { type: "string", description: "Database URL (optional, uses GUARD_DB_URL env var if not provided)" },
      },
      required: ["query"],
    },
  },
  {
    name: "git_run",
    description: "Run a git command. Read operations (status, log, diff) require git.read.*. Write operations (commit, push) require git.write.*.",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string", description: "Git subcommand and arguments (e.g., 'status', 'log --oneline -5', 'push origin main')" } },
      required: ["command"],
    },
  },
  {
    name: "http_request",
    description: "Make an HTTP request. GET requires http.get. POST requires http.post. PUT requires http.put. DELETE requires http.delete.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to request" },
        method: { type: "string", description: "HTTP method (default: GET)", enum: ["GET", "POST", "PUT", "DELETE", "PATCH"] },
        headers: { type: "object", description: "Request headers" },
        body: { type: "string", description: "Request body (for POST/PUT/PATCH)" },
      },
      required: ["url"],
    },
  },
  {
    name: "check_permission",
    description: "Check if a tool/action would be allowed without executing it.",
    inputSchema: {
      type: "object",
      properties: { tool: { type: "string", description: "Tool name to check (e.g., 'shell.read.ls', 'file.write', 'db.danger.delete')" } },
      required: ["tool"],
    },
  },
  {
    name: "list_categories",
    description: "List all permission categories and what they control.",
    inputSchema: { type: "object", properties: {} },
  },
];

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
