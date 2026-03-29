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

  // ── Environment / Secrets ──
  async env_list() {
    const toolName = "env.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const safe = Object.entries(process.env)
      .filter(([k]) => !k.match(/KEY|SECRET|TOKEN|PASSWORD|PASS|CRED|AUTH/i))
      .map(([k, val]) => `${k}=${val}`)
      .sort()
      .join("\n");
    return success(safe || "(no environment variables)", toolName);
  },

  async env_get({ name }) {
    if (!name) return error("name is required");
    const toolName = name.match(/KEY|SECRET|TOKEN|PASSWORD|PASS|CRED|AUTH/i)
      ? "env.read.secret"
      : "env.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const val = process.env[name];
    if (val === undefined) return success(`${name} is not set`, toolName);
    return success(`${name}=${val}`, toolName);
  },

  async env_set({ name, value }) {
    if (!name) return error("name is required");
    if (value === undefined) return error("value is required");
    const toolName = "env.write";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    process.env[name] = value;
    return success(`Set ${name}=${value}`, toolName);
  },

  // ── Process Management ──
  async process_list() {
    const toolName = "process.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync("ps aux --sort=-%cpu | head -20", {
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      // macOS ps doesn't support --sort
      try {
        const output = execSync("ps aux | head -20", {
          encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
        });
        return success(output, toolName);
      } catch (e) {
        return error(`Failed to list processes: ${e.message}`);
      }
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

  async process_info({ pid }) {
    if (!pid) return error("pid is required");
    const toolName = "process.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`ps -p ${parseInt(pid, 10)} -o pid,ppid,user,%cpu,%mem,stat,start,command`, {
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`Process ${pid} not found or inaccessible`);
    }
  },

  // ── Cron / Scheduling ──
  async cron_list() {
    const toolName = "cron.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync("crontab -l 2>/dev/null || echo '(no crontab)'", {
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
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
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
      }).trim();
      const newEntry = `${schedule} ${command}`;
      const updated = existing ? `${existing}\n${newEntry}` : newEntry;
      execSync(`echo "${updated.replace(/"/g, '\\"')}" | crontab -`, {
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
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
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(`Removed cron entries matching: ${pattern}`, toolName);
    } catch (err) {
      return error(`Failed to remove cron job: ${err.stderr || err.message}`);
    }
  },

  // ── Container Management ──
  async container_list({ all }) {
    const toolName = "container.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const flag = all ? "-a" : "";
    try {
      const output = execSync(`docker ps ${flag} --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}"`, {
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
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
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
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
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
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
      execSync(`docker start ${id}`, { encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"] });
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
      execSync(`docker stop ${id}`, { encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"] });
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
      execSync(`docker rm${forceFlag} ${id}`, { encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"] });
      return success(`Removed container ${id}`, toolName);
    } catch (err) {
      return error(`Failed to remove ${id}: ${err.message}`);
    }
  },

  // ── Network Diagnostics ──
  async network_ping({ host, count }) {
    if (!host) return error("host is required");
    const toolName = "network.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const c = count ? parseInt(count, 10) : 4;
    try {
      const output = execSync(`ping -c ${c} ${host}`, {
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
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
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
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
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no records)", toolName);
    } catch (err) {
      return error(`DNS lookup failed: ${err.message}`);
    }
  },

  // ── System Info ──
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

  // ── Log Management ──
  async log_read({ path: logPath, lines }) {
    if (!logPath) return error("path is required");
    const resolved = resolve(logPath);
    const n = lines ? parseInt(lines, 10) : 100;
    const toolName = "log.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`tail -n ${n} "${resolved}"`, {
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
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
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no matches)", toolName);
    } catch (err) {
      if (err.status === 1) return success("(no matches)", toolName);
      return error(`Log search failed: ${err.message}`);
    }
  },

  // ── SSH / Remote ──
  async ssh_run({ host, command: sshCmd, user, port }) {
    if (!host) return error("host is required");
    if (!sshCmd) return error("command is required");
    const sshUser = user || "root";
    const sshPort = port || "22";
    const toolName = `ssh.${host.replace(/[^a-zA-Z0-9]/g, "_")}`;
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(
        `ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${sshPort} ${sshUser}@${host} "${sshCmd.replace(/"/g, '\\"')}"`,
        { encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"] }
      );
      return success(`[${sshUser}@${host}] ${output}`, toolName);
    } catch (err) {
      return error(`SSH to ${host} failed: ${err.stderr || err.message}`);
    }
  },

  // ── Package Management ──
  async package_list({ manager }) {
    const toolName = "package.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const mgr = manager || "auto";
    let cmd;
    if (mgr === "npm" || mgr === "auto") { try { cmd = "npm list -g --depth=0 2>/dev/null"; } catch {} }
    if (mgr === "pip" || (!cmd && mgr === "auto")) { cmd = "pip list 2>/dev/null || pip3 list 2>/dev/null"; }
    if (mgr === "brew" || (!cmd && mgr === "auto")) { cmd = "brew list 2>/dev/null"; }
    if (mgr === "apt") { cmd = "dpkg -l 2>/dev/null | tail -20"; }
    if (!cmd) cmd = "echo 'No package manager detected'";

    try {
      const output = execSync(cmd, { encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"] });
      return success(output, toolName);
    } catch (err) {
      return error(`Package list failed: ${err.message}`);
    }
  },

  async package_info({ name: pkgName, manager }) {
    if (!pkgName) return error("name is required");
    const toolName = "package.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const mgr = manager || "npm";
    let cmd;
    if (mgr === "npm") cmd = `npm view ${pkgName} 2>/dev/null`;
    else if (mgr === "pip") cmd = `pip show ${pkgName} 2>/dev/null || pip3 show ${pkgName}`;
    else if (mgr === "brew") cmd = `brew info ${pkgName} 2>/dev/null`;
    else if (mgr === "apt") cmd = `apt show ${pkgName} 2>/dev/null`;
    else cmd = `echo 'Unsupported manager: ${mgr}'`;

    try {
      const output = execSync(cmd, { encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"] });
      return success(output || `(${pkgName} not found)`, toolName);
    } catch (err) {
      return error(`Package info failed: ${err.message}`);
    }
  },

  async package_install({ name: pkgName, manager }) {
    if (!pkgName) return error("name is required");
    const toolName = "package.danger.install";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const mgr = manager || "npm";
    let cmd;
    if (mgr === "npm") cmd = `npm install -g ${pkgName}`;
    else if (mgr === "pip") cmd = `pip install ${pkgName}`;
    else if (mgr === "brew") cmd = `brew install ${pkgName}`;
    else if (mgr === "apt") cmd = `sudo apt install -y ${pkgName}`;
    else return error(`Unsupported manager: ${mgr}`);

    try {
      const output = execSync(cmd, { encoding: "utf-8", timeout: 120000, stdio: ["pipe", "pipe", "pipe"] });
      return success(`Installed ${pkgName}:\n${output}`, toolName);
    } catch (err) {
      return error(`Install failed: ${err.stderr || err.message}`);
    }
  },

  // ── Cloud CLI (AWS) ──
  async aws_run({ command: awsCmd }) {
    if (!awsCmd) return error("command is required (e.g., 's3 ls', 'ec2 describe-instances')");

    const upper = awsCmd.trim().split(/\s+/);
    const service = upper[0] || "unknown";
    const action = upper[1] || "unknown";

    // Classify by risk
    let toolName;
    const readActions = ["ls", "list", "describe", "get", "head", "show"];
    const dangerActions = ["delete", "terminate", "remove", "destroy", "deregister", "purge"];
    if (readActions.some((a) => action.startsWith(a))) {
      toolName = `aws.read.${service}`;
    } else if (dangerActions.some((a) => action.startsWith(a))) {
      toolName = `aws.danger.${service}`;
    } else {
      toolName = `aws.write.${service}`;
    }

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`aws ${awsCmd}`, {
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`AWS CLI failed: ${err.stderr || err.message}`);
    }
  },

  // ── Kubectl ──
  async kubectl_run({ command: kubectlCmd }) {
    if (!kubectlCmd) return error("command is required (e.g., 'get pods', 'logs my-pod')");

    const parts = kubectlCmd.trim().split(/\s+/);
    const action = parts[0] || "unknown";

    let toolName;
    const readActions = ["get", "describe", "logs", "top", "explain", "api-resources", "cluster-info"];
    const dangerActions = ["delete", "drain", "cordon", "taint"];
    if (readActions.includes(action)) {
      toolName = `k8s.read.${action}`;
    } else if (dangerActions.includes(action)) {
      toolName = `k8s.danger.${action}`;
    } else {
      toolName = `k8s.write.${action}`;
    }

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`kubectl ${kubectlCmd}`, {
        encoding: "utf-8", timeout: TIMEOUT, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`kubectl failed: ${err.stderr || err.message}`);
    }
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
      "env.read": "Read non-secret environment variables",
      "env.read.secret": "Read secret environment variables (KEY, TOKEN, PASSWORD, etc.)",
      "env.write": "Set environment variables",
      "process.read": "List processes, get process info",
      "process.kill": "Kill processes by PID",
      "cron.read": "List cron jobs",
      "cron.write": "Add cron jobs",
      "cron.danger": "Remove cron jobs",
      "container.read": "List, inspect, view logs of Docker containers",
      "container.write": "Start/stop Docker containers",
      "container.danger": "Remove Docker containers",
      "network.read": "Ping, traceroute, DNS lookup, list ports",
      "system.read": "System info, disk usage, memory usage, uptime",
      "log.read": "Read and search log files",
      "ssh.*": "SSH commands scoped per host (ssh.hostname)",
      "package.read": "List packages, get package info",
      "package.danger.*": "Install/update packages",
      "aws.read.*": "AWS CLI read operations (ls, describe, get) per service",
      "aws.write.*": "AWS CLI write operations per service",
      "aws.danger.*": "AWS CLI destructive operations (delete, terminate) per service",
      "k8s.read.*": "kubectl read operations (get, describe, logs)",
      "k8s.write.*": "kubectl write operations (apply, create, scale)",
      "k8s.danger.*": "kubectl destructive operations (delete, drain)",
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
  // ── Environment ──
  {
    name: "env_list",
    description: "List environment variables (secrets auto-filtered). Requires env.read permission.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "env_get",
    description: "Get a specific environment variable. Secret-named vars (KEY, TOKEN, PASSWORD) require env.read.secret permission.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", description: "Environment variable name" } },
      required: ["name"],
    },
  },
  {
    name: "env_set",
    description: "Set an environment variable. Requires env.write permission.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Variable name" },
        value: { type: "string", description: "Variable value" },
      },
      required: ["name", "value"],
    },
  },
  // ── Process ──
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
  // ── Cron ──
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
  // ── Container ──
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
  // ── Network ──
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
  // ── System ──
  { name: "system_info", description: "Get system overview: OS, CPU, memory, disk, uptime. Requires system.read.", inputSchema: { type: "object", properties: {} } },
  { name: "disk_usage", description: "Get disk usage for a path. Requires system.read.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Mount point or path (default: /)" } } } },
  { name: "memory_usage", description: "Get memory usage breakdown. Requires system.read.", inputSchema: { type: "object", properties: {} } },
  // ── Logs ──
  { name: "log_read", description: "Read last N lines of a log file. Requires log.read.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to log file" }, lines: { type: "string", description: "Number of lines (default: 100)" } }, required: ["path"] } },
  { name: "log_search", description: "Search a log file for a pattern. Requires log.read.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to log file" }, pattern: { type: "string", description: "Search pattern (case-insensitive)" }, lines: { type: "string", description: "Max results (default: 50)" } }, required: ["path", "pattern"] } },
  // ── SSH ──
  { name: "ssh_run", description: "Run a command on a remote host via SSH. Permission scoped per host (ssh.hostname). Requires SSH keys configured.", inputSchema: { type: "object", properties: { host: { type: "string", description: "Remote hostname or IP" }, command: { type: "string", description: "Command to execute" }, user: { type: "string", description: "SSH user (default: root)" }, port: { type: "string", description: "SSH port (default: 22)" } }, required: ["host", "command"] } },
  // ── Packages ──
  { name: "package_list", description: "List installed packages. Requires package.read.", inputSchema: { type: "object", properties: { manager: { type: "string", description: "Package manager", enum: ["npm", "pip", "brew", "apt", "auto"] } } } },
  { name: "package_info", description: "Get info about a package. Requires package.read.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Package name" }, manager: { type: "string", description: "Package manager", enum: ["npm", "pip", "brew", "apt"] } }, required: ["name"] } },
  { name: "package_install", description: "Install a package. Requires package.danger.install (high risk).", inputSchema: { type: "object", properties: { name: { type: "string", description: "Package name" }, manager: { type: "string", description: "Package manager", enum: ["npm", "pip", "brew", "apt"] } }, required: ["name"] } },
  // ── AWS ──
  { name: "aws_run", description: "Run an AWS CLI command. Read ops (ls, describe) require aws.read.{service}. Write ops require aws.write.{service}. Destructive ops (delete, terminate) require aws.danger.{service}.", inputSchema: { type: "object", properties: { command: { type: "string", description: "AWS CLI command (e.g., 's3 ls', 'ec2 describe-instances')" } }, required: ["command"] } },
  // ── Kubernetes ──
  { name: "kubectl_run", description: "Run a kubectl command. Read ops (get, describe, logs) require k8s.read.*. Write ops (apply, create) require k8s.write.*. Destructive ops (delete, drain) require k8s.danger.*.", inputSchema: { type: "object", properties: { command: { type: "string", description: "kubectl command (e.g., 'get pods', 'logs my-pod -f', 'apply -f deploy.yaml')" } }, required: ["command"] } },
  // ── Utility ──
  {
    name: "check_permission",
    description: "Check if a tool/action would be allowed without executing it.",
    inputSchema: {
      type: "object",
      properties: { tool: { type: "string", description: "Tool name to check (e.g., 'shell.read.ls', 'file.write', 'container.danger')" } },
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
