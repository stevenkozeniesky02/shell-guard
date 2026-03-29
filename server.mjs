#!/usr/bin/env node

/**
 * Shell Guard — MCP server for safe shell access.
 *
 * Every command is validated against AgentsID permission rules before execution.
 * Agents can run `ls` and `cat` but can't run `rm` or `sudo` unless explicitly allowed.
 *
 * Usage:
 *   claude mcp add shell-guard -- npx @agentsid/shell-guard
 *
 * Environment:
 *   AGENTSID_PROJECT_KEY  — Your AgentsID project key (required)
 *   AGENTSID_AGENT_TOKEN  — Agent token for permission checks (required)
 *   SHELL_GUARD_CWD       — Working directory for commands (default: process.cwd())
 *   SHELL_GUARD_TIMEOUT   — Command timeout in ms (default: 30000)
 */

import { execSync } from "child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const PROJECT_KEY = process.env.AGENTSID_PROJECT_KEY || "";
const AGENT_TOKEN = process.env.AGENTSID_AGENT_TOKEN || "";
const BASE_URL = process.env.AGENTSID_BASE_URL || "https://agentsid.dev";
const CWD = process.env.SHELL_GUARD_CWD || process.cwd();
const TIMEOUT = parseInt(process.env.SHELL_GUARD_TIMEOUT || "30000", 10);

// ─── Command Categories ───
// These map command prefixes to AgentsID tool names for permission checks.
// "shell.read.ls" is a different permission than "shell.write.rm"

const COMMAND_MAP = {
  // Read-only (safe)
  ls: "shell.read.ls",
  cat: "shell.read.cat",
  head: "shell.read.head",
  tail: "shell.read.tail",
  find: "shell.read.find",
  grep: "shell.read.grep",
  wc: "shell.read.wc",
  du: "shell.read.du",
  df: "shell.read.df",
  pwd: "shell.read.pwd",
  whoami: "shell.read.whoami",
  date: "shell.read.date",
  uname: "shell.read.uname",
  env: "shell.read.env",
  echo: "shell.read.echo",
  which: "shell.read.which",
  file: "shell.read.file",
  stat: "shell.read.stat",
  diff: "shell.read.diff",
  sort: "shell.read.sort",
  uniq: "shell.read.uniq",
  tr: "shell.read.tr",
  cut: "shell.read.cut",
  awk: "shell.read.awk",
  sed: "shell.read.sed",
  jq: "shell.read.jq",
  curl: "shell.read.curl",
  wget: "shell.read.wget",
  ping: "shell.read.ping",
  dig: "shell.read.dig",
  nslookup: "shell.read.nslookup",
  ps: "shell.read.ps",
  top: "shell.read.top",
  uptime: "shell.read.uptime",
  free: "shell.read.free",

  // Git read
  "git status": "shell.git.status",
  "git log": "shell.git.log",
  "git diff": "shell.git.diff",
  "git branch": "shell.git.branch",
  "git show": "shell.git.show",
  "git blame": "shell.git.blame",

  // Git write
  "git add": "shell.git.add",
  "git commit": "shell.git.commit",
  "git push": "shell.git.push",
  "git pull": "shell.git.pull",
  "git merge": "shell.git.merge",
  "git checkout": "shell.git.checkout",
  "git rebase": "shell.git.rebase",
  "git reset": "shell.git.reset",
  "git stash": "shell.git.stash",

  // Write operations
  mkdir: "shell.write.mkdir",
  touch: "shell.write.touch",
  cp: "shell.write.cp",
  mv: "shell.write.mv",
  tee: "shell.write.tee",

  // Destructive operations
  rm: "shell.danger.rm",
  rmdir: "shell.danger.rmdir",
  chmod: "shell.danger.chmod",
  chown: "shell.danger.chown",
  kill: "shell.danger.kill",
  killall: "shell.danger.killall",
  pkill: "shell.danger.pkill",

  // Admin operations
  sudo: "shell.admin.sudo",
  su: "shell.admin.su",
  apt: "shell.admin.apt",
  brew: "shell.admin.brew",
  pip: "shell.admin.pip",
  npm: "shell.admin.npm",
  docker: "shell.admin.docker",
  systemctl: "shell.admin.systemctl",
  service: "shell.admin.service",
  reboot: "shell.admin.reboot",
  shutdown: "shell.admin.shutdown",
};

// ─── Classify a command ───

function classifyCommand(command) {
  const trimmed = command.trim();

  // Check multi-word matches first (e.g., "git push" before "git")
  const sortedKeys = Object.keys(COMMAND_MAP).sort(
    (a, b) => b.length - a.length
  );

  for (const prefix of sortedKeys) {
    if (trimmed === prefix || trimmed.startsWith(prefix + " ")) {
      return COMMAND_MAP[prefix];
    }
  }

  // Unknown command — maps to shell.unknown for deny-first
  return "shell.unknown." + trimmed.split(/\s+/)[0];
}

// ─── Validate against AgentsID ───

async function validateCommand(command) {
  const toolName = classifyCommand(command);

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
      body: JSON.stringify({
        token: AGENT_TOKEN,
        tool: toolName,
      }),
    });

    const result = await response.json();

    return {
      allowed: result.valid && result.permission?.allowed,
      tool: toolName,
      reason: result.permission?.reason || result.reason || "Unknown",
    };
  } catch (err) {
    // Fail closed — deny on network error
    return {
      allowed: false,
      tool: toolName,
      reason: `AgentsID validation failed: ${err.message}`,
    };
  }
}

// ─── Execute command safely ───

function executeCommand(command) {
  try {
    const output = execSync(command, {
      cwd: CWD,
      timeout: TIMEOUT,
      maxBuffer: 1024 * 1024, // 1MB
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { success: true, output: output || "(no output)" };
  } catch (err) {
    return {
      success: false,
      output: err.stderr || err.message || "Command failed",
      exitCode: err.status,
    };
  }
}

// ─── MCP Server ───

const server = new Server(
  {
    name: "shell-guard",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "run_command",
      description:
        "Run a shell command. Every command is validated against AgentsID permission rules before execution. Read commands (ls, cat, grep) are typically allowed. Destructive commands (rm, chmod) are blocked unless explicitly permitted.",
      inputSchema: {
        type: "object",
        properties: {
          command: {
            type: "string",
            description: "The shell command to run",
          },
        },
        required: ["command"],
      },
    },
    {
      name: "check_permission",
      description:
        "Check if a command would be allowed without running it. Returns the permission classification and whether it would be allowed or denied.",
      inputSchema: {
        type: "object",
        properties: {
          command: {
            type: "string",
            description: "The shell command to check",
          },
        },
        required: ["command"],
      },
    },
    {
      name: "list_categories",
      description:
        "List all command categories and their AgentsID tool names. Useful for understanding what permission rules to set.",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
  ],
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "list_categories") {
    const categories = {};
    for (const [cmd, tool] of Object.entries(COMMAND_MAP)) {
      const category = tool.split(".").slice(0, 2).join(".");
      if (!categories[category]) categories[category] = [];
      categories[category].push(`${cmd} → ${tool}`);
    }

    let output = "Shell Guard Command Categories:\n\n";
    for (const [cat, cmds] of Object.entries(categories).sort()) {
      output += `${cat}:\n`;
      for (const cmd of cmds) {
        output += `  ${cmd}\n`;
      }
      output += "\n";
    }

    output +=
      "\nPermission rules use AgentsID tool names.\n";
    output +=
      'Example: allow "shell.read.*" to permit all read commands.\n';
    output +=
      'Example: deny "shell.danger.*" to block all destructive commands.\n';

    return { content: [{ type: "text", text: output }] };
  }

  if (name === "check_permission") {
    const command = args?.command;
    if (!command) {
      return {
        content: [{ type: "text", text: "Error: command is required" }],
        isError: true,
      };
    }

    const validation = await validateCommand(command);
    const status = validation.allowed ? "ALLOWED ✓" : "BLOCKED ✗";

    return {
      content: [
        {
          type: "text",
          text: `Command: ${command}\nClassified as: ${validation.tool}\nStatus: ${status}\nReason: ${validation.reason}`,
        },
      ],
    };
  }

  if (name === "run_command") {
    const command = args?.command;
    if (!command) {
      return {
        content: [{ type: "text", text: "Error: command is required" }],
        isError: true,
      };
    }

    // Validate against AgentsID
    const validation = await validateCommand(command);

    if (!validation.allowed) {
      return {
        content: [
          {
            type: "text",
            text: `BLOCKED by Shell Guard\n\nCommand: ${command}\nClassified as: ${validation.tool}\nReason: ${validation.reason}\n\nThis command was denied by AgentsID permission rules. The denial has been logged to the audit trail.`,
          },
        ],
        isError: true,
      };
    }

    // Permission granted — execute
    const result = executeCommand(command);

    if (result.success) {
      return {
        content: [
          {
            type: "text",
            text: `${result.output}\n\n[✓ Allowed: ${validation.tool}]`,
          },
        ],
      };
    } else {
      return {
        content: [
          {
            type: "text",
            text: `Command failed (exit ${result.exitCode}):\n${result.output}\n\n[✓ Allowed: ${validation.tool}]`,
          },
        ],
        isError: true,
      };
    }
  }

  return {
    content: [{ type: "text", text: `Unknown tool: ${name}` }],
    isError: true,
  };
});

// ─── Start ───

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Shell Guard MCP server running (AgentsID protected)");
}

main().catch((err) => {
  console.error("Failed to start Shell Guard:", err);
  process.exit(1);
});
