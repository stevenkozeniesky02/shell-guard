import { validate, error } from "../core/validator.mjs";

export const handlers = {
  async check_permission({ tool: toolToCheck }) {
    if (!toolToCheck) return error("tool is required (e.g., 'shell.read.ls', 'file.write', 'db.danger.delete')");
    const v = await validate(toolToCheck);
    const status = v.allowed ? "ALLOWED ✓" : "BLOCKED ✗";
    return {
      content: [{ type: "text", text: `Tool: ${toolToCheck}\nStatus: ${status}\nReason: ${v.reason}` }],
    };
  },

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
      "secrets.read": "List secrets, view audit log, check anomalies (values never exposed)",
      "secrets.write": "Store secrets, set scope, set expiry",
      "secrets.proxy": "Make HTTP calls with secrets injected server-side (agent never sees values)",
      "secrets.danger": "Delete secrets from vault",
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

export const tools = [
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
