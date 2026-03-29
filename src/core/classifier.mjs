/**
 * Command classifier — maps shell commands, SQL queries, and git operations
 * to AgentsID tool name patterns for permission evaluation.
 *
 * Classification is deterministic and operates on command prefixes.
 * Unknown commands map to *.unknown.* for deny-first enforcement.
 */

// ─── Shell Command Map ───
// Sorted by specificity: multi-word prefixes checked before single-word.

const SHELL_COMMANDS = Object.freeze({
  // Read-only (safe)
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

  // Git read
  "git status": "git.read.status", "git log": "git.read.log",
  "git diff": "git.read.diff", "git branch": "git.read.branch",
  "git show": "git.read.show", "git blame": "git.read.blame",

  // Git write
  "git add": "git.write.add", "git commit": "git.write.commit",
  "git push": "git.write.push", "git pull": "git.write.pull",
  "git merge": "git.write.merge", "git checkout": "git.write.checkout",
  "git rebase": "git.write.rebase", "git stash": "git.write.stash",

  // Git danger
  "git reset": "git.danger.reset",

  // Write operations
  mkdir: "shell.write.mkdir", touch: "shell.write.touch",
  cp: "shell.write.cp", mv: "shell.write.mv", tee: "shell.write.tee",

  // Destructive operations
  rm: "shell.danger.rm", rmdir: "shell.danger.rmdir",
  chmod: "shell.danger.chmod", chown: "shell.danger.chown",
  kill: "shell.danger.kill", killall: "shell.danger.killall",

  // Admin operations
  sudo: "shell.admin.sudo", su: "shell.admin.su",
  apt: "shell.admin.apt", brew: "shell.admin.brew",
  pip: "shell.admin.pip", npm: "shell.admin.npm",
  docker: "shell.admin.docker", systemctl: "shell.admin.systemctl",
  reboot: "shell.admin.reboot", shutdown: "shell.admin.shutdown",
});

// Pre-sorted keys for prefix matching (longest first)
const SORTED_PREFIXES = Object.keys(SHELL_COMMANDS).sort(
  (a, b) => b.length - a.length
);

/**
 * Classify a shell command into an AgentsID tool name.
 * @param {string} command — Raw shell command
 * @returns {string} AgentsID tool name
 */
export function classifyShellCommand(command) {
  const trimmed = command.trim();

  for (const prefix of SORTED_PREFIXES) {
    if (trimmed === prefix || trimmed.startsWith(prefix + " ")) {
      return SHELL_COMMANDS[prefix];
    }
  }

  // Unknown command — deny-first
  return "shell.unknown." + trimmed.split(/\s+/)[0];
}

/**
 * Classify a SQL query into an AgentsID tool name.
 * @param {string} query — SQL query string
 * @returns {string} AgentsID tool name
 */
export function classifySqlQuery(query) {
  const upper = query.trim().toUpperCase();

  if (upper.startsWith("SELECT") || upper.startsWith("SHOW") ||
      upper.startsWith("DESCRIBE") || upper.startsWith("EXPLAIN")) {
    return "db.read";
  }
  if (upper.startsWith("INSERT")) return "db.write.insert";
  if (upper.startsWith("UPDATE")) return "db.write.update";
  if (upper.startsWith("CREATE")) return "db.write.create";
  if (upper.startsWith("DELETE")) return "db.danger.delete";
  if (upper.startsWith("DROP") || upper.startsWith("TRUNCATE") ||
      upper.startsWith("ALTER")) {
    return "db.danger.ddl";
  }

  return "db.unknown";
}

/**
 * Classify an AWS CLI command into an AgentsID tool name.
 * @param {string} command — AWS CLI command (e.g., "s3 ls", "ec2 terminate-instances")
 * @returns {string} AgentsID tool name
 */
export function classifyAwsCommand(command) {
  const parts = command.trim().split(/\s+/);
  const service = parts[0] || "unknown";
  const action = parts[1] || "unknown";

  const readActions = ["ls", "list", "describe", "get", "head", "show"];
  const dangerActions = ["delete", "terminate", "remove", "destroy", "deregister", "purge"];

  if (readActions.some((a) => action.startsWith(a))) return `aws.read.${service}`;
  if (dangerActions.some((a) => action.startsWith(a))) return `aws.danger.${service}`;
  return `aws.write.${service}`;
}

/**
 * Classify a kubectl command into an AgentsID tool name.
 * @param {string} command — kubectl command (e.g., "get pods", "delete deployment")
 * @returns {string} AgentsID tool name
 */
export function classifyKubectlCommand(command) {
  const action = command.trim().split(/\s+/)[0] || "unknown";

  const readActions = ["get", "describe", "logs", "top", "explain", "api-resources", "cluster-info"];
  const dangerActions = ["delete", "drain", "cordon", "taint"];

  if (readActions.includes(action)) return `k8s.read.${action}`;
  if (dangerActions.includes(action)) return `k8s.danger.${action}`;
  return `k8s.write.${action}`;
}

/**
 * Classify an environment variable access by sensitivity.
 * @param {string} name — Environment variable name
 * @returns {string} AgentsID tool name
 */
export function classifyEnvAccess(name) {
  if (name.match(/KEY|SECRET|TOKEN|PASSWORD|PASS|CRED|AUTH/i)) {
    return "env.read.secret";
  }
  return "env.read";
}
