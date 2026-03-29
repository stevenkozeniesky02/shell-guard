<p align="center">
  <h1 align="center">AgentsID Guard</h1>
  <p align="center">
    <strong>One MCP server. Every operation protected.</strong>
  </p>
</p>

<p align="center">
  <a href="https://agentsid.dev"><img src="https://img.shields.io/badge/powered%20by-AgentsID-f59e0b?style=flat-square" alt="AgentsID" /></a>
  <a href="https://github.com/stevenkozeniesky02/shell-guard/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-f59e0b?style=flat-square" alt="License" /></a>
</p>

---

Your AI agent has access to your shell, file system, database, git repos, and the internet. Right now, nothing controls what it can do with any of them.

**AgentsID Guard fixes that.** 11 tools across 5 categories — shell, files, database, git, HTTP — every operation validated against per-agent permission rules before execution.

## How It Works

```
Agent: shell_run("ls -la /src")
  → Classified: shell.read.ls
  → AgentsID: ALLOWED ✓
  → Executes normally

Agent: shell_run("rm -rf /data")
  → Classified: shell.danger.rm
  → AgentsID: BLOCKED ✗
  → Never executes

Agent: db_query("DROP TABLE users")
  → Classified: db.danger.ddl
  → AgentsID: BLOCKED ✗
  → Never executes

Agent: git_run("push origin main")
  → Classified: git.write.push
  → AgentsID: BLOCKED ✗
  → Never executes
```

## Quick Start

### 1. Install

```bash
npx @agentsid/guard
```

### 2. Get your keys

Sign up at [agentsid.dev/dashboard](https://agentsid.dev/dashboard) — free tier: 25 agents, 10K events/month.

### 3. Add to Claude Code

```bash
claude mcp add guard \
  -e AGENTSID_PROJECT_KEY=aid_proj_your_key \
  -e AGENTSID_AGENT_TOKEN=aid_tok_your_token \
  -- npx @agentsid/guard
```

### 4. Set permissions

```bash
npx agentsid register-agent --name "my-agent" \
  --permissions "shell.read.*" "file.read" "file.list" "git.read.*" "http.get"
```

## Tools

AgentsID Guard exposes 11 MCP tools:

| Tool | What it does | Permission pattern |
|------|-------------|-------------------|
| `shell_run` | Execute a shell command | `shell.read.*`, `shell.write.*`, `shell.danger.*`, `shell.admin.*` |
| `file_read` | Read a file | `file.read` |
| `file_write` | Write/create a file | `file.write` |
| `file_delete` | Delete a file | `file.delete` |
| `file_list` | List directory contents | `file.list` |
| `file_info` | Get file metadata | `file.info` |
| `db_query` | Run a SQL query | `db.read`, `db.write.*`, `db.danger.*` |
| `git_run` | Run a git command | `git.read.*`, `git.write.*`, `git.danger.*` |
| `http_request` | Make an HTTP request | `http.get`, `http.post`, `http.put`, `http.delete` |
| `check_permission` | Check if an action would be allowed | — |
| `list_categories` | List all permission categories | — |

## Permission Categories

### Shell

| Pattern | Commands | Risk |
|---------|----------|------|
| `shell.read.*` | ls, cat, grep, find, ps, df, curl, ping | Safe |
| `shell.write.*` | mkdir, touch, cp, mv | Moderate |
| `shell.danger.*` | rm, chmod, chown, kill | High |
| `shell.admin.*` | sudo, docker, apt, npm, systemctl | Critical |

### Files

| Pattern | Operations | Risk |
|---------|-----------|------|
| `file.read` | Read file contents | Safe |
| `file.list` | List directories | Safe |
| `file.info` | File metadata | Safe |
| `file.write` | Create/write files | Moderate |
| `file.delete` | Delete files | High |

### Database

| Pattern | Statements | Risk |
|---------|-----------|------|
| `db.read` | SELECT, SHOW, DESCRIBE, EXPLAIN | Safe |
| `db.write.insert` | INSERT | Moderate |
| `db.write.update` | UPDATE | Moderate |
| `db.write.create` | CREATE | Moderate |
| `db.danger.delete` | DELETE | High |
| `db.danger.ddl` | DROP, TRUNCATE, ALTER | Critical |

### Git

| Pattern | Commands | Risk |
|---------|----------|------|
| `git.read.*` | status, log, diff, branch, show, blame | Safe |
| `git.write.*` | add, commit, push, pull, merge, checkout, stash | Moderate |
| `git.danger.*` | reset, force-push | Critical |

### HTTP

| Pattern | Methods | Risk |
|---------|---------|------|
| `http.get` | GET | Safe |
| `http.post` | POST | Moderate |
| `http.put` | PUT | Moderate |
| `http.delete` | DELETE | High |

## Permission Examples

**Read-only research agent:**
```
shell.read.*    → allow
file.read       → allow
file.list       → allow
db.read         → allow
git.read.*      → allow
http.get        → allow
```

**Developer agent (read + write, no destructive):**
```
shell.read.*    → allow
shell.write.*   → allow
file.read       → allow
file.write      → allow
file.list       → allow
db.read         → allow
db.write.*      → allow
git.read.*      → allow
git.write.*     → allow
http.get        → allow
http.post       → allow
```

**Full access with approval gates:**
```
shell.read.*    → allow
shell.write.*   → allow
shell.danger.*  → allow (requires approval)
shell.admin.*   → allow (requires approval)
file.*          → allow
db.read         → allow
db.write.*      → allow
db.danger.*     → allow (requires approval)
git.*           → allow
http.*          → allow
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTSID_PROJECT_KEY` | Yes | Your AgentsID project key |
| `AGENTSID_AGENT_TOKEN` | Yes | Agent token for permission checks |
| `AGENTSID_BASE_URL` | No | API URL (default: https://agentsid.dev) |
| `GUARD_CWD` | No | Working directory (default: cwd) |
| `GUARD_TIMEOUT` | No | Command timeout in ms (default: 30000) |
| `GUARD_ALLOWED_DIRS` | No | Comma-separated allowed directories for file ops (default: cwd) |
| `GUARD_DB_URL` | No | Database connection string for db_query (postgresql://, mysql://, or .db path) |

## Security

- **Deny-first** — unknown commands and tools are blocked by default
- **Path containment** — file operations restricted to allowed directories
- **Fail-closed** — network errors to AgentsID result in denial, not bypass
- **Audit trail** — every allow and deny logged to AgentsID's tamper-evident hash chain
- **No shell injection** — commands executed via `execSync` with no shell interpolation of user input in tool arguments

## Dashboard

Every operation appears in your [AgentsID dashboard](https://agentsid.dev/dashboard):

- Which agent ran which command
- Whether it was allowed or denied and why
- Full audit trail across all 5 categories

## Links

- [AgentsID](https://agentsid.dev) — Identity & auth for AI agents
- [Documentation](https://agentsid.dev/docs)
- [Dashboard](https://agentsid.dev/dashboard)

## License

MIT
