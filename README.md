<p align="center">
  <h1 align="center">Shell Guard</h1>
  <p align="center">
    <strong>MCP server for safe shell access. Every command validated before execution.</strong>
  </p>
</p>

<p align="center">
  <a href="https://agentsid.dev"><img src="https://img.shields.io/badge/powered%20by-AgentsID-7c5bf0?style=flat-square" alt="AgentsID" /></a>
  <a href="https://github.com/stevenkozeniesky02/shell-guard/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-7c5bf0?style=flat-square" alt="License" /></a>
</p>

---

Your AI agent has shell access. It can run `ls` and `cat`. It can also run `rm -rf /` and `sudo shutdown now`. There's nothing stopping it.

**Shell Guard fixes that.** Every command is classified and validated against per-agent permission rules before execution. Read commands go through. Destructive commands get blocked. Everything is logged.

## How It Works

```
Agent runs: ls -la /src
  → Classified as: shell.read.ls
  → AgentsID check: ALLOWED ✓
  → Command executes normally

Agent runs: rm -rf /important-data
  → Classified as: shell.danger.rm
  → AgentsID check: BLOCKED ✗
  → Command never executes
  → Denial logged to audit trail
```

## Quick Start

### 1. Install

```bash
npx @agentsid/shell-guard
```

### 2. Get your keys

Sign up at [agentsid.dev/dashboard](https://agentsid.dev/dashboard) (free — 25 agents, 10K events/month).

Register an agent with shell permissions:

```bash
npx agentsid init
npx agentsid register-agent --name "my-shell-agent" \
  --permissions "shell.read.*" "shell.git.status" "shell.git.log" "shell.git.diff"
```

### 3. Add to Claude Code

```bash
claude mcp add shell-guard \
  -e AGENTSID_PROJECT_KEY=aid_proj_your_key \
  -e AGENTSID_AGENT_TOKEN=aid_tok_your_token \
  -- npx @agentsid/shell-guard
```

### 4. Your agent is now protected

```
You: "list the files in /src"
Claude: *runs ls /src* → works normally

You: "delete the temp files"
Claude: *runs rm -rf /tmp* → BLOCKED by Shell Guard

You: "push to main"
Claude: *runs git push origin main* → BLOCKED (not in permissions)
```

## Command Categories

Shell Guard classifies every command into categories:

| Category | Tool Pattern | Examples |
|----------|-------------|----------|
| **Read** | `shell.read.*` | `ls`, `cat`, `grep`, `find`, `ps`, `df` |
| **Git Read** | `shell.git.status`, `shell.git.log`, etc. | `git status`, `git diff`, `git log` |
| **Git Write** | `shell.git.push`, `shell.git.commit`, etc. | `git push`, `git commit`, `git merge` |
| **Write** | `shell.write.*` | `mkdir`, `touch`, `cp`, `mv` |
| **Destructive** | `shell.danger.*` | `rm`, `chmod`, `chown`, `kill` |
| **Admin** | `shell.admin.*` | `sudo`, `docker`, `systemctl`, `apt`, `npm` |

## Permission Examples

**Read-only agent** (safe for research/analysis):
```
shell.read.* → allow
shell.git.status → allow
shell.git.log → allow
shell.git.diff → allow
```

**Developer agent** (can write files and use git):
```
shell.read.* → allow
shell.write.* → allow
shell.git.* → allow
shell.danger.* → deny
shell.admin.* → deny
```

**CI/CD agent** (can deploy but with rate limits):
```
shell.read.* → allow
shell.git.* → allow
shell.admin.docker → allow (rate limit: 5/hour)
shell.admin.npm → allow
shell.danger.* → deny
```

**Full access with approval gates**:
```
shell.read.* → allow
shell.write.* → allow
shell.git.* → allow
shell.danger.* → allow (requires approval)
shell.admin.* → allow (requires approval)
```

## Tools

Shell Guard exposes 3 MCP tools:

| Tool | Description |
|------|-------------|
| `run_command` | Run a shell command (validated first) |
| `check_permission` | Check if a command would be allowed without running it |
| `list_categories` | List all command categories and their permission names |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTSID_PROJECT_KEY` | Yes | Your AgentsID project key |
| `AGENTSID_AGENT_TOKEN` | Yes | Agent token for permission checks |
| `SHELL_GUARD_CWD` | No | Working directory (default: cwd) |
| `SHELL_GUARD_TIMEOUT` | No | Command timeout in ms (default: 30000) |

## Dashboard

Every command — allowed or blocked — appears in your [AgentsID dashboard](https://agentsid.dev/dashboard):

- Which agent ran which command
- Whether it was allowed or denied (and why)
- Full audit trail with tamper-evident hash chain

## Why Not Just Block Commands in a Script?

You could write a bash wrapper with blocked patterns. But:

- **No per-agent scoping** — every agent gets the same restrictions
- **No audit trail** — you don't know which agent tried what
- **No remote management** — changing permissions means editing a file and restarting
- **No rate limiting** — an agent can retry blocked commands infinitely
- **No delegation** — sub-agents inherit full access from parents

Shell Guard + AgentsID gives you identity-based, auditable, remotely-manageable command authorization.

## Links

- [AgentsID](https://agentsid.dev) — Identity & auth for AI agents
- [Documentation](https://agentsid.dev/docs)
- [Dashboard](https://agentsid.dev/dashboard)

## License

MIT
