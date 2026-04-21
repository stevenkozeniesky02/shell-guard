/**
 * Guard configuration — loaded from environment variables.
 * All config is immutable after initialization.
 *
 * Env-var name history:
 *   - `AGENTSID_API_URL` is the canonical var name written by
 *     `@agentsid/setup` (and read by the Claude Code / Cursor hooks).
 *     Guard should prefer this so everything in the ecosystem agrees.
 *   - `AGENTSID_BASE_URL` was the original name used here; kept as a
 *     fallback for anyone who set it manually.
 *
 * The default `https://api.agentsid.dev` matches the production API host
 * the server actually serves from. The marketing site at
 * `https://agentsid.dev` is NOT the API and was a bug in 0.1.0.
 */

import { resolve } from "path";

export const config = Object.freeze({
  projectKey: process.env.AGENTSID_PROJECT_KEY || "",
  agentToken: process.env.AGENTSID_AGENT_TOKEN || "",
  baseUrl:
    process.env.AGENTSID_API_URL ||
    process.env.AGENTSID_BASE_URL ||
    "https://api.agentsid.dev",
  cwd: process.env.GUARD_CWD || process.cwd(),
  timeout: parseInt(process.env.GUARD_TIMEOUT || "30000", 10),
  allowedDirs: (process.env.GUARD_ALLOWED_DIRS || process.cwd())
    .split(",")
    .map((d) => resolve(d.trim())),
  dbUrl: process.env.GUARD_DB_URL || "",
});
