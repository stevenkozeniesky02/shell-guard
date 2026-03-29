/**
 * Guard configuration — loaded from environment variables.
 * All config is immutable after initialization.
 */

import { resolve } from "path";

export const config = Object.freeze({
  projectKey: process.env.AGENTSID_PROJECT_KEY || "",
  agentToken: process.env.AGENTSID_AGENT_TOKEN || "",
  baseUrl: process.env.AGENTSID_BASE_URL || "https://agentsid.dev",
  cwd: process.env.GUARD_CWD || process.cwd(),
  timeout: parseInt(process.env.GUARD_TIMEOUT || "30000", 10),
  allowedDirs: (process.env.GUARD_ALLOWED_DIRS || process.cwd())
    .split(",")
    .map((d) => resolve(d.trim())),
  dbUrl: process.env.GUARD_DB_URL || "",
});
