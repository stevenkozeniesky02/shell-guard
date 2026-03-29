import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";
import { classifySqlQuery } from "../core/classifier.mjs";

export const handlers = {
  async db_query({ query, database }) {
    if (!query) return error("query is required");

    const toolName = classifySqlQuery(query);

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    // Execute via shell (psql, mysql, sqlite3)
    const dbUrl = database || config.dbUrl;
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
        cwd: config.cwd, timeout: config.timeout, maxBuffer: 1024 * 1024,
        encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output || "(no results)", toolName);
    } catch (err) {
      return { content: [{ type: "text", text: `Query failed:\n${err.stderr || err.message}\n\n[✓ ${toolName}]` }], isError: true };
    }
  },
};

export const tools = [
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
];
