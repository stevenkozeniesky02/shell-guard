import { readFileSync, writeFileSync, unlinkSync, readdirSync, statSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";
import { isPathAllowed } from "../core/pathguard.mjs";

export const handlers = {
  async file_read({ path: filePath }) {
    if (!filePath) return error("path is required");
    const resolved = resolve(filePath);
    if (!isPathAllowed(resolved)) return blocked("file.read", "Path outside allowed directories");
    const v = await validate("file.read");
    if (!v.allowed) return blocked("file.read", v.reason);
    try {
      return success(readFileSync(resolved, "utf-8"), "file.read");
    } catch (err) {
      return error(`Failed to read ${filePath}: ${err.message}`);
    }
  },

  async file_write({ path: filePath, content }) {
    if (!filePath) return error("path is required");
    if (content === undefined) return error("content is required");
    const resolved = resolve(filePath);
    if (!isPathAllowed(resolved)) return blocked("file.write", "Path outside allowed directories");
    const v = await validate("file.write");
    if (!v.allowed) return blocked("file.write", v.reason);
    try {
      const dir = dirname(resolved);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(resolved, content, "utf-8");
      return success(`Written ${content.length} bytes to ${filePath}`, "file.write");
    } catch (err) {
      return error(`Failed to write ${filePath}: ${err.message}`);
    }
  },

  async file_delete({ path: filePath }) {
    if (!filePath) return error("path is required");
    const resolved = resolve(filePath);
    if (!isPathAllowed(resolved)) return blocked("file.delete", "Path outside allowed directories");
    const v = await validate("file.delete");
    if (!v.allowed) return blocked("file.delete", v.reason);
    try {
      unlinkSync(resolved);
      return success(`Deleted ${filePath}`, "file.delete");
    } catch (err) {
      return error(`Failed to delete ${filePath}: ${err.message}`);
    }
  },

  async file_list({ path: dirPath }) {
    const resolved = resolve(dirPath || config.cwd);
    if (!isPathAllowed(resolved)) return blocked("file.list", "Path outside allowed directories");
    const v = await validate("file.list");
    if (!v.allowed) return blocked("file.list", v.reason);
    try {
      const entries = readdirSync(resolved).map((name) => {
        try {
          const s = statSync(resolve(resolved, name));
          return `${s.isDirectory() ? "d" : "-"} ${String(s.size).padStart(8)} ${name}`;
        } catch { return `? ${name}`; }
      });
      return success(entries.join("\n") || "(empty directory)", "file.list");
    } catch (err) {
      return error(`Failed to list ${dirPath}: ${err.message}`);
    }
  },

  async file_info({ path: filePath }) {
    if (!filePath) return error("path is required");
    const resolved = resolve(filePath);
    if (!isPathAllowed(resolved)) return blocked("file.info", "Path outside allowed directories");
    const v = await validate("file.info");
    if (!v.allowed) return blocked("file.info", v.reason);
    try {
      const s = statSync(resolved);
      const info = [
        `Path: ${resolved}`, `Type: ${s.isDirectory() ? "directory" : "file"}`,
        `Size: ${s.size} bytes`, `Modified: ${s.mtime.toISOString()}`,
        `Created: ${s.birthtime.toISOString()}`, `Permissions: ${(s.mode & 0o777).toString(8)}`,
      ].join("\n");
      return success(info, "file.info");
    } catch (err) {
      return error(`Failed to stat ${filePath}: ${err.message}`);
    }
  },
};

export const tools = [
  { name: "file_read", description: "Read a file's contents. Restricted to allowed directories. Requires file.read permission.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to the file" } }, required: ["path"] } },
  { name: "file_write", description: "Write content to a file. Creates parent directories if needed. Requires file.write permission.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to the file" }, content: { type: "string", description: "Content to write" } }, required: ["path", "content"] } },
  { name: "file_delete", description: "Delete a file. Requires file.delete permission.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to the file" } }, required: ["path"] } },
  { name: "file_list", description: "List files in a directory with size and type info. Requires file.list permission.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Directory path (default: working directory)" } } } },
  { name: "file_info", description: "Get file metadata (size, type, permissions, timestamps). Requires file.info permission.", inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to the file" } }, required: ["path"] } },
];
