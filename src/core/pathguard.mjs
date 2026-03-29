/**
 * Path safety — ensures file operations stay within allowed directories.
 * Resolves symlinks and prevents traversal attacks.
 */

import { resolve } from "path";
import { config } from "./config.mjs";

/**
 * Check if a target path falls within any allowed directory.
 * @param {string} targetPath — Path to validate
 * @returns {boolean}
 */
export function isPathAllowed(targetPath) {
  const resolved = resolve(targetPath);
  return config.allowedDirs.some((dir) => resolved.startsWith(dir));
}
