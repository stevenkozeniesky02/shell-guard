import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";

export const handlers = {
  async package_list({ manager }) {
    const toolName = "package.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const mgr = manager || "auto";
    let cmd;
    if (mgr === "npm" || mgr === "auto") { try { cmd = "npm list -g --depth=0 2>/dev/null"; } catch {} }
    if (mgr === "pip" || (!cmd && mgr === "auto")) { cmd = "pip list 2>/dev/null || pip3 list 2>/dev/null"; }
    if (mgr === "brew" || (!cmd && mgr === "auto")) { cmd = "brew list 2>/dev/null"; }
    if (mgr === "apt") { cmd = "dpkg -l 2>/dev/null | tail -20"; }
    if (!cmd) cmd = "echo 'No package manager detected'";

    try {
      const output = execSync(cmd, { encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"] });
      return success(output, toolName);
    } catch (err) {
      return error(`Package list failed: ${err.message}`);
    }
  },

  async package_info({ name: pkgName, manager }) {
    if (!pkgName) return error("name is required");
    const toolName = "package.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const mgr = manager || "npm";
    let cmd;
    if (mgr === "npm") cmd = `npm view ${pkgName} 2>/dev/null`;
    else if (mgr === "pip") cmd = `pip show ${pkgName} 2>/dev/null || pip3 show ${pkgName}`;
    else if (mgr === "brew") cmd = `brew info ${pkgName} 2>/dev/null`;
    else if (mgr === "apt") cmd = `apt show ${pkgName} 2>/dev/null`;
    else cmd = `echo 'Unsupported manager: ${mgr}'`;

    try {
      const output = execSync(cmd, { encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"] });
      return success(output || `(${pkgName} not found)`, toolName);
    } catch (err) {
      return error(`Package info failed: ${err.message}`);
    }
  },

  async package_install({ name: pkgName, manager }) {
    if (!pkgName) return error("name is required");
    const toolName = "package.danger.install";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const mgr = manager || "npm";
    let cmd;
    if (mgr === "npm") cmd = `npm install -g ${pkgName}`;
    else if (mgr === "pip") cmd = `pip install ${pkgName}`;
    else if (mgr === "brew") cmd = `brew install ${pkgName}`;
    else if (mgr === "apt") cmd = `sudo apt install -y ${pkgName}`;
    else return error(`Unsupported manager: ${mgr}`);

    try {
      const output = execSync(cmd, { encoding: "utf-8", timeout: 120000, stdio: ["pipe", "pipe", "pipe"] });
      return success(`Installed ${pkgName}:\n${output}`, toolName);
    } catch (err) {
      return error(`Install failed: ${err.stderr || err.message}`);
    }
  },
};

export const tools = [
  { name: "package_list", description: "List installed packages. Requires package.read.", inputSchema: { type: "object", properties: { manager: { type: "string", description: "Package manager", enum: ["npm", "pip", "brew", "apt", "auto"] } } } },
  { name: "package_info", description: "Get info about a package. Requires package.read.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Package name" }, manager: { type: "string", description: "Package manager", enum: ["npm", "pip", "brew", "apt"] } }, required: ["name"] } },
  { name: "package_install", description: "Install a package. Requires package.danger.install (high risk).", inputSchema: { type: "object", properties: { name: { type: "string", description: "Package name" }, manager: { type: "string", description: "Package manager", enum: ["npm", "pip", "brew", "apt"] } }, required: ["name"] } },
];
