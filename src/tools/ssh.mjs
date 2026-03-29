import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";

export const handlers = {
  async ssh_run({ host, command: sshCmd, user, port }) {
    if (!host) return error("host is required");
    if (!sshCmd) return error("command is required");
    const sshUser = user || "root";
    const sshPort = port || "22";
    const toolName = `ssh.${host.replace(/[^a-zA-Z0-9]/g, "_")}`;
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(
        `ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${sshPort} ${sshUser}@${host} "${sshCmd.replace(/"/g, '\\"')}"`,
        { encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"] }
      );
      return success(`[${sshUser}@${host}] ${output}`, toolName);
    } catch (err) {
      return error(`SSH to ${host} failed: ${err.stderr || err.message}`);
    }
  },
};

export const tools = [
  { name: "ssh_run", description: "Run a command on a remote host via SSH. Permission scoped per host (ssh.hostname). Requires SSH keys configured.", inputSchema: { type: "object", properties: { host: { type: "string", description: "Remote hostname or IP" }, command: { type: "string", description: "Command to execute" }, user: { type: "string", description: "SSH user (default: root)" }, port: { type: "string", description: "SSH port (default: 22)" } }, required: ["host", "command"] } },
];
