import { validate, blocked, success, error } from "../core/validator.mjs";
import { classifyEnvAccess } from "../core/classifier.mjs";

export const handlers = {
  async env_list() {
    const toolName = "env.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const safe = Object.entries(process.env)
      .filter(([k]) => !k.match(/KEY|SECRET|TOKEN|PASSWORD|PASS|CRED|AUTH/i))
      .map(([k, val]) => `${k}=${val}`)
      .sort()
      .join("\n");
    return success(safe || "(no environment variables)", toolName);
  },

  async env_get({ name }) {
    if (!name) return error("name is required");
    const toolName = classifyEnvAccess(name);
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const val = process.env[name];
    if (val === undefined) return success(`${name} is not set`, toolName);
    return success(`${name}=${val}`, toolName);
  },

  async env_set({ name, value }) {
    if (!name) return error("name is required");
    if (value === undefined) return error("value is required");
    const toolName = "env.write";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    process.env[name] = value;
    return success(`Set ${name}=${value}`, toolName);
  },
};

export const tools = [
  {
    name: "env_list",
    description: "List environment variables (secrets auto-filtered). Requires env.read permission.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "env_get",
    description: "Get a specific environment variable. Secret-named vars (KEY, TOKEN, PASSWORD) require env.read.secret permission.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", description: "Environment variable name" } },
      required: ["name"],
    },
  },
  {
    name: "env_set",
    description: "Set an environment variable. Requires env.write permission.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Variable name" },
        value: { type: "string", description: "Variable value" },
      },
      required: ["name", "value"],
    },
  },
];
