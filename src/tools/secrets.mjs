import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";
import { initVault } from "../core/vault.mjs";

export const handlers = {
  async secrets_store({ name, value, metadata }) {
    if (!name) return error("name is required");
    if (!value) return error("value is required");
    const toolName = "secrets.write";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const vault = initVault();

    // Encrypt the value with per-secret derived key
    const encrypted = vault.encrypt(name, value);

    // Store with metadata
    const now = new Date().toISOString();
    const previous = vault.secrets[name];

    vault.secrets[name] = {
      encrypted,
      created: previous?.created || now,
      updated: now,
      version: (previous?.version || 0) + 1,
      metadata: metadata || previous?.metadata || {},
      // Access control: which tool patterns can use this secret
      allowedTools: previous?.allowedTools || ["*"],
      // Expiry: optional TTL
      expiresAt: previous?.expiresAt || null,
      // Rotation tracking
      rotationCount: (previous?.rotationCount || 0) + (previous ? 1 : 0),
    };

    // Track rotation history
    if (previous) {
      if (!vault.rotationHistory[name]) vault.rotationHistory[name] = [];
      vault.rotationHistory[name].push({
        version: previous.version,
        rotatedAt: now,
        reason: "manual_update",
      });
    }

    vault.persist();

    return success(
      `Secret "${name}" stored (version ${vault.secrets[name].version}, encrypted with per-secret derived key)`,
      toolName
    );
  },

  async secrets_list() {
    const toolName = "secrets.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const vault = initVault();

    const entries = Object.entries(vault.secrets).map(([name, s]) => {
      const expired = s.expiresAt && new Date(s.expiresAt) < new Date();
      return `${name} (v${s.version}, updated ${s.updated}${expired ? " EXPIRED" : ""})`;
    });

    return success(
      entries.length > 0
        ? `Secrets in vault (${entries.length}):\n${entries.join("\n")}\n\nValues are never exposed. Use secrets_inject to make API calls with secrets.`
        : "(vault is empty)",
      toolName
    );
  },

  async secrets_delete({ name }) {
    if (!name) return error("name is required");
    const toolName = "secrets.danger";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const vault = initVault();
    if (!vault.secrets[name]) return error(`Secret "${name}" not found`);

    delete vault.secrets[name];
    vault.persist();

    return success(`Secret "${name}" deleted from vault`, toolName);
  },

  async secrets_scope({ name, allowedTools }) {
    if (!name) return error("name is required");
    if (!allowedTools) return error("allowedTools is required (array of tool patterns, e.g. ['http.post', 'http.get'])");
    const toolName = "secrets.write";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const vault = initVault();
    if (!vault.secrets[name]) return error(`Secret "${name}" not found`);

    const scopedTools = Array.isArray(allowedTools) ? allowedTools : [allowedTools];
    vault.secrets[name].allowedTools = scopedTools;
    vault.persist();

    return success(`Secret "${name}" scoped to tools: ${scopedTools.join(", ")}`, toolName);
  },

  async secrets_expire({ name, ttlMinutes }) {
    if (!name) return error("name is required");
    if (!ttlMinutes) return error("ttlMinutes is required");
    const toolName = "secrets.write";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const vault = initVault();
    if (!vault.secrets[name]) return error(`Secret "${name}" not found`);

    const expiresAt = new Date(Date.now() + parseInt(ttlMinutes, 10) * 60000).toISOString();
    vault.secrets[name].expiresAt = expiresAt;
    vault.persist();

    return success(`Secret "${name}" expires at ${expiresAt} (${ttlMinutes} minutes)`, toolName);
  },

  // Proxy Inject — THE KEY FEATURE
  // Agent says "call this URL with {{API_KEY}} in the header"
  // Guard decrypts the secret, makes the HTTP call, returns the response
  // The agent NEVER sees the raw secret value
  async secrets_inject({ url, method, headers, body, secretMappings }) {
    if (!url) return error("url is required");
    if (!secretMappings) return error("secretMappings is required — object mapping placeholder names to vault secret names, e.g. {\"{{API_KEY}}\": \"openai_key\"}");

    const toolName = "secrets.proxy";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const vault = initVault();
    const httpMethod = (method || "GET").toUpperCase();
    const now = new Date().toISOString();

    // Resolve all secret mappings
    const resolvedMappings = {};
    for (const [placeholder, secretName] of Object.entries(secretMappings)) {
      const secret = vault.secrets[secretName];
      if (!secret) return error(`Secret "${secretName}" not found in vault`);

      // Check expiry
      if (secret.expiresAt && new Date(secret.expiresAt) < new Date()) {
        return error(`Secret "${secretName}" has expired (${secret.expiresAt}). Rotate or extend it.`);
      }

      // Check tool scoping — is this secret allowed for HTTP calls?
      const httpTool = `http.${httpMethod.toLowerCase()}`;
      const allowed = secret.allowedTools.some((pattern) => {
        if (pattern === "*") return true;
        if (pattern === httpTool) return true;
        if (pattern.endsWith("*") && httpTool.startsWith(pattern.slice(0, -1))) return true;
        return false;
      });
      if (!allowed) {
        return blocked("secrets.proxy", `Secret "${secretName}" is not scoped for ${httpTool}. Allowed: ${secret.allowedTools.join(", ")}`);
      }

      // Decrypt
      try {
        resolvedMappings[placeholder] = vault.decrypt(secretName, secret.encrypted);
      } catch (err) {
        return error(`Failed to decrypt secret "${secretName}": ${err.message}`);
      }

      // Log access
      vault.accessLog.push({
        secret: secretName,
        tool: "secrets.proxy",
        action: "inject",
        target: url,
        method: httpMethod,
        timestamp: now,
        version: secret.version,
      });
    }

    vault.persist();

    // Inject secrets into URL, headers, and body
    let resolvedUrl = url;
    let resolvedHeaders = { ...(headers || {}), "User-Agent": "AgentsID-Guard-Vault/0.1.0" };
    let resolvedBody = body;

    for (const [placeholder, value] of Object.entries(resolvedMappings)) {
      resolvedUrl = resolvedUrl.replaceAll(placeholder, value);
      for (const [hk, hv] of Object.entries(resolvedHeaders)) {
        if (typeof hv === "string") {
          resolvedHeaders[hk] = hv.replaceAll(placeholder, value);
        }
      }
      if (typeof resolvedBody === "string") {
        resolvedBody = resolvedBody.replaceAll(placeholder, value);
      }
    }

    // Make the HTTP call with secrets injected
    try {
      const fetchOptions = {
        method: httpMethod,
        headers: resolvedHeaders,
      };
      if (resolvedBody && httpMethod !== "GET") {
        fetchOptions.body = resolvedBody;
        if (!fetchOptions.headers["Content-Type"]) {
          fetchOptions.headers["Content-Type"] = "application/json";
        }
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeout);
      fetchOptions.signal = controller.signal;

      const response = await fetch(resolvedUrl, fetchOptions);
      clearTimeout(timeoutId);

      const responseText = await response.text();

      // Scrub response — make sure no secret values leak back
      let cleanResponse = responseText;
      for (const value of Object.values(resolvedMappings)) {
        if (value.length > 4) {
          cleanResponse = cleanResponse.replaceAll(value, `[REDACTED]`);
        }
      }

      return success(
        `HTTP ${response.status} ${response.statusText}\nURL: ${url} (secrets injected server-side)\n\n${cleanResponse.slice(0, 10000)}`,
        toolName
      );
    } catch (err) {
      return error(`Proxy request failed: ${err.message}`);
    }
  },

  async secrets_audit({ name }) {
    const toolName = "secrets.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const vault = initVault();

    let entries = vault.accessLog;
    if (name) {
      entries = entries.filter((e) => e.secret === name);
    }

    if (entries.length === 0) return success("(no access history)", toolName);

    const lines = entries.slice(-50).map((e) =>
      `${e.timestamp} | ${e.secret} v${e.version} | ${e.action} | ${e.method || ""} ${e.target || ""}`
    );

    return success(
      `Secret access log (last ${Math.min(entries.length, 50)} of ${entries.length}):\n${lines.join("\n")}`,
      toolName
    );
  },

  async secrets_history({ name }) {
    if (!name) return error("name is required");
    const toolName = "secrets.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const vault = initVault();
    const history = vault.rotationHistory[name];

    if (!history || history.length === 0) return success(`Secret "${name}" has never been rotated`, toolName);

    const lines = history.map((h) => `v${h.version} → rotated at ${h.rotatedAt} (${h.reason})`);
    return success(`Rotation history for "${name}":\n${lines.join("\n")}`, toolName);
  },

  async secrets_anomalies() {
    const toolName = "secrets.read";
    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    const vault = initVault();
    const anomalies = [];

    // Check for expired secrets still in vault
    for (const [name, s] of Object.entries(vault.secrets)) {
      if (s.expiresAt && new Date(s.expiresAt) < new Date()) {
        anomalies.push(`EXPIRED: "${name}" expired at ${s.expiresAt}`);
      }
    }

    // Check for secrets with wildcard scope (should be tightened)
    for (const [name, s] of Object.entries(vault.secrets)) {
      if (s.allowedTools.includes("*")) {
        anomalies.push(`BROAD_SCOPE: "${name}" has wildcard tool access — consider scoping to specific tools`);
      }
    }

    // Check for secrets never rotated
    for (const [name, s] of Object.entries(vault.secrets)) {
      if (s.rotationCount === 0 && s.version === 1) {
        const age = (Date.now() - new Date(s.created).getTime()) / 86400000;
        if (age > 30) {
          anomalies.push(`STALE: "${name}" is ${Math.floor(age)} days old and never rotated`);
        }
      }
    }

    // Check for unusual access patterns
    const accessCounts = {};
    const recentLog = vault.accessLog.filter((e) => Date.now() - new Date(e.timestamp).getTime() < 3600000);
    for (const entry of recentLog) {
      accessCounts[entry.secret] = (accessCounts[entry.secret] || 0) + 1;
    }
    for (const [name, count] of Object.entries(accessCounts)) {
      if (count > 50) {
        anomalies.push(`HIGH_FREQUENCY: "${name}" accessed ${count} times in the last hour`);
      }
    }

    if (anomalies.length === 0) return success("No anomalies detected in the vault", toolName);
    return success(`Vault anomalies (${anomalies.length}):\n${anomalies.join("\n")}`, toolName);
  },
};

export const tools = [
  { name: "secrets_store", description: "Store a secret in the encrypted vault. Per-secret derived encryption keys. Requires secrets.write.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Secret name (e.g., 'openai_key', 'db_password')" }, value: { type: "string", description: "Secret value" }, metadata: { type: "object", description: "Optional metadata" } }, required: ["name", "value"] } },
  { name: "secrets_list", description: "List secret names (values never exposed). Requires secrets.read.", inputSchema: { type: "object", properties: {} } },
  { name: "secrets_delete", description: "Delete a secret from the vault. Requires secrets.danger.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Secret name" } }, required: ["name"] } },
  { name: "secrets_scope", description: "Restrict which tools can use a secret. E.g., scope an API key to only http.post calls. Requires secrets.write.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Secret name" }, allowedTools: { type: "array", items: { type: "string" }, description: "Tool patterns that can use this secret (e.g., ['http.post', 'http.get'])" } }, required: ["name", "allowedTools"] } },
  { name: "secrets_expire", description: "Set a time-to-live on a secret. After expiry, proxy injection will refuse to use it. Requires secrets.write.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Secret name" }, ttlMinutes: { type: "string", description: "Minutes until expiry" } }, required: ["name", "ttlMinutes"] } },
  { name: "secrets_inject", description: "Make an HTTP request with vault secrets injected server-side. The agent NEVER sees the raw secret — Guard substitutes placeholders like {{API_KEY}} with the real value, makes the call, and scrubs secrets from the response. Requires secrets.proxy.", inputSchema: { type: "object", properties: { url: { type: "string", description: "URL (can contain {{SECRET_NAME}} placeholders)" }, method: { type: "string", description: "HTTP method", enum: ["GET", "POST", "PUT", "DELETE", "PATCH"] }, headers: { type: "object", description: "Request headers (can contain {{SECRET_NAME}} placeholders)" }, body: { type: "string", description: "Request body (can contain {{SECRET_NAME}} placeholders)" }, secretMappings: { type: "object", description: "Map of placeholder → vault secret name, e.g. {\"{{API_KEY}}\": \"openai_key\"}" } }, required: ["url", "secretMappings"] } },
  { name: "secrets_audit", description: "View access log for secrets — who accessed what, when, for what purpose. Requires secrets.read.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Filter by secret name (optional)" } } } },
  { name: "secrets_history", description: "View rotation history for a secret. Requires secrets.read.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Secret name" } }, required: ["name"] } },
  { name: "secrets_anomalies", description: "Detect vault anomalies: expired secrets, broad scopes, stale keys, unusual access patterns. Requires secrets.read.", inputSchema: { type: "object", properties: {} } },
];
