import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";

export const handlers = {
  async http_request({ url, method, headers: reqHeaders, body }) {
    if (!url) return error("url is required");

    const httpMethod = (method || "GET").toUpperCase();
    const toolName = `http.${httpMethod.toLowerCase()}`;

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const fetchOptions = {
        method: httpMethod,
        headers: { "User-Agent": "AgentsID-Guard/0.1.0", ...(reqHeaders || {}) },
      };
      if (body && httpMethod !== "GET") {
        fetchOptions.body = typeof body === "string" ? body : JSON.stringify(body);
        if (!fetchOptions.headers["Content-Type"]) {
          fetchOptions.headers["Content-Type"] = "application/json";
        }
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeout);
      fetchOptions.signal = controller.signal;

      const response = await fetch(url, fetchOptions);
      clearTimeout(timeoutId);

      const responseText = await response.text();
      const result = [
        `HTTP ${response.status} ${response.statusText}`,
        `URL: ${url}`,
        "",
        responseText.slice(0, 10000),
      ].join("\n");

      return success(result, toolName);
    } catch (err) {
      return error(`HTTP request failed: ${err.message}`);
    }
  },
};

export const tools = [
  {
    name: "http_request",
    description: "Make an HTTP request. GET requires http.get. POST requires http.post. PUT requires http.put. DELETE requires http.delete.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to request" },
        method: { type: "string", description: "HTTP method (default: GET)", enum: ["GET", "POST", "PUT", "DELETE", "PATCH"] },
        headers: { type: "object", description: "Request headers" },
        body: { type: "string", description: "Request body (for POST/PUT/PATCH)" },
      },
      required: ["url"],
    },
  },
];
