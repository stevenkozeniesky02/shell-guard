/**
 * AgentsID permission validator.
 *
 * Every tool call passes through validate() before execution.
 * Fail-closed: network errors result in denial, never bypass.
 */

import { config } from "./config.mjs";

/**
 * Validate a tool action against AgentsID permission rules.
 * @param {string} toolName — The classified tool name (e.g., "shell.read.ls")
 * @returns {Promise<{allowed: boolean, tool: string, reason: string}>}
 */
export async function validate(toolName) {
  if (!config.projectKey || !config.agentToken) {
    return {
      allowed: false,
      tool: toolName,
      reason: "AGENTSID_PROJECT_KEY and AGENTSID_AGENT_TOKEN required",
    };
  }

  try {
    const response = await fetch(`${config.baseUrl}/api/v1/validate`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.projectKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token: config.agentToken, tool: toolName }),
    });

    const result = await response.json();

    return {
      allowed: result.valid === true && result.permission?.allowed === true,
      tool: toolName,
      reason: result.permission?.reason || result.reason || "Unknown",
    };
  } catch (err) {
    // Fail closed — deny on any error
    return {
      allowed: false,
      tool: toolName,
      reason: `AgentsID validation failed: ${err.message}`,
    };
  }
}

/**
 * Standard response builders.
 * These ensure consistent response format across all tools.
 */

export function blocked(toolName, reason) {
  return {
    content: [
      {
        type: "text",
        text: `BLOCKED by AgentsID Guard\n\nTool: ${toolName}\nReason: ${reason}\n\nThis action was denied and logged to the audit trail.`,
      },
    ],
    isError: true,
  };
}

export function success(text, toolName) {
  return {
    content: [{ type: "text", text: `${text}\n\n[✓ ${toolName}]` }],
  };
}

export function error(text) {
  return {
    content: [{ type: "text", text }],
    isError: true,
  };
}
