import { execSync } from "child_process";
import { config } from "../core/config.mjs";
import { validate, blocked, success, error } from "../core/validator.mjs";
import { classifyAwsCommand, classifyKubectlCommand } from "../core/classifier.mjs";

export const handlers = {
  async aws_run({ command: awsCmd }) {
    if (!awsCmd) return error("command is required (e.g., 's3 ls', 'ec2 describe-instances')");

    const toolName = classifyAwsCommand(awsCmd);

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`aws ${awsCmd}`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`AWS CLI failed: ${err.stderr || err.message}`);
    }
  },

  async kubectl_run({ command: kubectlCmd }) {
    if (!kubectlCmd) return error("command is required (e.g., 'get pods', 'logs my-pod')");

    const toolName = classifyKubectlCommand(kubectlCmd);

    const v = await validate(toolName);
    if (!v.allowed) return blocked(toolName, v.reason);

    try {
      const output = execSync(`kubectl ${kubectlCmd}`, {
        encoding: "utf-8", timeout: config.timeout, stdio: ["pipe", "pipe", "pipe"],
      });
      return success(output, toolName);
    } catch (err) {
      return error(`kubectl failed: ${err.stderr || err.message}`);
    }
  },
};

export const tools = [
  { name: "aws_run", description: "Run an AWS CLI command. Read ops (ls, describe) require aws.read.{service}. Write ops require aws.write.{service}. Destructive ops (delete, terminate) require aws.danger.{service}.", inputSchema: { type: "object", properties: { command: { type: "string", description: "AWS CLI command (e.g., 's3 ls', 'ec2 describe-instances')" } }, required: ["command"] } },
  { name: "kubectl_run", description: "Run a kubectl command. Read ops (get, describe, logs) require k8s.read.*. Write ops (apply, create) require k8s.write.*. Destructive ops (delete, drain) require k8s.danger.*.", inputSchema: { type: "object", properties: { command: { type: "string", description: "kubectl command (e.g., 'get pods', 'logs my-pod -f', 'apply -f deploy.yaml')" } }, required: ["command"] } },
];
