#!/usr/bin/env node
import "dotenv/config";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { validateEnv } from "./lib/validate-env.js";
import { logger } from "./lib/logger.js";

import { analyzeRepoHealthV2 } from "./tools/analyzeRepoHealthV2.js";
import { generateUpgradePlanTool } from "./tools/generateUpgradePlan.js";
import { explainDependencyTool } from "./tools/explainDependencyTool.js";
import { buildDependencyGraphV2Tool } from "./tools/buildDependencyGraphV2.js";
import { predictBreakingChangesTool } from "./tools/predictBreakingChanges.js";
import { checkKnownVulnerabilitiesTool, CheckKnownVulnerabilitiesSchema } from './tools/checkKnownVulnerabilities.js';

validateEnv();

const server = new McpServer({
  name: "codebase-health-intelligence",
  version: "1.0.0",
});

// ─── Tool: analyze_repo_health ────────────────────────────────────────────────

server.registerTool(
  "analyze_repo_health",
  {
    description:
      "Analyze all dependencies in a project. Returns health score (0–100), per-package risk scores, risk groups, and top critical issues.",
    inputSchema: {
      projectPath: z.string().min(1).describe("Absolute or relative path to the project directory containing package.json"),
    },
  },
  async ({ projectPath }) => {
    logger.info("Tool called: analyze_repo_health", { projectPath });
    const result = await analyzeRepoHealthV2({ projectPath });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ─── Tool: generate_upgrade_plan ─────────────────────────────────────────────

server.registerTool(
  "generate_upgrade_plan",
  {
    description:
      "Generate a step-by-step dependency upgrade strategy. Returns safe ordering, per-package warnings, npm install commands, rollback commands, and a global rollback strategy.",
    inputSchema: {
      projectPath: z.string().min(1).describe("Absolute or relative path to the project directory containing package.json"),
    },
  },
  async ({ projectPath }) => {
    logger.info("Tool called: generate_upgrade_plan", { projectPath });
    const result = await generateUpgradePlanTool({ projectPath });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ─── Tool: explain_dependency ─────────────────────────────────────────────────

server.registerTool(
  "explain_dependency",
  {
    description:
      "Get a signal-based explanation of why a package is risky or safe. Covers ecosystem adoption, maintenance signals, and a concrete recommendation. Based entirely on real fetched data.",
    inputSchema: {
      packageName: z.string().min(1).describe("npm package name (e.g. 'lodash', '@types/node')"),
      version: z.string().optional().default("latest").describe("Version string (informational only)"),
    },
  },
  async ({ packageName, version }) => {
    logger.info("Tool called: explain_dependency", { packageName });
    const result = await explainDependencyTool({ packageName, version });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ─── Tool: build_dependency_graph ────────────────────────────────────────────

server.registerTool(
  "build_dependency_graph",
  {
    description:
      "Build an enhanced dependency graph with blast radius scores, critical node detection, circular dependency detection, and depth scoring.",
    inputSchema: {
      projectPath: z.string().min(1).describe("Absolute or relative path to the project directory containing package.json"),
    },
  },
  async ({ projectPath }) => {
    logger.info("Tool called: build_dependency_graph", { projectPath });
    const result = await buildDependencyGraphV2Tool({ projectPath });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

// ─── Tool: predict_breaking_changes ──────────────────────────────────────────

server.registerTool(
  "predict_breaking_changes",
  {
    description:
      "Predict which dependency updates are likely to introduce breaking changes. Returns impact severity, affected code areas, confidence score, and reasoning per package.",
    inputSchema: {
      projectPath: z.string().min(1).describe("Absolute or relative path to the project directory containing package.json"),
    },
  },
  async ({ projectPath }) => {
    logger.info("Tool called: predict_breaking_changes", { projectPath });
    const result = await predictBreakingChangesTool({ projectPath });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);


// ─── Tool: check_known_vulnerabilities ───────────────────────────────────

server.registerTool(
  "check_known_vulnerabilities",
  {
    description: "Checks for known vulnerabilities in a project’s dependencies using the OSV.dev API.",
    inputSchema: CheckKnownVulnerabilitiesSchema,
  },
  async (input) => {
    logger.info("Tool called: check_known_vulnerabilities", { input });
    const result = await checkKnownVulnerabilitiesTool(input as z.infer<typeof CheckKnownVulnerabilitiesSchema>);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);


// ─── Startup & Graceful Shutdown ──────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();

  // Graceful shutdown on SIGTERM / SIGINT
  const shutdown = async (signal: string) => {
    logger.info("Shutting down", { signal });
    try {
      await server.close();
    } catch {
      // best effort
    }
    process.exit(0);
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT",  () => void shutdown("SIGINT"));

  // Catch unhandled errors — log and keep running (don't crash the MCP host)
  process.on("uncaughtException", (err) => {
    logger.error("Uncaught exception", { error: err.message, stack: err.stack });
  });
  process.on("unhandledRejection", (reason) => {
    logger.error("Unhandled rejection", { reason: String(reason) });
  });

  await server.connect(transport);
  logger.info("Codebase Health Intelligence v1.0.0 started");
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  logger.error("Fatal startup error", { error: message });
  process.exit(1);
});
