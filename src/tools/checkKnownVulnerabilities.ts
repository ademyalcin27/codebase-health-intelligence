import { z } from "zod";
import { logger } from "../lib/logger.js";

export const checkKnownVulnerabilitiesSchema = z.object({
  projectPath: z.string().min(1).describe("Absolute or relative path to the project directory containing package.json"),
});

/**
 * Thin wrapper tool that orchestrates the known-vulnerabilities check.
 *
 * The actual vulnerability lookup (querying OSV.dev, caching results, and
 * grouping findings by severity) lives in the core OSV module. This
 * function is the MCP-facing entry point that validates input and will
 * delegate to that module once it is wired in.
 */
export async function checkKnownVulnerabilitiesTool(
  input: z.infer<typeof checkKnownVulnerabilitiesSchema>
): Promise<unknown> {
  const { projectPath } = input;
  logger.info("checkKnownVulnerabilitiesTool called", { projectPath });

  // TODO: delegate to the core OSV module to perform the actual scan,
  // grouping results by severity (critical/high/medium/low) and
  // gracefully degrading to "unknown" status on network errors.
  return {
    projectPath,
    status: "not_implemented",
  };
}
