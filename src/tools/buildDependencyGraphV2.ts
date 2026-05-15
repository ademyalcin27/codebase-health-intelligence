import { z } from "zod";
import { analyzeProject } from "../core/analyzer.js";
import { buildEnhancedGraph } from "../core/graph-engine.js";
import type { EnhancedDependencyGraph } from "../types.js";

export const buildDependencyGraphV2Schema = z.object({
  projectPath: z.string().min(1).describe("Path to project directory containing package.json"),
});

export async function buildDependencyGraphV2Tool(
  input: z.infer<typeof buildDependencyGraphV2Schema>
): Promise<EnhancedDependencyGraph> {
  const analysis = await analyzeProject(input.projectPath);
  return buildEnhancedGraph(analysis.dependencyGraph);
}
