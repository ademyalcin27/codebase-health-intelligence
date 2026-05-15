import { z } from "zod";
import { analyzeProject } from "../core/analyzer.js";
import { predictProjectBreakingChanges } from "../core/breaking-change-predictor.js";
import type { BreakingChangePrediction } from "../types.js";

export const predictBreakingChangesSchema = z.object({
  projectPath: z.string().min(1).describe("Path to project directory containing package.json"),
});

export async function predictBreakingChangesTool(
  input: z.infer<typeof predictBreakingChangesSchema>
): Promise<{ projectPath: string; analyzedAt: string; predictions: BreakingChangePrediction[] }> {
  const analysis = await analyzeProject(input.projectPath);
  const predictions = predictProjectBreakingChanges(analysis.dependencies);
  return { projectPath: input.projectPath, analyzedAt: new Date().toISOString(), predictions };
}
