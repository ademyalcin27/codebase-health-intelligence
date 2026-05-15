import { z } from "zod";
import { analyzeProject } from "../core/analyzer.js";
import { generateUpgradePlan } from "../core/upgrade-planner.js";
import type { UpgradePlan } from "../types.js";

export const generateUpgradePlanSchema = z.object({
  projectPath: z.string().min(1).describe("Path to project directory containing package.json"),
});

export async function generateUpgradePlanTool(
  input: z.infer<typeof generateUpgradePlanSchema>
): Promise<UpgradePlan> {
  const analysis = await analyzeProject(input.projectPath);
  return generateUpgradePlan(input.projectPath, analysis.dependencies);
}
