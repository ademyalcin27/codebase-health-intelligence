import { z } from "zod";
import { analyzeProject } from "../core/analyzer.js";
import { computeRepoHealthScore } from "../scoring/system-health.js";
import type { EnhancedAnalysisResult } from "../types.js";

export const analyzeRepoHealthV2Schema = z.object({
  projectPath: z.string().min(1).describe("Path to project directory containing package.json"),
});

export async function analyzeRepoHealthV2(
  input: z.infer<typeof analyzeRepoHealthV2Schema>
): Promise<EnhancedAnalysisResult> {
  const base = await analyzeProject(input.projectPath);
  const healthScore = computeRepoHealthScore(base.dependencies);

  const riskGroups = {
    critical: base.dependencies.filter((d) => d.riskLevel === "critical"),
    high: base.dependencies.filter((d) => d.riskLevel === "high"),
    medium: base.dependencies.filter((d) => d.riskLevel === "medium"),
    low: base.dependencies.filter((d) => d.riskLevel === "low"),
  };

  const criticalIssues = healthScore.topIssues;

  return { ...base, healthScore, criticalIssues, riskGroups };
}
