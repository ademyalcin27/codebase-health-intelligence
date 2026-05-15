import { z } from "zod";
import { analyzeSinglePackage } from "../core/analyzer.js";
import { explainDependency } from "../ai/explainer.js";
import type { DependencyExplanation } from "../types.js";

export const explainDependencySchema = z.object({
  packageName: z.string().min(1).describe("npm package name to explain"),
  version: z.string().optional().default("latest"),
});

export async function explainDependencyTool(
  input: z.infer<typeof explainDependencySchema>
): Promise<DependencyExplanation> {
  const dep = await analyzeSinglePackage(input.packageName, input.version);
  return explainDependency(dep);
}
