import { readFile } from "fs/promises";
import { resolve } from "path";
import { fetchNpmMetadata } from "../providers/npm.js";
import { fetchGitHubMetadata } from "../providers/github.js";
import { computeRiskScore } from "./risk-score.js";
import { validateProjectPath } from "../lib/validate-path.js";
import { logger } from "../lib/logger.js";
import type { AnalysisResult, DependencyGraph, DependencyRisk } from "../types.js";

export interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

const BATCH_SIZE = 10;

export async function analyzeSinglePackage(name: string, version: string): Promise<DependencyRisk> {
  const npm = await fetchNpmMetadata(name);
  const github = await fetchGitHubMetadata(npm.repositoryUrl);
  const { riskScore, riskLevel, scoreBreakdown } = computeRiskScore(npm, github);
  return { name, version, riskScore, riskLevel, npm, github, scoreBreakdown };
}

export async function readPackageJson(projectPath: string): Promise<PackageJson> {
  const path = resolve(projectPath, "package.json");
  let raw: string;
  try {
    raw = await readFile(path, "utf-8");
  } catch {
    throw new Error(`Cannot read package.json at: ${path}`);
  }
  try {
    return JSON.parse(raw) as PackageJson;
  } catch {
    throw new Error(`Invalid JSON in package.json at: ${path}`);
  }
}

function fallbackResult(name: string, version: string, errorMessage: string): DependencyRisk & { error: string } {
  return {
    name, version,
    riskScore: 50,
    riskLevel: "medium" as const,
    npm: { latestVersion: "unknown", publishedAt: null, daysSincePublish: null, weeklyDownloads: null, repositoryUrl: null },
    github: { owner: null, repo: null, openIssues: null, lastPushedAt: null, daysSinceLastCommit: null, available: false },
    scoreBreakdown: { stalePublish: 0, lowDownloads: 0, staleCommit: 0, missingRepo: 0, highIssues: 0, total: 50 },
    error: errorMessage,
  };
}

export async function analyzeProject(projectPath: string): Promise<AnalysisResult> {
  const validPath = await validateProjectPath(projectPath);

  logger.info("Starting project analysis", { projectPath: validPath });

  const pkg = await readPackageJson(validPath);

  const deps = Object.entries(pkg.dependencies ?? {}).map(([name, version]) => ({ name, version, type: "dependency" as const }));
  const devDeps = Object.entries(pkg.devDependencies ?? {}).map(([name, version]) => ({ name, version, type: "devDependency" as const }));
  const allEntries = [...deps, ...devDeps];

  logger.info("Analyzing packages", { total: allEntries.length });

  const dependencyGraph: DependencyGraph = {};
  for (const { name, version, type } of allEntries) {
    dependencyGraph[name] = { version, type };
  }

  const results: DependencyRisk[] = [];
  for (let i = 0; i < allEntries.length; i += BATCH_SIZE) {
    const batch = allEntries.slice(i, i + BATCH_SIZE);
    logger.debug("Processing batch", { batch: i / BATCH_SIZE + 1, size: batch.length });

    const batchResults = await Promise.all(
      batch.map(({ name, version }) =>
        analyzeSinglePackage(name, version).catch((err: unknown) => {
          const message = err instanceof Error ? err.message : String(err);
          logger.warn("Package analysis failed", { package: name, error: message });
          return fallbackResult(name, version, message);
        })
      )
    );
    results.push(...batchResults);
  }

  results.sort((a, b) => b.riskScore - a.riskScore);

  const summary = {
    critical: results.filter((d) => d.riskLevel === "critical").length,
    high: results.filter((d) => d.riskLevel === "high").length,
    medium: results.filter((d) => d.riskLevel === "medium").length,
    low: results.filter((d) => d.riskLevel === "low").length,
    averageRiskScore: results.length > 0
      ? Math.round(results.reduce((s, d) => s + d.riskScore, 0) / results.length)
      : 0,
  };

  logger.info("Analysis complete", { total: results.length, ...summary });

  return {
    projectPath: validPath,
    analyzedAt: new Date().toISOString(),
    totalDependencies: results.length,
    dependencies: results,
    dependencyGraph,
    summary,
  };
}
