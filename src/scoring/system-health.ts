import type { DependencyRisk, HealthLevel, RepoHealthScore } from "../types.js";

function healthLevelFromScore(score: number): HealthLevel {
  if (score >= 80) return "excellent";
  if (score >= 60) return "good";
  if (score >= 35) return "risky";
  return "critical";
}

export function computeRepoHealthScore(deps: DependencyRisk[]): RepoHealthScore {
  if (deps.length === 0) {
    return {
      healthScore: 100,
      healthLevel: "excellent",
      summary: "No dependencies found. Project is dependency-free.",
      breakdown: { avgRiskScore: 0, outdatedRatio: 0, criticalCount: 0, maintenanceScore: 100 },
      topIssues: [],
    };
  }

  const avgRiskScore = Math.round(deps.reduce((s, d) => s + d.riskScore, 0) / deps.length);
  const criticalCount = deps.filter((d) => d.riskLevel === "critical").length;
  const highCount = deps.filter((d) => d.riskLevel === "high").length;

  const outdated = deps.filter((d) => d.npm.daysSincePublish !== null && d.npm.daysSincePublish > 365).length;
  const outdatedRatio = Math.round((outdated / deps.length) * 100);

  const maintained = deps.filter(
    (d) => d.github.available && (d.github.daysSinceLastCommit === null || d.github.daysSinceLastCommit < 180)
  ).length;
  const maintenanceScore = Math.round((maintained / deps.length) * 100);

  // Health score: invert avg risk, penalize criticals and outdated ratio
  const rawHealth =
    (100 - avgRiskScore) * 0.4 +
    (100 - Math.min(100, criticalCount * 15)) * 0.25 +
    (100 - outdatedRatio) * 0.2 +
    maintenanceScore * 0.15;

  const healthScore = Math.round(Math.max(0, Math.min(100, rawHealth)));
  const healthLevel = healthLevelFromScore(healthScore);

  const topIssues: string[] = [];
  if (criticalCount > 0) topIssues.push(`${criticalCount} critical risk package${criticalCount > 1 ? "s" : ""} detected`);
  if (highCount > 0) topIssues.push(`${highCount} high risk package${highCount > 1 ? "s" : ""} need attention`);
  if (outdatedRatio > 30) topIssues.push(`${outdatedRatio}% of packages not published in over a year`);
  if (maintenanceScore < 50) topIssues.push(`Only ${maintenanceScore}% of packages show active GitHub maintenance`);
  if (avgRiskScore > 50) topIssues.push(`Average dependency risk score is ${avgRiskScore}/100 — above acceptable threshold`);

  const summary =
    healthLevel === "excellent"
      ? `Your dependency tree is in excellent shape. Average risk is low and most packages are actively maintained.`
      : healthLevel === "good"
      ? `Generally healthy with a few packages worth monitoring. Address high-risk items within the next sprint.`
      : healthLevel === "risky"
      ? `Several dependencies are showing maintenance or adoption problems. Immediate review recommended.`
      : `Codebase health is critical. Multiple abandoned or high-risk dependencies present real supply-chain risk.`;

  return {
    healthScore,
    healthLevel,
    summary,
    breakdown: { avgRiskScore, outdatedRatio, criticalCount, maintenanceScore },
    topIssues,
  };
}
