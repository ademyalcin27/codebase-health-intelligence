import type { NpmMetadata, GitHubMetadata, RiskLevel, ScoreBreakdown } from "../types.js";

export function computeRiskScore(
  npm: NpmMetadata,
  github: GitHubMetadata
): { riskScore: number; riskLevel: RiskLevel; scoreBreakdown: ScoreBreakdown } {
  const breakdown: ScoreBreakdown = {
    stalePublish: 0,
    lowDownloads: 0,
    staleCommit: 0,
    missingRepo: 0,
    highIssues: 0,
    total: 0,
  };

  if (npm.daysSincePublish !== null) {
    if (npm.daysSincePublish > 1000) breakdown.stalePublish = 50;
    else if (npm.daysSincePublish > 365) breakdown.stalePublish = 30;
  } else {
    breakdown.stalePublish = 15;
  }

  if (npm.weeklyDownloads !== null) {
    if (npm.weeklyDownloads < 100) breakdown.lowDownloads = 30;
    else if (npm.weeklyDownloads < 1000) breakdown.lowDownloads = 15;
  } else {
    breakdown.lowDownloads = 10;
  }

  if (!github.available || npm.repositoryUrl === null) {
    breakdown.missingRepo = 40;
  } else {
    if (github.daysSinceLastCommit !== null && github.daysSinceLastCommit > 180) {
      breakdown.staleCommit = 20;
    }
    if (github.openIssues !== null && github.openIssues > 200) {
      breakdown.highIssues = 10;
    }
  }

  const raw = breakdown.stalePublish + breakdown.lowDownloads + breakdown.staleCommit + breakdown.missingRepo + breakdown.highIssues;
  breakdown.total = Math.min(100, raw);

  return { riskScore: breakdown.total, riskLevel: scoreToLevel(breakdown.total), scoreBreakdown: breakdown };
}

export function scoreToLevel(score: number): RiskLevel {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}
