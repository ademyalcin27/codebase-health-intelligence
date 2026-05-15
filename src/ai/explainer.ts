import type { DependencyRisk, DependencyExplanation, ExplanationSignal } from "../types.js";

function formatDownloads(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M/week`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K/week`;
  return `${n}/week`;
}

function buildSignals(dep: DependencyRisk): ExplanationSignal[] {
  const signals: ExplanationSignal[] = [];

  // Publish date
  if (dep.npm.daysSincePublish !== null) {
    const days = dep.npm.daysSincePublish;
    signals.push({
      label: "Last published",
      value: `${days} days ago`,
      impact: days > 365 ? "negative" : days > 180 ? "neutral" : "positive",
    });
  } else {
    signals.push({ label: "Last published", value: "Unknown", impact: "negative" });
  }

  // Downloads
  if (dep.npm.weeklyDownloads !== null) {
    const dl = dep.npm.weeklyDownloads;
    signals.push({
      label: "Weekly downloads",
      value: formatDownloads(dl),
      impact: dl >= 100_000 ? "positive" : dl >= 1_000 ? "neutral" : "negative",
    });
  } else {
    signals.push({ label: "Weekly downloads", value: "Unavailable", impact: "neutral" });
  }

  // GitHub
  if (dep.github.available) {
    if (dep.github.daysSinceLastCommit !== null) {
      const d = dep.github.daysSinceLastCommit;
      signals.push({
        label: "Last commit",
        value: `${d} days ago`,
        impact: d > 365 ? "negative" : d > 90 ? "neutral" : "positive",
      });
    }
    if (dep.github.openIssues !== null) {
      signals.push({
        label: "Open issues",
        value: String(dep.github.openIssues),
        impact: dep.github.openIssues > 200 ? "negative" : dep.github.openIssues > 50 ? "neutral" : "positive",
      });
    }
  } else {
    signals.push({ label: "GitHub repository", value: "Not found or inaccessible", impact: "negative" });
  }

  return signals;
}

function buildEcosystemContext(dep: DependencyRisk): string {
  const dl = dep.npm.weeklyDownloads;
  if (dl === null) return "Download data unavailable — cannot assess ecosystem adoption.";
  if (dl >= 10_000_000) return "Extremely high adoption. Part of the JavaScript ecosystem's core infrastructure.";
  if (dl >= 1_000_000) return "Widely adopted. Used across thousands of production projects.";
  if (dl >= 100_000) return "Moderate adoption. Established within its domain.";
  if (dl >= 10_000) return "Niche adoption. Popular in specific communities but not mainstream.";
  if (dl >= 1_000) return "Low adoption. Limited community usage — evaluate necessity carefully.";
  return "Minimal adoption. Very few weekly downloads — this package may be experimental or abandoned.";
}

function buildMaintenanceAssessment(dep: DependencyRisk): string {
  const days = dep.npm.daysSincePublish;
  const commitDays = dep.github.daysSinceLastCommit;
  const hasRepo = dep.github.available;

  if (!hasRepo) return "No accessible repository found. Maintenance status cannot be verified — treat as high risk.";
  if (days !== null && days > 1000 && (commitDays === null || commitDays > 365)) {
    return "This package appears abandoned. No meaningful activity in over a year across both npm and GitHub.";
  }
  if (days !== null && days > 365) {
    return "Package has not been published in over a year. May still receive commits but releases are infrequent.";
  }
  if (commitDays !== null && commitDays > 180) {
    return "Repository activity is low. Issues may accumulate without timely resolution.";
  }
  return "Package shows active maintenance signals. Recent publishes and repository activity are healthy.";
}

function buildRecommendation(dep: DependencyRisk): string {
  if (dep.riskLevel === "critical") {
    return "REPLACE or pin version immediately. This package shows critical risk signals. Evaluate alternatives before your next release.";
  }
  if (dep.riskLevel === "high") {
    return "Review this dependency. Upgrade to latest if a newer version exists, or plan a replacement. Monitor for further deterioration.";
  }
  if (dep.riskLevel === "medium") {
    return "Keep on your watchlist. No immediate action required but re-evaluate in 90 days if signals do not improve.";
  }
  return "No action needed. This package is well-maintained and widely adopted.";
}

export function explainDependency(dep: DependencyRisk): DependencyExplanation {
  const signals = buildSignals(dep);
  const negativeCount = signals.filter((s) => s.impact === "negative").length;

  const verdict =
    dep.riskLevel === "critical"
      ? `⛔ ${dep.name} is critically risky`
      : dep.riskLevel === "high"
      ? `⚠️ ${dep.name} has elevated risk`
      : dep.riskLevel === "medium"
      ? `🟡 ${dep.name} has moderate risk`
      : `✅ ${dep.name} is in good health`;

  const riskSummary = `Risk score ${dep.riskScore}/100 (${dep.riskLevel}). ${negativeCount} of ${signals.length} signals indicate problems.`;

  return {
    packageName: dep.name,
    verdict,
    riskSummary,
    signals,
    ecosystemContext: buildEcosystemContext(dep),
    maintenanceAssessment: buildMaintenanceAssessment(dep),
    recommendation: buildRecommendation(dep),
  };
}
