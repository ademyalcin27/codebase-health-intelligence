import type { DependencyRisk, UpgradeAction, UpgradePlan, UpgradeStep } from "../types.js";
import { predictPackageBreakingChanges } from "./breaking-change-predictor.js";

function chooseAction(dep: DependencyRisk): UpgradeAction {
  const prediction = predictPackageBreakingChanges(dep);
  if (dep.riskScore >= 75 && prediction.versionDelta.majorBump) return "replace";
  if (prediction.versionDelta.majorBump) return "cautious-upgrade";
  if (dep.riskScore < 25 || prediction.versionDelta.patchBump) return "safe-upgrade";
  if (dep.riskScore >= 50) return "hold";
  return "cautious-upgrade";
}

function buildWarnings(dep: DependencyRisk, action: UpgradeAction): string[] {
  const warnings: string[] = [];
  const prediction = predictPackageBreakingChanges(dep);
  if (prediction.versionDelta.majorBump) {
    warnings.push(`Major version jump: ${prediction.currentVersion} → ${prediction.latestVersion}`);
  }
  if (dep.npm.daysSincePublish !== null && dep.npm.daysSincePublish > 365) {
    warnings.push(`Last published ${dep.npm.daysSincePublish} days ago — package may be unmaintained`);
  }
  if (dep.github.openIssues !== null && dep.github.openIssues > 100) {
    warnings.push(`${dep.github.openIssues} open GitHub issues`);
  }
  if (dep.github.daysSinceLastCommit !== null && dep.github.daysSinceLastCommit > 180) {
    warnings.push(`Repository inactive for ${dep.github.daysSinceLastCommit} days`);
  }
  if (action === "replace") {
    warnings.push("Consider replacing this package with a better-maintained alternative");
  }
  return warnings;
}

function sortByUpgradeSafety(deps: DependencyRisk[]): DependencyRisk[] {
  return [...deps].sort((a, b) => {
    const predA = predictPackageBreakingChanges(a);
    const predB = predictPackageBreakingChanges(b);
    const deltaScore = (d: typeof predA) =>
      d.versionDelta.patchBump ? 0 : d.versionDelta.minorBump ? 1 : d.versionDelta.majorBump ? 2 : 3;
    const ds = deltaScore(predA) - deltaScore(predB);
    if (ds !== 0) return ds;
    return a.riskScore - b.riskScore;
  });
}

export function generateUpgradePlan(projectPath: string, deps: DependencyRisk[]): UpgradePlan {
  const sorted = sortByUpgradeSafety(deps);

  const steps: UpgradeStep[] = sorted.map((dep, idx) => {
    const action = chooseAction(dep);
    const warnings = buildWarnings(dep, action);
    const prediction = predictPackageBreakingChanges(dep);
    const targetVersion = dep.npm.latestVersion !== "unknown" ? dep.npm.latestVersion : "latest";

    const reasoning =
      action === "safe-upgrade"
        ? `Low risk score (${dep.riskScore}) and non-breaking update. Safe to upgrade immediately.`
        : action === "cautious-upgrade"
        ? `Risk score ${dep.riskScore}. ${prediction.reasoning} Test thoroughly after upgrading.`
        : action === "hold"
        ? `High risk score (${dep.riskScore}) with uncertain stability. Hold until team reviews alternatives.`
        : `Critical risk (${dep.riskScore}). Signs of abandonment or critical issues. Plan a replacement.`;

    return {
      order: idx + 1,
      packageName: dep.name,
      currentVersion: dep.version,
      targetVersion,
      action,
      riskScore: dep.riskScore,
      warnings,
      upgradeCommand: `npm install ${dep.name}@${targetVersion}`,
      rollbackCommand: `npm install ${dep.name}@${dep.version.replace(/^[\^~]/, "")}`,
      reasoning,
    };
  });

  const summary = {
    safeUpgrades: steps.filter((s) => s.action === "safe-upgrade").length,
    cautiousUpgrades: steps.filter((s) => s.action === "cautious-upgrade").length,
    holdPackages: steps.filter((s) => s.action === "hold").length,
    replacePackages: steps.filter((s) => s.action === "replace").length,
  };

  const hasCritical = steps.some((s) => s.action === "replace" || s.riskScore >= 75);
  const hasHigh = steps.some((s) => s.riskScore >= 50);
  const estimatedRisk = hasCritical ? "critical" : hasHigh ? "high" : summary.cautiousUpgrades > 3 ? "medium" : "low";

  const globalWarnings: string[] = [];
  if (summary.replacePackages > 0) {
    globalWarnings.push(`${summary.replacePackages} package(s) flagged for replacement — high risk and potentially unmaintained`);
  }
  if (summary.holdPackages > 0) {
    globalWarnings.push(`${summary.holdPackages} package(s) on hold — review before upgrading`);
  }
  if (steps.some((s) => s.action === "cautious-upgrade" && s.warnings.some((w) => w.includes("Major")))) {
    globalWarnings.push("Multiple major version upgrades detected — run full test suite after each step");
  }

  return {
    projectPath,
    generatedAt: new Date().toISOString(),
    totalPackages: steps.length,
    estimatedRisk,
    steps,
    summary,
    executionOrder: steps
      .filter((s) => s.action !== "hold" && s.action !== "replace")
      .map((s) => s.packageName),
    globalWarnings,
    rollbackStrategy:
      "Use git stash or package-lock.json snapshot before starting upgrades. Run `npm install <pkg>@<oldVersion>` to rollback individual packages. Keep package-lock.json in version control.",
  };
}
