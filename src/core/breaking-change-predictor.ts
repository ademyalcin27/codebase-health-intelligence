import type { BreakingChangePrediction, DependencyRisk, ImpactSeverity, VersionDelta } from "../types.js";

function parseVersion(v: string): [number, number, number] {
  const clean = v.replace(/^[\^~>=<]/, "").split(".").map(Number);
  return [clean[0] ?? 0, clean[1] ?? 0, clean[2] ?? 0];
}

function computeVersionDelta(current: string, latest: string): VersionDelta {
  const [curMaj, curMin, curPat] = parseVersion(current);
  const [latMaj, latMin, latPat] = parseVersion(latest);

  const majorBump = latMaj > curMaj;
  const minorBump = !majorBump && latMin > curMin;
  const patchBump = !majorBump && !minorBump && latPat > curPat;

  // Rough estimate of how many releases behind
  const versionsOutdated = majorBump
    ? (latMaj - curMaj) * 10
    : minorBump
    ? latMin - curMin
    : latPat - curPat;

  return { current, latest, majorBump, minorBump, patchBump, versionsOutdated: Math.max(0, versionsOutdated) };
}

function predictBreakingChanges(name: string, delta: VersionDelta): string[] {
  const changes: string[] = [];

  if (delta.majorBump) {
    changes.push(`Major version bump (${delta.current} → ${delta.latest}): high probability of breaking API changes`);
    changes.push("Public API signatures likely modified or removed");
    changes.push("Peer dependency requirements may have changed");
    // Package-specific heuristics
    if (/^react/.test(name)) changes.push("JSX transform or hooks API may have changed");
    if (/^webpack|^vite|^rollup/.test(name)) changes.push("Config file format likely changed");
    if (/^eslint|^prettier/.test(name)) changes.push("Config schema or rule names may have changed");
    if (/^express|^fastify|^koa/.test(name)) changes.push("Middleware signature or routing API may differ");
    if (/^next|^nuxt/.test(name)) changes.push("Framework config, routing or rendering model likely changed");
    if (/^@types\//.test(name)) changes.push("Type definitions may be incompatible with your TypeScript version");
  } else if (delta.minorBump) {
    changes.push(`Minor version bump (${delta.current} → ${delta.latest}): new features, generally backward compatible`);
    if (delta.versionsOutdated > 5) {
      changes.push("Multiple minor versions behind — accumulated deprecations may affect your code");
    }
  } else if (delta.patchBump) {
    changes.push(`Patch update (${delta.current} → ${delta.latest}): bug fixes only, safe to update`);
  } else {
    changes.push("Version is current or parse failed");
  }

  return changes;
}

function computeImpactSeverity(delta: VersionDelta, riskScore: number): ImpactSeverity {
  if (delta.majorBump && riskScore >= 50) return "breaking";
  if (delta.majorBump) return "high";
  if (delta.minorBump && delta.versionsOutdated > 5) return "medium";
  if (delta.minorBump) return "low";
  if (delta.patchBump) return "none";
  return "none";
}

function identifyAffectedAreas(name: string, delta: VersionDelta): string[] {
  const areas: string[] = [];
  if (/react|vue|angular|svelte|nuxt|next/.test(name)) areas.push("UI Components", "Rendering Layer");
  if (/express|fastify|koa|hono|nestjs/.test(name)) areas.push("HTTP Routing", "Middleware Stack");
  if (/prisma|sequelize|mongoose|typeorm|drizzle/.test(name)) areas.push("Database Layer", "Data Models");
  if (/jest|vitest|mocha|chai|playwright|cypress/.test(name)) areas.push("Test Suite");
  if (/webpack|vite|rollup|esbuild|parcel/.test(name)) areas.push("Build Pipeline");
  if (/typescript|@types/.test(name)) areas.push("Type System", "Compilation");
  if (/eslint|prettier|biome/.test(name)) areas.push("Linting & Formatting");
  if (/tailwind|sass|postcss/.test(name)) areas.push("Styling System");
  if (delta.majorBump && areas.length === 0) areas.push("Core Application Logic");
  if (areas.length === 0) areas.push("Indirect / Transitive Dependencies");
  return areas;
}

function computeConfidence(delta: VersionDelta, npm: DependencyRisk["npm"]): number {
  let score = 50;
  if (delta.majorBump) score += 30;
  else if (delta.minorBump) score += 10;
  if (npm.weeklyDownloads !== null && npm.weeklyDownloads > 100_000) score += 10;
  if (npm.daysSincePublish !== null && npm.daysSincePublish < 90) score += 10;
  return Math.min(100, score);
}

export function predictPackageBreakingChanges(dep: DependencyRisk): BreakingChangePrediction {
  const currentVersion = dep.version.replace(/^[\^~]/, "");
  const latestVersion = dep.npm.latestVersion;

  const delta = computeVersionDelta(currentVersion, latestVersion);
  const likelyBreakingChanges = predictBreakingChanges(dep.name, delta);
  const impactSeverity = computeImpactSeverity(delta, dep.riskScore);
  const affectedAreas = identifyAffectedAreas(dep.name, delta);
  const confidenceScore = computeConfidence(delta, dep.npm);

  const reasoning = delta.majorBump
    ? `This package jumped ${delta.versionsOutdated > 1 ? `${delta.versionsOutdated} major versions` : "one major version"}. Major bumps almost always include breaking changes in the public API.`
    : delta.minorBump
    ? `Minor version updates are typically safe but ${delta.versionsOutdated} releases behind means accumulated deprecated patterns in your codebase may break.`
    : `Patch-level update. Safe to apply. No breaking changes expected by semver convention.`;

  return {
    packageName: dep.name,
    currentVersion,
    latestVersion,
    versionDelta: delta,
    impactSeverity,
    likelyBreakingChanges,
    affectedAreas,
    confidenceScore,
    reasoning,
  };
}

export function predictProjectBreakingChanges(deps: DependencyRisk[]): BreakingChangePrediction[] {
  return deps
    .map(predictPackageBreakingChanges)
    .sort((a, b) => {
      const severityOrder: Record<ImpactSeverity, number> = { breaking: 4, high: 3, medium: 2, low: 1, none: 0 };
      return severityOrder[b.impactSeverity] - severityOrder[a.impactSeverity];
    });
}
