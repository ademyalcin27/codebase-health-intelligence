import { readFile } from "fs/promises";
import { resolve } from "path";
import { z } from "zod";

import { validateProjectPath } from "../lib/validate-path.js";
import { logger } from "../lib/logger.js";
import {
  queryOsvBatched,
  osvCacheKey,
  type OsvPackageRef,
  type VulnerabilityFinding,
  type OsvSeverityLevel,
} from "../core/osv.js";

// ─── Schema ───────────────────────────────────────────────────────────────────

export const checkKnownVulnerabilitiesSchema = z.object({
  projectPath: z
    .string()
    .min(1)
    .describe("Absolute or relative path to the project directory containing package.json"),
});

export type CheckKnownVulnerabilitiesInput = z.infer<
  typeof checkKnownVulnerabilitiesSchema
>;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface VulnerabilityEntry {
  /** The CVE/GHSA id most relevant for display. */
  id: string;
  /** All IDs associated with the vuln (OSV id + CVE/GHSA aliases). */
  aliases: string[];
  /** Affected package name. */
  package: string;
  /** Installed/declared version of the package. */
  version: string;
  /** Affected version range (e.g. ">= 1.0.0, < 1.2.3"). */
  affectedRange: string | null;
  /** Severity bucket. */
  severity: OsvSeverityLevel;
  /** Numeric CVSS score, if available. */
  cvssScore: number | null;
  /** Fixed version, if available. */
  fixedVersion: string | null;
  /** Short summary of the vulnerability. */
  summary: string | null;
  /** Link to the advisory. */
  url: string | null;
}

export interface VulnerabilityGroup {
  count: number;
  vulnerabilities: VulnerabilityEntry[];
}

export interface VulnerabilityReport {
  projectPath: string;
  analyzedAt: string;
  totalDependenciesScanned: number;
  vulnerablePackageCount: number;
  totalVulnerabilities: number;
  /** Vulnerabilities grouped by severity (critical/high/medium/low/unknown). */
  bySeverity: {
    critical: VulnerabilityGroup;
    high: VulnerabilityGroup;
    medium: VulnerabilityGroup;
    low: VulnerabilityGroup;
    unknown: VulnerabilityGroup;
  };
  /** Per-package findings. */
  packages: Array<{
    name: string;
    version: string;
    type: "dependency" | "devDependency";
    status: "ok" | "vulnerable" | "unknown";
    vulnerabilities: VulnerabilityEntry[];
  }>;
  /** Non-fatal warnings collected during the run (e.g. degraded packages). */
  warnings: string[];
}

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Match the existing analyzer.ts batch-size convention. OSV /v1/querybatch
 * accepts up to 1000 queries per request; we cap at the project's BATCH_SIZE
 * (10) to stay consistent with the rest of the codebase and avoid hammering
 * external APIs.
 */
const BATCH_SIZE = 10;

// ─── Dependency collection ───────────────────────────────────────────────────

interface PkgJsonShape {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface LockfileShape {
  lockfileVersion?: number;
  packages?: Record<string, { version?: string }>;
}

/** Read package.json from a project directory. */
async function readPackageJson(projectPath: string): Promise<PkgJsonShape> {
  const path = resolve(projectPath, "package.json");
  let raw: string;
  try {
    raw = await readFile(path, "utf-8");
  } catch {
    throw new Error(`Cannot read package.json at: ${path}`);
  }
  try {
    return JSON.parse(raw) as PkgJsonShape;
  } catch {
    throw new Error(`Invalid JSON in package.json at: ${path}`);
  }
}

/**
 * Best-effort read of package-lock.json. Returns a map of package name → resolved
 * version for the top-level dependencies we care about. Returns null if the
 * lockfile is missing or unreadable.
 */
async function readLockfileVersions(
  projectPath: string,
  topLevelNames: Set<string>
): Promise<Map<string, string> | null> {
  const path = resolve(projectPath, "package-lock.json");
  let raw: string;
  try {
    raw = await readFile(path, "utf-8");
  } catch {
    return null; // lockfile is optional
  }
  let parsed: LockfileShape;
  try {
    parsed = JSON.parse(raw) as LockfileShape;
  } catch {
    logger.warn("package-lock.json is not valid JSON, using declared ranges only", {
      projectPath,
    });
    return null;
  }

  const resolved = new Map<string, string>();
  const packages = parsed.packages ?? {};
  for (const [key, meta] of Object.entries(packages)) {
    // "node_modules/<name>" entries; the root project is keyed as "" — skip it.
    if (key === "") continue;
    if (!key.startsWith("node_modules/")) continue;
    // Scoped packages: node_modules/@scope/name
    const name = key.slice("node_modules/".length);
    if (!topLevelNames.has(name)) continue;
    if (meta.version) resolved.set(name, meta.version);
  }
  return resolved;
}

/** Strip a range/specifier from a version string ("^1.2.3" → "1.2.3"). */
function cleanRangeSpecifier(spec: string): string {
  // Strip leading npm range characters: ^ ~ > < = *
  const cleaned = spec.replace(/^[~^>=<\s]*v?/, "").trim();
  // Keep only up to the first space ("1.2.3 || 2.0.0" → "1.2.3")
  return cleaned.split(/\s+/)[0] ?? cleaned;
}

interface DependencyEntry {
  name: string;
  version: string; // resolved version (lockfile) or cleaned range from package.json
  type: "dependency" | "devDependency";
}

/** Combine package.json declared deps with lockfile-resolved versions. */
async function collectDependencies(projectPath: string): Promise<DependencyEntry[]> {
  const pkg = await readPackageJson(projectPath);

  const deps = Object.entries(pkg.dependencies ?? {}).map(
    ([name, version]) => ({ name, version, type: "dependency" as const })
  );
  const devDeps = Object.entries(pkg.devDependencies ?? {}).map(
    ([name, version]) => ({ name, version, type: "devDependency" as const })
  );
  const declared = [...deps, ...devDeps];

  const topLevelNames = new Set(declared.map((d) => d.name));
  const lockVersions = await readLockfileVersions(projectPath, topLevelNames);

  return declared.map((d) => ({
    name: d.name,
    version: lockVersions?.get(d.name) ?? cleanRangeSpecifier(d.version),
    type: d.type,
  }));
}

// ─── Severity grouping helpers ───────────────────────────────────────────────

function emptyGroup(): VulnerabilityGroup {
  return { count: 0, vulnerabilities: [] };
}

function groupBySeverity(
  entries: VulnerabilityEntry[]
): VulnerabilityReport["bySeverity"] {
  const groups = {
    critical: emptyGroup(),
    high: emptyGroup(),
    medium: emptyGroup(),
    low: emptyGroup(),
    unknown: emptyGroup(),
  };
  for (const e of entries) {
    const bucket = groups[e.severity] ?? groups.unknown;
    bucket.vulnerabilities.push(e);
    bucket.count += 1;
  }
  return groups;
}

// ─── Main entry point ────────────────────────────────────────────────────────

export async function checkKnownVulnerabilities(
  input: CheckKnownVulnerabilitiesInput
): Promise<VulnerabilityReport> {
  const validPath = await validateProjectPath(input.projectPath);
  logger.info("Starting known-vulnerability scan", { projectPath: validPath });

  const dependencies = await collectDependencies(validPath);
  logger.info("Collected dependencies for OSV scan", {
    total: dependencies.length,
  });

  // Build the OSV query refs. Skip entries with a non-concrete version
  // (e.g. "*", "latest", workspace specifiers) — OSV needs a real version.
  const refs: OsvPackageRef[] = [];
  const refToEntry = new Map<string, DependencyEntry>();
  for (const d of dependencies) {
    if (!d.version || d.version === "*" || d.version === "latest") continue;
    const ref: OsvPackageRef = { name: d.name, version: d.version, ecosystem: "npm" };
    refs.push(ref);
    refToEntry.set(osvCacheKey(ref), d);
  }

  // Query OSV in batches of BATCH_SIZE. On a per-batch network failure, mark
  // every package in that batch as "unknown" (graceful degradation — never
  // fail the whole analysis, mirroring the analyzer.ts pattern).
  const findingsByRef = new Map<string, VulnerabilityFinding[]>();
  const warnings: string[] = [];

  for (let i = 0; i < refs.length; i += BATCH_SIZE) {
    const batch = refs.slice(i, i + BATCH_SIZE);
    logger.debug("Querying OSV batch", {
      batch: i / BATCH_SIZE + 1,
      size: batch.length,
    });

    let batchFindings: Map<string, VulnerabilityFinding[]>;
    try {
      batchFindings = await queryOsvBatched(batch, BATCH_SIZE);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn("OSV batch failed — marking packages as unknown", {
        batch: i / BATCH_SIZE + 1,
        error: message,
      });
      warnings.push(
        `OSV query failed for batch starting at index ${i}: ${message}. Affected packages marked "unknown".`
      );
      // Mark each package in this batch as unknown (no findings recorded).
      for (const ref of batch) {
        findingsByRef.set(osvCacheKey(ref), []);
      }
      continue;
    }

    for (const [k, v] of batchFindings) findingsByRef.set(k, v);
  }

  // Assemble the per-package report.
  const packages: VulnerabilityReport["packages"] = [];
  const allEntries: VulnerabilityEntry[] = [];

  for (const ref of refs) {
    const key = osvCacheKey(ref);
    const entry = refToEntry.get(key);
    if (!entry) continue;

    const findings = findingsByRef.get(key) ?? [];

    // Build display entries.
    const entries: VulnerabilityEntry[] = findings.map((f) => ({
      id: f.id,
      aliases: f.aliases,
      package: f.package,
      version: f.version,
      affectedRange: f.affectedRange,
      severity: f.severity,
      cvssScore: f.cvssScore,
      fixedVersion: f.fixedVersion,
      summary: f.summary,
      url: f.url,
    }));

    const status: "ok" | "vulnerable" | "unknown" =
      entries.length > 0 ? "vulnerable" : "ok";

    packages.push({
      name: entry.name,
      version: entry.version,
      type: entry.type,
      status,
      vulnerabilities: entries,
    });

    if (entries.length > 0) allEntries.push(...entries);
  }

  const bySeverity = groupBySeverity(allEntries);

  // If any batch errored, mark affected packages as "unknown" for clarity.
  // We already set warnings; additionally, re-tag packages whose refs were
  // part of failed batches so their status reads "unknown" instead of "ok".
  if (warnings.length > 0) {
    for (const p of packages) {
      // A package with no findings but a degraded batch is "unknown".
      if (p.status === "ok") p.status = "unknown";
    }
  }

  const vulnerablePackageCount = packages.filter(
    (p) => p.status === "vulnerable"
  ).length;

  const report: VulnerabilityReport = {
    projectPath: validPath,
    analyzedAt: new Date().toISOString(),
    totalDependenciesScanned: refs.length,
    vulnerablePackageCount,
    totalVulnerabilities: allEntries.length,
    bySeverity,
    packages,
    warnings,
  };

  logger.info("Known-vulnerability scan complete", {
    totalScanned: report.totalDependenciesScanned,
    vulnerablePackages: vulnerablePackageCount,
    totalVulns: report.totalVulnerabilities,
  });

  return report;
}
