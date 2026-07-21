import { readFile } from "fs/promises";
import { resolve } from "path";
import { z } from "zod";
import { logger } from "../lib/logger.js";
import { validateProjectPath } from "../lib/validate-path.js";
import {
  queryVulnerabilities,
  groupBySeverity,
  type PackageVulnerabilityQuery,
  type PackageVulnerabilityResult,
  type SeverityGroups,
} from "../core/osv.js";

export const checkKnownVulnerabilitiesSchema = z.object({
  projectPath: z.string().min(1).describe("Absolute or relative path to the project directory containing package.json"),
});

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface PackageLockJson {
  packages?: Record<string, { version?: string }>;
  dependencies?: Record<string, { version?: string }>;
}

export interface CheckKnownVulnerabilitiesResult {
  projectPath: string;
  totalPackagesScanned: number;
  packagesWithVulnerabilities: number;
  packagesUnknown: number;
  packages: PackageVulnerabilityResult[];
  vulnerabilitiesBySeverity: SeverityGroups;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

async function readPackageJson(projectPath: string): Promise<PackageJson> {
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

async function readPackageLockJson(projectPath: string): Promise<PackageLockJson | null> {
  const path = resolve(projectPath, "package-lock.json");
  try {
    const raw = await readFile(path, "utf-8");
    return JSON.parse(raw) as PackageLockJson;
  } catch {
    // package-lock.json is optional; absence or parse failure just means we
    // fall back to the (possibly range-based) versions from package.json.
    return null;
  }
}

/**
 * Resolves the concrete, locked version for a dependency if `package-lock.json`
 * is available, falling back to the version/range declared in package.json.
 */
function resolveLockedVersion(
  name: string,
  declaredVersion: string,
  lock: PackageLockJson | null
): string {
  if (!lock) return declaredVersion;

  // npm v7+ lockfile format: packages["node_modules/<name>"].version
  const fromPackages = lock.packages?.[`node_modules/${name}`]?.version;
  if (fromPackages) return fromPackages;

  // npm v6 lockfile format: dependencies[<name>].version
  const fromDependencies = lock.dependencies?.[name]?.version;
  if (fromDependencies) return fromDependencies;

  return declaredVersion;
}

/**
 * Reads package.json (and, if present, package-lock.json) from `projectPath`
 * to build the full list of dependencies + devDependencies, then queries the
 * OSV module for known vulnerabilities and groups the findings by severity.
 */
export async function checkKnownVulnerabilitiesTool(
  input: z.infer<typeof checkKnownVulnerabilitiesSchema>
): Promise<CheckKnownVulnerabilitiesResult> {
  const { projectPath } = input;
  const validPath = await validateProjectPath(projectPath);

  logger.info("checkKnownVulnerabilitiesTool called", { projectPath: validPath });

  const pkg = await readPackageJson(validPath);
  const lock = await readPackageLockJson(validPath);

  const allDeps: Record<string, string> = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
  };

  const queries: PackageVulnerabilityQuery[] = Object.entries(allDeps).map(([name, version]) => ({
    name,
    version: resolveLockedVersion(name, version, lock),
  }));

  logger.info("Checking dependencies for known vulnerabilities", {
    projectPath: validPath,
    total: queries.length,
    usedLockfile: lock !== null,
  });

  const packages = await queryVulnerabilities(queries);
  const vulnerabilitiesBySeverity = groupBySeverity(packages);

  const summary = {
    critical: vulnerabilitiesBySeverity.critical.length,
    high: vulnerabilitiesBySeverity.high.length,
    medium: vulnerabilitiesBySeverity.medium.length,
    low: vulnerabilitiesBySeverity.low.length,
    total:
      vulnerabilitiesBySeverity.critical.length +
      vulnerabilitiesBySeverity.high.length +
      vulnerabilitiesBySeverity.medium.length +
      vulnerabilitiesBySeverity.low.length,
  };

  const result: CheckKnownVulnerabilitiesResult = {
    projectPath: validPath,
    totalPackagesScanned: packages.length,
    packagesWithVulnerabilities: packages.filter((p) => p.vulnerabilities.length > 0).length,
    packagesUnknown: packages.filter((p) => p.status === "unknown").length,
    packages,
    vulnerabilitiesBySeverity,
    summary,
  };

  logger.info("checkKnownVulnerabilitiesTool complete", {
    projectPath: validPath,
    totalPackagesScanned: result.totalPackagesScanned,
    packagesWithVulnerabilities: result.packagesWithVulnerabilities,
    packagesUnknown: result.packagesUnknown,
    summary: result.summary,
  });

  return result;
}
