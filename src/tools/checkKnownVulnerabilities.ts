import { readFile } from "fs/promises";
import { resolve } from "path";
import { z } from "zod";
import { readPackageJson } from "../core/analyzer.js";
import { fetchVulnerabilities } from "../core/osv.js";
import { validateProjectPath } from "../lib/validate-path.js";
import { logger } from "../lib/logger.js";
import type {
  PackageVulnerabilityResult,
  Vulnerability,
  VulnerabilityFinding,
  VulnerabilityReport,
} from "../types.js";

export const checkKnownVulnerabilitiesSchema = z.object({
  projectPath: z.string().min(1).describe("Path to project directory containing package.json"),
});

const BATCH_SIZE = 10;

interface LockPackageEntry {
  version?: string;
}

interface PackageLockJson {
  packages?: Record<string, LockPackageEntry>;
  dependencies?: Record<string, LockPackageEntry & { dependencies?: Record<string, LockPackageEntry> }>;
}

/**
 * Reads package-lock.json (if present) and returns the resolved installed
 * version for each dependency name, falling back to the declared range in
 * package.json when the lockfile is missing or doesn't cover a package.
 */
async function readLockedVersions(projectPath: string): Promise<Map<string, string>> {
  const locked = new Map<string, string>();
  const path = resolve(projectPath, "package-lock.json");

  let raw: string;
  try {
    raw = await readFile(path, "utf-8");
  } catch {
    logger.debug("No package-lock.json found, falling back to package.json version ranges", { projectPath });
    return locked;
  }

  let lock: PackageLockJson;
  try {
    lock = JSON.parse(raw) as PackageLockJson;
  } catch {
    logger.warn("Invalid JSON in package-lock.json, falling back to package.json version ranges", { path });
    return locked;
  }

  // lockfileVersion 2/3 format: "packages" keyed by "node_modules/<name>"
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (!key.startsWith("node_modules/")) continue;
    const name = key.slice("node_modules/".length);
    if (name.includes("node_modules/")) continue; // nested transitive dep, keep top-level only
    if (entry.version) locked.set(name, entry.version);
  }

  // lockfileVersion 1 format: "dependencies" keyed by name directly
  for (const [name, entry] of Object.entries(lock.dependencies ?? {})) {
    if (!locked.has(name) && entry.version) locked.set(name, entry.version);
  }

  return locked;
}

function cleanVersionRange(version: string): string {
  return version.replace(/^[\^~>=<]/, "");
}

function fallbackPackageResult(name: string, version: string, errorMessage: string): PackageVulnerabilityResult {
  return {
    name,
    version,
    vulnerabilities: [],
    status: "unknown",
    error: errorMessage,
  };
}

function toFindings(name: string, version: string, vulns: Vulnerability[]): VulnerabilityFinding[] {
  return vulns.map((v) => ({ ...v, packageName: name, packageVersion: version }));
}

export async function checkKnownVulnerabilities(
  input: z.infer<typeof checkKnownVulnerabilitiesSchema>
): Promise<VulnerabilityReport> {
  const validPath = await validateProjectPath(input.projectPath);

  logger.info("Starting known vulnerability scan", { projectPath: validPath });

  const pkg = await readPackageJson(validPath);
  const lockedVersions = await readLockedVersions(validPath);

  const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  const entries = Object.entries(deps).map(([name, declaredRange]) => ({
    name,
    version: lockedVersions.get(name) ?? cleanVersionRange(declaredRange),
  }));

  logger.info("Checking packages for known vulnerabilities", { total: entries.length });

  const packages: PackageVulnerabilityResult[] = [];

  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const batch = entries.slice(i, i + BATCH_SIZE);
    logger.debug("Processing vulnerability batch", { batch: i / BATCH_SIZE + 1, size: batch.length });

    const batchResults = await Promise.all(
      batch.map(async ({ name, version }): Promise<PackageVulnerabilityResult> => {
        try {
          const vulnerabilities = await fetchVulnerabilities(name, version);
          return { name, version, vulnerabilities, status: "checked" };
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          logger.warn("Vulnerability lookup failed, marking package as unknown", {
            package: name,
            version,
            error: message,
          });
          return fallbackPackageResult(name, version, message);
        }
      })
    );

    packages.push(...batchResults);
  }

  const bySeverity: VulnerabilityReport["bySeverity"] = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    unknown: [],
  };

  const packagesWithUnknownStatus: string[] = [];
  let totalVulnerabilities = 0;

  for (const pkgResult of packages) {
    if (pkgResult.status === "unknown") {
      packagesWithUnknownStatus.push(pkgResult.name);
      continue;
    }

    const findings = toFindings(pkgResult.name, pkgResult.version, pkgResult.vulnerabilities);
    totalVulnerabilities += findings.length;

    for (const finding of findings) {
      bySeverity[finding.severity].push(finding);
    }
  }

  logger.info("Vulnerability scan complete", {
    total: packages.length,
    totalVulnerabilities,
    unknown: packagesWithUnknownStatus.length,
  });

  return {
    projectPath: validPath,
    analyzedAt: new Date().toISOString(),
    totalPackagesChecked: packages.length,
    totalVulnerabilities,
    packagesWithUnknownStatus,
    bySeverity,
    packages,
  };
}
