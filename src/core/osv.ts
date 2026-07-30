import type { PackageVulnerabilityAnalysis, FoundVulnerability, VulnerabilitySeverity } from "../types.js";
import { fetchWithRetry } from "../lib/fetch-with-retry.js";
import { BoundedCache } from "../lib/bounded-cache.js";
import { logger } from "../lib/logger.js";
import { BATCH_SIZE } from "./analyzer.js";

const OSV_API = "https://api.osv.dev/v1/querybatch";

// Cache for individual package vulnerability results
const cache = new BoundedCache<PackageVulnerabilityAnalysis>(500, 10 * 60 * 1000); // 500 items, 10 min TTL

// OSV's severity scoring
function getSeverity(score: string): VulnerabilitySeverity {
  const numericScore = parseFloat(score);
  if (numericScore >= 9.0) return "critical";
  if (numericScore >= 7.0) return "high";
  if (numericScore >= 4.0) return "medium";
  if (numericScore > 0) return "low";
  return "none";
}

async function _fetchVulnerabilities(packages: { name: string; version: string }[]): Promise<PackageVulnerabilityAnalysis[]> {
  const results: PackageVulnerabilityAnalysis[] = [];
  const queries = packages.map(pkg => ({ package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version }));

  try {
    const response = await fetchWithRetry(OSV_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
    });

    if (!response.ok) {
      logger.warn("OSV API returned non-OK status", { status: response.status });
      return packages.map(pkg => ({ packageName: pkg.name, version: pkg.version, status: 'unknown', vulnerabilities: [] }));
    }

    const data = await response.json() as { results: { vulns: any[] }[] };
    
    for (let i = 0; i < packages.length; i++) {
      const pkg = packages[i];
      const res = data.results[i];
      const vulnerabilities: FoundVulnerability[] = (res.vulns || []).map(v => ({
        id: v.id,
        severity: v.database_specific?.severity ?? (v.severity?.[0]?.score ? getSeverity(v.severity[0].score) : 'none'),
        description: v.summary || v.details || 'No description provided.',
        affectedVersions: v.affected.map((a: any) => a.versions).flat().join(', '),
        fixedIn: v.affected.find((a: any) => a.versions.includes(pkg.version))?.ranges.find((r: any) => r.type === 'SEMVER')?.events.find((e: any) => e.fixed)?.fixed || null,
      }));
      
      const analysis: PackageVulnerabilityAnalysis = {
        packageName: pkg.name,
        version: pkg.version,
        status: 'scanned',
        vulnerabilities,
      };

      cache.set(`${pkg.name}@${pkg.version}`, analysis);
      results.push(analysis);
    }

  } catch (error) {
    logger.error("Failed to fetch vulnerabilities from OSV", { error: (error as Error).message });
    return packages.map(pkg => ({ packageName: pkg.name, version: pkg.version, status: 'unknown', vulnerabilities: [] }));
  }

  return results;
}

export async function queryOsvByBatch(packages: { name: string; version: string }[]): Promise<PackageVulnerabilityAnalysis[]> {
  const results: PackageVulnerabilityAnalysis[] = [];
  const toFetch: { name: string; version: string }[] = [];

  for (const pkg of packages) {
    const cached = cache.get(`${pkg.name}@${pkg.version}`);
    if (cached) {
      results.push(cached);
    } else {
      toFetch.push(pkg);
    }
  }

  if (toFetch.length > 0) {
    for (let i = 0; i < toFetch.length; i += BATCH_SIZE) {
        const batch = toFetch.slice(i, i + BATCH_SIZE);
        const batchResults = await _fetchVulnerabilities(batch);
        results.push(...batchResults);
    }
  }

  return results;
}
