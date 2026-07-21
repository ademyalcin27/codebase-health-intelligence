import fetch from "node-fetch";
import { logger } from "../lib/logger.js";

// ─── Types ─────────────────────────────────────────────────────────────────

export type VulnerabilitySeverity = "critical" | "high" | "medium" | "low";

export interface OsvVulnerability {
  id: string;
  summary: string | null;
  severity: VulnerabilitySeverity;
  cvssScore: number | null;
  fixedVersion: string | null;
  references: string[];
}

export interface PackageVulnerabilityQuery {
  name: string;
  version: string;
}

export interface PackageVulnerabilityResult {
  name: string;
  version: string;
  status: "ok" | "unknown";
  vulnerabilities: OsvVulnerability[];
  error?: string;
}

export interface VulnerabilityFinding extends OsvVulnerability {
  packageName: string;
  packageVersion: string;
}

export interface SeverityGroups {
  critical: VulnerabilityFinding[];
  high: VulnerabilityFinding[];
  medium: VulnerabilityFinding[];
  low: VulnerabilityFinding[];
}

// ─── Config ────────────────────────────────────────────────────────────────

const OSV_API_BASE = "https://api.osv.dev/v1";
const ECOSYSTEM = "npm";

// Kept consistent with the BATCH_SIZE used elsewhere (e.g. core/analyzer.ts)
// so we never hammer a third-party API harder than our own npm/GitHub calls do.
const BATCH_SIZE = 10;

// In-memory cache: "name@version" → { data, fetchedAt }
// Reuses the same process-scoped Map + 10 minute TTL pattern used by
// core/npm.ts and core/github.ts.
const cache = new Map<string, { data: PackageVulnerabilityResult; fetchedAt: number }>();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// ─── Helpers ───────────────────────────────────────────────────────────────

function cacheKey(name: string, version: string): string {
  return `${name}@${version}`;
}

/**
 * OSV's querybatch endpoint expects a concrete version, not a semver range.
 * package.json entries are often ranges (^4.17.21, ~1.2.3, >=2.0.0), so we
 * strip the leading range operators to get the best-effort concrete version.
 */
function cleanVersion(version: string): string {
  return version.replace(/^[\^~>=<\s]+/, "").trim();
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

function mapDatabaseSeverityLabel(raw: string): VulnerabilitySeverity {
  switch (raw.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "medium";
  }
}

function bucketByCvssScore(score: number): VulnerabilitySeverity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

/**
 * Attempts to extract a numeric CVSS base score out of an OSV `severity[].score`
 * entry. OSV mostly stores CVSS vector strings here (e.g. "CVSS:3.1/AV:N/...")
 * rather than a bare number, so this only succeeds for the (rarer) numeric case;
 * vector strings fall back to the database_specific.severity label instead.
 */
function extractNumericCvssScore(score: unknown): number | null {
  if (typeof score !== "string") return null;
  const asNumber = Number(score);
  return Number.isNaN(asNumber) ? null : asNumber;
}

/**
 * Determines a coarse severity bucket for a raw OSV vulnerability record.
 * Prefers the ecosystem-provided severity label (present on most GHSA-sourced
 * npm advisories) and falls back to a CVSS score bucket, defaulting to
 * "medium" when nothing usable is present.
 */
function determineSeverity(raw: Record<string, unknown>): { severity: VulnerabilitySeverity; cvssScore: number | null } {
  const databaseSpecific = raw["database_specific"] as Record<string, unknown> | undefined;
  const label = databaseSpecific?.["severity"];
  if (typeof label === "string" && label.length > 0) {
    return { severity: mapDatabaseSeverityLabel(label), cvssScore: null };
  }

  const severityEntries = raw["severity"] as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(severityEntries)) {
    for (const entry of severityEntries) {
      const numeric = extractNumericCvssScore(entry["score"]);
      if (numeric !== null) {
        return { severity: bucketByCvssScore(numeric), cvssScore: numeric };
      }
    }
  }

  return { severity: "medium", cvssScore: null };
}

function extractFixedVersion(raw: Record<string, unknown>): string | null {
  const affected = raw["affected"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(affected)) return null;

  for (const entry of affected) {
    const ranges = entry["ranges"] as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(ranges)) continue;
    for (const range of ranges) {
      const events = range["events"] as Array<Record<string, unknown>> | undefined;
      if (!Array.isArray(events)) continue;
      for (const event of events) {
        if (typeof event["fixed"] === "string") {
          return event["fixed"] as string;
        }
      }
    }
  }

  return null;
}

function extractReferences(raw: Record<string, unknown>): string[] {
  const refs = raw["references"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(refs)) return [];
  return refs
    .map((r) => (typeof r["url"] === "string" ? (r["url"] as string) : null))
    .filter((url): url is string => url !== null);
}

/**
 * Parses a single raw OSV vulnerability detail object (the response body of
 * GET /v1/vulns/{id}) into our normalized OsvVulnerability shape.
 */
export function parseVulnerabilityDetail(raw: Record<string, unknown>): OsvVulnerability {
  const { severity, cvssScore } = determineSeverity(raw);
  return {
    id: String(raw["id"] ?? "unknown"),
    summary: typeof raw["summary"] === "string" ? (raw["summary"] as string) : null,
    severity,
    cvssScore,
    fixedVersion: extractFixedVersion(raw),
    references: extractReferences(raw),
  };
}

/**
 * Parses the response of POST /v1/querybatch into a map of
 * "name@version" → vulnerability IDs found for that package.
 */
export function parseBatchResponse(
  queries: PackageVulnerabilityQuery[],
  raw: { results?: Array<{ vulns?: Array<{ id: string }> }> }
): Map<string, string[]> {
  const result = new Map<string, string[]>();
  const rawResults = raw.results ?? [];

  queries.forEach((query, index) => {
    const key = cacheKey(query.name, query.version);
    const vulns = rawResults[index]?.vulns ?? [];
    result.set(key, vulns.map((v) => v.id));
  });

  return result;
}

// ─── Network calls ─────────────────────────────────────────────────────────

async function queryOsvBatch(
  queries: PackageVulnerabilityQuery[]
): Promise<Map<string, string[]>> {
  const body = {
    queries: queries.map((q) => ({
      version: cleanVersion(q.version),
      package: { name: q.name, ecosystem: ECOSYSTEM },
    })),
  };

  const response = await fetch(`${OSV_API_BASE}/querybatch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`OSV querybatch returned HTTP ${response.status}`);
  }

  const data = (await response.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
  return parseBatchResponse(queries, data);
}

async function fetchVulnerabilityDetail(id: string): Promise<OsvVulnerability | null> {
  try {
    const response = await fetch(`${OSV_API_BASE}/vulns/${encodeURIComponent(id)}`);
    if (!response.ok) {
      logger.warn("OSV vuln detail fetch failed", { id, status: response.status });
      return null;
    }
    const raw = (await response.json()) as Record<string, unknown>;
    return parseVulnerabilityDetail(raw);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn("OSV vuln detail fetch errored", { id, error: message });
    return null;
  }
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Queries OSV.dev for known vulnerabilities affecting the given packages.
 *
 * - Uses the batch endpoint (/v1/querybatch) so many packages can be checked
 *   in a single round trip, chunked by BATCH_SIZE to avoid rate-limiting.
 * - Results are cached per "name@version" for CACHE_TTL_MS, reusing the same
 *   process-scoped Map pattern as core/npm.ts and core/github.ts.
 * - On network failure, affected packages degrade gracefully to
 *   status: "unknown" instead of throwing / aborting the whole scan.
 */
export async function queryVulnerabilities(
  packages: PackageVulnerabilityQuery[]
): Promise<PackageVulnerabilityResult[]> {
  const results: PackageVulnerabilityResult[] = [];
  const toFetch: PackageVulnerabilityQuery[] = [];

  for (const pkg of packages) {
    const cached = cache.get(cacheKey(pkg.name, pkg.version));
    if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
      results.push(cached.data);
    } else {
      toFetch.push(pkg);
    }
  }

  const batches = chunk(toFetch, BATCH_SIZE);

  for (const batch of batches) {
    logger.debug("Querying OSV.dev batch", { size: batch.length });

    let idsByPackage: Map<string, string[]>;
    try {
      idsByPackage = await queryOsvBatch(batch);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn("OSV querybatch failed, marking batch as unknown", {
        size: batch.length,
        error: message,
      });

      for (const pkg of batch) {
        const unknownResult: PackageVulnerabilityResult = {
          name: pkg.name,
          version: pkg.version,
          status: "unknown",
          vulnerabilities: [],
          error: message,
        };
        // Intentionally not cached: a transient outage shouldn't poison the
        // cache with a false "no known info" result for the full TTL window.
        results.push(unknownResult);
      }
      continue;
    }

    for (const pkg of batch) {
      const ids = idsByPackage.get(cacheKey(pkg.name, pkg.version)) ?? [];

      const details = await Promise.all(ids.map((id) => fetchVulnerabilityDetail(id)));
      const vulnerabilities = details.filter((d): d is OsvVulnerability => d !== null);

      const result: PackageVulnerabilityResult = {
        name: pkg.name,
        version: pkg.version,
        status: "ok",
        vulnerabilities,
      };

      cache.set(cacheKey(pkg.name, pkg.version), { data: result, fetchedAt: Date.now() });
      results.push(result);
    }
  }

  return results;
}

/**
 * Flattens per-package vulnerability results and groups every individual
 * finding by severity (critical/high/medium/low).
 */
export function groupBySeverity(results: PackageVulnerabilityResult[]): SeverityGroups {
  const groups: SeverityGroups = { critical: [], high: [], medium: [], low: [] };

  for (const result of results) {
    for (const vuln of result.vulnerabilities) {
      const finding: VulnerabilityFinding = {
        ...vuln,
        packageName: result.name,
        packageVersion: result.version,
      };
      groups[vuln.severity].push(finding);
    }
  }

  return groups;
}
