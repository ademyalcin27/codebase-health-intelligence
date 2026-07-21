import { fetchWithRetry } from "../lib/fetch-with-retry.js";
import { logger } from "../lib/logger.js";
import type { Vulnerability, VulnerabilitySeverity } from "../types.js";

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const GHSA_ADVISORIES_URL = "https://api.github.com/advisories";

// Process-scoped cache: `${name}@${version}` → { data, fetchedAt }
// Reuses the 10-minute TTL / Map pattern established in providers/npm.ts.
const cache = new Map<string, { data: Vulnerability[]; fetchedAt: number }>();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function cacheKey(name: string, version: string): string {
  return `${name}@${version}`;
}

interface OsvSeverityEntry {
  type?: string;
  score?: string;
}

interface OsvAffectedRange {
  type?: string;
  events?: { introduced?: string; fixed?: string; last_affected?: string }[];
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: OsvAffectedRange[];
  versions?: string[];
  database_specific?: { severity?: string };
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: OsvSeverityEntry[];
  affected?: OsvAffected[];
  references?: { url?: string }[];
  database_specific?: { severity?: string };
}

interface OsvQueryResponse {
  vulns?: OsvVuln[];
}

interface GhsaAdvisory {
  ghsa_id: string;
  summary?: string;
  description?: string;
  severity?: string; // "critical" | "high" | "moderate" | "low"
  html_url?: string;
  vulnerabilities?: {
    package?: { ecosystem?: string; name?: string };
    vulnerable_version_range?: string;
    first_patched_version?: string;
  }[];
}

function normalizeGhsaSeverity(severity: string | undefined): VulnerabilitySeverity {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
      return "medium";
    case "low":
      return "low";
    default:
      return "unknown";
  }
}

function severityFromCvssScore(score: number): VulnerabilitySeverity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "unknown";
}

function parseCvssScore(vector: string): number | null {
  // CVSS vector strings don't carry a numeric score directly in OSV's `severity[].score`
  // field for CVSS_V3 — some feeds put the numeric score itself in `score`. Handle both.
  const asNumber = Number(vector);
  if (!Number.isNaN(asNumber)) return asNumber;
  return null;
}

function extractOsvSeverity(vuln: OsvVuln, affected: OsvAffected | undefined): VulnerabilitySeverity {
  const dbSeverity = affected?.database_specific?.severity ?? vuln.database_specific?.severity;
  if (dbSeverity) {
    const normalized = normalizeGhsaSeverity(dbSeverity);
    if (normalized !== "unknown") return normalized;
  }

  for (const entry of vuln.severity ?? []) {
    if (!entry.score) continue;
    const score = parseCvssScore(entry.score);
    if (score !== null) {
      const level = severityFromCvssScore(score);
      if (level !== "unknown") return level;
    }
  }

  return "unknown";
}

function extractFixedVersion(affected: OsvAffected | undefined): string | null {
  for (const range of affected?.ranges ?? []) {
    for (const event of range.events ?? []) {
      if (event.fixed) return event.fixed;
    }
  }
  return null;
}

function extractAffectedVersions(affected: OsvAffected | undefined): string | null {
  if (!affected) return null;
  if (affected.versions && affected.versions.length > 0) {
    return affected.versions.join(", ");
  }
  for (const range of affected.ranges ?? []) {
    const introduced = range.events?.find((e) => e.introduced)?.introduced;
    const fixed = range.events?.find((e) => e.fixed)?.fixed;
    if (introduced) {
      return fixed ? `>=${introduced}, <${fixed}` : `>=${introduced}`;
    }
  }
  return null;
}

function mapOsvVuln(name: string, vuln: OsvVuln): Vulnerability {
  const affected = vuln.affected?.find((a) => a.package?.name === name) ?? vuln.affected?.[0];
  return {
    id: vuln.id,
    source: "osv",
    summary: vuln.summary ?? vuln.details ?? "No summary available",
    severity: extractOsvSeverity(vuln, affected),
    affectedVersions: extractAffectedVersions(affected),
    fixedVersion: extractFixedVersion(affected),
    references: (vuln.references ?? []).map((r) => r.url).filter((u): u is string => Boolean(u)),
  };
}

export async function fetchOsvVulnerabilities(name: string, version: string): Promise<Vulnerability[]> {
  logger.debug("Querying OSV.dev", { package: name, version });

  const response = await fetchWithRetry(OSV_QUERY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      version,
      package: { name, ecosystem: "npm" },
    }),
  });

  if (!response.ok) {
    throw new Error(`OSV.dev returned HTTP ${response.status} for "${name}@${version}"`);
  }

  const data = (await response.json()) as OsvQueryResponse;
  return (data.vulns ?? []).map((v) => mapOsvVuln(name, v));
}

function mapGhsaAdvisory(name: string, advisory: GhsaAdvisory): Vulnerability {
  const match = advisory.vulnerabilities?.find((v) => v.package?.name === name) ?? advisory.vulnerabilities?.[0];
  return {
    id: advisory.ghsa_id,
    source: "ghsa",
    summary: advisory.summary ?? advisory.description ?? "No summary available",
    severity: normalizeGhsaSeverity(advisory.severity),
    affectedVersions: match?.vulnerable_version_range ?? null,
    fixedVersion: match?.first_patched_version ?? null,
    references: advisory.html_url ? [advisory.html_url] : [],
  };
}

export async function fetchGhsaVulnerabilities(name: string, version: string): Promise<Vulnerability[]> {
  logger.debug("Querying GitHub Advisory API", { package: name, version });

  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "codebase-health-intelligence/1.0",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (process.env.GITHUB_TOKEN) {
    headers["Authorization"] = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  const url = `${GHSA_ADVISORIES_URL}?ecosystem=npm&affects=${encodeURIComponent(name)}&per_page=100`;
  const response = await fetchWithRetry(url, { headers });

  if (response.status === 404) return [];

  if (!response.ok) {
    throw new Error(`GitHub Advisory API returned HTTP ${response.status} for "${name}"`);
  }

  const advisories = (await response.json()) as GhsaAdvisory[];
  return advisories.map((a) => mapGhsaAdvisory(name, a));
}

function dedupeVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
  const byId = new Map<string, Vulnerability>();
  for (const vuln of vulns) {
    const existing = byId.get(vuln.id);
    if (!existing) {
      byId.set(vuln.id, vuln);
    }
  }
  return [...byId.values()];
}

/**
 * Fetches known vulnerabilities for a single package/version from both
 * OSV.dev and the GitHub Advisory API, merging and de-duplicating results.
 * Cached for CACHE_TTL_MS per process, keyed by `name@version`.
 *
 * Throws if both upstream sources fail — callers are expected to catch this
 * and mark the package as "unknown" rather than aborting the whole scan
 * (see core/analyzer.ts's fallbackResult pattern).
 */
export async function fetchVulnerabilities(name: string, version: string): Promise<Vulnerability[]> {
  const key = cacheKey(name, version);
  const cached = cache.get(key);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.data;
  }

  const [osvResult, ghsaResult] = await Promise.allSettled([
    fetchOsvVulnerabilities(name, version),
    fetchGhsaVulnerabilities(name, version),
  ]);

  if (osvResult.status === "rejected" && ghsaResult.status === "rejected") {
    const message =
      osvResult.reason instanceof Error ? osvResult.reason.message : String(osvResult.reason);
    throw new Error(`Failed to fetch vulnerability data for "${name}@${version}": ${message}`);
  }

  if (osvResult.status === "rejected") {
    logger.warn("OSV.dev lookup failed, continuing with GHSA results only", {
      package: name,
      version,
      error: osvResult.reason instanceof Error ? osvResult.reason.message : String(osvResult.reason),
    });
  }
  if (ghsaResult.status === "rejected") {
    logger.warn("GitHub Advisory lookup failed, continuing with OSV results only", {
      package: name,
      version,
      error: ghsaResult.reason instanceof Error ? ghsaResult.reason.message : String(ghsaResult.reason),
    });
  }

  const combined = dedupeVulnerabilities([
    ...(osvResult.status === "fulfilled" ? osvResult.value : []),
    ...(ghsaResult.status === "fulfilled" ? ghsaResult.value : []),
  ]);

  cache.set(key, { data: combined, fetchedAt: Date.now() });
  return combined;
}
