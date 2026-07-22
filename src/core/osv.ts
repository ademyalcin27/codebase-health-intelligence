import { fetchWithRetry } from "../lib/fetch-with-retry.js";
import { BoundedCache } from "../lib/bounded-cache.js";
import { logger } from "../lib/logger.js";

// ─── OSV.dev endpoints ────────────────────────────────────────────────────────

const OSV_BASE = "https://api.osv.dev";
const OSV_QUERY_BATCH_URL = `${OSV_BASE}/v1/querybatch`;
const OSV_QUERY_URL = `${OSV_BASE}/v1/query`;
const OSV_VULN_URL = (id: string) => `${OSV_BASE}/v1/vulns/${encodeURIComponent(id)}`;

// ─── Cache (process-scoped Map, 10-min TTL, matches existing pattern) ─────────
// Declared after the VulnerabilityFinding type below; see `const cache`.

// ─── Types ────────────────────────────────────────────────────────────────────

/** A dependency reference: an npm package name and a (resolved) version. */
export interface OsvPackageRef {
  name: string;
  version: string;
  /** ecosystem, defaults to "npm" when omitted */
  ecosystem?: string;
}

/** OSV severity vector. */
export interface OsvSeverity {
  type: string; // e.g. "CVSS", "CVSS_V3", "CVSS_V4"
  score: string; // e.g. "CVSS:3.1/AV:N/..." or numeric string
}

/** A single OSV "affected" entry. */
export interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: Array<{
    type: string; // "SEMVER" | "ECOSYSTEM" | "GIT"
    events: Array<Record<string, string>>; // {introduced}, {fixed}, {last_affected}
    repo?: string;
  }>;
  ecosystem_specific?: Record<string, unknown>;
  database_specific?: Record<string, unknown>;
  versions?: string[];
}

/** The subset of an OSV vulnerability record we consume. */
export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[]; // CVE IDs, alternative GHSA IDs, etc.
  affected?: OsvAffected[];
  severity?: OsvSeverity[];
  database_specific?: Record<string, unknown>;
  references?: Array<{ type: string; url: string }>;
  published?: string;
  modified?: string;
}

/** OSV /v1/querybatch response wrapper. */
interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVulnerability[] } | null>;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function cacheKey(ref: OsvPackageRef): string {
  const eco = (ref.ecosystem ?? "npm").toLowerCase();
  return `${eco}:${ref.name}@${ref.version}`;
}

/** Public alias of the cache key used by the OSV module, for callers that need
 *  to look up results returned by `queryOsvBatched`. */
export function osvCacheKey(ref: OsvPackageRef): string {
  return cacheKey(ref);
}

/** Build a single OSV query body for one package/version pair. */
function buildQueryBody(ref: OsvPackageRef): Record<string, unknown> {
  const ecosystem = ref.ecosystem ?? "npm";
  return {
    package: { name: ref.name, ecosystem },
    version: ref.version,
  };
}

/**
 * Pull the most informative ID from an OSV record. Prefers CVE/GHSA aliases
 * (which users recognize) over the internal OSV id.
 */
function pickId(vuln: OsvVulnerability): string {
  const al = vuln.aliases ?? [];
  const cve = al.find((a) => /^CVE-\d+-\d+$/i.test(a));
  if (cve) return cve;
  const ghsa = al.find((a) => /^GHSA(-[a-z0-9]{4}){3}$/i.test(a));
  if (ghsa) return ghsa;
  if (al.length > 0) return al[0];
  return vuln.id;
}

/** Collect all known IDs (CVE/GHSA aliases + the OSV id) for a record. */
function collectIds(vuln: OsvVulnerability): string[] {
  const ids = new Set<string>();
  ids.add(vuln.id);
  for (const a of vuln.aliases ?? []) ids.add(a);
  return [...ids];
}

/** Parse a CVSS vector string into a numeric score (0–10). */
function cvssVectorToScore(vector: string): number | null {
  // OSV sometimes carries a bare numeric score string instead of a vector.
  const asNum = Number(vector);
  if (!Number.isNaN(asNum) && asNum >= 0 && asNum <= 10) return asNum;

  // CVSS:3.1/AV:N/AC:L/... — extract base score via the standard formula.
  const parts = vector.split("/");
  if (parts.length === 0) return null;

  // crude heuristic: look for an explicit "AV"/"AC"/"PR"/"UI"/"C"/"I"/"A"
  // and compute the base metric. If we cannot parse confidently, return null.
  const get = (k: string): string | undefined =>
    parts.find((p) => p.startsWith(`${k}:`))?.split(":")[1];

  const av = get("AV");
  const ac = get("AC");
  const pr = get("PR");
  const ui = get("UI");
  const c = get("C");
  const i = get("I");
  const a = get("A");
  if (!av || !ac || !pr || !ui || !c || !i || !a) return null;

  // Standard CVSS 3.1 lookup tables
  const avValue: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const acValue: Record<string, number> = { L: 0.77, H: 0.44 };
  const uiValue: Record<string, number> = { N: 0.85, R: 0.56 };

  const scope = get("S") ?? "U";
  const prValueScopeU: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };

  const ciaValue: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

  const iss =
    1 - ((1 - ciaValue[c]!) * (1 - ciaValue[i]! as number) * (1 - ciaValue[a]! as number));

  const isScopeChanged = scope === "C";
  const impact = isScopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    : 6.42 * iss;

  const exploitability =
    8.22 * avValue[av]! * acValue[ac]! * prValueScopeU[pr]! * uiValue[ui]!;

  const base = isScopeChanged
    ? exploitability >= impact
      ? impact
      : Math.min(impact, exploitability)
    : Math.min(impact + exploitability, 10);

  const rounded = Math.ceil(base * 10) / 10;
  return rounded;
}

/**
 * Determine severity level from an OSV record. Uses CVSS score when available,
 * otherwise falls back to a database_specific severity string, then "unknown".
 */
export type OsvSeverityLevel = "critical" | "high" | "medium" | "low" | "unknown";

export function severityFromVuln(vuln: OsvVulnerability): OsvSeverityLevel {
  // 1. CVSS vectors
  for (const s of vuln.severity ?? []) {
    const score = cvssVectorToScore(s.score);
    if (score !== null) return scoreToLevel(score);
  }

  // 2. database_specific severity string (GitHub Advisory provides e.g. "MODERATE")
  const dbSpecific = vuln.database_specific;
  if (dbSpecific && typeof dbSpecific === "object") {
    const sev = (dbSpecific as Record<string, unknown>)["severity"];
    if (typeof sev === "string") {
      const level = severityStringToLevel(sev);
      if (level !== "unknown") return level;
    }
  }

  return "unknown";
}

function scoreToLevel(score: number): OsvSeverityLevel {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "unknown";
}

function severityStringToLevel(sev: string): OsvSeverityLevel {
  const s = sev.trim().toUpperCase();
  if (s === "CRITICAL") return "critical";
  if (s === "HIGH") return "high";
  if (s === "MODERATE" || s === "MEDIUM") return "medium";
  if (s === "LOW") return "low";
  return "unknown";
}

/** Extract the affected version range(s) for a given package from a vuln. */
function extractVersionRange(
  vuln: OsvVulnerability,
  ref: OsvPackageRef
): string | null {
  const eco = ref.ecosystem ?? "npm";
  for (const aff of vuln.affected ?? []) {
    if (aff.package?.ecosystem && aff.package.ecosystem !== eco) continue;
    if (aff.package?.name && aff.package.name !== ref.name) continue;

    for (const range of aff.ranges ?? []) {
      if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") continue;
      const parts: string[] = [];
      for (const ev of range.events) {
        if (ev["introduced"]) parts.push(`>= ${ev["introduced"]}`);
        if (ev["fixed"]) parts.push(`< ${ev["fixed"]}`);
        if (ev["last_affected"]) parts.push(`<= ${ev["last_affected"]}`);
      }
      if (parts.length > 0) return parts.join(", ");
    }

    // Fall back to explicit versions list
    if (aff.versions && aff.versions.length > 0) {
      return aff.versions.join(", ");
    }
  }
  return null;
}

/** Extract the first fixed version available for a given package from a vuln. */
function extractFixedVersion(
  vuln: OsvVulnerability,
  ref: OsvPackageRef
): string | null {
  const eco = ref.ecosystem ?? "npm";
  for (const aff of vuln.affected ?? []) {
    if (aff.package?.ecosystem && aff.package.ecosystem !== eco) continue;
    if (aff.package?.name && aff.package.name !== ref.name) continue;
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events) {
        if (ev["fixed"]) return ev["fixed"];
      }
    }
  }
  return null;
}

/** Extract a numeric CVSS score (0–10) if available. */
function extractCvssScore(vuln: OsvVulnerability): number | null {
  for (const s of vuln.severity ?? []) {
    const score = cvssVectorToScore(s.score);
    if (score !== null) return score;
  }
  return null;
}

// ─── Normalized output ────────────────────────────────────────────────────────

export interface VulnerabilityFinding {
  /** The OSV id (or chosen CVE/GHSA id if more user-friendly). */
  id: string;
  /** All IDs associated with the vuln (OSV id + CVE/GHSA aliases). */
  aliases: string[];
  /** The CVE/GHSA ID most relevant for display. */
  cveOrGhsaId: string;
  package: string;
  version: string;
  /** Affected version range (e.g. ">= 1.0.0, < 1.2.3"). */
  affectedRange: string | null;
  severity: OsvSeverityLevel;
  cvssScore: number | null;
  fixedVersion: string | null;
  summary: string | null;
  url: string | null;
}

// Process-scoped cache of normalized findings, keyed by `ecosystem:name@version`.
const cache = new BoundedCache<VulnerabilityFinding[]>(500, 10 * 60 * 1000);

// Process-scoped cache of full OSV vulnerability records, keyed by vuln id.
// /v1/querybatch only returns minimal records (id + modified), so each id is
// hydrated via /v1/vulns/{id}; these are shared across packages and cached.
const vulnRecordCache = new BoundedCache<OsvVulnerability>(2000, 10 * 60 * 1000);
const vulnRecordInflight = new Map<string, Promise<OsvVulnerability | null>>();

/** Fetch the full record for a single OSV vulnerability id (cache-aware). */
async function fetchVulnRecord(id: string): Promise<OsvVulnerability | null> {
  const cached = vulnRecordCache.get(id);
  if (cached) return cached;

  const existing = vulnRecordInflight.get(id);
  if (existing) return existing;

  const promise = (async () => {
    try {
      const res = await fetchWithRetry(OSV_VULN_URL(id), {
        headers: { Accept: "application/json" },
      });
      if (!res.ok) {
        logger.warn("OSV vuln detail fetch returned non-OK", { id, status: res.status });
        return null;
      }
      const data = (await res.json()) as OsvVulnerability;
      vulnRecordCache.set(id, data);
      return data;
    } catch (err) {
      logger.warn("OSV vuln detail fetch failed", {
        id,
        error: err instanceof Error ? err.message : String(err),
      });
      return null;
    } finally {
      vulnRecordInflight.delete(id);
    }
  })();

  vulnRecordInflight.set(id, promise);
  return promise;
}

/**
 * Hydrate a list of minimal batch-returned vuln records (id + modified only)
 * into full records via /v1/vulns/{id}. Returns the full records in order;
 * entries whose detail fetch failed are omitted.
 *
 * Fetches are throttled in sub-batches of `detailBatchSize` to avoid
 * overwhelming the API.
 */
async function hydrateVulnRecords(
  minimal: OsvVulnerability[],
  detailBatchSize = 20
): Promise<OsvVulnerability[]> {
  const out: OsvVulnerability[] = [];
  for (let i = 0; i < minimal.length; i += detailBatchSize) {
    const slice = minimal.slice(i, i + detailBatchSize);
    const detailed = await Promise.all(
      slice.map((m) => fetchVulnRecord(m.id))
    );
    for (const d of detailed) {
      if (d) out.push(d);
    }
  }
  return out;
}

/** Normalize a raw OSV record into a finding scoped to a specific package ref. */
export function normalizeVuln(
  vuln: OsvVulnerability,
  ref: OsvPackageRef
): VulnerabilityFinding {
  const url = vuln.references?.find((r) => r.type === "ADVISORY")?.url
    ?? (vuln.references && vuln.references.length > 0 ? vuln.references[0]!.url : null)
    ?? `https://osv.dev/vulnerability/${vuln.id}`;

  return {
    id: vuln.id,
    aliases: collectIds(vuln),
    cveOrGhsaId: pickId(vuln),
    package: ref.name,
    version: ref.version,
    affectedRange: extractVersionRange(vuln, ref),
    severity: severityFromVuln(vuln),
    cvssScore: extractCvssScore(vuln),
    fixedVersion: extractFixedVersion(vuln, ref),
    summary: vuln.summary ?? null,
    url,
  };
}

// ─── Batch query (the main entry point) ───────────────────────────────────────

/** Fetch vulnerabilities for a batch of package/version refs (max 1000 per OSV spec). */
async function queryBatchUncached(refs: OsvPackageRef[]): Promise<Map<string, VulnerabilityFinding[]>> {
  // Filter cached entries first; only query the rest.
  const toQuery: OsvPackageRef[] = [];
  const results = new Map<string, VulnerabilityFinding[]>();

  for (const ref of refs) {
    const key = cacheKey(ref);
    const cached = cache.get(key);
    if (cached) {
      results.set(key, cached);
    } else {
      toQuery.push(ref);
    }
  }

  if (toQuery.length === 0) return results;

  logger.debug("Querying OSV.dev batch", { count: toQuery.length });

  const body = JSON.stringify({
    queries: toQuery.map(buildQueryBody),
  });

  let res;
  try {
    res = await fetchWithRetry(OSV_QUERY_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
  } catch (err) {
    // Single-package fallback path — keeps partial progress even if batch fails.
    logger.warn("OSV batch query failed, falling back to per-package queries", {
      error: err instanceof Error ? err.message : String(err),
    });
    for (const ref of toQuery) {
      const key = cacheKey(ref);
      try {
        const single = await querySingle(ref);
        results.set(key, single);
        cache.set(key, single);
      } catch (innerErr) {
        logger.warn("OSV single query failed", {
          package: ref.name,
          version: ref.version,
          error: innerErr instanceof Error ? innerErr.message : String(innerErr),
        });
        results.set(key, []);
        cache.set(key, []);
      }
    }
    return results;
  }

  if (!res.ok) {
    throw new Error(`OSV querybatch returned HTTP ${res.status}`);
  }

  const data = (await res.json()) as OsvBatchResponse;
  const batchResults = data.results ?? [];

  for (let i = 0; i < toQuery.length; i++) {
    const ref = toQuery[i]!;
    const key = cacheKey(ref);
    const entry = batchResults[i];
    // /v1/querybatch returns only minimal records (id + modified). Hydrate
    // each into a full record so we can extract aliases/affected/severity.
    const minimal = entry?.vulns ?? [];
    const detailed = await hydrateVulnRecords(minimal);
    const findings = detailed.map((v) => normalizeVuln(v, ref));
    results.set(key, findings);
    cache.set(key, findings);
  }

  return results;
}

/** Fallback single-package query against /v1/query. */
async function querySingle(ref: OsvPackageRef): Promise<VulnerabilityFinding[]> {
  const body = JSON.stringify(buildQueryBody(ref));
  const res = await fetchWithRetry(OSV_QUERY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  if (!res.ok) {
    throw new Error(`OSV query returned HTTP ${res.status}`);
  }
  const data = (await res.json()) as { vulns?: OsvVulnerability[] };
  return (data.vulns ?? []).map((v) => normalizeVuln(v, ref));
}

/**
 * Query OSV.dev for vulnerabilities for a list of package/version refs,
 * honoring the given batch size. Returns a map keyed by `ecosystem:name@version`.
 *
 * On network failure for the entire batch, an Error is thrown — callers should
 * catch it and degrade gracefully per-package.
 */
export async function queryOsvBatched(
  refs: OsvPackageRef[],
  batchSize = 1000
): Promise<Map<string, VulnerabilityFinding[]>> {
  const merged = new Map<string, VulnerabilityFinding[]>();
  for (let i = 0; i < refs.length; i += batchSize) {
    const slice = refs.slice(i, i + batchSize);
    const partial = await queryBatchUncached(slice);
    for (const [k, v] of partial) merged.set(k, v);
  }
  return merged;
}

/** Look up a single package's findings (cache-aware). */
export async function queryOsv(ref: OsvPackageRef): Promise<VulnerabilityFinding[]> {
  const key = cacheKey(ref);
  const cached = cache.get(key);
  if (cached) return cached;
  const map = await queryOsvBatched([ref]);
  return map.get(key) ?? [];
}
