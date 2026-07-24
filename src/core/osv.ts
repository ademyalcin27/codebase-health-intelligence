
import { BoundedCache } from "../lib/bounded-cache.js";
import { fetchWithRetry } from "../lib/fetch-with-retry.js";
import { logger } from "../lib/logger.js";

const OSV_API_URL = "https://api.osv.dev/v1/querybatch";
const CACHE_MAX_SIZE = 100;
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

const cache = new BoundedCache<OsvVulnerability[]>(CACHE_MAX_SIZE, CACHE_TTL_MS);

export interface OsvVulnerability {
  id: string;
  summary: string;
  details: string;
  affected: {
    package: {
      name: string;
      ecosystem: string;
    };
    versions: string[];
  }[];
  references: {
    type: string;
    url: string;
  }[];
  severity?: {
    type: string;
    score: string;
  }[];
}

export interface OsvQueryResult {
  vulns: OsvVulnerability[];
}

export interface OsvBatchQueryResult {
  results: OsvQueryResult[];
}

async function queryOsvApi(packages: { name: string; version?: string }[]): Promise<OsvBatchQueryResult> {
  const queries = packages.map(pkg => ({
    package: {
      name: pkg.name,
      ecosystem: "npm",
    },
    version: pkg.version,
  }));

  const response = await fetchWithRetry(OSV_API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    logger.error("OSV API error", { status: response.status, text: errorText });
    throw new Error(`OSV API request failed with status ${response.status}`);
  }

  return response.json() as Promise<OsvBatchQueryResult>;
}

export async function queryOsv(
  packages: { name: string; version?: string }[]
): Promise<Map<string, OsvVulnerability[]>> {
  const results = new Map<string, OsvVulnerability[]>();
  const notInCache: { name: string; version?: string }[] = [];

  for (const pkg of packages) {
    const cacheKey = `${pkg.name}@${pkg.version ?? "latest"}`;
    const cached = cache.get(cacheKey);
    if (cached) {
      results.set(pkg.name, cached);
    } else {
      notInCache.push(pkg);
    }
  }

  if (notInCache.length > 0) {
    logger.info("Querying OSV for packages not in cache", { count: notInCache.length });
    const batchResult = await queryOsvApi(notInCache);
    for (let i = 0; i < notInCache.length; i++) {
      const pkg = notInCache[i];
      const res = batchResult.results[i];
      const vulns = res?.vulns ?? [];
      const cacheKey = `${pkg.name}@${pkg.version ?? "latest"}`;
      cache.set(cacheKey, vulns);
      results.set(pkg.name, vulns);
    }
  }

  return results;
}
