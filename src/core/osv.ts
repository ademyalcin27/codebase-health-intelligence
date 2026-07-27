
import { BoundedCache } from '../lib/bounded-cache.js';
import { fetchWithRetry } from '../lib/fetch-with-retry.js';
import { logger } from '../lib/logger.js';
import { Vulnerability } from '../types.js';

const OSV_API_URL = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;

// Process-scoped cache for OSV API responses.
const cache = new BoundedCache<Vulnerability[]>(1000, 10 * 60 * 1000);

/**
 * Queries the OSV.dev API for vulnerabilities for a given set of packages.
 * @param packages A map of package names to their versions.
 * @returns A map of package names to a list of vulnerabilities.
 */
export async function getVulnerabilitiesForPackages(
  packages: Map<string, string>
): Promise<Map<string, Vulnerability[]>> {
  const results = new Map<string, Vulnerability[]>();
  const packagesToQuery: { package: { name: string; ecosystem: string }; version: string }[] = [];

  for (const [name, version] of packages.entries()) {
    const cacheKey = `${name}@${version}`;
    const cached = cache.get(cacheKey);
    if (cached) {
      results.set(name, cached);
    } else {
      packagesToQuery.push({
        package: { name, ecosystem: 'npm' },
        version,
      });
    }
  }

  if (packagesToQuery.length === 0) {
    return results;
  }

  logger.info(`Querying OSV.dev for ${packagesToQuery.length} packages...`);

  try {
    for (let i = 0; i < packagesToQuery.length; i += BATCH_SIZE) {
      const batch = packagesToQuery.slice(i, i + BATCH_SIZE);
      const response = await fetchWithRetry(`${OSV_API_URL}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries: batch }),
      });

      if (!response.ok) {
        logger.warn(`OSV.dev API request failed with status ${response.status}`);
        // Mark all packages in the batch as "unknown"
        for (const pkg of batch) {
          results.set(pkg.package.name, []);
        }
        continue;
      }

      const data = await response.json() as { results: { vulns?: any[] }[] };

      for (let j = 0; j < batch.length; j++) {
        const pkg = batch[j];
        const res = data.results[j];
        const cacheKey = `${pkg.package.name}@${pkg.version}`;

        if (res && res.vulns) {
          const vulns = res.vulns.map((v: any) => ({
            id: v.id,
            summary: v.summary,
            details: v.details,
            affected: v.affected,
            references: v.references,
            severity: v.database_specific?.severity || 'UNKNOWN',
          }));
          results.set(pkg.package.name, vulns);
          cache.set(cacheKey, vulns);
        } else {
          results.set(pkg.package.name, []);
          cache.set(cacheKey, []);
        }
      }
    }
  } catch (error) {
    logger.error('Error querying OSV.dev API:', { error: (error as Error).message });
    // Mark all remaining packages as "unknown"
    for (const pkg of packagesToQuery) {
      if (!results.has(pkg.package.name)) {
        results.set(pkg.package.name, []);
      }
    }
  }

  return results;
}
