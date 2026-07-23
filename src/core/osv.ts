
import { z } from 'zod';

import { BoundedCache } from '../lib/bounded-cache.js';
import { fetchWithRetry } from '../lib/fetch-with-retry.js';

// https://osv.dev/docs/#tag/osv/operation/OSV_QueryBatch
const OSV_API_URL = 'https://api.osv.dev/v1/querybatch';

const osvVulnerabilitySchema = z.object({
  id: z.string(),
  summary: z.string(),
  details: z.string(),
  aliases: z.array(z.string()),
  modified: z.string(),
  published: z.string(),
  database_specific: z.object({
    severity: z.string(),
  }).nullable(),
  references: z.array(z.object({
    type: z.string(),
    url: z.string(),
  })),
});

const osvResponseSchema = z.object({
  results: z.array(z.object({
    vulns: z.array(osvVulnerabilitySchema),
  })),
});

export type OsvVulnerability = z.infer<typeof osvVulnerabilitySchema>;

// Process-scoped cache with a 10-minute TTL.
const cache = new BoundedCache<OsvVulnerability[]>({ ttl: 1000 * 60 * 10 });

/**
 * Queries the OSV.dev API for known vulnerabilities in a batch of packages.
 *
 * @param packages - A map of package names to their versions.
 * @returns A map of package names to their vulnerabilities.
 */
export async function queryBatch(packages: Map<string, string>): Promise<Map<string, OsvVulnerability[] | 'unknown'>> {
  const results = new Map<string, OsvVulnerability[] | 'unknown'>();
  const queries: { package: { name: string, ecosystem: 'npm' }, version: string }[] = [];

  for (const [pkg, version] of packages.entries()) {
    const cacheKey = `${pkg}@${version}`;
    const cached = cache.get(cacheKey);
    if (cached) {
      results.set(pkg, cached);
    } else {
      queries.push({
        package: { name: pkg, ecosystem: 'npm' },
        version,
      });
    }
  }

  if (queries.length === 0) {
    return results;
  }

  try {
    const response = await fetchWithRetry(OSV_API_URL, {
      method: 'POST',
      body: JSON.stringify({ queries }),
    });

    if (!response.ok) {
      console.error(`OSV API request failed with status: ${response.status}`);
      for (const query of queries) {
        results.set(query.package.name, 'unknown');
      }
      return results;
    }

    const data = await response.json();
    const parsed = osvResponseSchema.parse(data);

    for (let i = 0; i < queries.length; i++) {
      const query = queries[i];
      const pkg = query.package.name;
      const version = query.version;
      const cacheKey = `${pkg}@${version}`;
      const vulns = parsed.results[i]?.vulns ?? [];
      
      cache.set(cacheKey, vulns);
      results.set(pkg, vulns);
    }
  } catch (error) {
    console.error('Error querying OSV API:', error);
    for (const query of queries) {
      results.set(query.package.name, 'unknown');
    }
  }

  return results;
}
