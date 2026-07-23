// src/core/osv.ts
import { z } from 'zod';
import { BoundedCache } from '../lib/bounded-cache.js';
import { fetchWithRetry } from '../lib/fetch-with-retry.js';
import { logger } from '../lib/logger.js';

const OSV_API_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 1000;
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

const VulnerabilitySchema = z.object({
  id: z.string(),
  summary: z.string().optional(),
  details: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  modified: z.string(),
  published: z.string(),
  database_specific: z.any().optional(),
  references: z.array(z.object({
    type: z.string(),
    url: z.string(),
  })).optional(),
  severity: z.array(z.object({
    type: z.string(),
    score: z.string(),
  })).optional(),
  affected: z.array(z.object({
    package: z.object({
      name: z.string(),
      ecosystem: z.string(),
      purl: z.string().optional(),
    }),
    ranges: z.array(z.object({
      type: z.string(),
      repo: z.string().optional(),
      events: z.array(z.object({
        introduced: z.string().optional(),
        fixed: z.string().optional(),
        last_affected: z.string().optional(),
        limit: z.string().optional(),
      })),
    })),
    versions: z.array(z.string()).optional(),
    database_specific: z.any().optional(),
    ecosystem_specific: z.any().optional(),
  })),
});

const OsvApiResponseSchema = z.object({
  results: z.array(z.object({
    vulns: z.array(VulnerabilitySchema).optional(),
  })),
});

export type Vulnerability = z.infer<typeof VulnerabilitySchema>;

const cache = new BoundedCache<Vulnerability[]>(100, CACHE_TTL_MS);

async function queryOsv(queries: { package: { name: string; ecosystem: 'npm' }; version: string }[]): Promise<Vulnerability[]> {
  if (queries.length === 0) {
    return [];
  }

  const cacheKey = JSON.stringify(queries);
  const cached = cache.get(cacheKey);
  if (cached) {
    logger.info(`[OSV] Cache hit for ${queries.length} packages.`);
    return cached;
  }

  logger.info(`[OSV] Querying for ${queries.length} packages.`);

  try {
    const response = await fetchWithRetry(OSV_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
    });

    if (!response.ok) {
      logger.error(`[OSV] API request failed with status ${response.status}: ${await response.text()}`);
      return [];
    }

    const rawData = await response.json();
    const parsed = OsvApiResponseSchema.safeParse(rawData);

    if (!parsed.success) {
      logger.error(`[OSV] Failed to parse API response: ${parsed.error.message}`);
      return [];
    }

    const vulnerabilities = parsed.data.results.flatMap(r => r.vulns || []);
    cache.set(cacheKey, vulnerabilities);
    return vulnerabilities;
  } catch (error) {
    logger.error('[OSV] Network or other error fetching vulnerabilities.', { error });
    return [];
  }
}

export async function getVulnerabilitiesForPackages(packages: { name: string; version: string }[]): Promise<Vulnerability[]> {
  const allVulnerabilities: Vulnerability[] = [];
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE).map(p => ({
      package: { name: p.name, ecosystem: 'npm' as const },
      version: p.version,
    }));
    const vulnerabilities = await queryOsv(batch);
    allVulnerabilities.push(...vulnerabilities);
  }
  return allVulnerabilities;
}